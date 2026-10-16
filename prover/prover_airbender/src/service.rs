use z6m_common::{EthProofsConfig, EthproofsClient};

use crate::guest::{Guest, GuestFiles};
use crate::prove::{BlockProver, ProverSettings, MAX_PROVABLE_CYCLES};
use eyre::{bail, Result};
use prover_pipeline::ProverBackend;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};
use url::Url;
use z6m_common::alloy_provider::{Provider, ProviderBuilder};
use z6m_common::{fetch_block_and_witness, FetchRequest};

/// Capacity of the fetcher → prover-worker work queue.
///
/// At most this many pre-fetched blocks can sit on disk (their MFBD flat-bundle
/// files already written) before the fetcher backpressures on
/// `tx.send().await`. Raising this lets the fetcher get further ahead when
/// the GPU is the bottleneck; each in-flight item costs one MFBD flat-bundle
/// file under `data_dir`.
const PROVER_QUEUE_CAPACITY: usize = 4;

/// The longest an `eth_blockNumber` call, and the newHeads subscription at startup, may take:
/// the RPC clients have no timeout of their own, so a node that stops answering would hold the
/// fetcher forever.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub prove_every: Option<u64>,
    pub execute_every: Option<u64>,
    pub post_every: Option<u64>,
    pub rpc_url: String,
    /// Optional WebSocket endpoint for newHeads push notifications.
    /// When set, the fetcher wakes on new blocks instead of polling.
    pub ws_url: Option<String>,
    pub save_all_responses: bool,
    pub data_dir: PathBuf,
    pub output_dir: PathBuf,
    pub guest: GuestFiles,
    pub max_cycles: usize,
    /// The prover's trace replay threads (None: the backend's default).
    pub replay_threads: Option<usize>,
    pub gpu: bool,
    pub ethproofs: Option<EthProofsConfig>,
    /// The longest one attempt at fetching a block (the block, its RLP and its execution
    /// witness) may take before it counts as failed.
    pub fetch_timeout: Duration,
    /// Once the fetcher has reached the chain tip, the most blocks it may fall behind before it
    /// skips ahead to the tip; 0 never skips.
    pub max_lag: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvingLog {
    pub block_number: u64,
    pub gas_used: u64,
    pub cycle_count: u64,
    pub num_proofs: usize,
    pub proving_millis: u64,
    pub message: String,
}

/// One unit of work handed from the fetcher to the prover worker.
///
/// The MFBD flat bundle is already on disk at `bundle_path` when the item is
/// enqueued; only the path travels through the channel to keep queue
/// memory bounded.
#[derive(Debug)]
struct WorkItem {
    block_number: u64,
    bundle_path: PathBuf,
    execute: bool,
    prove: bool,
    /// The block's Ethproofs `queued` post, sent when the fetcher picks the block, which its
    /// `proving` post waits for: the posts are background tasks, and one that lands late would
    /// move the block's status back.
    queued_post: Option<tokio::task::JoinHandle<()>>,
    /// The block's preflight run, which the fetcher makes as soon as the bundle exists, before
    /// enqueueing the block; None with Z6M_CONCURRENT_PREFLIGHT, where the worker runs it
    /// alongside proving.
    preflight: Option<Result<VmRunOutcome>>,
}

pub struct AirbenderService {
    config: ServiceConfig,
    eth_client: Option<Arc<EthproofsClient>>,
    /// The prover, built once and reused for every block (rebuilt after a panic). Only the
    /// prover worker uses it.
    prover: Option<Arc<Mutex<BlockProver>>>,
    /// The guest, decoded once for simulator runs (preflight and execute-only).
    guest: Arc<Guest>,
    /// A block's preflight completes before its proving starts, unless
    /// Z6M_CONCURRENT_PREFLIGHT is set (see `prove_item`).
    serial_preflight: bool,
}

/// Result of running a block through the VM simulator (no proving).
#[derive(Debug)]
struct VmRunOutcome {
    /// The input's gas used once the guest's public output has matched the input; 0 when the
    /// guest did not finish successfully.
    gas_used: u64,
    cycle_count: u64,
    reached_end: bool,
    final_pc: u32,
    elapsed_secs: f64,
}

impl VmRunOutcome {
    /// The guest signals success by parking in the EXIT_SEQUENCE self-loop;
    /// a validation failure parks in `finish_error`'s loop at a different PC.
    fn succeeded(&self, exit_pc: u32) -> bool {
        self.reached_end && self.final_pc == exit_pc
    }
}

impl AirbenderService {
    pub fn new(config: ServiceConfig) -> Result<Self> {
        info!("Guest binary: {}", config.guest.bin.display());

        // Decode the guest once for simulator runs (preflight and execute-only runs), and
        // locate the canonical exit point so runs that take the finish_error path can be
        // recognized.
        let guest = Arc::new(Guest::load(config.guest.clone())?);
        info!("Guest exit sequence PC: 0x{:08x}", guest.exit_pc);

        let eth_client = config
            .ethproofs
            .clone()
            .map(|c| Arc::new(EthproofsClient::new(c)));

        // Build the prover once; every block reuses it.
        let prover = if config.gpu {
            crate::vk::check_recursion_environment()?;
            info!("Building the GPU prover (one-time; {})", crate::fsv_dir_note());
            let settings = ProverSettings::new(
                config.guest.clone(),
                ProverBackend::Gpu,
                config.max_cycles,
                config.replay_threads,
            )?;
            Some(Arc::new(Mutex::new(BlockProver::new(settings)?)))
        } else {
            if config.prove_every.is_some() {
                bail!("--prove-every needs --gpu");
            }
            None
        };

        Ok(Self {
            config,
            eth_client,
            prover,
            guest,
            serial_preflight: std::env::var("Z6M_CONCURRENT_PREFLIGHT").is_err(),
        })
    }

    fn format_timestamp() -> String {
        chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string()
    }

    /// Run the service.
    ///
    /// Topology:
    /// - A **fetcher** task walks block numbers, pulls each one off the RPC,
    ///   writes the MFBD flat bundle to disk, runs the block's preflight, and
    ///   pushes a `WorkItem` into a bounded channel. It fires
    ///   `ethproofs.queued(block)` as a background `tokio::spawn` so the
    ///   fetcher never waits on HTTP.
    /// - A **prover worker** task drains the channel, running execute
    ///   and/or prove for each item. `ethproofs.proving(block)` and
    ///   `.proved(..)` are both spawned background tasks so the worker
    ///   immediately picks up the next item once the GPU returns.
    ///
    /// Fetching is therefore independent of the GPU: while a proof is
    /// running, the fetcher can pre-queue up to `PROVER_QUEUE_CAPACITY`
    /// blocks, preflights done. If the fetcher gets ahead, `tx.send().await`
    /// backpressures naturally.
    pub async fn run(self) -> Result<()> {
        info!("Starting airbender service (pipelined fetch / prove)");
        let me = Arc::new(self);
        let (tx, rx) = mpsc::channel::<WorkItem>(PROVER_QUEUE_CAPACITY);

        let fetcher = tokio::spawn({
            let me = Arc::clone(&me);
            async move { me.fetcher_loop(tx).await }
        });
        let worker = tokio::spawn({
            let me = Arc::clone(&me);
            async move { me.prover_worker_loop(rx).await }
        });

        let (fr, wr) = tokio::join!(fetcher, worker);
        fr.map_err(|e| eyre::eyre!("fetcher task panicked: {e}"))??;
        wr.map_err(|e| eyre::eyre!("prover worker task panicked: {e}"))??;
        Ok(())
    }

    /// Walk blocks forward, fetch each one, and enqueue work items.
    ///
    /// Never blocks on proving. Ethproofs `queued` is fired as a detached
    /// background task so a slow HTTP response can't stall the fetch loop.
    async fn fetcher_loop(self: Arc<Self>, tx: mpsc::Sender<WorkItem>) -> Result<()> {
        let url = Url::parse(&self.config.rpc_url)?;
        let provider = ProviderBuilder::new().connect_http(url);

        // Optional newHeads subscription: wake on push instead of polling.
        // Any failure falls back to the polling loop below.
        let mut new_heads = match &self.config.ws_url {
            Some(ws_url) => {
                let subscribe = async {
                    let connect = z6m_common::alloy_provider::WsConnect::new(ws_url.clone());
                    let ws_provider = ProviderBuilder::new().connect_ws(connect).await?;
                    let sub = ws_provider.subscribe_blocks().await?;
                    // keep the provider alive alongside the subscription
                    Ok::<_, eyre::Report>((ws_provider, sub))
                };
                match timeout(RPC_TIMEOUT, subscribe).await {
                    Ok(Ok(heads)) => {
                        info!("Subscribed to newHeads via {}", ws_url);
                        Some(heads)
                    }
                    Ok(Err(err)) => {
                        warn!(error = %err, "newHeads subscription failed; falling back to polling");
                        None
                    }
                    Err(_) => {
                        warn!("newHeads subscription timed out; falling back to polling");
                        None
                    }
                }
            }
            None => None,
        };

        let mut next_block = if let Some(start) = self.config.start_block {
            start
        } else {
            match get_block_number_with_retry(&provider, 3).await {
                Ok(n) => n.saturating_add(1),
                Err(e) => {
                    error!("Failed to get initial block number: {}", e);
                    return Err(e);
                }
            }
        };
        info!("Fetcher starting from block {}", next_block);

        // Consecutive failed fetches of next_block. A failed block is retried on the next pass
        // and skipped only after MAX_FETCH_ATTEMPTS, so a transient RPC error loses nothing.
        const MAX_FETCH_ATTEMPTS: u32 = 5;
        let mut fetch_failures: u32 = 0;
        // The `queued` post of a block whose fetch failed and is retried: it is sent once.
        let mut retried_queued_post: Option<(u64, tokio::task::JoinHandle<()>)> = None;
        // Whether the fetcher has reached the chain tip, from where it keeps within max_lag
        // blocks of it. A run from --start-block works through its backlog first, until a
        // backlog block cannot be fetched at all (a node may serve no witnesses that far back).
        let mut caught_up = self.config.start_block.is_none();

        'outer: loop {
            let latest = if let Some(end) = self.config.end_block {
                if next_block > end {
                    break 'outer;
                }
                end
            } else {
                match get_block_number_with_retry(&provider, 6).await {
                    Ok(n) => n,
                    Err(err) => {
                        error!(error = %err, "Failed to get latest block, retrying in 30s");
                        sleep(Duration::from_secs(30)).await;
                        continue;
                    }
                }
            };

            // A block the chain has left behind is worth little to a real-time prover, and a
            // node can take far longer over its witness than over the tip's (or never answer):
            // working through such blocks one by one, the service can fall behind for good. So
            // once at the tip, it skips ahead to the tip when it falls more than max_lag behind.
            // A failed fetch comes back here before its retry, so a block whose witness doesn't
            // come is given up once the tip has moved on.
            let lag = latest.saturating_sub(next_block);
            if caught_up
                && self.config.end_block.is_none()
                && self.config.max_lag > 0
                && lag > self.config.max_lag
            {
                warn!(
                    from = next_block,
                    to = latest,
                    "{lag} blocks behind the tip (more than {}); skipping ahead to it",
                    self.config.max_lag
                );
                next_block = latest;
                fetch_failures = 0;
                retried_queued_post = None;
            }

            for block_number in next_block..=latest {
                let should_prove = matches_interval(self.config.prove_every, block_number);
                let should_execute =
                    matches_interval(self.config.execute_every, block_number) && !should_prove;
                let should_anything =
                    should_prove || should_execute || self.config.save_all_responses;

                if !should_anything {
                    next_block = block_number + 1;
                    continue;
                }

                println!(
                    "[{}] Fetching block {}",
                    Self::format_timestamp(),
                    block_number
                );

                // "queued" goes out as the block is picked, in the background: its HTTP round
                // trip (up to a few seconds) overlaps the fetch, so the block's "proving" post,
                // which waits for it, is not held back once proving starts.
                let mut queued_post = None;
                if should_prove {
                    queued_post = match retried_queued_post.take() {
                        Some((bn, post)) if bn == block_number => Some(post),
                        _ => self.eth_client.as_ref().map(|c| {
                            let c = Arc::clone(c);
                            tokio::spawn(async move { c.queued(block_number).await; })
                        }),
                    };
                }

                // Bounded: the RPC calls have no timeout of their own, and a node that never
                // answers a witness request would otherwise hold the fetcher on this block.
                let fetch = fetch_block_and_witness(FetchRequest {
                    rpc_url: &self.config.rpc_url,
                    block_number: Some(block_number),
                    data_dir: self.config.data_dir.clone(),
                    save_all_responses: self.config.save_all_responses,
                    geth: false,
                    force_rebuild: false,
                });
                let fetched = timeout(self.config.fetch_timeout, fetch)
                    .await
                    .unwrap_or_else(|_| {
                        Err(eyre::eyre!(
                            "no answer within {} s",
                            self.config.fetch_timeout.as_secs()
                        ))
                    });
                let outcome = match fetched {
                    Ok(o) => {
                        fetch_failures = 0;
                        o
                    }
                    Err(err) => {
                        fetch_failures += 1;
                        if fetch_failures < MAX_FETCH_ATTEMPTS {
                            error!(%block_number, attempt = fetch_failures, error = %err, "Failed to fetch block; will retry");
                            // Retry from this block after the wait below.
                            retried_queued_post = queued_post.map(|post| (block_number, post));
                            break;
                        }
                        error!(%block_number, attempts = fetch_failures, error = %err, "Failed to fetch block; skipping it");
                        fetch_failures = 0;
                        next_block = block_number + 1;
                        caught_up = true;
                        continue;
                    }
                };

                // The preflight runs as soon as the bundle exists, off the async runtime: a block
                // that would wait in the queue for an earlier block's proof has it done by then
                // instead of after. The worker gets the run with the block and checks it before
                // proving (see prove_item).
                let preflight = if should_prove && self.serial_preflight {
                    let svc = Arc::clone(&self);
                    let path = outcome.flat_bundle_path.clone();
                    Some(
                        tokio::task::spawn_blocking(move || {
                            svc.preflight_block(block_number, &path)
                        })
                        .await
                        .unwrap_or_else(|err| Err(eyre::eyre!("preflight task failed: {err}"))),
                    )
                } else {
                    None
                };

                let item = WorkItem {
                    block_number,
                    bundle_path: outcome.flat_bundle_path,
                    execute: should_execute,
                    prove: should_prove,
                    queued_post,
                    preflight,
                };

                // Backpressure: if the GPU is slower than fetching, the queue
                // fills and we wait here. An Err means the worker dropped the
                // receiver (panicked or exited) — stop fetching.
                if tx.send(item).await.is_err() {
                    warn!("Prover worker dropped the queue; fetcher exiting");
                    return Ok(());
                }
                next_block = block_number + 1;
            }
            if next_block > latest {
                caught_up = true;
            }

            // next_block only advances past blocks handled above: a lagging RPC that reports a
            // lower latest leaves it in place instead of re-proving blocks.
            // Tip-following: prefer newHeads push (with a safety timeout in
            // case the subscription stalls); fall back to tight polling —
            // wake-up delay is on the block->proof latency path.
            let mut ws_dead = false;
            if let Some((_, sub)) = new_heads.as_mut() {
                tokio::select! {
                    received = sub.recv() => {
                        if received.is_err() {
                            warn!("newHeads subscription closed; falling back to polling");
                            ws_dead = true;
                        }
                    }
                    _ = sleep(Duration::from_secs(2)) => {}
                }
            } else {
                sleep(Duration::from_millis(300)).await;
            }
            if ws_dead {
                new_heads = None;
            }
        }

        // Drop tx so the worker can drain and exit cleanly.
        drop(tx);
        info!("Fetcher exiting (end_block reached)");
        Ok(())
    }

    /// Drain `WorkItem`s and run them against the shared GPU prover.
    ///
    /// Single-consumer by design: there is only one GPU. Ethproofs state
    /// transitions (`proving`, `proved`) are both spawned as detached tasks
    /// so the worker returns to `rx.recv()` immediately after the GPU
    /// yields the proof.
    async fn prover_worker_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<WorkItem>,
    ) -> Result<()> {
        while let Some(mut item) = rx.recv().await {
            if item.execute {
                println!(
                    "[{}] Executing block {}",
                    Self::format_timestamp(),
                    item.block_number
                );
                if let Err(err) = self.execute_block(item.block_number, &item.bundle_path) {
                    error!(block = item.block_number, error = %err, "Execution failed");
                }
            }

            if item.prove {
                let queued_post = item.queued_post.take();
                let preflight = item.preflight.take();
                self.prove_item(&item, queued_post, preflight).await;
            }
        }

        info!("Prover worker exiting (queue closed)");
        Ok(())
    }

    /// Proves one block, gated by the preflight: a proof is written and posted only if the
    /// simulator ran the block to the guest's exit point and the proof commits the block's hash.
    /// Its Ethproofs posts go out in order: `proving` after `queued_post`, `proved` after
    /// `proving`. `preflight` is the fetcher's run of the block, if it made one.
    async fn prove_item(
        self: &Arc<Self>,
        item: &WorkItem,
        queued_post: Option<tokio::task::JoinHandle<()>>,
        preflight: Option<Result<VmRunOutcome>>,
    ) {
        let skip = |cycle_count: u64, message: String| {
            error!(block = item.block_number, "{message}");
            let _ = self.persist_proving_log(&ProvingLog {
                block_number: item.block_number,
                gas_used: 0,
                cycle_count,
                num_proofs: 0,
                proving_millis: 0,
                message,
            });
        };

        // The preflight runs the block on the simulator, with the prover's machine and cycle
        // bound, before proving: a block that fails it is not proved at all. It must be: the
        // prover proves a run that ends in the guest's error exit, and then aborts the whole
        // process in the recursion layer (a panic in its JIT code, which cannot unwind), so
        // the service restarts and misses the blocks of the next minute. The fetcher runs it
        // as soon as the block's bundle exists: at the chain tip the worker is idle by then and
        // proving follows it at once, while a block that waits for an earlier block's proof has
        // it done during that proof (sharing the CPU with the pipeline's own simulation)
        // instead of after it. Z6M_CONCURRENT_PREFLIGHT=1 runs it alongside proving instead,
        // gating only the proof's writing and posting, which saves its time (about 0.5 s) on
        // every block at the cost of that abort on a block that fails it.
        let mut preflight_handle = None;
        if self.serial_preflight {
            let run = preflight
                .unwrap_or_else(|| self.preflight_block(item.block_number, &item.bundle_path));
            match run {
                Ok(run) => {
                    if let Some(reason) = self.preflight_failure(&run) {
                        return skip(run.cycle_count, format!("SKIPPED: {reason}"));
                    }
                }
                Err(err) => return skip(0, format!("SKIPPED: preflight error: {err}")),
            }
        } else {
            let svc = Arc::clone(self);
            let bn = item.block_number;
            let path = item.bundle_path.clone();
            preflight_handle =
                Some(tokio::task::spawn_blocking(move || svc.preflight_block(bn, &path)));
        }

        println!(
            "[{}] Proving block {}",
            Self::format_timestamp(),
            item.block_number
        );

        // "proving" state transition, in the background once "queued" is through.
        let mut proving_post = None;
        if let Some(c) = &self.eth_client {
            let c = Arc::clone(c);
            let bn = item.block_number;
            proving_post = Some(tokio::spawn(async move {
                if let Some(queued) = queued_post {
                    let _ = queued.await;
                }
                c.proving(bn).await;
            }));
        }

        let prove_result = self.prove_inner(item).await;

        if let Some(handle) = preflight_handle.take() {
            let failure = match handle.await {
                Ok(Ok(run)) => self
                    .preflight_failure(&run)
                    .map(|reason| (run.cycle_count, reason)),
                Ok(Err(err)) => Some((0, format!("preflight error: {err}"))),
                Err(err) => Some((0, format!("preflight task failed: {err}"))),
            };
            if let Some((cycle_count, reason)) = failure {
                return skip(cycle_count, format!("SKIPPED: {reason}; proof discarded"));
            }
        }

        match prove_result {
            Ok((proof_bytes, log)) => {
                // Written only now, once the preflight has passed and the proof's output has
                // matched the block: proof_bytes is the gzip(EPROOF01 v2) proof file.
                let block_dir = self.config.output_dir.join(log.block_number.to_string());
                if let Err(e) = fs::create_dir_all(&block_dir)
                    .and_then(|()| fs::write(block_dir.join("proof.bin"), &proof_bytes))
                {
                    error!(block = log.block_number, error = %e, "Failed to write proof.bin");
                }
                println!(
                    "[{}] Proved block {} gas_used={} cycles={} proofs={} time={}ms",
                    Self::format_timestamp(),
                    log.block_number,
                    log.gas_used,
                    log.cycle_count,
                    log.num_proofs,
                    log.proving_millis,
                );

                // "proved" submission, in the background once "proving" is through. proof_bytes
                // is moved into the task so the worker can immediately pick up the next item.
                if let Some(c) = &self.eth_client {
                    let c = Arc::clone(c);
                    let bn = log.block_number;
                    let cycles = log.cycle_count;
                    let ms = log.proving_millis;
                    tokio::spawn(async move {
                        if let Some(proving) = proving_post {
                            let _ = proving.await;
                        }
                        c.proved(&proof_bytes, bn, cycles, ms).await;
                    });
                }

                let _ = self.persist_proving_log(&log);
            }
            Err(err) => {
                error!(block = item.block_number, error = %err, "Proving failed");
                let fail_log = ProvingLog {
                    block_number: item.block_number,
                    gas_used: 0,
                    cycle_count: 0,
                    num_proofs: 0,
                    proving_millis: 0,
                    message: format!("FAILED: {}", err),
                };
                let _ = self.persist_proving_log(&fail_log);
            }
        }
    }

    /// Why a preflight run rules its block out, if it does.
    fn preflight_failure(&self, run: &VmRunOutcome) -> Option<String> {
        // The simulator bounds its steps, the prover the timestamp, which a delegation call
        // advances by more than one cycle: a run can reach the exit point past the prover's
        // bound, which the prover would cut short.
        let bound = self.config.max_cycles.min(MAX_PROVABLE_CYCLES) as u64;
        if run.cycle_count >= bound {
            Some(format!(
                "the block takes {} cycles or more, more than the prover takes ({} cycles)",
                run.cycle_count, bound
            ))
        } else if run.succeeded(self.guest.exit_pc) {
            None
        } else {
            Some(format!(
                "guest validation failure (final_pc=0x{:08x} reached_end={} cycles={})",
                run.final_pc, run.reached_end, run.cycle_count
            ))
        }
    }

    /// Run a block through the VM simulator (no proving) using the decoded guest, for at most
    /// `max_cycles` cycles, and report the final machine state.
    fn run_vm(&self, input_path: &Path, max_cycles: usize) -> Result<VmRunOutcome> {
        let oracle = crate::build_oracle(input_path, false)?;
        let state = self.guest.run(oracle, max_cycles, None)?;
        let mut run = VmRunOutcome {
            gas_used: 0,
            cycle_count: state.cycles,
            reached_end: state.reached_end,
            final_pc: state.final_pc,
            elapsed_secs: state.elapsed.as_secs_f64(),
        };
        // A successful run commits the hash of its last block in a0..a7. Any other value means
        // the run, and a proof of it, covers some other block: fail (preflight then skips or
        // discards the proof).
        if run.succeeded(self.guest.exit_pc) {
            let expected = crate::public_output::expected_for_file(input_path, false)?;
            crate::public_output::check(&expected.block_hash, &state.output)?;
            run.gas_used = expected.gas_used;
        }
        Ok(run)
    }

    fn execute_block(&self, block_number: u64, input_path: &Path) -> Result<()> {
        let run = self.run_vm(input_path, self.config.max_cycles)?;
        println!(
            "[{}] Executed block {} gas_used={} cycles={} time={:.2}s reached_end={} ok={}",
            Self::format_timestamp(),
            block_number,
            run.gas_used,
            run.cycle_count,
            run.elapsed_secs,
            run.reached_end,
            run.succeeded(self.guest.exit_pc),
        );
        Ok(())
    }

    /// The simulator's run of a block before (or while) the prover proves it, on the
    /// prover's machine and within its cycle bound. Only a run that ends at the guest's exit
    /// point, with the block's hash as its output, lets the block's proof be kept: any other
    /// run (a guest validation failure such as a state root mismatch, a block over the cycle
    /// bound, an instruction the machine lacks) would make a proof of something else.
    fn preflight_block(&self, block_number: u64, input_path: &Path) -> Result<VmRunOutcome> {
        let run = self.run_vm(input_path, self.config.max_cycles.min(MAX_PROVABLE_CYCLES))?;
        println!(
            "[{}] Preflight block {} cycles={} time={:.2}s ok={} (final_pc=0x{:08x})",
            Self::format_timestamp(),
            block_number,
            run.cycle_count,
            run.elapsed_secs,
            run.succeeded(self.guest.exit_pc),
            run.final_pc,
        );
        Ok(run)
    }

    /// Prove a single block and return the proof file bytes plus a `ProvingLog`; the worker
    /// writes `proof.bin` once the preflight verdict is in.
    ///
    /// Does **not** touch ethproofs — the caller is responsible for
    /// spawning any state-transition HTTP calls in the background.
    async fn prove_inner(&self, item: &WorkItem) -> Result<(Vec<u8>, ProvingLog)> {
        let prover = self
            .prover
            .clone()
            .ok_or_else(|| eyre::eyre!("no prover (the service runs without --gpu)"))?;
        let block_number = item.block_number;
        let input_path = item.bundle_path.clone();

        // The reported proving time is the prover's own: from handing it the block's input to
        // the proof, which is the pipeline's simulation feeding the GPUs and their proving.
        // Fetching the block and its witness, converting it, reading the input words and the
        // preflight come before it and are excluded.
        let proved = tokio::task::spawn_blocking(move || {
            let words = crate::build_oracle(&input_path, false)?;
            let mut prover = prover.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            prover.prove(words)
        })
        .await
        .map_err(|e| eyre::eyre!("proving task failed: {e}"))??;
        let proving_millis = (proved.elapsed.as_millis() as u64).max(1);

        // A proof that commits another block than the input's is worthless: never keep it.
        // proof.bin is written by the worker, only once the preflight has passed too.
        let expected = crate::public_output::expected_for_file(&item.bundle_path, false)?;
        crate::prove::check_output(&expected, &proved.output())?;

        let proof_bytes = crate::proof_format::proof_file_bytes(&proved.artifact)?;
        let log = ProvingLog {
            block_number,
            gas_used: expected.gas_used,
            cycle_count: proved.program_cycles(),
            num_proofs: proved.proof_count(),
            proving_millis,
            message: String::from("Success"),
        };
        Ok((proof_bytes, log))
    }

    fn persist_proving_log(&self, log: &ProvingLog) -> Result<()> {
        let log_file = self.config.data_dir.join("provingLogs.log");
        if let Some(parent) = log_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let timestamp = Self::format_timestamp();
        writeln!(
            &mut file,
            "{} block={} gas={} cycles={} proofs={} time={}ms {}",
            timestamp,
            log.block_number,
            log.gas_used,
            log.cycle_count,
            log.num_proofs,
            log.proving_millis,
            log.message,
        )?;
        Ok(())
    }
}

fn matches_interval(interval: Option<u64>, block_number: u64) -> bool {
    match interval {
        Some(0) => false,
        Some(n) => block_number % n == 0,
        None => false,
    }
}

async fn get_block_number_with_retry<P: Provider>(
    provider: &P,
    max_retries: u32,
) -> Result<u64> {
    let mut attempts = 0;
    loop {
        let answer = match timeout(RPC_TIMEOUT, provider.get_block_number()).await {
            Ok(answer) => answer.map_err(eyre::Report::from),
            Err(_) => Err(eyre::eyre!(
                "eth_blockNumber: no answer within {} s",
                RPC_TIMEOUT.as_secs()
            )),
        };
        match answer {
            Ok(n) => return Ok(n),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err);
                }
                let delay = Duration::from_secs(2u64.pow(attempts));
                warn!(attempt = attempts, delay_secs = delay.as_secs(), "RPC retry");
                sleep(delay).await;
            }
        }
    }
}
