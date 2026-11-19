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

/// Capacity of the fetcher -> prover-worker queue; each queued item holds one MFBD bundle on disk.
const PROVER_QUEUE_CAPACITY: usize = 4;

/// Cap on `eth_blockNumber` and the newHeads subscription: the RPC clients have no timeout of their own.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub prove_every: Option<u64>,
    pub execute_every: Option<u64>,
    pub post_every: Option<u64>,
    pub rpc_url: String,
    /// Optional WebSocket endpoint for newHeads; unset, the fetcher polls.
    pub ws_url: Option<String>,
    pub save_all_responses: bool,
    pub data_dir: PathBuf,
    pub output_dir: PathBuf,
    pub guest: GuestFiles,
    pub max_cycles: usize,
    pub replay_threads: Option<usize>,
    pub gpu: bool,
    pub ethproofs: Option<EthProofsConfig>,
    /// Cap on one block-fetch attempt (block, RLP, witness) before it counts as failed.
    pub fetch_timeout: Duration,
    /// At the chain tip, the most blocks the fetcher may fall behind before skipping ahead; 0 never skips.
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

/// One block for the prover worker; only `bundle_path` travels through the channel, the bundle is already on disk.
#[derive(Debug)]
struct WorkItem {
    block_number: u64,
    bundle_path: PathBuf,
    execute: bool,
    prove: bool,
    /// The `queued` post, awaited by the `proving` post: a late `queued` would move the status back.
    queued_post: Option<tokio::task::JoinHandle<()>>,
    /// The fetcher's preflight run; None with Z6M_CONCURRENT_PREFLIGHT, where the worker runs it alongside proving.
    preflight: Option<Result<VmRunOutcome>>,
}

pub struct AirbenderService {
    config: ServiceConfig,
    eth_client: Option<Arc<EthproofsClient>>,
    /// Built once and rebuilt after a panic; only the prover worker uses it.
    prover: Option<Arc<Mutex<BlockProver>>>,
    guest: Arc<Guest>,
    /// Preflight completes before proving unless Z6M_CONCURRENT_PREFLIGHT is set.
    serial_preflight: bool,
}

#[derive(Debug)]
struct VmRunOutcome {
    /// The input's gas used once the guest's output matched the input; 0 if the guest did not finish successfully.
    gas_used: u64,
    cycle_count: u64,
    reached_end: bool,
    final_pc: u32,
    elapsed_secs: f64,
}

impl VmRunOutcome {
    /// Success parks in the EXIT_SEQUENCE self-loop; a validation failure parks in finish_error's loop.
    fn succeeded(&self, exit_pc: u32) -> bool {
        self.reached_end && self.final_pc == exit_pc
    }
}

impl AirbenderService {
    pub fn new(config: ServiceConfig) -> Result<Self> {
        info!("Guest binary: {}", config.guest.bin.display());

        let guest = Arc::new(Guest::load(config.guest.clone())?);
        info!("Guest exit sequence PC: 0x{:08x}", guest.exit_pc);

        let eth_client = config
            .ethproofs
            .clone()
            .map(|c| Arc::new(EthproofsClient::new(c)));

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

    /// Fetcher task (RPC -> MFBD bundle -> preflight -> channel) and prover worker; Ethproofs posts are background tasks.
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

    /// Fetches and enqueues blocks in order; never blocks on proving or Ethproofs (`queued` is detached).
    async fn fetcher_loop(self: Arc<Self>, tx: mpsc::Sender<WorkItem>) -> Result<()> {
        let url = Url::parse(&self.config.rpc_url)?;
        let provider = ProviderBuilder::new().connect_http(url);

        // Optional newHeads subscription; any failure falls back to polling.
        let mut new_heads = match &self.config.ws_url {
            Some(ws_url) => {
                let subscribe = async {
                    let connect = z6m_common::alloy_provider::WsConnect::new(ws_url.clone());
                    let ws_provider = ProviderBuilder::new().connect_ws(connect).await?;
                    let sub = ws_provider.subscribe_blocks().await?;
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

        // Failed fetches of next_block are retried next pass and skipped only after MAX_FETCH_ATTEMPTS.
        const MAX_FETCH_ATTEMPTS: u32 = 5;
        let mut fetch_failures: u32 = 0;
        // The `queued` post of a block whose fetch failed and is retried: it is sent once.
        let mut retried_queued_post: Option<(u64, tokio::task::JoinHandle<()>)> = None;
        // Set at the tip; a --start-block run first clears its backlog, until a block cannot be fetched.
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

            // At the tip, skip ahead when more than max_lag behind: stale blocks are worth little.
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

                // "queued" is posted in the background so it delays neither the fetch nor "proving".
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

                // Bounded: the RPC calls have no timeout, so a silent node would hold the fetcher here.
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

                // Preflight off the async runtime once the bundle exists, done by the block's turn.
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

                // Backpressure when the GPU is slower; Err means the worker dropped the receiver: stop fetching.
                if tx.send(item).await.is_err() {
                    warn!("Prover worker dropped the queue; fetcher exiting");
                    return Ok(());
                }
                next_block = block_number + 1;
            }
            if next_block > latest {
                caught_up = true;
            }

            // next_block only passes handled blocks: a lagging RPC's lower latest must not re-prove.
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

        drop(tx);
        info!("Fetcher exiting (end_block reached)");
        Ok(())
    }

    /// One consumer (one GPU); Ethproofs posts are detached so the loop is back at `rx.recv()` at once.
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

    /// Proves one block; the proof is kept only if the preflight reached the exit and it commits the block.
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

        // Preflight first: a run ending in finish_error is proved, then aborts the recursion layer.
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
                // Written only once the preflight passed and the proof matched the block.
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

                // proof_bytes moves into the background "proved" task so the worker takes the next item at once.
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
        // Steps bound the simulator, the timestamp the prover: past the latter a run is cut short.
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
        // A successful run commits its last block's hash in a0..a7; any other value means the run covers another block.
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

    /// The simulator's run; the proof is kept only if it ends at the exit with the block's hash.
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

    /// Proves one block into bytes and a `ProvingLog`; no Ethproofs state; the worker writes `proof.bin`.
    async fn prove_inner(&self, item: &WorkItem) -> Result<(Vec<u8>, ProvingLog)> {
        let prover = self
            .prover
            .clone()
            .ok_or_else(|| eyre::eyre!("no prover (the service runs without --gpu)"))?;
        let block_number = item.block_number;
        let input_path = item.bundle_path.clone();

        // Proving time is the prover's alone, input to proof; fetch, conversion and preflight are excluded.
        let proved = tokio::task::spawn_blocking(move || {
            let words = crate::build_oracle(&input_path, false)?;
            let mut prover = prover.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            prover.prove(words)
        })
        .await
        .map_err(|e| eyre::eyre!("proving task failed: {e}"))??;
        let proving_millis = (proved.elapsed.as_millis() as u64).max(1);

        // A proof committing another block is never kept; the worker writes proof.bin after the preflight.
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
