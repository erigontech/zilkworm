use z6m_common::{EthProofsConfig, EthproofsClient};
use crate::prove::ProvingLimit;

use z6m_common::alloy_provider::{Provider, ProviderBuilder};
use eyre::{bail, Result};
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use riscv_transpiler::ir::{preprocess_bytecode, FullMachineDecoderConfig};
use riscv_transpiler::vm::{DelegationsCounters, RamWithRomRegion, SimpleTape, State, VM};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;
use z6m_common::{fetch_block_and_witness, FetchRequest};

#[cfg(feature = "gpu")]
use execution_utils::unrolled_gpu::UnrolledProver;

/// Capacity of the fetcher → prover-worker work queue.
///
/// At most this many pre-fetched blocks can sit on disk (their MFBD flat-bundle
/// files already written) before the fetcher backpressures on
/// `tx.send().await`. Raising this lets the fetcher get further ahead when
/// the GPU is the bottleneck; each in-flight item costs one MFBD flat-bundle
/// file under `data_dir`.
const PROVER_QUEUE_CAPACITY: usize = 4;

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub prove_every: Option<u64>,
    pub execute_every: Option<u64>,
    pub post_every: Option<u64>,
    pub rpc_url: String,
    pub save_all_responses: bool,
    pub data_dir: PathBuf,
    pub output_dir: PathBuf,
    pub guest_base: PathBuf,
    pub max_cycles: usize,
    pub gpu: bool,
    pub until: Option<ProvingLimit>,
    pub setup_dir: Option<PathBuf>,
    pub ethproofs: Option<EthProofsConfig>,
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
}

pub struct AirbenderService {
    config: ServiceConfig,
    eth_client: Option<Arc<EthproofsClient>>,
    #[cfg(feature = "gpu")]
    gpu_prover: Option<Arc<UnrolledProver>>,
    /// Hex-encoded end_params from the highest recursion level setup.
    /// Used as verifier_id when posting to ethproofs.
    verifier_id: String,
}

impl AirbenderService {
    pub fn new(config: ServiceConfig) -> Result<Self> {
        let bin_path = format!("{}.bin", config.guest_base.display());
        info!("Guest binary: {}", bin_path);
        if !Path::new(&bin_path).exists() {
            bail!("Guest binary not found at {}", bin_path);
        }

        let eth_client = config
            .ethproofs
            .clone()
            .map(|c| Arc::new(EthproofsClient::new(c)));

        // Initialize GPU prover once — reused for all blocks
        #[cfg(feature = "gpu")]
        let gpu_prover = if config.gpu {
            info!("Initializing GPU prover (one-time)");
            let start = Instant::now();
            let prover = if let Some(ref dir) = config.setup_dir {
                let setup_path = dir.join("setup.bin");
                let cache = crate::prove::load_setup(&setup_path)?;
                crate::prove::create_gpu_prover_from_cache(cache)
            } else {
                let guest_path = config.guest_base.display().to_string();
                let until = config.until.clone().unwrap_or(ProvingLimit::Base);
                crate::prove::create_gpu_prover(&guest_path, &until)
            };
            info!("GPU prover initialized in {:.2}s", start.elapsed().as_secs_f64());
            Some(Arc::new(prover))
        } else {
            None
        };

        // Compute verifier_id from the highest-level setup's end_params
        #[cfg(feature = "gpu")]
        let verifier_id = if let Some(ref p) = gpu_prover {
            let max_level = p.max_level;
            let data = &p.level_data[&max_level];
            let end_params = &data.setup.end_params;
            let hex: String = end_params.iter().map(|w| format!("{:08x}", w)).collect();
            info!("Verifier ID (end_params): 0x{}", hex);
            format!("0x{}", hex)
        } else {
            "airbender-z6m".to_string()
        };
        #[cfg(not(feature = "gpu"))]
        let verifier_id = "airbender-z6m".to_string();

        Ok(Self {
            config,
            eth_client,
            #[cfg(feature = "gpu")]
            gpu_prover,
            verifier_id,
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
    ///   writes the MFBD flat bundle to disk, and pushes a `WorkItem` into a
    ///   bounded channel. It fires `ethproofs.queued(block)` as a
    ///   background `tokio::spawn` so the fetcher never waits on HTTP.
    /// - A **prover worker** task drains the channel, running execute
    ///   and/or prove for each item. `ethproofs.proving(block)` and
    ///   `.proved(..)` are both spawned background tasks so the worker
    ///   immediately picks up the next item once the GPU returns.
    ///
    /// Fetching is therefore independent of the GPU: while a proof is
    /// running, the fetcher can pre-queue up to `PROVER_QUEUE_CAPACITY`
    /// blocks. If the fetcher gets ahead, `tx.send().await` backpressures
    /// naturally.
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

            for block_number in next_block..=latest {
                let should_prove = matches_interval(self.config.prove_every, block_number);
                let should_execute =
                    matches_interval(self.config.execute_every, block_number) && !should_prove;
                let should_anything =
                    should_prove || should_execute || self.config.save_all_responses;

                if !should_anything {
                    continue;
                }

                println!(
                    "[{}] Fetching block {}",
                    Self::format_timestamp(),
                    block_number
                );

                let outcome = match fetch_block_and_witness(FetchRequest {
                    rpc_url: &self.config.rpc_url,
                    block_number: Some(block_number),
                    data_dir: self.config.data_dir.clone(),
                    save_all_responses: self.config.save_all_responses,
                    geth: false,
                    force_rebuild: false,
                })
                .await
                {
                    Ok(o) => o,
                    Err(err) => {
                        error!(%block_number, error = %err, "Failed to fetch block");
                        continue;
                    }
                };

                // Fire-and-forget "queued" state transition. We fire this at
                // enqueue time (not at proving start) so it accurately
                // reflects that the block is now in the prover's queue.
                if should_prove {
                    if let Some(c) = &self.eth_client {
                        let c = Arc::clone(c);
                        let bn = block_number;
                        tokio::spawn(async move { c.queued(bn).await; });
                    }
                }

                let item = WorkItem {
                    block_number,
                    bundle_path: outcome.flat_bundle_path,
                    execute: should_execute,
                    prove: should_prove,
                };

                // Backpressure: if the GPU is slower than fetching, the queue
                // fills and we wait here. An Err means the worker dropped the
                // receiver (panicked or exited) — stop fetching.
                if tx.send(item).await.is_err() {
                    warn!("Prover worker dropped the queue; fetcher exiting");
                    return Ok(());
                }
            }

            next_block = latest + 1;
            sleep(Duration::from_secs(2)).await;
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
        while let Some(item) = rx.recv().await {
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
                println!(
                    "[{}] Proving block {}",
                    Self::format_timestamp(),
                    item.block_number
                );

                // Fire-and-forget "proving" state transition.
                if let Some(c) = &self.eth_client {
                    let c = Arc::clone(c);
                    let bn = item.block_number;
                    tokio::spawn(async move { c.proving(bn).await; });
                }

                match self.prove_inner(item.block_number, &item.bundle_path).await {
                    Ok((proof_bytes, log)) => {
                        println!(
                            "[{}] Proved block {} gas_used={} cycles={} proofs={} time={}ms",
                            Self::format_timestamp(),
                            log.block_number,
                            log.gas_used,
                            log.cycle_count,
                            log.num_proofs,
                            log.proving_millis,
                        );

                        // Fire-and-forget "proved" submission. proof_bytes is
                        // moved into the task so the worker can immediately
                        // pick up the next item.
                        if let Some(c) = &self.eth_client {
                            let c = Arc::clone(c);
                            let bn = log.block_number;
                            let cycles = log.cycle_count;
                            let ms = log.proving_millis;
                            let vid = self.verifier_id.clone();
                            tokio::spawn(async move {
                                c.proved(&proof_bytes, bn, cycles, ms, &vid).await;
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
        }

        info!("Prover worker exiting (queue closed)");
        Ok(())
    }

    fn execute_block(&self, block_number: u64, input_path: &Path) -> Result<()> {
        let oracle = crate::build_oracle(input_path, false)?;
        let source = QuasiUARTSource::new_with_reads(oracle);

        let bin_path = format!("{}.bin", self.config.guest_base.display());
        let text_path = format!("{}.text", self.config.guest_base.display());

        let (_, binary_u32) = execution_utils::setups::read_binary(Path::new(&bin_path));
        let (_, text_u32) = execution_utils::setups::read_binary(Path::new(&text_path));

        let instructions = preprocess_bytecode::<FullMachineDecoderConfig>(&text_u32);
        let tape = SimpleTape::new(&instructions);
        let mut ram =
            RamWithRomRegion::<{ prover::common_constants::rom::ROM_SECOND_WORD_BITS }>::from_rom_content(
                &binary_u32,
                crate::DEFAULT_RAM_BOUND,
            );

        let mut state = State::initial_with_counters(DelegationsCounters::default());
        let mut non_determinism_source = source;

        let wall_start = Instant::now();
        let finished = VM::<DelegationsCounters>::run_basic_unrolled(
            &mut state,
            &mut ram,
            &mut (),
            &tape,
            self.config.max_cycles,
            &mut non_determinism_source,
        );
        let wall_elapsed = wall_start.elapsed();

        let cycles = (state.timestamp - riscv_transpiler::common_constants::INITIAL_TIMESTAMP)
            / riscv_transpiler::common_constants::TIMESTAMP_STEP;
        let gas_used = state.registers[10].value as u64;

        println!(
            "[{}] Executed block {} gas_used={} cycles={} time={:.2}s reached_end={}",
            Self::format_timestamp(),
            block_number,
            gas_used,
            cycles,
            wall_elapsed.as_secs_f64(),
            finished,
        );

        Ok(())
    }

    /// Run the GPU proof for a single block, write `proof.bin`, and return
    /// the serialized proof bytes plus a `ProvingLog` ready for persistence.
    ///
    /// Does **not** touch ethproofs — the caller is responsible for
    /// spawning any state-transition HTTP calls in the background.
    async fn prove_inner(
        &self,
        block_number: u64,
        input_path: &Path,
    ) -> Result<(Vec<u8>, ProvingLog)> {
        let oracle = crate::build_oracle(input_path, false)?;
        let start = Instant::now();

        #[cfg(feature = "gpu")]
        {
            let prover = self
                .gpu_prover
                .as_ref()
                .ok_or_else(|| eyre::eyre!("GPU prover not initialized (--gpu not set?)"))?
                .clone();

            let result = tokio::task::spawn_blocking(move || {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    crate::prove::gpu_prove(&prover, oracle, block_number)
                }))
            })
            .await
            .map_err(|e| eyre::eyre!("Proving task join error: {}", e))?;

            let (proof, cycles) = match result {
                Ok(v) => v,
                Err(payload) => {
                    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                        (*s).to_string()
                    } else if let Some(s) = payload.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "non-string panic payload".to_string()
                    };
                    bail!("gpu_prove panicked: {}", msg);
                }
            };

            let proving_millis = start.elapsed().as_millis() as u64;

            // Write proof.bin to output_dir/{block}/proof.bin
            let block_dir = self.config.output_dir.join(block_number.to_string());
            fs::create_dir_all(&block_dir)?;
            crate::prove::serialize_proof_to_file(&proof, &block_dir.join("proof.bin"));

            let gas_used = proof.register_final_values[10].value as u64;
            let (family_proofs, init_proofs, delegation_proofs) = proof.get_proof_counts();
            let total_proofs = family_proofs + init_proofs + delegation_proofs;

            let proof_bytes = crate::prove::serialize_proof_to_bytes(&proof);
            let log = ProvingLog {
                block_number,
                gas_used,
                cycle_count: cycles,
                num_proofs: total_proofs,
                proving_millis,
                message: String::from("Success"),
            };
            Ok((proof_bytes, log))
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (input_path, block_number, start);
            bail!("Compiled without GPU support. Rebuild with --features gpu");
        }
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
        match provider.get_block_number().await {
            Ok(n) => return Ok(n),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err.into());
                }
                let delay = Duration::from_secs(2u64.pow(attempts));
                warn!(attempt = attempts, delay_secs = delay.as_secs(), "RPC retry");
                sleep(delay).await;
            }
        }
    }
}
