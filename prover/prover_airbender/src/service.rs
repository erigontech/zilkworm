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
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;
use z6m_common::{fetch_block_and_witness, FetchRequest};

#[cfg(feature = "gpu")]
use execution_utils::unrolled_gpu::UnrolledProver;

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

pub struct AirbenderService {
    config: ServiceConfig,
    eth_client: Option<EthproofsClient>,
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

        let eth_client = config.ethproofs.clone().map(EthproofsClient::new);

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

    pub async fn run(&self) -> Result<()> {
        info!("Starting airbender service");
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

        info!("Service starting from block {}", next_block);

        loop {
            let latest = if let Some(end) = self.config.end_block {
                if next_block > end {
                    break Ok(());
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
                if let Err(err) = self.process_block(block_number).await {
                    error!(%block_number, error = %err, "Failed to process block");
                }
            }

            next_block = latest + 1;
            sleep(Duration::from_secs(2)).await;
        }
    }

    async fn process_block(&self, block_number: u64) -> Result<()> {
        let should_prove = matches_interval(self.config.prove_every, block_number);
        let should_execute =
            matches_interval(self.config.execute_every, block_number) && !should_prove;
        let should_anything =
            should_prove || should_execute || self.config.save_all_responses;

        if !should_anything {
            return Ok(());
        }

        println!(
            "[{}] Fetching block {}",
            Self::format_timestamp(),
            block_number
        );

        let outcome = fetch_block_and_witness(FetchRequest {
            rpc_url: &self.config.rpc_url,
            block_number: Some(block_number),
            data_dir: self.config.data_dir.clone(),
            save_all_responses: self.config.save_all_responses,
            build_eth_test: false,
            geth: false,
        })
        .await?;

        let unified_path = outcome.unified_rlp_path;

        if should_execute {
            println!(
                "[{}] Executing block {}",
                Self::format_timestamp(),
                block_number
            );
            if let Err(err) = self.execute_block(block_number, &unified_path) {
                error!(%block_number, error = %err, "Execution failed");
            }
        }

        if should_prove {
            println!(
                "[{}] Proving block {}",
                Self::format_timestamp(),
                block_number
            );

            if let Some(client) = &self.eth_client {
                client.queued(block_number).await;
            }

            match self.prove_block(block_number, &unified_path).await {
                Ok(log) => {
                    println!(
                        "[{}] Proved block {} gas_used={} cycles={} proofs={} time={}ms",
                        Self::format_timestamp(),
                        log.block_number,
                        log.gas_used,
                        log.cycle_count,
                        log.num_proofs,
                        log.proving_millis,
                    );
                }
                Err(err) => {
                    error!(%block_number, error = %err, "Proving failed");
                    let fail_log = ProvingLog {
                        block_number,
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

    async fn prove_block(
        &self,
        block_number: u64,
        input_path: &Path,
    ) -> Result<ProvingLog> {
        let oracle = crate::build_oracle(input_path, false)?;

        if let Some(client) = &self.eth_client {
            client.proving(block_number).await;
        }

        let start = Instant::now();

        #[cfg(feature = "gpu")]
        {
            let prover = self.gpu_prover.as_ref()
                .ok_or_else(|| eyre::eyre!("GPU prover not initialized (--gpu not set?)"))?
                .clone();

            let (proof, cycles) = tokio::task::spawn_blocking(move || {
                crate::prove::gpu_prove(&prover, oracle, block_number)
            })
            .await
            .map_err(|e| eyre::eyre!("Proving task panicked: {}", e))?;

            let proving_millis = start.elapsed().as_millis() as u64;

            // Write proof
            let block_dir = self.config.output_dir.join(block_number.to_string());
            fs::create_dir_all(&block_dir)?;
            crate::prove::serialize_proof_to_file(&proof, &block_dir.join("proof.bin"));

            let gas_used = proof.register_final_values[10].value as u64;
            let (family_proofs, init_proofs, delegation_proofs) = proof.get_proof_counts();
            let total_proofs = family_proofs + init_proofs + delegation_proofs;

            // Post to ethproofs
            if let Some(client) = &self.eth_client {
                let proof_bytes = crate::prove::serialize_proof_to_bytes(&proof);
                client
                    .proved(
                        &proof_bytes,
                        block_number,
                        cycles,
                        proving_millis,
                        &self.verifier_id,
                    )
                    .await;
            }

            let log = ProvingLog {
                block_number,
                gas_used,
                cycle_count: cycles,
                num_proofs: total_proofs,
                proving_millis,
                message: String::from("Success"),
            };
            self.persist_proving_log(&log)?;
            Ok(log)
        }
        #[cfg(not(feature = "gpu"))]
        {
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
