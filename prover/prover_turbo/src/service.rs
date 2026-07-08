// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use crate::ethproofs_client::{EthProofsConfig, EthproofsClient};
use crate::stdin_builders::{build_stdin_from_eth_tests, build_stdin_from_mfbd};
use alloy_provider::{Provider, ProviderBuilder};
use eyre::{bail, Context, Result};
use z6m_common::{fetch_block_and_witness, FetchOutcome, FetchRequest};

use chrono;
use serde::Serialize;
use sp1_sdk::{
    include_elf, EnvProver, Prover, ProverClient, SP1ProofMode, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;

pub const SILK_ST_ELF: &[u8] = include_elf!("z6m_guest");

// Dynamic prover enum to handle both CPU and CUDA provers
enum DynamicProver {
    Env(EnvProver),
    Cuda(sp1_sdk::CudaProver),
}

impl DynamicProver {
    fn new() -> Result<Self> {
        if env::var("SP1_PROVER").unwrap_or_default() == "cuda" {
            Ok(DynamicProver::Cuda(ProverClient::builder().cuda().build()))
        } else {
            Ok(DynamicProver::Env(ProverClient::from_env()))
        }
    }

    fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        match self {
            DynamicProver::Env(prover) => prover.setup(elf),
            DynamicProver::Cuda(prover) => prover.setup(elf),
        }
    }

    fn prove(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<(SP1ProofWithPublicValues, u64)> {
        match self {
            DynamicProver::Env(prover) => {
                // Pre-execute to get cycle count
                let (mut output, report) = prover
                    .execute(SILK_ST_ELF, stdin)
                    .run()
                    .map_err(|e| eyre::eyre!("Execution failed: {}", e))?;
                let _gas_used = output.read::<u64>();
                let cycle_count = report.total_instruction_count();

                // Now prove
                let proof_result = match mode {
                    SP1ProofMode::Core => prover.prove(pk, stdin).core().run(),
                    SP1ProofMode::Compressed => prover.prove(pk, stdin).compressed().run(),
                    SP1ProofMode::Plonk => prover.prove(pk, stdin).plonk().run(),
                    SP1ProofMode::Groth16 => prover.prove(pk, stdin).groth16().run(),
                };
                let proof = proof_result.map_err(|e| eyre::eyre!("Proving failed: {}", e))?;
                Ok((proof, cycle_count))
            }
            DynamicProver::Cuda(prover) => prover
                .prove_with_cycles(pk, stdin, mode)
                .map_err(|e| eyre::eyre!("Proving failed: {}", e)),
        }
    }

    fn verify(&self, proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> Result<()> {
        match self {
            DynamicProver::Env(prover) => prover
                .verify(proof, vk)
                .map_err(|e| eyre::eyre!("Verification failed: {}", e)),
            DynamicProver::Cuda(prover) => prover
                .verify(proof, vk)
                .map_err(|e| eyre::eyre!("Verification failed: {}", e)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub data_dir: PathBuf,
    #[allow(dead_code)]
    pub rpc_url: Option<String>,
    #[allow(dead_code)]
    pub save_all_responses: bool,
    pub ethproofs: Option<EthProofsConfig>,
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub start_block: Option<u64>,
    pub end_block: Option<u64>,
    pub prove_every: Option<u64>,
    pub execute_every: Option<u64>,
    pub post_every: Option<u64>,
    pub rpc_url: String,
    pub save_all_responses: bool,
    pub proving_key_path: Option<PathBuf>,
    pub proof_type: String,
}

#[derive(Clone, Debug)]
pub struct SetupOptions {
    pub pk_path: PathBuf,
    pub vk_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub block_number: Option<u64>,
    pub rpc_url: String,
    pub save_all_responses: bool,
    pub data_dir: PathBuf,
    pub build_eth_test: bool,
}

#[derive(Clone, Debug)]
pub struct ExecuteOptions {
    pub block_number: u64,
    pub file_name: Option<PathBuf>,
    pub is_test: bool,
    pub data_dir: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ProveOptions {
    pub block_number: u64,
    pub file_name: Option<PathBuf>,
    pub is_test: bool,
    pub data_dir: PathBuf,
    pub pk_path: PathBuf,
    pub proof_path: Option<PathBuf>,
    pub proof_type: String,
}

#[derive(Clone, Debug)]
pub struct VerifyOptions {
    pub proof_path: PathBuf,
    pub vk_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecutionLog {
    pub block_number: u64,
    pub gas_used: u64,
    pub cycle_count: u64,
    pub prover_gas: u64,
    pub syscall_count: u64,
    pub input_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProvingLog {
    pub block_number: u64,
    pub gas_used: u64,
    pub cycle_count: u64,
    pub proof_path: PathBuf,
    pub proof_type: String,
    pub proving_millis: u64,
    pub message: String,
}

pub struct Z6mProverService {
    client: Arc<Mutex<DynamicProver>>,
    config: AppConfig,
    eth_client: Option<EthproofsClient>,
}

impl Z6mProverService {
    fn format_timestamp() -> String {
        chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string()
    }

    pub fn new(config: AppConfig) -> Result<Self> {
        let client = Arc::new(Mutex::new(DynamicProver::new()?));
        let eth_client = config.ethproofs.clone().map(EthproofsClient::new);
        Ok(Self {
            client,
            config,
            eth_client,
        })
    }

    pub async fn setup_keys(&self, opts: SetupOptions) -> Result<()> {
        let client = self.client.lock().await;
        let (pk, vk) = client.setup(SILK_ST_ELF);
        std::fs::create_dir_all(opts.pk_path.parent().unwrap_or_else(|| Path::new(".")))?;
        std::fs::create_dir_all(opts.vk_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let cfg = bincode::config::standard();
        let mut fpk = BufWriter::new(File::create(&opts.pk_path)?);
        bincode::serde::encode_into_std_write(&pk, &mut fpk, cfg)?;
        let mut fvk = BufWriter::new(File::create(&opts.vk_path)?);
        bincode::serde::encode_into_std_write(&vk, &mut fvk, cfg)?;
        info!(
            "setup completed: pk={}, vk={}",
            opts.pk_path.display(),
            opts.vk_path.display()
        );
        Ok(())
    }

    pub async fn fetch_block(&self, opts: FetchOptions) -> Result<FetchOutcome> {
        let outcome = fetch_block_and_witness(FetchRequest {
            rpc_url: &opts.rpc_url,
            block_number: opts.block_number,
            data_dir: opts.data_dir,
            save_all_responses: opts.save_all_responses,
            build_eth_test: opts.build_eth_test,
        })
        .await?;
        Ok(outcome)
    }

    pub fn execute_block(&self, opts: ExecuteOptions) -> Result<ExecutionLog> {
        let input_path = self.resolve_input_path(
            opts.block_number,
            opts.file_name,
            opts.is_test,
            &opts.data_dir,
        )?;
        if !input_path.exists() {
            bail!(
                "input file for block {} not found at {}",
                opts.block_number,
                input_path.display()
            );
        }
        let stdin = if opts.is_test {
            build_stdin_from_eth_tests(&input_path)?
        } else {
            build_stdin_from_mfbd(&input_path)?
        };

        let client = ProverClient::from_env();
        let client2 = Exe
    

        let (mut output, report) = client.execute(SILK_ST_ELF, &stdin).run().unwrap();

        let gas_used = output.read::<u64>();
        let cycle_count = report.total_instruction_count();
        let prover_gas = report.gas.unwrap_or_default();
        let syscall_count = report.total_syscall_count();
        info!(
            "execution complete, block={} gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}",
            opts.block_number, gas_used, cycle_count, prover_gas, syscall_count
        );

        let log = ExecutionLog {
            block_number: opts.block_number,
            gas_used,
            cycle_count,
            prover_gas,
            syscall_count,
            input_path: input_path.clone(),
        };
        self.persist_execution_logs(&opts.data_dir, &log)?;
        Ok(log)
    }

    pub async fn prove_block(&self, opts: &ProveOptions) -> Result<ProvingLog> {
        let input_path = self.resolve_input_path(
            opts.block_number,
            opts.file_name.clone(),
            opts.is_test,
            &opts.data_dir,
        )?;
        if !input_path.exists() {
            bail!(
                "input file for block {} not found at {}",
                opts.block_number,
                input_path.display()
            );
        }

        let stdin = if opts.is_test {
            build_stdin_from_eth_tests(&input_path)?
        } else {
            build_stdin_from_mfbd(&input_path)?
        };

        let cfg = bincode::config::standard();
        let pk: SP1ProvingKey = {
            let mut r = BufReader::new(File::open(&opts.pk_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        // Lock the client for exclusive proving access
        let client = self.client.lock().await;

        let start = Instant::now();
        let proof_mode = match opts.proof_type.as_str() {
            "core" => SP1ProofMode::Core,
            "groth16" => SP1ProofMode::Groth16,
            "plonk" => SP1ProofMode::Plonk,
            _ => SP1ProofMode::Compressed,
        };

        let (mut proof, cycle_count) = client.prove(&pk, &stdin, proof_mode)?;
        let proving_millis = start.elapsed().as_millis() as u64;
        let gas_used = proof.public_values.read::<u64>();

        // Drop the client lock here so other operations can proceed
        drop(client);

        let proof_path = self.write_proof(&opts, &proof)?;
        let log = ProvingLog {
            block_number: opts.block_number,
            gas_used,
            cycle_count,
            proof_path: proof_path.clone(),
            proof_type: opts.proof_type.clone(),
            proving_millis,
            message: String::from("Success"),
        };
        self.persist_proving_logs(&opts.data_dir, &log)?;
        Ok(log)
    }

    // Static version of prove_block that takes client as parameter for concurrent use
    async fn prove_block_with_client(
        opts: &ProveOptions,
        client_arc: Arc<Mutex<DynamicProver>>,
        eth_client: Option<&EthproofsClient>,
    ) -> Result<ProvingLog> {
        let input_path = if let Some(file_name) = &opts.file_name {
            file_name.clone()
        } else {
            let file_path = if opts.is_test {
                format!("ethTests{}.json", opts.block_number)
            } else {
                format!("unifiedBlockAndStateRlp{}.bin", opts.block_number)
            };
            opts.data_dir
                .join(opts.block_number.to_string())
                .join(file_path)
        };

        if !input_path.exists() {
            bail!(
                "input file for block {} not found at {}",
                opts.block_number,
                input_path.display()
            );
        }

        let stdin = if opts.is_test {
            build_stdin_from_eth_tests(&input_path)?
        } else {
            build_stdin_from_mfbd(&input_path)?
        };

        let cfg = bincode::config::standard();
        let pk: SP1ProvingKey = {
            let mut r = BufReader::new(File::open(&opts.pk_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        // Write proof to file
        let proof_path = opts
            .data_dir
            .join(opts.block_number.to_string())
            .join(format!("proof{}.bin", opts.block_number));

        if let Some(parent) = proof_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Call proving hook
        if let Some(client) = eth_client {
            client.proving(opts.block_number).await;
        }

        let mut start = Instant::now();
        // Lock the client for exclusive proving access and prove with timeout
        let proof_result = tokio::time::timeout(
            Duration::from_secs(1800), // 30 minutes timeout
            async {
                let client = client_arc.lock().await;
                let proof_mode = match opts.proof_type.as_str() {
                    "core" => SP1ProofMode::Core,
                    "groth16" => SP1ProofMode::Groth16,
                    "plonk" => SP1ProofMode::Plonk,
                    _ => SP1ProofMode::Compressed,
                };
                start = Instant::now();
                client.prove(&pk, &stdin, proof_mode)
            },
        )
        .await;

        let proving_millis = start.elapsed().as_millis() as u64;

        match proof_result {
            Ok(Ok((mut proof, cycle_count))) => {
                let gas_used = proof.public_values.read::<u64>();

                println!(
                    "[{}] Successfully proved block {}, gas_used={}, cycles={}, proving_ms={}",
                    Self::format_timestamp(),
                    opts.block_number,
                    gas_used,
                    cycle_count,
                    proving_millis
                );

                let cfg = bincode::config::standard();
                let mut fp = BufWriter::new(File::create(&proof_path)?);
                bincode::serde::encode_into_std_write(&proof, &mut fp, cfg)?;

                // Call proved hook
                if let Some(client) = eth_client {
                    // Read proof bytes back from file
                    let proof_bytes = std::fs::read(&proof_path)?;
                    // Get vk from pk
                    let vk = &pk.vk;
                    client
                        .proved(
                            &proof_bytes,
                            opts.block_number,
                            cycle_count,
                            proving_millis,
                            vk,
                        )
                        .await;
                }

                let log = ProvingLog {
                    block_number: opts.block_number,
                    gas_used,
                    cycle_count,
                    proof_path: proof_path.clone(),
                    proof_type: opts.proof_type.clone(),
                    proving_millis,
                    message: String::from("Success"),
                };

                // Write log to file
                Self::persist_proving_logs_static(&opts.data_dir, &log)?;
                Ok(log)
            }
            Ok(Err(err)) => {
                // Proving operation failed
                println!(
                    "[{}] Error trying to prove block {}: {}",
                    Self::format_timestamp(),
                    opts.block_number,
                    err
                );

                let log = ProvingLog {
                    block_number: opts.block_number,
                    gas_used: 0,
                    cycle_count: 0,
                    proof_path: proof_path.clone(),
                    proof_type: opts.proof_type.clone(),
                    proving_millis,
                    message: err.to_string(),
                };

                Self::persist_proving_logs_static(&opts.data_dir, &log)?;
                bail!("Proving failed: {}", err)
            }
            Err(_timeout_err) => {
                // Timeout occurred
                let err_msg = format!("Proving timed out after {} seconds", 1800);
                println!("[{}] {}", Self::format_timestamp(), err_msg);

                let log = ProvingLog {
                    block_number: opts.block_number,
                    gas_used: 0,
                    cycle_count: 0,
                    proof_path: proof_path.clone(),
                    proof_type: opts.proof_type.clone(),
                    proving_millis,
                    message: err_msg.clone(),
                };

                Self::persist_proving_logs_static(&opts.data_dir, &log)?;
                bail!("{}", err_msg)
            }
        }
    }

    pub async fn verify_proof(&self, opts: VerifyOptions) -> Result<()> {
        let cfg = bincode::config::standard();
        let mut proof: SP1ProofWithPublicValues = {
            let mut r = BufReader::new(File::open(&opts.proof_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        let vk: SP1VerifyingKey = {
            let mut r = BufReader::new(File::open(&opts.vk_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        let client = self.client.lock().await;
        client
            .verify(&proof, &vk)
            .wrap_err("failed to verify proof")?;

        let gas_used = proof.public_values.read::<u64>();
        info!("verification complete, gas_used={}", gas_used);
        Ok(())
    }

    pub async fn run_service(&self, service: ServiceConfig) -> Result<()> {
        info!("starting service mode");
        let url = Url::parse(&service.rpc_url)?;
        let provider = ProviderBuilder::new().connect_http(url);

        let mut next_block = if let Some(start) = service.start_block {
            start
        } else {
            match Self::get_block_number_with_retry(&provider, 3).await {
                Ok(block_num) => block_num.saturating_add(1),
                Err(e) => {
                    error!("Failed to get initial block number after retries: {}", e);
                    return Err(e);
                }
            }
        };

        info!("Service starting from block: {}", next_block);

        loop {
            // let mut latest = match Self::get_block_number_with_retry(&provider, 3).await {
            //     Ok(latest) => latest,
            //     Err(err) => {
            //         error!(error = %err, "Failed to get latest block number after retries, will retry in 30 seconds");
            //         sleep(Duration::from_secs(30)).await;
            //         continue;
            //     }
            // };

            if service.end_block.is_some() {
                let end = service.end_block.unwrap();
                if next_block > end {
                    break Ok(());
                }
                if latest > end {
                    latest = end;
                }
            }

            // Collect blocks to process
            let blocks_to_process: Vec<u64> = (next_block..=latest).collect();

            // Process all blocks concurrently
            let data_dir = self.config.data_dir.clone();
            let client_arc = self.client.clone(); // Clone the Arc<Mutex<DynamicProver>>
            let eth_client = self.eth_client.clone();
            let tasks: Vec<_> = blocks_to_process
                .into_iter()
                .map(|block_num| {
                    let service_clone = service.clone();
                    let data_dir_clone = data_dir.clone();
                    let client_clone = client_arc.clone();
                    let eth_client_clone = eth_client.clone();
                    tokio::spawn(async move {
                        if let Err(err) = Self::process_block_static(
                            block_num,
                            &service_clone,
                            &data_dir_clone,
                            client_clone,
                            eth_client_clone.as_ref(),
                        )
                        .await
                        {
                            error!(%block_num, error = %err, "failed to process block");
                        }
                    })
                })
                .collect();

            if !tasks.is_empty() {
                // Wait for all spawned tasks to complete
                for task in tasks {
                    let _ = task.await;
                }
                next_block = latest + 1;
            }

            sleep(Duration::from_secs(6)).await;
        }
    }

    // Helper method to get block number with retry logic
    async fn get_block_number_with_retry<P>(provider: &P, max_retries: u32) -> Result<u64>
    where
        P: Provider,
    {
        let mut attempts = 0;

        loop {
            match provider.get_block_number().await {
                Ok(block_number) => return Ok(block_number),
                Err(err) => {
                    attempts += 1;
                    if attempts >= max_retries {
                        return Err(err.into());
                    }

                    let delay = Duration::from_secs(2_u64.pow(attempts.min(5))); // Exponential backoff, max 32 seconds
                    warn!(
                        attempt = attempts,
                        max_retries = max_retries,
                        delay_secs = delay.as_secs(),
                        error = %err,
                        "Failed to get block number, retrying..."
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    // Process block using shared client for proper synchronization
    async fn process_block_static(
        block_number: u64,
        service: &ServiceConfig,
        data_dir: &PathBuf,
        client: Arc<Mutex<DynamicProver>>,
        eth_client: Option<&EthproofsClient>,
    ) -> Result<()> {
        println!(
            "[{}] Received block number from RPC {}",
            Self::format_timestamp(),
            block_number
        );
        let should_prove = matches_interval(service.prove_every, block_number);
        let should_execute = matches_interval(service.execute_every, block_number) && !should_prove;
        let should_post = matches_interval(service.post_every, block_number) || should_prove;

        let should_anything = should_prove || should_execute || service.save_all_responses;
        if !should_anything {
            println!(
                "[{}] Nothing to do for block {}",
                Self::format_timestamp(),
                block_number
            );
            return Ok(());
        }

        let outcome = fetch_block_and_witness(FetchRequest {
            rpc_url: &service.rpc_url,
            block_number: Some(block_number),
            data_dir: data_dir.clone(),
            save_all_responses: service.save_all_responses,
            build_eth_test: false,
        })
        .await?;
        let unified_path = outcome.unified_rlp_path.clone();

        if should_execute {
            println!(
                "[{}] Executing only block {}",
                Self::format_timestamp(),
                block_number
            );
            if let Err(err) = Self::execute_block_static(block_number, &unified_path, data_dir) {
                error!(%block_number, error = %err, "execution failed");
            }
        }

        let mut proof_log: Option<ProvingLog> = None;
        if should_prove {
            println!(
                "[{}] Proving block {}",
                Self::format_timestamp(),
                block_number
            );

            // Call queued hook
            if let Some(client) = eth_client {
                client.queued(block_number).await;
            }

            let pk_path = match service.proving_key_path.clone() {
                Some(path) => path,
                None => {
                    warn!(%block_number, "skipping proving because no pk_path provided");
                    return Ok(());
                }
            };
            let prove_opts = ProveOptions {
                block_number,
                file_name: Some(unified_path.clone()),
                is_test: false,
                data_dir: data_dir.clone(),
                pk_path: pk_path.clone(),
                proof_path: None, // Will be generated by prove_block method
                proof_type: service.proof_type.clone(),
            };

            match tokio::time::timeout(
                Duration::from_secs(1800), // 30 minutes timeout
                Self::prove_block_with_client(&prove_opts, client.clone(), eth_client),
            )
            .await
            {
                Ok(Ok(log)) => {
                    proof_log = Some(log);
                }
                Ok(Err(err)) => {
                    error!(%block_number, error = %err, "proving failed");
                }
                Err(_) => {
                    error!(%block_number, "proving timed out after 30 minutes");
                }
            }
        }

        Ok(())
    }

    fn execute_block_static(
        block_number: u64,
        input_path: &PathBuf,
        data_dir: &PathBuf,
    ) -> Result<ExecutionLog> {
        if !input_path.exists() {
            bail!(
                "input file for block {} not found at {}",
                block_number,
                input_path.display()
            );
        }

        let stdin = build_stdin_from_mfbd(input_path)?;

        // Use CPU executor for the service
        let client = ProverClient::from_env();

        let (mut output, report) = client.execute(SILK_ST_ELF, &stdin).run().unwrap();
        let gas_used = output.read::<u64>();
        let cycle_count = report.total_instruction_count();
        let prover_gas = report.gas.unwrap_or_default();
        let syscall_count = report.total_syscall_count();
        info!(
            "execution complete, block={} gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}",
            block_number, gas_used, cycle_count, prover_gas, syscall_count
        );

        let log = ExecutionLog {
            block_number: block_number,
            gas_used,
            cycle_count,
            prover_gas,
            syscall_count,
            input_path: input_path.clone(),
        };
        Self::persist_execution_logs_static(data_dir, &log)?;
        Ok(log)
    }

    fn persist_execution_logs_static(data_dir: &Path, log: &ExecutionLog) -> Result<()> {
        let log_file: PathBuf = data_dir.join("executionLogs.log");
        let mut text_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let timestamp = Self::format_timestamp();
        writeln!(
            &mut text_file,
            "[{}] block {} executed, gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}, input={}",
            timestamp,
            log.block_number,
            log.gas_used,
            log.cycle_count,
            log.prover_gas,
            log.syscall_count,
            log.input_path.display()
        )?;
        Ok(())
    }

    fn persist_proving_logs_static(data_dir: &Path, log: &ProvingLog) -> Result<()> {
        let log_file: PathBuf = data_dir.join("provingLogs.log");
        let mut text_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let timestamp = Self::format_timestamp();
        writeln!(
            &mut text_file,
            "[{}] block {} proved, gas_used={}, cycles={}, proof_path={}, proof_type={}, proving_ms={}",
            timestamp,
            log.block_number,
            log.gas_used,
            log.cycle_count,
            log.proof_path.display(),
            log.proof_type,
            log.proving_millis
        )?;
        Ok(())
    }

    fn resolve_input_path(
        &self,
        block_number: u64,
        file_name: Option<PathBuf>,
        is_test: bool,
        data_dir: &Path,
    ) -> Result<PathBuf> {
        if let Some(file) = file_name {
            return Ok(file);
        }
        if block_number == 0 {
            bail!("must provide --block-number > 0 or explicit input file");
        }
        let dir = data_dir.join("blocks/".to_owned() + &block_number.to_string());
        let file_name = if is_test {
            format!("ethTests{}.json", block_number)
        } else {
            format!("unifiedBlockAndStateRlp{}.bin", block_number)
        };
        Ok(dir.join(file_name))
    }

    fn write_proof(
        &self,
        opts: &ProveOptions,
        proof: &SP1ProofWithPublicValues,
    ) -> Result<PathBuf> {
        let cfg = bincode::config::standard();
        let target_path = if let Some(path) = &opts.proof_path {
            path.clone()
        } else {
            opts.data_dir
                .join(opts.block_number.to_string())
                .join(format!("proof{}.bin", opts.block_number))
        };
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut fp = BufWriter::new(File::create(&target_path)?);
        bincode::serde::encode_into_std_write(proof, &mut fp, cfg)?;
        Ok(target_path)
    }

    fn persist_execution_logs(&self, data_dir: &Path, log: &ExecutionLog) -> Result<()> {
        let log_file: PathBuf = data_dir.join("executionLogs.log");
        let mut text_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let timestamp = Self::format_timestamp();
        writeln!(
            &mut text_file,
            "[{}] block {} executed, gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}, input={}",
            timestamp,
            log.block_number,
            log.gas_used,
            log.cycle_count,
            log.prover_gas,
            log.syscall_count,
            log.input_path.display()
        )?;
        Ok(())
    }

    fn persist_proving_logs(&self, data_dir: &Path, log: &ProvingLog) -> Result<()> {
        let log_file: PathBuf = data_dir.join("provingLogs.log");
        let mut text_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)?;
        let timestamp = Self::format_timestamp();
        writeln!(
            &mut text_file,
            "[{}] block {} proved, gas_used={}, cycles={}, proof_path={}, proof_type={}, proving_ms={}",
            timestamp,
            log.block_number,
            log.gas_used,
            log.cycle_count,
            log.proof_path.display(),
            log.proof_type,
            log.proving_millis
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
