// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use crate::ethproofs_client::{EthProofsConfig, EthproofsClient};
use crate::stdin_builders::{build_stdin_from_eth_tests, build_stdin_from_mfbd};
use alloy::pubsub::Subscription;
use alloy::transports::ws::{WebSocketConfig, WsConnect};
use alloy_primitives::B256;
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types::Header;
use eyre::{bail, Context, Result};
use z6m_common::{fetch_block_and_witness, FetchOutcome, FetchRequest};

use chrono;
use serde::Serialize;
use sp1_cuda::CudaProvingKey;
use sp1_sdk::{
    include_elf, CpuProver, CudaProver, Elf, ProveRequest, Prover,
    ProverClient, ProvingKey, SP1ProofMode, SP1ProofWithPublicValues, SP1Stdin,
    SP1VerifyingKey, SP1ProvingKey
};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::env;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;

pub const Z6M_ELF: Elf = include_elf!("z6m_guest");

/// Wall-clock ms since the Unix epoch. Used by the inline phase-boundary
/// markers (BEGIN_FETCH / BEGIN_EXEC / END_EXEC) emitted from the live
/// service loop, all of which tag a `now_ms=` field. fetcher.rs emits its
/// own BEGIN_BUNDLE marker with an equivalent SystemTime capture.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Guest-committed public values (see docs/architecture.md for encoding details).
#[derive(Debug, Clone)]
struct PublicValues {
    gas_used: u64,
    pre_state_root: B256,
    post_state_root: B256,
    block_hash: B256,
    chain_id: u64,
}

impl PublicValues {
    fn parse(pv: &[u8]) -> Result<Self> {
        if pv.len() < 112 {
            bail!("public values too short: {} bytes (expected >= 112)", pv.len());
        }
        Ok(Self {
            gas_used: u64::from_le_bytes(pv[0..8].try_into().unwrap()),
            pre_state_root: B256::from_slice(&pv[8..40]),
            post_state_root: B256::from_slice(&pv[40..72]),
            block_hash: B256::from_slice(&pv[72..104]),
            chain_id: u64::from_le_bytes(pv[104..112].try_into().unwrap()),
        })
    }
}

// Dynamic prover enum to handle both CPU and CUDA provers
enum DynamicProver {
    Env(CpuProver),
    Cuda(CudaProver),
}

#[derive(Clone)]
enum DynProvingKey {
    Env(SP1ProvingKey),
    Cuda(CudaProvingKey),
}

impl DynamicProver {
    async fn new() -> Result<Self> {
        if env::var("SP1_PROVER").unwrap_or_default() == "cuda" {
            Ok(DynamicProver::Cuda(
                ProverClient::builder().cuda().build().await,
            ))
        } else {
            Ok(DynamicProver::Env(
                ProverClient::builder().cpu().build().await,
            ))
        }
    }

    async fn setup(&self, elf: Elf) -> DynProvingKey {
        match self {
            DynamicProver::Env(prover) => DynProvingKey::Env(prover.setup(elf).await.unwrap()),
            DynamicProver::Cuda(prover) => DynProvingKey::Cuda(prover.setup(elf).await.unwrap()),
        }
    }

    async fn prove(
        &self,
        pk: &DynProvingKey,
        stdin: &SP1Stdin,
        mode: SP1ProofMode,
    ) -> Result<(SP1ProofWithPublicValues, u64)> {
        match (self, pk) {
            (DynamicProver::Env(prover), DynProvingKey::Env(env_pk)) => {
                // Pre-execute to get cycle count
                let (mut output, report) = prover
                    .execute(Z6M_ELF, stdin.clone())
                    .await
                    .map_err(|e| eyre::eyre!("Execution failed: {}", e))?;
                let _gas_used = output.read::<u64>();
                let cycle_count = report.total_instruction_count();

                // Now prove
                let proof_result = match mode {
                    SP1ProofMode::Core => prover.prove(env_pk, stdin.clone()).core().await,
                    SP1ProofMode::Compressed => {
                        prover.prove(env_pk, stdin.clone()).compressed().await
                    }
                    SP1ProofMode::Plonk => prover.prove(env_pk, stdin.clone()).plonk().await,
                    SP1ProofMode::Groth16 => prover.prove(env_pk, stdin.clone()).groth16().await,
                };
                let proof = proof_result.map_err(|e| eyre::eyre!("Proving failed: {}", e))?;
                Ok((proof, cycle_count))
            }
            (DynamicProver::Cuda(prover), DynProvingKey::Cuda(cuda_pk)) => {
                let (proof, cycles) = prover
                    .prove_with_cycles(cuda_pk, stdin.clone(), mode)
                    .await
                    .map_err(|e| eyre::eyre!("Proving failed: {}", e))?;
                Ok((proof, cycles))
            }
            (DynamicProver::Env(_cpu_prover), DynProvingKey::Cuda(_cuda_proving_key)) => todo!(),
            (DynamicProver::Cuda(_cuda_prover), DynProvingKey::Env(_cpuproving_key)) => todo!(),
        }
    }

    #[allow(dead_code)]
    fn verify(&self, proof: &SP1ProofWithPublicValues, vk: &SP1VerifyingKey) -> Result<()> {
        match self {
            DynamicProver::Env(prover) => prover
                .verify(proof, vk, None)
                .map_err(|e| eyre::eyre!("Verification failed: {}", e)),
            DynamicProver::Cuda(prover) => prover
                .verify(proof, vk, None)
                .map_err(|e| eyre::eyre!("Verification failed: {}", e)),
        }
    }

    /// Execute the guest ELF for a single block and return public values plus
    /// execution report. Mirrors `Prover::execute` for both backends so the
    /// service can race a CPU and CUDA client without branching at call sites.
    async fn execute(
        &self,
        stdin: SP1Stdin,
    ) -> Result<(sp1_sdk::SP1PublicValues, sp1_sdk::ExecutionReport)> {
        match self {
            DynamicProver::Env(prover) => prover
                .execute(Z6M_ELF, stdin)
                .await
                .map_err(|e| eyre::eyre!("Execution failed: {}", e)),
            DynamicProver::Cuda(prover) => prover
                .execute(Z6M_ELF, stdin)
                .await
                .map_err(|e| eyre::eyre!("Execution failed: {}", e)),
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
    /// Opt-in WebSocket EL endpoint (`ws`/`wss`). `None` → poll-based behaviour
    /// identical to today. Validated at [`Z6mProverService::run_service`]
    /// startup by [`validate_ws_url`].
    pub ws_url: Option<String>,
    pub save_all_responses: bool,
    pub download_only: bool,
    #[allow(dead_code)]
    pub proving_key_path: Option<PathBuf>,
    pub proof_type: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct SetupOptions {
    pub pk_path: PathBuf,
    pub vk_path: PathBuf,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub block_number: Option<u64>,
    pub rpc_url: String,
    pub save_all_responses: bool,
    pub data_dir: PathBuf,
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
    #[allow(dead_code)]
    pub proof_path: Option<PathBuf>,
    pub proof_type: String,
}

#[allow(dead_code)]
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
    /// Respects the `SP1_PROVER` env var (CUDA when set, CPU otherwise). Used
    /// for proving and as one half of the execute fallback race.
    client1: Arc<Mutex<DynamicProver>>,
    /// Always a `CpuProver`. Used as the second contender for execution work
    /// so executes never wait for the (possibly busy) primary client.
    client2: Arc<Mutex<DynamicProver>>,
    proving_key: DynProvingKey,
    verifying_key: SP1VerifyingKey,
    config: AppConfig,
    eth_client: Option<EthproofsClient>,
}

impl Z6mProverService {
    fn format_timestamp() -> String {
        chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.6fZ")
            .to_string()
    }

    pub async fn new(config: AppConfig) -> Result<Self> {
        let prover_client = DynamicProver::new().await?;
        let proving_key = prover_client.setup(Z6M_ELF).await;
        let verifying_key = match &proving_key {
            DynProvingKey::Env(env_pk) => env_pk.verifying_key().clone(),
            DynProvingKey::Cuda(cuda_pk) => cuda_pk.verifying_key().clone(),
        };
        let eth_client = config.ethproofs.clone().map(EthproofsClient::new);
        let client1: Arc<Mutex<DynamicProver>> = Arc::new(Mutex::new(prover_client));
        // Always-CPU sibling client. Used so executes can run on a free client
        // while client1 is busy proving (or vice versa).
        let cpu_for_exec = ProverClient::builder().cpu().build().await;
        let client2: Arc<Mutex<DynamicProver>> =
            Arc::new(Mutex::new(DynamicProver::Env(cpu_for_exec)));
        Ok(Self {
            client1,
            client2,
            proving_key,
            verifying_key,
            config,
            eth_client,
        })
    }

    #[allow(dead_code)]
    pub async fn setup_keys(&self, opts: SetupOptions) -> Result<()> {
        let client = self.client1.lock().await;
        let pk = client.setup(Z6M_ELF).await;

        let vk = match &pk {
            DynProvingKey::Env(env_pk) => env_pk.verifying_key().clone(),
            DynProvingKey::Cuda(cuda_pk) => cuda_pk.verifying_key().clone(),
        };

        std::fs::create_dir_all(opts.pk_path.parent().unwrap_or_else(|| Path::new(".")))?;
        std::fs::create_dir_all(opts.vk_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let _cfg = bincode::config::standard();
        // let mut fpk = BufWriter::new(File::create(&opts.pk_path)?);
        // bincode::serde::encode_into_std_write(&pk, &mut fpk, _cfg)?;
        let mut fvk = BufWriter::new(File::create(&opts.vk_path)?);
        bincode::serde::encode_into_std_write(&vk, &mut fvk, _cfg)?;
        info!(
            "setup completed: pk={}, vk={}",
            opts.pk_path.display(),
            opts.vk_path.display()
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn fetch_block(&self, opts: FetchOptions) -> Result<FetchOutcome> {
        let outcome = fetch_block_and_witness(FetchRequest {
            rpc_url: &opts.rpc_url,
            block_number: opts.block_number,
            data_dir: opts.data_dir,
            save_all_responses: opts.save_all_responses,
            geth: false,
            force_rebuild: false,
        })
        .await?;
        Ok(outcome)
    }

    pub async fn prove_block(&self, opts: &ProveOptions) -> Result<ProvingLog> {
        let input_path = Self::resolve_input_path(
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

        let _cfg = bincode::config::standard();
        // let pk: DynProvingKey = {
        //     let mut r = BufReader::new(File::open(&opts.pk_path)?);
        //     bincode::serde::decode_from_std_read(&mut r, _cfg)?
        // };

        // Lock the client for exclusive proving access
        // let client = self.client1.lock().await;

        // let start = Instant::now();
        // let proof_mode = match opts.proof_type.as_str() {
        //     "core" => SP1ProofMode::Core,
        //     "groth16" => SP1ProofMode::Groth16,
        //     "plonk" => SP1ProofMode::Plonk,
        //     _ => SP1ProofMode::Compressed,
        // };
        println!("=========  SPIDEY SPIEDY prove_block  ============");

        let client = ProverClient::builder().cuda().build().await;
        let pk_res = client.setup(Z6M_ELF).await;
        match pk_res {
            Ok(pk) => {
                let _proof = client.prove(&pk, stdin.clone()).compressed().await;
            }
            Err(err) => println!("ERROR {err}"),
        }
        // let proof = client.core(&pk, stdin.clone(), [0; 4]).await.unwrap();
        // let _compressed = client.compress(&pk.verifying_key(), proof, vec![]).await.unwrap();

        // let pk = client.setup(Z6M_ELF).await;
        // let (mut proof, cycle_count) = client.prove(&pk, &stdin, proof_mode).await.unwrap();
        // let proving_millis = start.elapsed().as_millis() as u64;
        // let gas_used = proof.public_values.read::<u64>();

        // // Drop the client lock here so other operations can proceed
        // drop(client);

        // let proof_path = self.write_proof(&opts, &proof)?;
        // let log = ProvingLog {
        //     block_number: opts.block_number,
        //     gas_used,
        //     cycle_count,
        //     proof_path: proof_path.clone(),
        //     proof_type: opts.proof_type.clone(),
        //     proving_millis,
        //     message: String::from("Success"),
        // };
        // self.persist_proving_logs(&opts.data_dir, &log)?;
        // Ok(log)

        let log = ProvingLog {
            block_number: opts.block_number,
            gas_used: 0,
            cycle_count: 0,
            proof_path: PathBuf::new(),
            proof_type: opts.proof_type.clone(),
            proving_millis: 0,
            message: String::from("Success"),
        };
        Ok(log)
    }

    // Per-block proving driver. The caller owns the prover lock guard and
    // hands it in so dispatch logic stays in `run_service`. The guard is
    // dropped before any file I/O so another block can grab the prover ASAP.
    async fn prove_block_with_client(
        opts: &ProveOptions,
        guard: tokio::sync::OwnedMutexGuard<DynamicProver>,
        eth_client: Option<&EthproofsClient>,
        proving_key: DynProvingKey,
        verifying_key: SP1VerifyingKey,
    ) -> Result<ProvingLog> {
        let input_path = if let Some(file_name) = &opts.file_name {
            file_name.clone()
        } else {
            let file_path = if opts.is_test {
                format!("ethTests{}.json", opts.block_number)
            } else {
                format!("flatWitnessBundle{}.mfbd", opts.block_number)
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

        let _cfg = bincode::config::standard();
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

        let proof_mode = match opts.proof_type.as_str() {
            "core" => SP1ProofMode::Core,
            "groth16" => SP1ProofMode::Groth16,
            "plonk" => SP1ProofMode::Plonk,
            _ => SP1ProofMode::Compressed,
        };

        let start = Instant::now();

        // Apply timeout only to the prove operation. The caller-owned guard
        // is what serialises prover access; we don't re-lock here.
        let proof_result = tokio::time::timeout(
            Duration::from_secs(1800), // 30 minutes timeout
            guard.prove(&proving_key.clone(), &stdin, proof_mode),
        )
        .await;

        // Explicitly drop the guard before processing results so the next
        // block can take the lock while we persist artifacts.
        drop(guard);

        let proving_millis = start.elapsed().as_millis() as u64;

        match proof_result {
            Ok(Ok((proof, cycle_count))) => {
                let pv = PublicValues::parse(proof.public_values.as_slice());
                let gas_used = pv.as_ref().map(|v| v.gas_used).unwrap_or(0);

                println!(
                    "[{}] Successfully proved block {}, gas_used={}, cycles={}, proving_ms={}",
                    Self::format_timestamp(),
                    opts.block_number,
                    gas_used,
                    cycle_count,
                    proving_millis
                );
                match &pv {
                    Ok(v) => println!(
                        "[{}]   public values: pre_root={} post_root={} block_hash={} chain_id={}",
                        Self::format_timestamp(),
                        v.pre_state_root, v.post_state_root, v.block_hash, v.chain_id
                    ),
                    Err(e) => warn!("block {}: public values parse failed: {}", opts.block_number, e),
                }

                let cfg = bincode::config::standard();
                let mut fp = BufWriter::new(File::create(&proof_path)?);
                bincode::serde::encode_into_std_write(&proof, &mut fp, cfg)?;

                // Call proved hook
                if let Some(client) = eth_client {
                    // Read proof bytes back from file
                    let proof_bytes = std::fs::read(&proof_path)?;

                    client
                        .proved(
                            &proof_bytes,
                            opts.block_number,
                            cycle_count,
                            proving_millis,
                            &verifying_key.clone(),
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
                let log = ProvingLog {
                    block_number: opts.block_number,
                    gas_used: 0,
                    cycle_count: 0,
                    proof_path: proof_path.clone(),
                    proof_type: opts.proof_type.clone(),
                    proving_millis: 0,
                    message: String::from("FAILED"),
                };

                // Write log to file
                Self::persist_proving_logs_static(&opts.data_dir, &log)?;

                // Proving operation failed
                println!(
                    "[{}] Error trying to prove block {}: {}",
                    Self::format_timestamp(),
                    opts.block_number,
                    err
                );

                bail!("Proving failed: {}", err)
            }
            Err(_timeout_err) => {
                // Timeout occurred
                let err_msg = format!("Proving timed out after {} seconds", 1800);
                println!("[{}] {}", Self::format_timestamp(), err_msg);
                bail!("{}", err_msg)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn verify_proof(&self, opts: VerifyOptions) -> Result<()> {
        let cfg = bincode::config::standard();
        let proof: SP1ProofWithPublicValues = {
            let mut r = BufReader::new(File::open(&opts.proof_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        let vk: SP1VerifyingKey = {
            let mut r = BufReader::new(File::open(&opts.vk_path)?);
            bincode::serde::decode_from_std_read(&mut r, cfg)?
        };

        let client = self.client1.lock().await;
        client
            .verify(&proof, &vk)
            .wrap_err("failed to verify proof")?;

        let pv = PublicValues::parse(proof.public_values.as_slice())?;
        info!(
            "verification complete, gas_used={} pre_root={} post_root={} block_hash={} chain_id={}",
            pv.gas_used, pv.pre_state_root, pv.post_state_root, pv.block_hash, pv.chain_id
        );
        Ok(())
    }

    pub async fn run_service(&mut self, service: ServiceConfig) -> Result<()> {
        info!("starting service mode");
        // Fail fast on a malformed `--ws-url` before any connection attempt.
        // A valid `ws`/`wss` URL is consumed by the `Ws` head source in a later
        // task; here we only validate.
        if let Some(ws_url) = &service.ws_url {
            validate_ws_url(ws_url)?;
        }
        let url = Url::parse(&service.rpc_url)?;
        let provider = ProviderBuilder::new().connect_http(url).erased();

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

        // Tip-watermark source. Task 1 wires `Poll` unconditionally (verbatim
        // extraction of the historical `eth_blockNumber` poll); the `--ws-url`
        // selection of a `Ws` variant arrives in a later task.
        let mut head_source = HeadSource::Poll { provider };

        // Handles for tasks dispatched per block. We only join them when the
        // loop is about to exit (end_block reached) so each iteration advances
        // as soon as a prover lock is acquired, not when the work finishes.
        let mut in_flight: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        loop {
            // Bounds: in end_block mode, stop once we're past it. In live mode
            // (no end_block) we wait for the head source to expose the next
            // block.
            if let Some(end) = service.end_block {
                if next_block > end {
                    break;
                }
            } else {
                match head_source.wait_for_tip(next_block).await {
                    TipStatus::Ready => {}
                    TipStatus::NotReady => continue,
                }
            }

            let block_number = next_block;

            println!(
                "[{}] Received block number from RPC {}",
                Self::format_timestamp(),
                block_number
            );

            let should_prove = matches_interval(service.prove_every, block_number);
            let should_execute =
                matches_interval(service.execute_every, block_number) && !should_prove;
            let _should_post =
                matches_interval(service.post_every, block_number) || should_prove;

            let should_anything = should_prove
                || should_execute
                || service.save_all_responses
                || service.download_only;
            if !should_anything {
                println!(
                    "[{}] Nothing to do for block {}",
                    Self::format_timestamp(),
                    block_number
                );
                next_block += 1;
                continue;
            }

            // Live service: regenerate the flat bundle on every block so that
            // a stale `flatWitnessBundle<N>.mfbd` from a prior run never sneaks
            // past the freshly-fetched RPC data.
            let data_dir = self.config.data_dir.clone();

            // BEGIN_FETCH: just before the RPC fetch starts. block_ts_ms is
            // unknown at this point (header hasn't been fetched) — it's
            // attached to BEGIN_BUNDLE inside fetcher.rs once the header is in
            // hand.
            println!(
                "BEGIN_FETCH block={} now_ms={}",
                block_number,
                now_ms()
            );

            let outcome = match fetch_block_and_witness(FetchRequest {
                rpc_url: &service.rpc_url,
                block_number: Some(block_number),
                data_dir: data_dir.clone(),
                save_all_responses: service.save_all_responses,
                geth: false,
                force_rebuild: true,
            })
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    error!(%block_number, error = %err, "fetch_block_and_witness failed");
                    next_block += 1;
                    continue;
                }
            };
            let unified_path = outcome.flat_bundle_path.clone();

            if service.download_only {
                println!(
                    "[{}] Downloaded block {} to {}",
                    Self::format_timestamp(),
                    block_number,
                    unified_path.display()
                );
                next_block += 1;
                continue;
            }

            if should_prove {
                println!(
                    "[{}] Proving block {}",
                    Self::format_timestamp(),
                    block_number
                );

                // Call queued hook before we even wait for the lock.
                if let Some(client) = &self.eth_client {
                    client.queued(block_number).await;
                }

                // Backpressure: wait until client1 is free, then advance.
                let guard = self.client1.clone().lock_owned().await;

                let prove_opts = ProveOptions {
                    block_number,
                    file_name: Some(unified_path.clone()),
                    is_test: false,
                    data_dir: data_dir.clone(),
                    proof_path: None,
                    proof_type: service.proof_type.clone(),
                };
                let proving_key = self.proving_key.clone();
                let verifying_key = self.verifying_key.clone();
                let eth_client = self.eth_client.clone();

                let handle = tokio::spawn(async move {
                    match Self::prove_block_with_client(
                        &prove_opts,
                        guard,
                        eth_client.as_ref(),
                        proving_key,
                        verifying_key,
                    )
                    .await
                    {
                        Ok(_log) => {}
                        Err(err) => {
                            error!(
                                block_number = prove_opts.block_number,
                                error = %err,
                                "proving failed"
                            );
                        }
                    }
                });
                in_flight.push(handle);
            } else if should_execute {
                println!(
                    "[{}] Executing only block {}",
                    Self::format_timestamp(),
                    block_number
                );

                // Race the two clients: whichever lock resolves first owns
                // this block's execution. tokio Mutex::lock_owned is
                // cancel-safe — dropping the loser's future cleanly aborts.
                let c1 = self.client1.clone();
                let c2 = self.client2.clone();
                let guard = tokio::select! {
                    g = c1.lock_owned() => g,
                    g = c2.lock_owned() => g,
                };

                let input_path = unified_path.clone();
                let log_path = data_dir.join("executionLogs.log");

                let handle = tokio::spawn(async move {
                    let stdin = match build_stdin_from_mfbd(&input_path) {
                        Ok(s) => s,
                        Err(e) => {
                            error!(
                                %block_number,
                                error = %e,
                                "failed to build stdin"
                            );
                            return;
                        }
                    };
                    // BEGIN_EXEC: stdin built, guard acquired, just before the
                    // prover execute. END_EXEC fires the moment execute returns.
                    println!(
                        "BEGIN_EXEC block={} now_ms={}",
                        block_number,
                        now_ms()
                    );
                    let (mut output, report) = match guard.execute(stdin).await {
                        Ok(result) => result,
                        Err(e) => {
                            error!(%block_number, error = %e, "execution failed");
                            return;
                        }
                    };
                    println!(
                        "END_EXEC block={} now_ms={}",
                        block_number,
                        now_ms()
                    );
                    let gas_used = output.read::<u64>();
                    let cycle_count = report.total_instruction_count();
                    let prover_gas = report.gas().unwrap_or_default();
                    let syscall_count = report.total_syscall_count();
                    // Release the prover lock before file I/O.
                    drop(guard);

                    if gas_used == 0 {
                        error!(%block_number, cycles = cycle_count, prover_gas, "block execution FAILED (gas_used=0)");
                        println!(
                            "FAILED block {} (gas_used=0, cycles={}, prover_gas={}, syscall_count={})",
                            block_number, cycle_count, prover_gas, syscall_count
                        );
                    } else {
                        println!(
                            "Executed block {} (gas_used={}, cycles={}, prover_gas={}, syscall_count={})",
                            block_number, gas_used, cycle_count, prover_gas, syscall_count
                        );
                    }

                    let log = ExecutionLog {
                        block_number,
                        gas_used,
                        cycle_count,
                        prover_gas,
                        syscall_count,
                        input_path: input_path.clone(),
                    };
                    if let Err(err) = Self::persist_execution_logs_static(&log_path, &log) {
                        error!(%block_number, error = %err, "failed to persist execution log");
                    }
                });
                in_flight.push(handle);
            }

            next_block += 1;
        }

        // Drain in-flight task handles so the process doesn't drop unfinished
        // proves/executes when end_block is reached.
        for h in in_flight.drain(..) {
            let _ = h.await;
        }

        Ok(())
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

                    let delay = Duration::from_secs(2);
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

    pub async fn run_test_service(
        start_block: u64,
        end_block: u64,
        execute_every: Option<u64>,
        data_dir: PathBuf,
        execution_log_file: Option<PathBuf>,
    ) -> Result<()> {
        if start_block > end_block {
            bail!("--start-block ({}) must be <= --end-block ({})", start_block, end_block);
        }
        info!("starting test service mode, blocks {} to {}", start_block, end_block);
        let execute_every = match execute_every {
            Some(0) => {
                bail!("--execute-every 0 is invalid in test service mode; use a positive value or omit the flag");
            }
            Some(v) => v,
            None => 1,
        };

        // Create ONE CpuProver upfront and reuse for all blocks
        let client = ProverClient::builder().cpu().build().await;

        // Resolve log path once before the loop
        let log_path = execution_log_file
            .unwrap_or_else(|| data_dir.join("executionLogs.log"));

        for block_number in start_block..=end_block {
            if block_number % execute_every != 0 {
                continue;
            }

            let input_path = Self::resolve_input_path(block_number, None, false, &data_dir)?;
            if !input_path.exists() {
                warn!("block {} not found at {}, skipping", block_number, input_path.display());
                continue;
            }

            let stdin = match build_stdin_from_mfbd(&input_path) {
                Ok(s) => s,
                Err(e) => {
                    warn!("block {} failed to build stdin: {}, skipping", block_number, e);
                    continue;
                }
            };
            let (mut output, report) = match client.execute(Z6M_ELF, stdin).await {
                Ok(result) => result,
                Err(e) => {
                    warn!("block {} execution failed: {}, skipping", block_number, e);
                    continue;
                }
            };

            let gas_used = output.read::<u64>();
            let cycle_count = report.total_instruction_count();
            let prover_gas = report.gas().unwrap_or_default();
            let syscall_count = report.total_syscall_count();

            if gas_used == 0 {
                error!(%block_number, cycles = cycle_count, prover_gas, "block execution FAILED (gas_used=0)");
                println!(
                    "FAILED block {} (gas_used=0, cycles={}, prover_gas={}, syscall_count={})",
                    block_number, cycle_count, prover_gas, syscall_count
                );
            } else {
                println!(
                    "Executed block {} (gas_used={}, cycles={}, prover_gas={}, syscall_count={})",
                    block_number, gas_used, cycle_count, prover_gas, syscall_count
                );
            }

            let log = ExecutionLog {
                block_number,
                gas_used,
                cycle_count,
                prover_gas,
                syscall_count,
                input_path: input_path.clone(),
            };
            Self::persist_execution_logs_static(&log_path, &log)?;
        }
        Ok(())
    }

    pub async fn run_test_service_eest(
        test_dir: PathBuf,
        execution_log_file: Option<PathBuf>,
        max_file_size: u64,
    ) -> Result<()> {
        if !test_dir.is_dir() {
            bail!("--test-dir {} is not a directory", test_dir.display());
        }

        // Collect all EEST test files recursively: .mfbd bundles produced by
        // eest_to_flat_bundle, or raw .json fixtures. The guest dispatches on
        // the leading magic, so both extensions are valid inputs.
        let mut test_files: Vec<PathBuf> = Vec::new();
        Self::collect_test_files(&test_dir, &mut test_files)?;
        test_files.sort();

        if test_files.is_empty() {
            bail!("no .mfbd or .json test files found in {}", test_dir.display());
        }

        info!("starting EEST test-service mode, {} test files from {}", test_files.len(), test_dir.display());

        // Create ONE CpuProver upfront and reuse for all tests
        let client = ProverClient::builder().cpu().build().await;

        let log_path = execution_log_file
            .unwrap_or_else(|| test_dir.join("executionLogs.log"));

        let mut passed = 0u64;
        let mut failed = 0u64;
        let mut skipped = 0u64;
        let total = test_files.len();

        for (i, test_file) in test_files.iter().enumerate() {
            let file_name = test_file.file_name().unwrap_or_default().to_string_lossy();

            // Skip files exceeding size limit
            if max_file_size > 0 {
                if let Ok(meta) = std::fs::metadata(test_file) {
                    if meta.len() > max_file_size {
                        println!(
                            "[{}/{}] SKIP {} (file_size={}MB > limit={}MB)",
                            i + 1, total, file_name,
                            meta.len() / (1024 * 1024),
                            max_file_size / (1024 * 1024)
                        );
                        skipped += 1;
                        continue;
                    }
                }
            }

            info!("[{}/{}] executing {}", i + 1, total, test_file.display());

            let is_json = test_file.extension().map_or(false, |ext| ext == "json");
            let stdin_result = if is_json {
                build_stdin_from_eth_tests(test_file)
            } else {
                build_stdin_from_mfbd(test_file)
            };
            let stdin = match stdin_result {
                Ok(s) => s,
                Err(e) => {
                    warn!("test {} failed to build stdin: {}, skipping", file_name, e);
                    failed += 1;
                    continue;
                }
            };

            let (mut output, report) = match client.execute(Z6M_ELF, stdin).await {
                Ok(result) => result,
                Err(e) => {
                    warn!("test {} execution failed: {}", file_name, e);
                    failed += 1;
                    continue;
                }
            };

            let result = output.read::<u64>();
            let cycle_count = report.total_instruction_count();
            let prover_gas = report.gas().unwrap_or_default();
            let syscall_count = report.total_syscall_count();

            // Guest return protocol (see "Public output" docs/architecture.md).
            const RUN_FAILURE: u64 = u64::MAX;
            const RUN_SKIPPED: u64 = u64::MAX - 1;
            let gas_used = match result {
                RUN_FAILURE => {
                    error!(test = %file_name, cycles = cycle_count, prover_gas, "test execution FAILED");
                    println!(
                        "[{}/{}] FAILED {} (cycles={}, prover_gas={}, syscall_count={})",
                        i + 1, total, file_name, cycle_count, prover_gas, syscall_count
                    );
                    failed += 1;
                    0
                }
                RUN_SKIPPED => {
                    println!(
                        "[{}/{}] SKIP {} (guest reported skipped)",
                        i + 1, total, file_name
                    );
                    skipped += 1;
                    0
                }
                gas => {
                    println!(
                        "[{}/{}] PASS {} (gas_used={}, cycles={}, prover_gas={}, syscall_count={})",
                        i + 1, total, file_name, gas, cycle_count, prover_gas, syscall_count
                    );
                    passed += 1;
                    gas
                }
            };

            let log = ExecutionLog {
                block_number: 0,
                gas_used,
                cycle_count,
                prover_gas,
                syscall_count,
                input_path: test_file.clone(),
            };
            Self::persist_execution_logs_static(&log_path, &log)?;
        }

        println!("\n=== EEST Test Service Summary ===");
        println!("Total: {}, Passed: {}, Failed: {}, Skipped: {}", total, passed, failed, skipped);
        Ok(())
    }

    fn collect_test_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                Self::collect_test_files(&path, files)?;
            } else if path
                .extension()
                .map_or(false, |ext| ext == "mfbd" || ext == "json")
            {
                files.push(path);
            }
        }
        Ok(())
    }

    pub async fn execute_block_static(opts: ExecuteOptions) -> Result<ExecutionLog> {
        let input_path = Self::resolve_input_path(
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
        // Use CPU executor for the service
        // let client = ProverClient::from_env().await;

        // let mut sp1_core_opts_default = SP1CoreOpts::default();

        let client = ProverClient::builder().cpu().build().await;
        let (mut output, report) = client.execute(Z6M_ELF, stdin.clone()).await.unwrap();
        let gas_used = output.read::<u64>();
        let cycle_count = report.total_instruction_count();
        let prover_gas = report.gas().unwrap_or_default();
        let syscall_count = report.total_syscall_count();
        if gas_used == 0 {
            error!(block_number = opts.block_number, cycles = cycle_count, prover_gas, "block execution FAILED (gas_used=0)");
            println!(
                "FAILED block {} (gas_used=0, cycles={}, prover_gas={}, syscall_count={})",
                opts.block_number, cycle_count, prover_gas, syscall_count
            );
        } else {
            info!(
                "execution complete, block={} gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}",
                opts.block_number, gas_used, cycle_count, prover_gas, syscall_count
            );
        }

        let log = ExecutionLog {
            block_number: opts.block_number,
            gas_used,
            cycle_count,
            prover_gas,
            syscall_count,
            input_path: input_path.clone(),
        };
        let log_file = opts.data_dir.join("executionLogs.log");
        Self::persist_execution_logs_static(&log_file, &log)?;
        Ok(log)
    }

    fn persist_execution_logs_static(log_file: &Path, log: &ExecutionLog) -> Result<()> {
        if let Some(parent) = log_file.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut text_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)?;
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
            format!("flatWitnessBundle{}.mfbd", block_number)
        };
        Ok(dir.join(file_name))
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

/// Silence window before the `Ws` head source falls back to a single
/// `eth_blockNumber` backstop poll. Chosen well above mainnet's ~12s block
/// interval so a healthy `newHeads` subscription never triggers it, yet short
/// enough to keep the service advancing if the stream stalls or dies.
const WS_BACKSTOP: Duration = Duration::from_secs(24);

/// Incoming-message cap for the WS connection. tungstenite 0.26 defaults to
/// 64 MiB (`WebSocketConfig::max_message_size` = 64 MiB, `max_frame_size` =
/// 16 MiB), which would *reject* a large `debug_executionWitness` response
/// (10–80 MB of hex JSON) riding this same socket — a correctness item, not
/// tuning. 256 MiB leaves comfortable headroom.
const WS_MAX_MESSAGE_SIZE: usize = 256 << 20;

/// Source of the chain-tip watermark that gates the live service loop.
///
/// `Poll` is a verbatim extraction of the historical per-iteration
/// `eth_blockNumber` poll. `Ws` is a `newHeads` subscription used purely as a
/// tip watermark: during catch-up the loop drains buffered heads
/// non-blockingly ([`HeadSource::drain_tip`]) and never waits on the socket;
/// at tip it awaits the next head or a backstop poll ([`HeadSource::await_tip`]).
/// Both watermark advances go through [`advance_watermark`], so a reorg
/// re-announcement can never move the cursor backward.
enum HeadSource {
    /// Poll `eth_blockNumber` once per live iteration. Memoryless: every
    /// iteration compares `next_block` against a freshly-polled `latest` with
    /// no persisted maximum, matching the pre-watermark behaviour byte for
    /// byte (persisting a max here would diverge whenever `eth_blockNumber`
    /// decreases).
    Poll { provider: DynProvider },
    /// `newHeads` subscription used purely as a tip watermark. Reconnect with
    /// capped backoff on stream death, and never-fatal backstop degradation,
    /// live in [`HeadSource::await_tip`]; `run_service` wiring (mode selection +
    /// watermark seeding) is Task 5. Until then the only constructor is the unit
    /// tests, which inject a channel-backed head stream and a canned backstop.
    #[allow(dead_code)] // constructed by tests now; wired into run_service in Task 5
    Ws {
        /// Pubsub provider hosting both the subscription and the backstop poll
        /// over one connection (alloy multiplexes requests and subscriptions).
        /// Retained for the WS-routed fetch path and for resubscribe. `None` in
        /// unit tests (which inject a channel-backed head stream) and after an
        /// initial connect failure — with no provider a resubscribe cannot
        /// succeed, so the source stays on the backstop.
        provider: Option<DynProvider>,
        /// Live head stream, or `None` while the subscription is down;
        /// `await_tip` resubscribes with capped backoff on the next call.
        heads: Option<HeadStream>,
        /// Fallback watermark poll fired by the `WS_BACKSTOP` timer.
        backstop: Backstop,
        /// Consecutive resubscribe failures; feeds [`backoff_delay`]. Reset to
        /// `0` on a successful resubscribe.
        backoff_attempt: u32,
    },
}

/// Thin seam over the live `newHeads` subscription, mapping each announced
/// header to its block height. alloy 1.0 facts (verified against alloy 1.0.35):
/// `provider.subscribe_blocks()` issues `eth_subscribe("newHeads")` and yields
/// a `Subscription<Header>`; `Header` derefs to `alloy_consensus::Header`,
/// whose `number: u64` is the height. Unit tests substitute an in-memory
/// channel so head semantics run without a live socket. Subscription lag or a
/// dropped item is harmless — only `max(height)` feeds the watermark.
enum HeadStream {
    /// Production: the alloy `newHeads` subscription.
    Live(Subscription<Header>),
    /// Test seam: heights fed directly over a channel.
    #[cfg(test)]
    Channel(tokio::sync::mpsc::UnboundedReceiver<u64>),
}

impl HeadStream {
    /// Non-blocking: return one already-buffered height, or `None` when nothing
    /// is ready (empty channel), the receiver lagged, or the stream closed.
    /// Backs [`HeadSource::drain_tip`]. A lagged/closed result simply ends this
    /// drain pass; the watermark is monotonic and any newer buffered head is
    /// picked up on the next pass or by the backstop.
    fn try_next_height(&mut self) -> Option<u64> {
        match self {
            HeadStream::Live(sub) => sub.try_recv().ok().map(|h| h.number),
            #[cfg(test)]
            HeadStream::Channel(rx) => rx.try_recv().ok(),
        }
    }

    /// Await the next announced height. `None` when the stream ends (the
    /// subscription closed or lagged out, or the test channel was dropped).
    /// Backs [`HeadSource::await_tip`]; a broadcast/mpsc `recv` future is
    /// cancel-safe, so racing it on the `WS_BACKSTOP` timer loses no head.
    async fn next_height(&mut self) -> Option<u64> {
        match self {
            HeadStream::Live(sub) => sub.recv().await.ok().map(|h| h.number),
            #[cfg(test)]
            HeadStream::Channel(rx) => rx.recv().await,
        }
    }
}

/// Fallback watermark source fired by the `WS_BACKSTOP` timer when the head
/// stream is silent. Production issues a single `eth_blockNumber` over the WS
/// provider (requests and subscriptions multiplex over one pubsub connection);
/// tests return a canned height so the backstop path runs without a socket.
enum Backstop {
    #[allow(dead_code)] // constructed by the Task 5 run_service wiring
    Provider(DynProvider),
    #[cfg(test)]
    Canned(u64),
}

impl Backstop {
    /// One watermark poll. `None` on RPC error — the caller keeps the current
    /// watermark and retries on the next backstop tick.
    async fn poll(&self) -> Option<u64> {
        match self {
            Backstop::Provider(provider) => provider.get_block_number().await.ok(),
            #[cfg(test)]
            Backstop::Canned(height) => Some(*height),
        }
    }

    /// Apply one backstop poll to the running watermark; never regresses it.
    async fn watermark(&self, latest: u64) -> u64 {
        match self.poll().await {
            Some(height) => advance_watermark(latest, height),
            None => latest,
        }
    }
}

/// Result of one [`HeadSource::await_tip`] race between the next announced
/// head, a stream end, and the `WS_BACKSTOP` timer.
enum AwaitOutcome {
    Head(u64),
    Ended,
    Timer,
}

/// Build a pubsub provider over `url` and subscribe to `newHeads`, returning
/// the provider (retained for the fetch path and resubscribe) plus the mapped
/// head stream. Raises the incoming-message cap to [`WS_MAX_MESSAGE_SIZE`] so a
/// large `debug_executionWitness` response sharing this socket is not rejected
/// by tungstenite's 64 MiB default.
///
/// alloy 1.0 facts (verified against alloy 1.0.35): `WsConnect::with_config`
/// takes a `WebSocketConfig`; `ProviderBuilder::connect_ws` builds the pubsub
/// provider; `.erased()` yields the same `DynProvider` used for the HTTP path.
#[allow(dead_code)] // wired into run_service in Task 5
async fn connect_ws_head_stream(url: &Url) -> Result<(DynProvider, HeadStream)> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE_SIZE))
        .max_frame_size(Some(WS_MAX_MESSAGE_SIZE));
    let ws = WsConnect::new(url.as_str()).with_config(config);
    let provider = ProviderBuilder::new().connect_ws(ws).await?.erased();
    let heads = provider.subscribe_blocks().await?;
    Ok((provider, HeadStream::Live(heads)))
}

/// Capped exponential backoff between WS resubscribe attempts: `2^attempt`
/// seconds, capped at 32s (`attempt >= 5`). Mirrors the retry cadence in
/// `z6m_common`'s fetcher (`2_u64.pow(attempts.min(5))`); those helpers are
/// private to that crate, so this small duplication is deliberate. Pure, so the
/// progression is unit-testable without a socket.
#[allow(dead_code)] // wired into run_service in Task 5
fn backoff_delay(attempt: u32) -> Duration {
    Duration::from_secs(2_u64.pow(attempt.min(5)))
}

/// Attempt to re-establish the `newHeads` subscription over the retained pubsub
/// provider. alloy manages the underlying WS transport's own reconnection, so
/// re-issuing `subscribe_blocks()` picks up a healed connection; a failure just
/// leaves the source on the backstop until the next attempt. `None` — provider
/// absent (unit tests, or an initial connect that never produced a provider) or
/// the resubscribe RPC errored — keeps the subscription down.
#[allow(dead_code)] // wired into run_service in Task 5
async fn try_resubscribe(provider: &Option<DynProvider>) -> Option<HeadStream> {
    let provider = provider.as_ref()?;
    match provider.subscribe_blocks().await {
        Ok(sub) => Some(HeadStream::Live(sub)),
        Err(err) => {
            warn!(error = %err, "newHeads resubscribe failed; staying on backstop poll");
            None
        }
    }
}

/// Whether the next block is available to fetch, as reported by the head
/// source. `NotReady` means the source has already applied the appropriate
/// backoff sleep and the caller must skip this loop iteration.
enum TipStatus {
    Ready,
    NotReady,
}

impl HeadSource {
    /// Decide whether `next_block` is at or below the current chain tip.
    ///
    /// For [`HeadSource::Poll`] this is the exact historical live-mode logic:
    /// poll `eth_blockNumber` with 6 retries (flat 2s delay inside
    /// [`Z6mProverService::get_block_number_with_retry`]), compare against the
    /// fresh value, sleep 2s and skip when the block is beyond the tip, and on
    /// retry exhaustion log the same warning, sleep 30s, and skip.
    async fn wait_for_tip(&mut self, next_block: u64) -> TipStatus {
        match self {
            HeadSource::Poll { provider } => {
                match Z6mProverService::get_block_number_with_retry(provider, 6).await {
                    Ok(latest) => {
                        if next_block > latest {
                            sleep(Duration::from_secs(2)).await;
                            TipStatus::NotReady
                        } else {
                            TipStatus::Ready
                        }
                    }
                    Err(err) => {
                        error!(error = %err, "Failed to get latest block number after retries, will retry in 30 seconds");
                        sleep(Duration::from_secs(30)).await;
                        TipStatus::NotReady
                    }
                }
            }
            // Ws mode never routes through `wait_for_tip`: the live loop drains
            // heads (`drain_tip`) during catch-up and awaits them (`await_tip`)
            // at tip. Unreachable today — `run_service` only builds `Poll` until
            // the Task 5 mode-selection wiring lands.
            HeadSource::Ws { .. } => {
                unreachable!("wait_for_tip is Poll-only; Ws mode uses drain_tip/await_tip")
            }
        }
    }

    /// Non-blocking watermark refresh from any buffered `newHeads` (Ws mode).
    /// Used during catch-up (`next_block <= latest`), where the loop must never
    /// wait on the socket: it drains every already-buffered head and folds each
    /// through [`advance_watermark`]. Returns `latest` unchanged for the `Poll`
    /// variant (which advances via [`HeadSource::wait_for_tip`]).
    #[allow(dead_code)] // wired into run_service in Task 5
    fn drain_tip(&mut self, latest: u64) -> u64 {
        let mut latest = latest;
        if let HeadSource::Ws {
            heads: Some(stream),
            ..
        } = self
        {
            while let Some(height) = stream.try_next_height() {
                latest = advance_watermark(latest, height);
            }
        }
        latest
    }

    /// Await the next watermark advance at tip (Ws mode).
    ///
    /// When the subscription is live, race the next announced head against the
    /// `WS_BACKSTOP` timer: a head advances the watermark, the timer falls back
    /// to a single backstop poll, and a stream end drops the (dead) stream so
    /// the next call re-establishes it. When the subscription is down — the
    /// stream ended, or was never established after an initial connect failure —
    /// wait out the capped [`backoff_delay`], attempt one resubscribe, and reset
    /// the backoff on success. Either way the backstop poll advances the
    /// watermark, so a dead or absent subscription is never fatal: the service
    /// keeps draining the backlog on backstop-paced watermarks until WS
    /// recovers.
    ///
    /// Returns `latest` unchanged for the `Poll` variant.
    #[allow(dead_code)] // wired into run_service in Task 5
    async fn await_tip(&mut self, latest: u64) -> u64 {
        let HeadSource::Ws {
            provider,
            heads,
            backstop,
            backoff_attempt,
        } = self
        else {
            return latest;
        };

        // Subscription down: back off, try to re-establish it, and reset the
        // backoff on success. The backstop still advances the watermark whether
        // or not the resubscribe succeeds, so the service never stalls.
        if heads.is_none() {
            sleep(backoff_delay(*backoff_attempt)).await;
            match try_resubscribe(provider).await {
                Some(stream) => {
                    *heads = Some(stream);
                    *backoff_attempt = 0;
                }
                None => {
                    *backoff_attempt = backoff_attempt.saturating_add(1);
                }
            }
            return backstop.watermark(latest).await;
        }

        // Subscription live: take the stream out so the match arms can restore
        // or drop it without a borrow conflict inside `select!`.
        let mut stream = heads.take().expect("await_tip: heads is Some");
        let outcome = tokio::select! {
            next = stream.next_height() => match next {
                Some(height) => AwaitOutcome::Head(height),
                None => AwaitOutcome::Ended,
            },
            _ = sleep(WS_BACKSTOP) => AwaitOutcome::Timer,
        };
        match outcome {
            AwaitOutcome::Head(height) => {
                *heads = Some(stream);
                advance_watermark(latest, height)
            }
            AwaitOutcome::Timer => {
                *heads = Some(stream);
                backstop.watermark(latest).await
            }
            AwaitOutcome::Ended => {
                // `stream` is dropped here; `heads` stays `None` so the next
                // call takes the resubscribe branch above. The backstop supplies
                // this iteration's watermark.
                backstop.watermark(latest).await
            }
        }
    }
}

/// Watermark update rule for the `Ws` head source: the tip never moves
/// backward, so a reorg re-announcement at the same or lower height is
/// ignored and each height is processed exactly once. Kept as a pure free
/// function so it is unit-testable without a live socket.
///
/// The `Poll` arm deliberately does NOT call this — it stays memoryless for
/// byte-identical behaviour. Currently only exercised by tests; the `Ws`
/// variant becomes its first production caller in a later task.
#[allow(dead_code)]
fn advance_watermark(latest: u64, announced: u64) -> u64 {
    latest.max(announced)
}

/// Parse and validate the opt-in `--ws-url` flag. Accepts only `ws`/`wss`
/// schemes; anything else (including HTTP endpoints or schemeless input) is a
/// startup error so a misconfigured flag fails fast rather than silently
/// falling back to polling. Pure so it is unit-testable without a socket.
fn validate_ws_url(url: &str) -> Result<Url> {
    let parsed =
        Url::parse(url).with_context(|| format!("--ws-url is not a valid URL: {url:?}"))?;
    match parsed.scheme() {
        "ws" | "wss" => Ok(parsed),
        other => bail!("--ws-url must use the ws:// or wss:// scheme, got {other:?} in {url:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_watermark_advances_on_higher() {
        assert_eq!(advance_watermark(10, 15), 15);
    }

    #[test]
    fn advance_watermark_holds_on_equal() {
        // A re-announcement of the same height must not change the watermark.
        assert_eq!(advance_watermark(10, 10), 10);
    }

    #[test]
    fn advance_watermark_ignores_lower_reorg() {
        // A reorg re-announcement at a lower height must never move the
        // watermark backward.
        assert_eq!(advance_watermark(10, 7), 10);
    }

    #[test]
    fn advance_watermark_seeds_from_zero() {
        assert_eq!(advance_watermark(0, 1), 1);
    }

    #[test]
    fn validate_ws_url_accepts_ws_with_port() {
        let url = validate_ws_url("ws://host:8545").expect("ws:// should be accepted");
        assert_eq!(url.scheme(), "ws");
    }

    #[test]
    fn validate_ws_url_accepts_wss() {
        let url = validate_ws_url("wss://host").expect("wss:// should be accepted");
        assert_eq!(url.scheme(), "wss");
    }

    #[test]
    fn validate_ws_url_rejects_http() {
        assert!(validate_ws_url("http://host:8545").is_err());
    }

    #[test]
    fn validate_ws_url_rejects_https() {
        assert!(validate_ws_url("https://host").is_err());
    }

    #[test]
    fn validate_ws_url_rejects_schemeless() {
        assert!(validate_ws_url("host:8545").is_err());
    }

    #[test]
    fn validate_ws_url_rejects_garbage() {
        assert!(validate_ws_url("not a url").is_err());
    }

    // ---- Ws head source (channel-injected seam, no live socket) ----

    /// Build a `HeadSource::Ws` whose head stream is a plain mpsc channel and
    /// whose backstop returns `backstop_height`. Returns the source and the
    /// sender so a test drives announced heights directly.
    fn ws_with_channel(
        backstop_height: u64,
    ) -> (HeadSource, tokio::sync::mpsc::UnboundedSender<u64>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let source = HeadSource::Ws {
            provider: None,
            heads: Some(HeadStream::Channel(rx)),
            backstop: Backstop::Canned(backstop_height),
            backoff_attempt: 0,
        };
        (source, tx)
    }

    #[test]
    fn ws_drain_tip_advances_watermark_from_heads() {
        let (mut source, tx) = ws_with_channel(0);
        tx.send(5).unwrap();
        tx.send(7).unwrap();
        // Non-blocking drain of already-buffered heads takes the max height.
        assert_eq!(source.drain_tip(3), 7);
    }

    #[test]
    fn ws_drain_tip_ignores_equal_and_lower_heads() {
        // Neither a same-height re-announcement nor a lower reorg regresses the
        // watermark.
        let (mut source, tx) = ws_with_channel(0);
        tx.send(10).unwrap(); // fresh tip
        tx.send(10).unwrap(); // re-announcement at the same height
        tx.send(8).unwrap(); // reorg to a lower height
        assert_eq!(source.drain_tip(10), 10);
    }

    #[test]
    fn ws_drain_tip_noop_on_empty_channel() {
        let (mut source, _tx) = ws_with_channel(0);
        // Empty channel: drain returns the input watermark immediately.
        assert_eq!(source.drain_tip(42), 42);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_returns_on_first_head() {
        let (mut source, tx) = ws_with_channel(0);
        tx.send(12).unwrap();
        // The buffered head resolves before the paused-clock backstop timer.
        assert_eq!(source.await_tip(9).await, 12);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_ignores_lower_head() {
        let (mut source, tx) = ws_with_channel(0);
        tx.send(4).unwrap(); // a reorg re-announcement below the watermark
        assert_eq!(source.await_tip(10).await, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_fires_backstop_when_silent() {
        // No heads are sent (sender kept alive), so the `WS_BACKSTOP` timer must
        // win and the canned backstop (height 20) advances the watermark.
        let (mut source, _tx) = ws_with_channel(20);
        assert_eq!(source.await_tip(5).await, 20);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_backstop_after_stream_end() {
        // Dropping the sender ends the stream; `await_tip` falls back to the
        // backstop rather than stalling.
        let (mut source, tx) = ws_with_channel(15);
        drop(tx);
        assert_eq!(source.await_tip(5).await, 15);
    }

    #[tokio::test(start_paused = true)]
    async fn poll_variant_head_methods_are_noops() {
        // The `Poll` variant must not drive the Ws head machinery: both helpers
        // return the watermark unchanged. (HTTP providers construct lazily, so
        // this makes no network call.)
        let provider = ProviderBuilder::new()
            .connect_http("http://localhost:8545".parse().unwrap())
            .erased();
        let mut source = HeadSource::Poll { provider };
        assert_eq!(source.drain_tip(7), 7);
        assert_eq!(source.await_tip(7).await, 7);
    }

    // ---- WS reconnect / backoff (Task 4) ----

    #[test]
    fn backoff_delay_progression_and_cap() {
        // `2^attempt` seconds, matching the fetcher's `2_u64.pow(attempts.min(5))`,
        // capped at 32s once the exponent saturates at 5.
        assert_eq!(backoff_delay(0), Duration::from_secs(1));
        assert_eq!(backoff_delay(1), Duration::from_secs(2));
        assert_eq!(backoff_delay(2), Duration::from_secs(4));
        assert_eq!(backoff_delay(3), Duration::from_secs(8));
        assert_eq!(backoff_delay(4), Duration::from_secs(16));
        assert_eq!(backoff_delay(5), Duration::from_secs(32));
        assert_eq!(backoff_delay(6), Duration::from_secs(32));
        assert_eq!(backoff_delay(100), Duration::from_secs(32));
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_clears_stream_on_end() {
        // A stream end drops the dead stream (`heads` -> None) so the next call
        // takes the resubscribe branch, while still returning a backstop
        // watermark for this iteration. The end itself attempts no resubscribe,
        // so the backoff counter is untouched.
        let (mut source, tx) = ws_with_channel(30);
        drop(tx);
        assert_eq!(source.await_tip(5).await, 30);
        match &source {
            HeadSource::Ws {
                heads,
                backoff_attempt,
                ..
            } => {
                assert!(heads.is_none(), "dead stream should be cleared");
                assert_eq!(*backoff_attempt, 0);
            }
            _ => panic!("expected Ws"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_serves_backstop_and_backs_off_while_down() {
        // With no provider a resubscribe can never succeed, so the subscription
        // stays down (mirrors an initial connect failure). Each down-state call
        // still advances the watermark from the backstop — the service never
        // stalls — and bumps the capped backoff counter, evidencing a
        // resubscribe attempt per iteration.
        let (mut source, tx) = ws_with_channel(30);
        drop(tx);
        // First call: stream Ended, heads cleared, counter still 0.
        assert_eq!(source.await_tip(5).await, 30);
        // Down-branch call #1: resubscribe attempted, fails (provider None) -> 1.
        assert_eq!(source.await_tip(5).await, 30);
        match &source {
            HeadSource::Ws {
                heads,
                backoff_attempt,
                ..
            } => {
                assert!(heads.is_none());
                assert_eq!(*backoff_attempt, 1);
            }
            _ => panic!("expected Ws"),
        }
        // Down-branch call #2: 1 -> 2, still serving the backstop watermark.
        assert_eq!(source.await_tip(30).await, 30);
        match &source {
            HeadSource::Ws {
                backoff_attempt, ..
            } => assert_eq!(*backoff_attempt, 2),
            _ => panic!("expected Ws"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_never_stalls_across_many_down_iterations() {
        // Never-fatal invariant: however long WS stays down, every await_tip
        // returns the backstop watermark and the backoff counter keeps climbing
        // toward its cap without the future ever hanging (auto-advanced clock).
        let (mut source, tx) = ws_with_channel(50);
        drop(tx);
        for _ in 0..8 {
            assert_eq!(source.await_tip(10).await, 50);
        }
        match &source {
            HeadSource::Ws {
                backoff_attempt, ..
            } => {
                // 1 Ended call (no bump) + 7 down-branch bumps.
                assert_eq!(*backoff_attempt, 7);
            }
            _ => panic!("expected Ws"),
        }
    }
}
