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
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::Mutex;
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
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
    /// identical to today.
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
            // One-shot fetch: always build the HTTP provider from `rpc_url`.
            provider: None,
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
        let validated_ws_url: Option<Url> = match &service.ws_url {
            Some(raw) => Some(validate_ws_url(raw)?),
            None => None,
        };
        let url = Url::parse(&service.rpc_url)?;
        // On HTTP so poll, backstop, and fetch fallback all work while WS is down.
        let http_provider = ProviderBuilder::new().connect_http(url).erased();
        let http_fallback = http_provider.clone();

        // One poll serves both the cursor start and the Ws watermark seed. Poll
        // mode with `--start-block` never polled at startup and still doesn't.
        let start_tip: u64 = if service.start_block.is_none() || validated_ws_url.is_some() {
            match Self::get_block_number_with_retry(&http_provider, 3).await {
                Ok(block_num) => block_num,
                Err(e) => {
                    error!("Failed to get initial block number after retries: {}", e);
                    return Err(e);
                }
            }
        } else {
            0
        };
        let mut next_block = service
            .start_block
            .unwrap_or_else(|| start_tip.saturating_add(1));

        info!("Service starting from block: {}", next_block);

        // `latest` is the persistent Ws watermark; stays 0/unused in Poll mode.
        let mut latest: u64 = 0;
        let mut head_source = match validated_ws_url {
            None => HeadSource::Poll {
                provider: http_provider,
            },
            Some(ws_url) => {
                // Unseeded, a behind-tip start would stall in `await_tip`.
                latest = start_tip;
                // Best-effort: on failure run on the backstop poll and re-dial
                // from `await_tip`, never fatal.
                let (provider, heads) = match connect_ws_head_stream(&ws_url).await {
                    Ok((provider, heads)) => (Some(provider), Some(heads)),
                    Err(err) => {
                        warn!(error = %err, ws_url = %redact_url(&ws_url), "initial WS connect failed; running on backstop poll");
                        (None, None)
                    }
                };
                info!(ws_url = %redact_url(&ws_url), "head source: ws newHeads watermark");
                HeadSource::Ws {
                    provider,
                    heads,
                    backstop: Backstop::Provider(http_provider),
                    ws_url: Some(ws_url),
                }
            }
        };

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
                match head_source.wait_for_tip_live(next_block, &mut latest).await {
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

            let outcome = match fetch_block_with_fallback(
                &head_source,
                &service,
                &data_dir,
                block_number,
                &http_fallback,
            )
            .await
            {
                BlockFetch::Fetched(outcome) => outcome,
                BlockFetch::AwaitRecede(tip) => {
                    latest = tip;
                    continue;
                }
                BlockFetch::Skip => {
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

/// Silence window before the `Ws` source falls back to one backstop poll —
/// above mainnet's ~12s blocks so a healthy subscription never triggers it.
const WS_BACKSTOP: Duration = Duration::from_secs(24);

/// tungstenite's 64 MiB default would reject a large `debug_executionWitness`
/// response (10–80 MB hex JSON) on this socket — correctness, not tuning.
const WS_MAX_MESSAGE_SIZE: usize = 256 << 20;

/// Cap on one WS-routed fetch attempt. While the socket is down alloy queues
/// and re-issues in-flight requests across its unbounded reconnect budget —
/// they hang rather than fail — so without this cap the per-block HTTP
/// fallback is unreachable. Generous enough for a multi-MB witness on a
/// healthy socket.
const WS_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on one backstop `eth_blockNumber` poll; the reqwest default has no
/// total timeout, and this poll is awaited inline in the live loop.
const BACKSTOP_POLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on one at-tip WS re-dial (connect + subscribe), awaited inline in
/// `await_tip` after the backstop sleep.
const WS_RECONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Chain-tip watermark source gating the live service loop: `Poll` is the
/// verbatim historical per-iteration poll; `Ws` treats `newHeads` purely as a
/// watermark — drained non-blockingly during catch-up, awaited at tip.
enum HeadSource {
    /// Memoryless per-iteration `eth_blockNumber` poll, byte-identical to the
    /// pre-watermark behaviour (a persisted max would diverge on a lower tip).
    Poll { provider: DynProvider },
    /// `newHeads` as tip watermark. alloy heals transient socket drops under
    /// the same handle ([`connect_ws_head_stream`]); a missing subscription
    /// (boot-time outage or closed stream) degrades to the backstop and is
    /// re-dialed once per backstop cycle — never fatal, never permanent.
    Ws {
        /// Pubsub provider shared by the subscription and the fetch RPCs.
        /// `None` until a (re)connect succeeds (and in unit tests).
        provider: Option<DynProvider>,
        /// Head stream; `None` while gone → backstop pacing + re-dial.
        heads: Option<HeadStream>,
        /// Fallback watermark poll fired by the `WS_BACKSTOP` timer.
        backstop: Backstop,
        /// Endpoint for re-dials; `None` disables them (unit tests).
        ws_url: Option<Url>,
    },
}

/// `newHeads` subscription mapped to block heights; tests inject a channel.
/// Lag or dropped items are harmless — only `max(height)` feeds the watermark.
enum HeadStream {
    /// Production: the alloy `newHeads` subscription.
    Live(Subscription<Header>),
    /// Test seam: heights fed directly over a channel.
    #[cfg(test)]
    Channel(tokio::sync::mpsc::UnboundedReceiver<u64>),
}

impl HeadStream {
    /// Non-blocking: one buffered height, or `None` (empty or closed).
    fn try_next_height(&mut self) -> Option<u64> {
        match self {
            HeadStream::Live(sub) => loop {
                match sub.try_recv() {
                    Ok(h) => return Some(h.number),
                    // Overran the broadcast ring: the receiver is repositioned
                    // to the oldest retained head — keep receiving, only
                    // max(height) feeds the watermark.
                    Err(TryRecvError::Lagged(_)) => continue,
                    Err(TryRecvError::Empty | TryRecvError::Closed) => return None,
                }
            },
            #[cfg(test)]
            HeadStream::Channel(rx) => rx.try_recv().ok(),
        }
    }

    /// Next announced height; `None` only on a genuinely closed stream. A
    /// `Lagged` overrun (e.g. the loop sat on the prover lock for longer than
    /// the ring buffers) repositions and keeps receiving — it must NOT be
    /// conflated with stream end, or one long proof at tip permanently
    /// degrades the service to backstop pacing. `recv` is cancel-safe, so
    /// racing the `WS_BACKSTOP` timer loses no head.
    async fn next_height(&mut self) -> Option<u64> {
        match self {
            HeadStream::Live(sub) => loop {
                match sub.recv().await {
                    Ok(h) => return Some(h.number),
                    Err(RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "newHeads receiver lagged; repositioned to oldest retained head"
                        );
                        continue;
                    }
                    Err(RecvError::Closed) => return None,
                }
            },
            #[cfg(test)]
            HeadStream::Channel(rx) => rx.recv().await,
        }
    }
}

/// Watermark fallback poll — HTTP (`--rpc-url`), so it works while WS is down.
enum Backstop {
    Provider(DynProvider),
    #[cfg(test)]
    Canned(u64),
}

impl Backstop {
    /// One poll; `None` on RPC error or timeout (caller keeps the current
    /// watermark).
    async fn poll(&self) -> Option<u64> {
        match self {
            Backstop::Provider(provider) => {
                timeout(BACKSTOP_POLL_TIMEOUT, provider.get_block_number())
                    .await
                    .ok()?
                    .ok()
            }
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

/// Pubsub provider + `newHeads` stream over `url`. Reconnection is alloy's
/// job: on a socket drop it reconnects and re-subscribes into the same handle
/// (`alloy-pubsub::service::reconnect`), and the per-outage `u32::MAX` retry
/// budget at 3s intervals makes a permanent stream end practically unreachable.
async fn connect_ws_head_stream(url: &Url) -> Result<(DynProvider, HeadStream)> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE_SIZE))
        .max_frame_size(Some(WS_MAX_MESSAGE_SIZE));
    let ws = WsConnect::new(url.as_str())
        .with_config(config)
        .with_max_retries(u32::MAX);
    let provider = ProviderBuilder::new().connect_ws(ws).await?.erased();
    let heads = provider.subscribe_blocks().await?;
    Ok((provider, HeadStream::Live(heads)))
}

/// Outcome of one per-block fetch attempt ([`fetch_block_with_fallback`]).
enum BlockFetch {
    Fetched(FetchOutcome),
    /// Downward reorg: roll the watermark back to this tip, retry the height.
    AwaitRecede(u64),
    /// Genuine failure: advance the cursor (byte-identical Poll-mode skip).
    Skip,
}

/// Fetch one block through the head source's provider, classifying failures.
/// The reorg check runs before the HTTP retry — one `eth_blockNumber` vs a
/// multi-MB refetch, and "not found" at tip (announcement racing read
/// availability) is the common case. Rollback is live-mode only: with
/// `--end-block` there is no watermark gate, so it would refetch forever.
async fn fetch_block_with_fallback(
    head_source: &HeadSource,
    service: &ServiceConfig,
    data_dir: &Path,
    block_number: u64,
    http_fallback: &DynProvider,
) -> BlockFetch {
    let request = |provider: Option<DynProvider>| FetchRequest {
        rpc_url: &service.rpc_url,
        block_number: Some(block_number),
        data_dir: data_dir.to_path_buf(),
        save_all_responses: service.save_all_responses,
        geth: false,
        force_rebuild: true,
        provider,
    };

    let fetch_provider = head_source.fetch_provider();
    let ws_routed = fetch_provider.is_some();
    // WS-routed only: while the socket is down alloy re-queues the request
    // across reconnect attempts instead of failing it, and the HTTP fallback
    // below can only fire on an error. The plain-HTTP path (Poll mode) keeps
    // its historical no-timeout behavior.
    let attempt = fetch_block_and_witness(request(fetch_provider));
    let result = if ws_routed {
        match timeout(WS_FETCH_TIMEOUT, attempt).await {
            Ok(result) => result,
            Err(_) => Err(eyre::eyre!(
                "WS-routed fetch timed out after {WS_FETCH_TIMEOUT:?} (socket down or stalled)"
            )),
        }
    } else {
        attempt.await
    };
    let err = match result {
        Ok(outcome) => return BlockFetch::Fetched(outcome),
        Err(err) => err,
    };

    if service.end_block.is_none() {
        if let Some(tip) = head_source.tip_receded_below(block_number).await {
            warn!(%block_number, tip, "block not canonical yet (downward reorg); awaiting re-canonicalization instead of skipping");
            return BlockFetch::AwaitRecede(tip);
        }
    }

    if !ws_routed {
        error!(%block_number, error = %err, "fetch_block_and_witness failed");
        return BlockFetch::Skip;
    }

    // A dead WS connection must not skip a block HTTP could still serve.
    warn!(%block_number, error = %err, "WS-routed fetch failed; retrying once over HTTP");
    match fetch_block_and_witness(request(Some(http_fallback.clone()))).await {
        Ok(outcome) => BlockFetch::Fetched(outcome),
        Err(err) => {
            error!(%block_number, error = %err, "fetch_block_and_witness failed (HTTP fallback)");
            BlockFetch::Skip
        }
    }
}

/// Whether the next block is available to fetch, as reported by the head
/// source. `NotReady` means the source has already applied the appropriate
/// pacing sleep and the caller must skip this loop iteration.
enum TipStatus {
    Ready,
    NotReady,
}

impl HeadSource {
    /// Poll-mode tip gate — the exact historical logic (6 retries, 2s tip
    /// sleep, 30s on exhaustion); byte-identity is load-bearing here.
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
            // `wait_for_tip_live` routes only Poll here.
            HeadSource::Ws { .. } => {
                unreachable!("wait_for_tip is Poll-only; Ws mode uses drain_tip/await_tip")
            }
        }
    }

    /// Live-mode tip gate. Poll never touches `latest` (memoryless); Ws drains
    /// non-blockingly during catch-up (`next_block <= latest`) and awaits a
    /// head or the backstop at tip — no busy spin.
    async fn wait_for_tip_live(&mut self, next_block: u64, latest: &mut u64) -> TipStatus {
        if matches!(self, HeadSource::Poll { .. }) {
            return self.wait_for_tip(next_block).await;
        }
        if next_block <= *latest {
            *latest = self.drain_tip(*latest);
            TipStatus::Ready
        } else {
            *latest = self.await_tip(*latest).await;
            if next_block <= *latest {
                TipStatus::Ready
            } else {
                TipStatus::NotReady
            }
        }
    }

    /// The WS pubsub clone when established (fetches ride the `newHeads`
    /// socket), else `None` → the fetcher builds HTTP from `--rpc-url` as today.
    fn fetch_provider(&self) -> Option<DynProvider> {
        match self {
            HeadSource::Ws {
                provider: Some(provider),
                ..
            } => Some(provider.clone()),
            _ => None,
        }
    }

    /// After a downward reorg the monotonic watermark still gates a height the
    /// chain no longer has — a plain skip would drop it forever. `Some(tip)`
    /// when the backstop poll shows the tip receded below `block` (roll back
    /// and wait); `None` otherwise, and always for `Poll` (no extra RPC).
    async fn tip_receded_below(&self, block: u64) -> Option<u64> {
        match self {
            HeadSource::Ws { backstop, .. } => match backstop.poll().await {
                Some(tip) if tip < block => Some(tip),
                _ => None,
            },
            HeadSource::Poll { .. } => None,
        }
    }

    /// Non-blocking drain of buffered heads — catch-up must never wait on the
    /// socket. `latest` unchanged for `Poll`.
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

    /// At-tip wait: next head raced against the `WS_BACKSTOP` timer. Transient
    /// drops never surface here (alloy reconnects under the handle); a missing
    /// stream degrades to backstop pacing and is re-dialed once per cycle —
    /// never fatal. `latest` unchanged for `Poll`.
    async fn await_tip(&mut self, latest: u64) -> u64 {
        let HeadSource::Ws {
            provider,
            heads,
            backstop,
            ws_url,
        } = self
        else {
            return latest;
        };

        // Take the stream out for the `select!` arms.
        let Some(mut stream) = heads.take() else {
            sleep(WS_BACKSTOP).await;
            // One bounded re-dial per backstop cycle: a boot-time outage or a
            // closed stream must not pin the process on 24s polling forever.
            if let Some(url) = ws_url.as_ref() {
                match timeout(WS_RECONNECT_TIMEOUT, connect_ws_head_stream(url)).await {
                    Ok(Ok((new_provider, new_heads))) => {
                        info!(ws_url = %redact_url(url), "WS reconnected; newHeads watermark restored");
                        *provider = Some(new_provider);
                        *heads = Some(new_heads);
                    }
                    Ok(Err(err)) => {
                        debug!(error = %err, "WS re-dial failed; staying on backstop")
                    }
                    Err(_) => debug!("WS re-dial timed out; staying on backstop"),
                }
            }
            return backstop.watermark(latest).await;
        };
        tokio::select! {
            next = stream.next_height() => match next {
                Some(height) => {
                    *heads = Some(stream);
                    advance_watermark(latest, height)
                }
                None => {
                    // Ends only if alloy gave up; stay on the backstop.
                    warn!("newHeads stream ended; continuing on backstop poll");
                    backstop.watermark(latest).await
                }
            },
            _ = sleep(WS_BACKSTOP) => {
                *heads = Some(stream);
                backstop.watermark(latest).await
            }
        }
    }
}

/// Ws watermark rule: never moves backward, so each height is processed once.
/// The Poll arm must NOT call this — it stays memoryless (byte-identity).
fn advance_watermark(latest: u64, announced: u64) -> u64 {
    latest.max(announced)
}

/// `--ws-url` must be `ws`/`wss`; anything else fails startup fast rather than
/// silently falling back to polling.
fn validate_ws_url(url: &str) -> Result<Url> {
    // Never echo the raw input: hosted endpoints embed API keys and errors
    // land in startup logs. Scheme mismatches go through `redact_url`.
    let parsed = Url::parse(url).with_context(|| "--ws-url is not a valid URL")?;
    match parsed.scheme() {
        "ws" | "wss" => Ok(parsed),
        other => bail!(
            "--ws-url must use the ws:// or wss:// scheme, got {other:?} in {}",
            redact_url(&parsed)
        ),
    }
}

/// `scheme://host[:port]` only — hosted endpoints embed API keys in
/// path/userinfo, which must not reach logs.
fn redact_url(url: &Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
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
    fn redact_url_strips_path_userinfo_and_query() {
        // An embedded API key (path, userinfo, or query) must never reach logs.
        let url = Url::parse("wss://user:secret@eth-mainnet.example.com/v2/APIKEY?token=xyz")
            .expect("valid url");
        assert_eq!(redact_url(&url), "wss://eth-mainnet.example.com");
    }

    #[test]
    fn redact_url_keeps_explicit_port() {
        let url = Url::parse("ws://node.example.com:8546/ws/v3/SECRET").expect("valid url");
        assert_eq!(redact_url(&url), "ws://node.example.com:8546");
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

    /// Channel-backed `HeadSource::Ws` with a canned backstop; the sender
    /// drives announced heights.
    fn ws_with_channel(
        backstop_height: u64,
    ) -> (HeadSource, tokio::sync::mpsc::UnboundedSender<u64>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let source = HeadSource::Ws {
            provider: None,
            heads: Some(HeadStream::Channel(rx)),
            backstop: Backstop::Canned(backstop_height),
            ws_url: None,
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

    #[tokio::test]
    async fn tip_receded_below_signals_wait_after_downward_reorg() {
        // Backstop tip 8 has receded below the gated block 10 (downward reorg):
        // the block is not canonical yet, so the caller must wait and retry it
        // rather than skip it forever.
        let (source, _tx) = ws_with_channel(8);
        assert_eq!(source.tip_receded_below(10).await, Some(8));
    }

    #[tokio::test]
    async fn tip_receded_below_skips_when_tip_covers_block() {
        // Tip still at or above the block → not a reorg → a genuine fetch
        // failure, so the caller keeps today's skip behaviour.
        let (source, _tx) = ws_with_channel(10);
        assert_eq!(source.tip_receded_below(10).await, None);
        let (source, _tx) = ws_with_channel(12);
        assert_eq!(source.tip_receded_below(10).await, None);
    }

    #[tokio::test]
    async fn tip_receded_below_is_none_for_poll() {
        // Poll mode keeps its byte-identical skip-on-error path: the method
        // short-circuits to `None` on the enum arm without polling any provider.
        let source = HeadSource::Poll {
            provider: dummy_provider(),
        };
        assert_eq!(source.tip_receded_below(10).await, None);
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
    async fn poll_variant_head_methods_are_noops() {
        // The `Poll` variant must not drive the Ws head machinery: both helpers
        // return the watermark unchanged. (HTTP providers construct lazily, so
        // this makes no network call.)
        let mut source = HeadSource::Poll {
            provider: dummy_provider(),
        };
        assert_eq!(source.drain_tip(7), 7);
        assert_eq!(source.await_tip(7).await, 7);
    }

    // ---- Stream end / backstop degradation ----

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_clears_stream_on_end() {
        // A stream end falls back to the backstop for this iteration and drops
        // the dead stream (`heads` -> None); later calls stay on the backstop.
        let (mut source, tx) = ws_with_channel(30);
        drop(tx);
        assert_eq!(source.await_tip(5).await, 30);
        match &source {
            HeadSource::Ws { heads, .. } => {
                assert!(heads.is_none(), "dead stream should be cleared");
            }
            _ => panic!("expected Ws"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_never_stalls_while_down() {
        // Never-fatal invariant: however long the subscription stays gone,
        // every await_tip returns a backstop watermark on WS_BACKSTOP pacing
        // (auto-advanced clock) without the future ever hanging.
        let (mut source, tx) = ws_with_channel(50);
        drop(tx);
        for _ in 0..8 {
            assert_eq!(source.await_tip(10).await, 50);
        }
    }

    // ---- Live-mode routing (Task 5) ----

    #[tokio::test(start_paused = true)]
    async fn ws_wait_for_tip_live_catch_up_is_ready_without_awaiting() {
        // Behind-tip start: next_block (1) <= seeded watermark (5). Catch-up must
        // return Ready immediately via the non-blocking drain, never entering
        // await_tip (which would block on the WS_BACKSTOP timer). A buffered head
        // still folds into the watermark, but readiness does not depend on it.
        let (mut source, tx) = ws_with_channel(0);
        tx.send(9).unwrap();
        let started = tokio::time::Instant::now();
        let mut latest = 5;
        assert!(matches!(
            source.wait_for_tip_live(1, &mut latest).await,
            TipStatus::Ready
        ));
        assert_eq!(latest, 9, "drain should have advanced the watermark");
        // Paused clock: any sleep/await in the catch-up path would auto-advance
        // time, so zero elapsed proves the non-blocking route was taken.
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "catch-up must not await the socket or a timer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ws_wait_for_tip_live_catch_up_ready_on_empty_channel_without_waiting() {
        // Readiness during catch-up must not depend on a buffered head: an
        // empty channel still yields Ready instantly (zero paused-clock time).
        let (mut source, _tx) = ws_with_channel(0);
        let started = tokio::time::Instant::now();
        let mut latest = 5;
        assert!(matches!(
            source.wait_for_tip_live(1, &mut latest).await,
            TipStatus::Ready
        ));
        assert_eq!(latest, 5, "no heads -> watermark unchanged");
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "catch-up must not await the socket or a timer"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn ws_wait_for_tip_live_at_tip_ready_when_head_reaches_next() {
        // At tip (next_block 10 > watermark 5): must await. A head at 10 makes the
        // block ready and advances the watermark.
        let (mut source, tx) = ws_with_channel(0);
        tx.send(10).unwrap();
        let mut latest = 5;
        assert!(matches!(
            source.wait_for_tip_live(10, &mut latest).await,
            TipStatus::Ready
        ));
        assert_eq!(latest, 10);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_wait_for_tip_live_at_tip_not_ready_when_head_below_next() {
        // At tip with a head that doesn't reach next_block: the watermark advances
        // but the block isn't ready, so the loop must retry (NotReady).
        let (mut source, tx) = ws_with_channel(0);
        tx.send(7).unwrap();
        let mut latest = 5;
        assert!(matches!(
            source.wait_for_tip_live(10, &mut latest).await,
            TipStatus::NotReady
        ));
        assert_eq!(latest, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn ws_wait_for_tip_live_at_tip_falls_back_to_backstop() {
        // At tip with a silent stream: the WS_BACKSTOP timer fires, the canned
        // backstop (height 12) advances the watermark past next_block, and the
        // block becomes Ready — the service never stalls at tip.
        let (mut source, _tx) = ws_with_channel(12);
        let mut latest = 5;
        assert!(matches!(
            source.wait_for_tip_live(10, &mut latest).await,
            TipStatus::Ready
        ));
        assert_eq!(latest, 12);
    }

    // ---- Fetch provider selection (Task 6) ----

    /// A throwaway erased HTTP provider. alloy HTTP providers construct lazily,
    /// so this makes no network call.
    fn dummy_provider() -> DynProvider {
        ProviderBuilder::new()
            .connect_http("http://localhost:8545".parse().unwrap())
            .erased()
    }

    #[test]
    fn fetch_provider_none_for_poll() {
        // Poll mode fetches over HTTP from `--rpc-url` (provider: None).
        let source = HeadSource::Poll {
            provider: dummy_provider(),
        };
        assert!(source.fetch_provider().is_none());
    }

    #[test]
    fn fetch_provider_some_for_ws_with_established_provider() {
        // Ws mode with an established subscription routes the fetch over the WS
        // pubsub provider.
        let source = HeadSource::Ws {
            provider: Some(dummy_provider()),
            heads: None,
            backstop: Backstop::Canned(0),
            ws_url: None,
        };
        assert!(source.fetch_provider().is_some());
    }

    #[test]
    fn fetch_provider_none_for_ws_without_provider() {
        // Ws mode after an initial connect failure has no provider, so the fetch
        // falls back to HTTP (provider: None).
        let source = HeadSource::Ws {
            provider: None,
            heads: None,
            backstop: Backstop::Canned(0),
            ws_url: None,
        };
        assert!(source.fetch_provider().is_none());
    }

    // ---- Lagged-stream resilience (review fix) ----

    /// Real `Subscription<Header>` over a capacity-limited broadcast ring —
    /// the production type; the mpsc `Channel` seam cannot lag.
    fn live_stream_with_capacity(
        capacity: usize,
    ) -> (
        tokio::sync::broadcast::Sender<Box<serde_json::value::RawValue>>,
        HeadStream,
    ) {
        let (tx, rx) = tokio::sync::broadcast::channel(capacity);
        let sub: Subscription<Header> = alloy::pubsub::RawSubscription {
            rx,
            local_id: Default::default(),
        }
        .into();
        (tx, HeadStream::Live(sub))
    }

    fn raw_header(number: u64) -> Box<serde_json::value::RawValue> {
        let mut header: Header = Header::default();
        header.inner.number = number;
        serde_json::value::to_raw_value(&header).expect("serialize header")
    }

    #[tokio::test]
    async fn live_next_height_survives_lag() {
        // Overrun the capacity-2 ring while nothing receives (the loop sitting
        // on the prover lock through a long proof): recv() yields Err(Lagged)
        // first. next_height must reposition and keep serving heights — NOT
        // report stream end, which would permanently degrade to backstop
        // pacing.
        let (tx, mut stream) = live_stream_with_capacity(2);
        for n in 1..=5 {
            tx.send(raw_header(n)).expect("send");
        }
        assert_eq!(
            stream.next_height().await,
            Some(4),
            "oldest retained head after the lag"
        );
        assert_eq!(stream.next_height().await, Some(5));
        drop(tx);
        assert_eq!(stream.next_height().await, None, "closed stream ends");
    }

    #[tokio::test]
    async fn live_try_next_height_drains_through_lag() {
        // drain_tip's non-blocking path: a lag mid-drain must reposition and
        // keep draining rather than end the pass early.
        let (tx, mut stream) = live_stream_with_capacity(2);
        for n in 1..=5 {
            tx.send(raw_header(n)).expect("send");
        }
        assert_eq!(stream.try_next_height(), Some(4));
        assert_eq!(stream.try_next_height(), Some(5));
        assert_eq!(stream.try_next_height(), None, "empty after drain");
    }

    #[tokio::test(start_paused = true)]
    async fn ws_await_tip_survives_lagged_stream() {
        // One lag must not kill the subscription: await_tip returns the lagged
        // head and RETAINS the stream for the next wait.
        let (tx, stream) = live_stream_with_capacity(2);
        for n in 1..=5 {
            tx.send(raw_header(n)).expect("send");
        }
        let mut source = HeadSource::Ws {
            provider: None,
            heads: Some(stream),
            backstop: Backstop::Canned(0),
            ws_url: None,
        };
        assert_eq!(source.await_tip(3).await, 4);
        match &source {
            HeadSource::Ws { heads, .. } => {
                assert!(heads.is_some(), "stream must survive a lag")
            }
            _ => unreachable!(),
        }
        assert_eq!(source.await_tip(4).await, 5);
    }

    // ---- fetch_block_with_fallback classification (review fix) ----

    fn mock_provider(asserter: &alloy::transports::mock::Asserter) -> DynProvider {
        ProviderBuilder::new()
            .connect_mocked_client(asserter.clone())
            .erased()
    }

    fn test_service_config() -> ServiceConfig {
        ServiceConfig {
            start_block: None,
            // Live mode: the reorg recede-check is end_block-gated.
            end_block: None,
            prove_every: None,
            execute_every: None,
            post_every: None,
            // Unreachable port: the Poll-mode fetch builds HTTP from rpc_url
            // and must fail fast, not hit a live node.
            rpc_url: "http://127.0.0.1:1".into(),
            ws_url: None,
            save_all_responses: false,
            download_only: false,
            proving_key_path: None,
            proof_type: "core".into(),
        }
    }

    fn scratch_data_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("z6m-fbwf-{tag}-{}", std::process::id()))
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_fallback_awaits_recede_on_downward_reorg() {
        // WS-routed fetch fails and the backstop shows the tip receded below
        // the requested height: classify as AwaitRecede BEFORE burning the
        // HTTP retry (an empty HTTP mock queue would error into Skip if the
        // ordering regressed).
        let ws_asserter = alloy::transports::mock::Asserter::new();
        for _ in 0..3 {
            ws_asserter.push_failure_msg("ws fetch down");
        }
        let source = HeadSource::Ws {
            provider: Some(mock_provider(&ws_asserter)),
            heads: None,
            backstop: Backstop::Canned(6),
            ws_url: None,
        };
        let http_asserter = alloy::transports::mock::Asserter::new();
        let http = mock_provider(&http_asserter);
        let service = test_service_config();
        match fetch_block_with_fallback(&source, &service, &scratch_data_dir("recede"), 8, &http)
            .await
        {
            BlockFetch::AwaitRecede(tip) => assert_eq!(tip, 6),
            _ => panic!("expected AwaitRecede on a receded tip"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_fallback_retries_over_http_when_not_receded() {
        // WS-routed fetch fails, tip still covers the height: one HTTP retry,
        // then Skip when it also fails. Drained mock queues prove both
        // attempts actually ran.
        let ws_asserter = alloy::transports::mock::Asserter::new();
        let http_asserter = alloy::transports::mock::Asserter::new();
        for _ in 0..3 {
            ws_asserter.push_failure_msg("ws fetch down");
            http_asserter.push_failure_msg("http also down");
        }
        let source = HeadSource::Ws {
            provider: Some(mock_provider(&ws_asserter)),
            heads: None,
            backstop: Backstop::Canned(9),
            ws_url: None,
        };
        let http = mock_provider(&http_asserter);
        let service = test_service_config();
        match fetch_block_with_fallback(&source, &service, &scratch_data_dir("fallback"), 8, &http)
            .await
        {
            BlockFetch::Skip => {}
            _ => panic!("expected Skip after WS + HTTP both fail"),
        }
        assert!(
            ws_asserter.read_q().is_empty(),
            "WS attempt should consume its retries"
        );
        assert!(
            http_asserter.read_q().is_empty(),
            "HTTP fallback should consume its retries"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fetch_fallback_poll_mode_skips_without_http_retry() {
        // Poll mode is not WS-routed: a failed fetch is a plain Skip — no
        // recede-check RPC, no HTTP retry (byte-identical single attempt).
        // The sentinel response must stay unconsumed.
        let source = HeadSource::Poll {
            provider: dummy_provider(),
        };
        let http_asserter = alloy::transports::mock::Asserter::new();
        http_asserter.push_success(&12345u64);
        let http = mock_provider(&http_asserter);
        let service = test_service_config();
        match fetch_block_with_fallback(&source, &service, &scratch_data_dir("poll"), 8, &http)
            .await
        {
            BlockFetch::Skip => {}
            _ => panic!("expected Skip in Poll mode"),
        }
        assert_eq!(
            http_asserter.read_q().len(),
            1,
            "Poll mode must never touch the HTTP fallback provider"
        );
    }

    // ---- Anvil integration tests (need `anvil` in PATH) ----
    // Run: cargo test -p z6m_prover -- --ignored ws_
    // multi_thread so alloy's pubsub service task runs independently.

    use alloy::node_bindings::Anvil;

    /// Watermark advances past the seed as Anvil mines (~1 block/s, inside
    /// `WS_BACKSTOP`, so a stuck subscription fails instead of hanging).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires anvil in PATH; run: cargo test -p z6m_prover -- --ignored ws_"]
    async fn ws_watermark_advances_as_anvil_mines() {
        let anvil = Anvil::new().block_time(1).spawn();
        let (provider, heads) = connect_ws_head_stream(&anvil.ws_endpoint_url())
            .await
            .expect("ws connect to anvil");
        let http = ProviderBuilder::new()
            .connect_http(anvil.endpoint_url())
            .erased();
        let seed = http.get_block_number().await.expect("seed poll");
        let mut source = HeadSource::Ws {
            provider: Some(provider),
            heads: Some(heads),
            // Backstop is the HTTP provider (Task 5), but heads should win here.
            backstop: Backstop::Provider(http.clone()),
            ws_url: None,
        };
        let advanced = tokio::time::timeout(Duration::from_secs(30), async {
            let mut latest = seed;
            while latest <= seed {
                latest = source.await_tip(latest).await;
            }
            latest
        })
        .await
        .expect("watermark should advance within 30s");
        assert!(
            advanced > seed,
            "watermark {advanced} should exceed seed {seed}"
        );
    }

    /// Behind-tip start catches up sequentially via `drain_tip` only: blocks
    /// are mined before subscribing, so heads can't supply 1..=5, and the 2s
    /// per-step timeout proves catch-up never waits on `WS_BACKSTOP`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires anvil in PATH; run: cargo test -p z6m_prover -- --ignored ws_"]
    async fn ws_behind_tip_start_catches_up_sequentially_via_drain() {
        let anvil = Anvil::new().block_time(1).spawn();
        let http = ProviderBuilder::new()
            .connect_http(anvil.endpoint_url())
            .erased();
        // Wait for the tip to reach ≥5 so the start is genuinely behind it.
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if http.get_block_number().await.expect("poll tip") >= 5 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("anvil should mine >=5 blocks within 60s");
        // Subscribe only now: the subscription sees new heads only, so catch-up
        // over 1..=5 cannot rely on it — exactly the behind-tip case.
        let (provider, heads) = connect_ws_head_stream(&anvil.ws_endpoint_url())
            .await
            .expect("ws connect to anvil");
        let mut source = HeadSource::Ws {
            provider: Some(provider),
            heads: Some(heads),
            backstop: Backstop::Provider(http.clone()),
            ws_url: None,
        };
        // Seed the watermark via the startup poll (Task 5 semantics).
        let mut latest = http.get_block_number().await.expect("seed poll");
        assert!(latest >= 5, "expected a behind-tip seed, got {latest}");

        let mut observed = Vec::new();
        let mut next_block = 1u64;
        while next_block <= 5 {
            // Catch-up invariant: the cursor never exceeds the seeded watermark,
            // so `wait_for_tip_live` takes the non-blocking drain branch.
            assert!(
                next_block <= latest,
                "catch-up must never exceed the watermark"
            );
            let status = tokio::time::timeout(
                Duration::from_secs(2),
                source.wait_for_tip_live(next_block, &mut latest),
            )
            .await
            .expect("drain branch must return without awaiting the backstop");
            assert!(
                matches!(status, TipStatus::Ready),
                "catch-up block {next_block} should be Ready"
            );
            observed.push(next_block);
            next_block += 1;
        }
        assert_eq!(
            observed,
            vec![1, 2, 3, 4, 5],
            "catch-up must observe heights strictly sequentially"
        );
    }
}
