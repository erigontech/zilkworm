// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use crate::stdin_builders::{
    build_stdin, build_stdin_from_eth_tests, build_stdin_from_mfbd, envelope_from_mfbd,
    read_envelope,
};
use alloy_primitives::B256;
use alloy_provider::{Provider, ProviderBuilder};
use eyre::{bail, eyre, Result, WrapErr};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{error, info, warn};
use url::Url;
use z6m_common::{fetch_block_and_witness, FetchRequest};
use zisk_common::io::ZiskStdin as RawStdin;
use zisk_common::EmuTrace;
use zisk_core::ZiskRom;
use zisk_prover_backend::{ExecuteClient, ProverClientBuilder};
use zisk_sdk::{
    AsmOptions, ExecutorKind, GuestProgram, Proof, ProofKind, ProveResult, ZiskClient, ZiskStdin,
};
use zisk_transpiler_riscv::Riscv2zisk;
use ziskemu::{Emu, EmuOptions};

/// Path set by build.rs.
pub const Z6M_ELF: &[u8] = include_bytes!(env!("Z6M_ZISK_ELF"));

/// See "Public output" in docs/architecture.md.
const RUN_FAILURE: u64 = u64::MAX;
const RUN_SKIPPED: u64 = u64::MAX - 1;
const PV_LEN: usize = 112;

#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn format_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// Guest-committed public values (see docs/architecture.md for encoding details).
#[derive(Debug, Clone)]
pub struct PublicValues {
    pub gas_used: u64,
    pub pre_state_root: B256,
    pub post_state_root: B256,
    pub block_hash: B256,
    pub chain_id: u64,
}

impl PublicValues {
    pub fn parse(pv: &[u8]) -> Result<Self> {
        if pv.len() < PV_LEN {
            bail!(
                "public values too short: {} bytes (expected >= {})",
                pv.len(),
                PV_LEN
            );
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

/// Classified by the gas sentinel, never gas==0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed,
    Skipped,
    /// OOM, fatal() or trap: unprovable.
    Aborted,
}

#[derive(Debug, Clone)]
pub struct RunReport {
    pub steps: u64,
    /// 0 when execute-only (no cost model).
    pub cost: u64,
    pub pv: [u8; PV_LEN],
    /// Only the ziskemu path sees this flag.
    pub halted_with_error: bool,
}

impl RunReport {
    pub fn gas(&self) -> u64 {
        u64::from_le_bytes(self.pv[0..8].try_into().unwrap())
    }

    pub fn outcome(&self) -> Outcome {
        // An abort halts before the commit.
        if self.halted_with_error || self.pv.iter().all(|&b| b == 0) {
            return Outcome::Aborted;
        }
        match self.gas() {
            RUN_FAILURE => Outcome::Failed,
            RUN_SKIPPED => Outcome::Skipped,
            _ => Outcome::Passed,
        }
    }

    /// Non-passing runs log gas_used=0.
    pub fn logged_gas(&self) -> u64 {
        if self.outcome() == Outcome::Passed {
            self.gas()
        } else {
            0
        }
    }

    pub fn pv_hex(&self) -> String {
        hex::encode(self.pv)
    }
}

pub fn load_program(elf: Option<&Path>) -> Result<GuestProgram> {
    match elf {
        Some(path) => {
            let uri = path.to_str().ok_or_else(|| eyre!("non-UTF-8 --elf path"))?;
            GuestProgram::from_uri(uri)
                .map_err(|e| eyre!("failed to load --elf {}: {}", path.display(), e))
        }
        None => Ok(GuestProgram::from_bytes("z6m_guest", Z6M_ELF.to_vec())),
    }
}

/// Mirrors zisk_common::ZiskPaths.
fn zisk_home() -> Result<PathBuf> {
    if let Some(home) = env::var_os("ZISK_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; pass --proving-key"))?;
    Ok(PathBuf::from(home).join(".zisk"))
}

/// Fail with guidance before the SDK does.
fn resolve_proving_key(
    cli: Option<&Path>,
    dir_name: &str,
    marker: Option<&str>,
) -> Result<PathBuf> {
    let pk = match cli {
        Some(p) => p.to_path_buf(),
        None => zisk_home()?.join(dir_name),
    };
    let complete = marker.is_none_or(|m| pk.join(m).is_file());
    if !pk.is_dir() || !complete {
        bail!(
            "ZisK proving key not found at {}.\n\
             Proving needs the v1.3.1-alpha key (~5 GB download, ~25-64 GB RAM; PLONK adds ~22 GB):\n  \
             ziskup --version 1.3.1-alpha --provingkey\n\
             or pass --proving-key DIR, or prove on a coordinator with --remote URL.\n\
             `execute` and `--test-service` need no key.",
            pk.display()
        );
    }
    Ok(pk)
}

/// "compressed" keeps hypercube's default value.
pub fn parse_proof_kind(s: &str) -> Result<ProofKind> {
    match s {
        "compressed" | "vadcop" => Ok(ProofKind::VadcopFinal),
        "minimal" => Ok(ProofKind::VadcopFinalMinimal),
        "plonk" => Ok(ProofKind::Plonk),
        other => {
            bail!("unsupported --proof-type {other} (ZisK: compressed|vadcop, minimal, plonk)")
        }
    }
}

type ExecClient = Box<dyn ExecuteClient + Send + Sync>;

fn build_exec_client(program: &GuestProgram, executor: ExecutorKind) -> Result<ExecClient> {
    let client: ExecClient = match executor {
        ExecutorKind::Emulator => Box::new(
            ProverClientBuilder::new()
                .emu()
                .execute_only()
                .build()
                .map_err(|e| eyre!("{e:#}"))?,
        ),
        ExecutorKind::Assembly => Box::new(
            ProverClientBuilder::new()
                .asm()
                .execute_only()
                .build()
                .map_err(|e| eyre!("{e:#}"))?,
        ),
    };
    client
        .setup(program, false)
        .map_err(|e| eyre!("ZisK setup failed: {e:#}"))?;
    Ok(client)
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecMode {
    /// 16 emulator threads, then count and plan.
    Sdk(ExecutorKind),
    /// ziskemu engine, one thread: 20-30x less CPU.
    Ziskemu,
}

enum ExecBackend {
    Sdk(ExecClient),
    Ziskemu(ZiskRom),
}

fn build_backend(program: &GuestProgram, mode: ExecMode) -> Result<ExecBackend> {
    Ok(match mode {
        ExecMode::Sdk(kind) => ExecBackend::Sdk(build_exec_client(program, kind)?),
        ExecMode::Ziskemu => ExecBackend::Ziskemu(
            Riscv2zisk::new(program.elf())
                .run()
                .map_err(|e| eyre!("failed to transpile ELF: {e}"))?,
        ),
    })
}

/// The SDK's client is single-instance; aborts poison it.
pub struct ZiskExecutor {
    backend: ExecBackend,
    program: GuestProgram,
    mode: ExecMode,
}

impl ZiskExecutor {
    pub fn new(program: GuestProgram, mode: ExecMode) -> Result<Self> {
        let backend = build_backend(&program, mode)?;
        Ok(Self {
            backend,
            program,
            mode,
        })
    }

    pub fn execute(&mut self, envelope: &[u8]) -> Result<RunReport> {
        // Frames as [u64 len][envelope][pad8].
        let stdin = RawStdin::new();
        stdin.write_slice(envelope);
        let client = match &self.backend {
            ExecBackend::Ziskemu(rom) => return run_ziskemu(rom, stdin.read_data()),
            ExecBackend::Sdk(client) => client,
        };
        let run = catch_unwind(AssertUnwindSafe(|| {
            client.execute(&self.program, stdin, None)
        }));
        let out = match run {
            Ok(out) => out.map_err(|e| eyre!("ZisK execution failed: {e:#}"))?,
            Err(payload) => {
                let msg = panic_message(payload.as_ref());
                self.backend = build_backend(&self.program, self.mode)?;
                bail!("ZisK emulator panicked ({msg}); the guest most likely halted with error");
            }
        };
        let mut pv = [0u8; PV_LEN];
        out.get_public_values_slice(&mut pv);
        Ok(RunReport {
            steps: out.get_execution_steps(),
            cost: out.get_execution_cost().unwrap_or(0),
            pv,
            halted_with_error: false,
        })
    }
}

/// What `ziskemu -i` does, minus the CLI.
fn run_ziskemu(rom: &ZiskRom, framed: Vec<u8>) -> Result<RunReport> {
    let options = EmuOptions::default();
    let mut emu = Emu::new(rom);
    emu.run(framed, &options, None::<fn(EmuTrace)>);
    if !emu.terminated() {
        bail!(
            "ZisK emulation did not finish within {} steps",
            options.max_steps
        );
    }
    let out = emu.get_output_8();
    let mut pv = [0u8; PV_LEN];
    pv.copy_from_slice(&out[..PV_LEN]);
    Ok(RunReport {
        steps: emu.number_of_steps(),
        cost: 0,
        pv,
        halted_with_error: emu.ctx.inst_ctx.error,
    })
}

#[derive(Clone, Debug)]
pub struct ProverOpts {
    pub executor: ExecutorKind,
    pub proving_key: Option<PathBuf>,
    pub remote: Option<String>,
    pub proof_kind: ProofKind,
}

pub struct ZiskProver {
    client: ZiskClient,
    program: GuestProgram,
    proof_kind: ProofKind,
}

impl ZiskProver {
    pub async fn new(program: GuestProgram, opts: &ProverOpts) -> Result<Self> {
        let client = if let Some(url) = &opts.remote {
            ZiskClient::remote(url.clone()).build()?
        } else {
            let pk = resolve_proving_key(
                opts.proving_key.as_deref(),
                "provingKey",
                // First file the SDK reads from the key.
                Some("pilout.globalInfo.json"),
            )?;
            let mut builder = ZiskClient::embedded()
                .executor(opts.executor)
                .proving_key(pk);
            if opts.executor == ExecutorKind::Assembly {
                builder = builder.asm_options(AsmOptions::default().unlock_mapped_memory());
            }
            if opts.proof_kind == ProofKind::Plonk {
                let pk_snark = resolve_proving_key(None, "provingKeySnark", None)?;
                builder = builder.plonk().proving_key_plonk(pk_snark);
            }
            #[cfg(feature = "gpu")]
            {
                builder = builder.gpu();
            }
            builder.build()?
        };
        client.upload(&program).run()?;
        let start = Instant::now();
        client.setup(&program).run()?.await?;
        info!("ZisK setup done in {:.1}s", start.elapsed().as_secs_f64());
        Ok(Self {
            client,
            program,
            proof_kind: opts.proof_kind,
        })
    }

    pub async fn execute(&self, stdin: ZiskStdin) -> Result<RunReport> {
        let out = self.client.execute(&self.program, stdin).run()?.await?;
        let mut pv = [0u8; PV_LEN];
        out.get_public_values_slice(&mut pv);
        Ok(RunReport {
            steps: out.get_execution_steps(),
            cost: out.get_execution_cost().unwrap_or(0),
            pv,
            halted_with_error: false,
        })
    }

    pub async fn prove(&self, stdin: ZiskStdin) -> Result<ProveResult> {
        let req = self
            .client
            .prove(&self.program, stdin)
            .wrap(self.proof_kind);
        Ok(req.run()?.await?)
    }

    pub fn program(&self) -> &GuestProgram {
        &self.program
    }
}

/// The SDK allows one client per process.
pub enum Engine {
    Execute(ZiskExecutor),
    Prove(ZiskProver),
}

impl Engine {
    pub async fn execute(&mut self, envelope: &[u8]) -> Result<RunReport> {
        match self {
            Engine::Execute(e) => e.execute(envelope),
            Engine::Prove(p) => p.execute(build_stdin(envelope)).await,
        }
    }
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
    pub download_only: bool,
    pub data_dir: PathBuf,
    pub proof_type: String,
}

#[derive(Clone, Debug)]
pub struct ExecuteOptions {
    pub block_number: u64,
    pub file_name: Option<PathBuf>,
    pub is_test: bool,
    pub data_dir: PathBuf,
    pub save_input: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ProveOptions {
    pub block_number: u64,
    pub file_name: Option<PathBuf>,
    pub is_test: bool,
    pub data_dir: PathBuf,
    pub proof_path: Option<PathBuf>,
    pub proof_type: String,
}

#[derive(Clone, Debug)]
pub struct ExecutionLog {
    pub block_number: u64,
    pub gas_used: u64,
    pub cycle_count: u64,
    pub prover_gas: u64,
    pub syscall_count: u64,
    pub input_path: PathBuf,
}

impl ExecutionLog {
    fn new(block_number: u64, report: &RunReport, input_path: &Path) -> Self {
        Self {
            block_number,
            gas_used: report.logged_gas(),
            cycle_count: report.steps,
            prover_gas: report.cost,
            syscall_count: 0,
            input_path: input_path.to_path_buf(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProvingLog {
    pub block_number: u64,
    pub gas_used: u64,
    pub cycle_count: u64,
    pub proof_path: PathBuf,
    pub proof_type: String,
    pub proving_millis: u64,
}

fn print_block_result(block_number: u64, report: &RunReport) -> Outcome {
    let outcome = report.outcome();
    let (steps, cost) = (report.steps, report.cost);
    match outcome {
        Outcome::Passed => println!(
            "Executed block {} (gas_used={}, cycles={}, prover_gas={}, syscall_count=0)",
            block_number,
            report.gas(),
            steps,
            cost
        ),
        Outcome::Skipped => println!(
            "SKIPPED block {} (guest reported skipped, cycles={}, prover_gas={})",
            block_number, steps, cost
        ),
        Outcome::Failed => {
            error!(%block_number, cycles = steps, prover_gas = cost, "block execution FAILED");
            println!(
                "FAILED block {} (gas_used=0, cycles={}, prover_gas={}, syscall_count=0)",
                block_number, steps, cost
            );
        }
        Outcome::Aborted => {
            error!(%block_number, cycles = steps, "guest aborted before committing public values");
            println!(
                "FAILED block {} (guest aborted, no public values; cycles={})",
                block_number, steps
            );
        }
    }
    outcome
}

pub async fn execute_block(
    engine: &mut Engine,
    opts: ExecuteOptions,
) -> Result<(ExecutionLog, Outcome)> {
    let input_path = resolve_input_path(
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
    let envelope = read_envelope(&input_path, opts.is_test)?;
    if let Some(path) = &opts.save_input {
        build_stdin(&envelope).save(path)?;
        info!("framed input saved to {} (ziskemu -i)", path.display());
    }

    let report = engine.execute(&envelope).await?;
    let outcome = print_block_result(opts.block_number, &report);
    // Same line format as the native state_transition runner.
    println!("Public Values: 0x{}", report.pv_hex());

    let log = ExecutionLog::new(opts.block_number, &report, &input_path);
    persist_execution_log(&opts.data_dir.join("executionLogs.log"), &log)?;
    Ok((log, outcome))
}

pub async fn prove_block(prover: &ZiskProver, opts: &ProveOptions) -> Result<ProvingLog> {
    let input_path = resolve_input_path(
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
    let block_number = if opts.block_number > 0 {
        opts.block_number
    } else {
        block_number_from_filename(&input_path)
    };
    let proof_path = opts.proof_path.clone().unwrap_or_else(|| {
        opts.data_dir
            .join(block_number.to_string())
            .join(format!("proof{}.bin", block_number))
    });
    if let Some(parent) = proof_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let stdin = if opts.is_test {
        build_stdin_from_eth_tests(&input_path)?
    } else {
        build_stdin_from_mfbd(&input_path)?
    };
    println!(
        "[{}] Proving block {} (proof_type={}, input={})",
        format_timestamp(),
        block_number,
        opts.proof_type,
        input_path.display()
    );
    let start = Instant::now();
    let result = prover.prove(stdin).await.wrap_err("proving failed")?;
    let proving_millis = start.elapsed().as_millis() as u64;
    result
        .verify()
        .map_err(|e| eyre!("freshly generated proof failed verification: {e:#}"))?;

    let mut pv = [0u8; PV_LEN];
    result.get_public_values_slice(&mut pv);
    let report = RunReport {
        steps: result.get_execution_steps(),
        cost: result.get_execution_cost(),
        pv,
        halted_with_error: false,
    };
    let outcome = report.outcome();
    let parsed = PublicValues::parse(&pv)?;
    println!(
        "[{}] Proved block {} ({:?}), gas_used={}, cycles={}, prover_gas={}, proving_ms={}",
        format_timestamp(),
        block_number,
        outcome,
        parsed.gas_used,
        report.steps,
        report.cost,
        proving_millis
    );
    println!(
        "[{}]   public values: pre_root={} post_root={} block_hash={} chain_id={}",
        format_timestamp(),
        parsed.pre_state_root,
        parsed.post_state_root,
        parsed.block_hash,
        parsed.chain_id
    );

    result
        .save_proof(&proof_path)
        .map_err(|e| eyre!("failed to save proof {}: {e:#}", proof_path.display()))?;
    let log = ProvingLog {
        block_number,
        gas_used: report.logged_gas(),
        cycle_count: report.steps,
        proof_path,
        proof_type: opts.proof_type.clone(),
        proving_millis,
    };
    persist_proving_log(&opts.data_dir, &log)?;
    Ok(log)
}

pub fn verify_proof(program: &GuestProgram, proof_path: &Path) -> Result<PublicValues> {
    let proof = Proof::load(proof_path)
        .map_err(|e| eyre!("failed to load proof {}: {}", proof_path.display(), e))?;
    let vk = program.vk().map_err(|e| {
        eyre!("program VK unavailable ({e}); run `z6m_prover_zisk setup` for this ELF first")
    })?;
    proof
        .with_program_vk(&vk)
        .verify()
        .map_err(|e| eyre!("proof verification failed: {e}"))?;
    let mut pv = [0u8; PV_LEN];
    proof.publics().read_slice(&mut pv);
    PublicValues::parse(&pv)
}

pub async fn run_service(engine: &mut Engine, service: ServiceConfig) -> Result<()> {
    info!("starting service mode");
    let url = Url::parse(&service.rpc_url)?;
    let provider = ProviderBuilder::new().connect_http(url);

    let mut next_block = if let Some(start) = service.start_block {
        start
    } else {
        get_block_number_with_retry(&provider, 3)
            .await
            .wrap_err("failed to get initial block number")?
            .saturating_add(1)
    };
    info!("Service starting from block: {}", next_block);

    loop {
        if let Some(end) = service.end_block {
            if next_block > end {
                break;
            }
        } else {
            match get_block_number_with_retry(&provider, 6).await {
                Ok(latest) if next_block > latest => {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Ok(_) => {}
                Err(err) => {
                    error!(error = %err, "Failed to get latest block number after retries, will retry in 30 seconds");
                    sleep(Duration::from_secs(30)).await;
                    continue;
                }
            }
        }

        let block_number = next_block;
        next_block += 1;
        println!(
            "[{}] Received block number from RPC {}",
            format_timestamp(),
            block_number
        );

        let should_prove = matches_interval(service.prove_every, block_number);
        let should_execute = matches_interval(service.execute_every, block_number) && !should_prove;
        let _should_post = matches_interval(service.post_every, block_number) || should_prove;
        if !(should_prove || should_execute || service.save_all_responses || service.download_only)
        {
            println!(
                "[{}] Nothing to do for block {}",
                format_timestamp(),
                block_number
            );
            continue;
        }

        println!("BEGIN_FETCH block={} now_ms={}", block_number, now_ms());
        let outcome = match fetch_block_and_witness(FetchRequest {
            rpc_url: &service.rpc_url,
            block_number: Some(block_number),
            data_dir: service.data_dir.clone(),
            save_all_responses: service.save_all_responses,
            geth: false,
            force_rebuild: true,
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                error!(%block_number, error = %err, "fetch_block_and_witness failed");
                continue;
            }
        };
        let bundle = outcome.flat_bundle_path.clone();

        if service.download_only {
            println!(
                "[{}] Downloaded block {} to {}",
                format_timestamp(),
                block_number,
                bundle.display()
            );
            continue;
        }

        if should_prove {
            let Engine::Prove(prover) = &*engine else {
                unreachable!("--prove-every builds a proving engine");
            };
            println!("[{}] Proving block {}", format_timestamp(), block_number);
            let opts = ProveOptions {
                block_number,
                file_name: Some(bundle),
                is_test: false,
                data_dir: service.data_dir.clone(),
                proof_path: None,
                proof_type: service.proof_type.clone(),
            };
            if let Err(err) = prove_block(prover, &opts).await {
                error!(%block_number, error = %err, "proving failed");
            }
        } else if should_execute {
            println!(
                "[{}] Executing only block {}",
                format_timestamp(),
                block_number
            );
            let envelope = match envelope_from_mfbd(&bundle) {
                Ok(e) => e,
                Err(e) => {
                    error!(%block_number, error = %e, "failed to build stdin");
                    continue;
                }
            };
            println!("BEGIN_EXEC block={} now_ms={}", block_number, now_ms());
            let report = match engine.execute(&envelope).await {
                Ok(r) => r,
                Err(e) => {
                    error!(%block_number, error = %e, "execution failed");
                    continue;
                }
            };
            println!("END_EXEC block={} now_ms={}", block_number, now_ms());
            print_block_result(block_number, &report);
            let log = ExecutionLog::new(block_number, &report, &bundle);
            if let Err(err) =
                persist_execution_log(&service.data_dir.join("executionLogs.log"), &log)
            {
                error!(%block_number, error = %err, "failed to persist execution log");
            }
        }
    }
    Ok(())
}

async fn get_block_number_with_retry<P: Provider>(provider: &P, max_retries: u32) -> Result<u64> {
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
                    max_retries,
                    delay_secs = delay.as_secs(),
                    error = %err,
                    "Failed to get block number, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

pub fn run_test_service(
    executor: &mut ZiskExecutor,
    start_block: u64,
    end_block: u64,
    execute_every: Option<u64>,
    data_dir: PathBuf,
    execution_log_file: Option<PathBuf>,
) -> Result<()> {
    if start_block > end_block {
        bail!(
            "--start-block ({}) must be <= --end-block ({})",
            start_block,
            end_block
        );
    }
    info!(
        "starting test service mode, blocks {} to {}",
        start_block, end_block
    );
    let execute_every = match execute_every {
        Some(0) => bail!(
            "--execute-every 0 is invalid in test service mode; use a positive value or omit the flag"
        ),
        Some(v) => v,
        None => 1,
    };
    let log_path = execution_log_file.unwrap_or_else(|| data_dir.join("executionLogs.log"));

    for block_number in start_block..=end_block {
        if block_number % execute_every != 0 {
            continue;
        }
        let input_path = resolve_input_path(block_number, None, false, &data_dir)?;
        if !input_path.exists() {
            warn!(
                "block {} not found at {}, skipping",
                block_number,
                input_path.display()
            );
            continue;
        }
        let envelope = match envelope_from_mfbd(&input_path) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    "block {} failed to build stdin: {}, skipping",
                    block_number, e
                );
                continue;
            }
        };
        let report = match executor.execute(&envelope) {
            Ok(r) => r,
            Err(e) => {
                warn!("block {} execution failed: {}, skipping", block_number, e);
                continue;
            }
        };
        print_block_result(block_number, &report);
        persist_execution_log(
            &log_path,
            &ExecutionLog::new(block_number, &report, &input_path),
        )?;
    }
    Ok(())
}

pub fn run_test_service_eest(
    executor: &mut ZiskExecutor,
    test_dir: PathBuf,
    execution_log_file: Option<PathBuf>,
    max_file_size: u64,
) -> Result<()> {
    if !test_dir.is_dir() {
        bail!("--test-dir {} is not a directory", test_dir.display());
    }
    // The guest dispatches on the envelope magic.
    let mut test_files: Vec<PathBuf> = Vec::new();
    collect_test_files(&test_dir, &mut test_files)?;
    test_files.sort();
    if test_files.is_empty() {
        bail!(
            "no .mfbd or .json test files found in {}",
            test_dir.display()
        );
    }
    info!(
        "starting EEST test-service mode, {} test files from {}",
        test_files.len(),
        test_dir.display()
    );

    let log_path = execution_log_file.unwrap_or_else(|| test_dir.join("executionLogs.log"));
    let (mut passed, mut failed, mut skipped) = (0u64, 0u64, 0u64);
    let total = test_files.len();

    for (i, test_file) in test_files.iter().enumerate() {
        let file_name = test_file.file_name().unwrap_or_default().to_string_lossy();

        if max_file_size > 0 {
            if let Ok(meta) = std::fs::metadata(test_file) {
                if meta.len() > max_file_size {
                    println!(
                        "[{}/{}] SKIP {} (file_size={}MB > limit={}MB)",
                        i + 1,
                        total,
                        file_name,
                        meta.len() / (1024 * 1024),
                        max_file_size / (1024 * 1024)
                    );
                    skipped += 1;
                    continue;
                }
            }
        }

        info!("[{}/{}] executing {}", i + 1, total, test_file.display());
        let is_json = test_file.extension().is_some_and(|ext| ext == "json");
        let envelope = match read_envelope(test_file, is_json) {
            Ok(e) => e,
            Err(e) => {
                warn!("test {} failed to build stdin: {}, skipping", file_name, e);
                failed += 1;
                continue;
            }
        };
        let report = match executor.execute(&envelope) {
            Ok(r) => r,
            Err(e) => {
                warn!("test {} execution failed: {}", file_name, e);
                println!(
                    "[{}/{}] FAILED {} (execution error)",
                    i + 1,
                    total,
                    file_name
                );
                failed += 1;
                continue;
            }
        };

        let (steps, cost) = (report.steps, report.cost);
        match report.outcome() {
            Outcome::Failed => {
                error!(test = %file_name, cycles = steps, prover_gas = cost, "test execution FAILED");
                println!(
                    "[{}/{}] FAILED {} (cycles={}, prover_gas={}, syscall_count=0)",
                    i + 1,
                    total,
                    file_name,
                    steps,
                    cost
                );
                failed += 1;
            }
            Outcome::Aborted => {
                error!(test = %file_name, cycles = steps, "guest aborted before committing public values");
                println!(
                    "[{}/{}] FAILED {} (guest aborted, cycles={})",
                    i + 1,
                    total,
                    file_name,
                    steps
                );
                failed += 1;
            }
            Outcome::Skipped => {
                println!(
                    "[{}/{}] SKIP {} (guest reported skipped)",
                    i + 1,
                    total,
                    file_name
                );
                skipped += 1;
            }
            Outcome::Passed => {
                println!(
                    "[{}/{}] PASS {} (gas_used={}, cycles={}, prover_gas={}, syscall_count=0)",
                    i + 1,
                    total,
                    file_name,
                    report.gas(),
                    steps,
                    cost
                );
                passed += 1;
            }
        }
        persist_execution_log(&log_path, &ExecutionLog::new(0, &report, test_file))?;
    }

    println!("\n=== EEST Test Service Summary ===");
    println!(
        "Total: {}, Passed: {}, Failed: {}, Skipped: {}",
        total, passed, failed, skipped
    );
    Ok(())
}

fn collect_test_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_test_files(&path, files)?;
        } else if path
            .extension()
            .is_some_and(|ext| ext == "mfbd" || ext == "json")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn persist_execution_log(log_file: &Path, log: &ExecutionLog) -> Result<()> {
    if let Some(parent) = log_file.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut text_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    // Byte-compatible with sp1_benchmark.py LOG_PATTERN.
    writeln!(
        &mut text_file,
        "[{}] block {} executed, gas_used={}, cycle_count={}, prover_gas={}, syscall_count={}, input={}",
        format_timestamp(),
        log.block_number,
        log.gas_used,
        log.cycle_count,
        log.prover_gas,
        log.syscall_count,
        log.input_path.display()
    )?;
    Ok(())
}

fn persist_proving_log(data_dir: &Path, log: &ProvingLog) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let mut text_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("provingLogs.log"))?;
    writeln!(
        &mut text_file,
        "[{}] block {} proved, gas_used={}, cycles={}, proof_path={}, proof_type={}, proving_ms={}",
        format_timestamp(),
        log.block_number,
        log.gas_used,
        log.cycle_count,
        log.proof_path.display(),
        log.proof_type,
        log.proving_millis
    )?;
    Ok(())
}

pub fn resolve_input_path(
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
    let dir = data_dir.join("blocks").join(block_number.to_string());
    let file_name = if is_test {
        format!("ethTests{}.json", block_number)
    } else {
        format!("flatWitnessBundle{}.mfbd", block_number)
    };
    Ok(dir.join(file_name))
}

/// flatWitnessBundle24491136.mfbd -> 24491136.
fn block_number_from_filename(path: &Path) -> u64 {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let digits: String = stem
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn matches_interval(interval: Option<u64>, block_number: u64) -> bool {
    match interval {
        Some(0) | None => false,
        Some(n) => block_number % n == 0,
    }
}
