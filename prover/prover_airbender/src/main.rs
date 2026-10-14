use clap::{Parser, Subcommand};
use eyre::{bail, eyre, Result};
use prover_pipeline::ProverBackend;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

mod guest;
mod proof_format;
mod prove;
mod public_output;
mod service;
mod vk;

use guest::{Guest, GuestFiles};
use prove::{BlockProver, ProverSettings, MAX_PROVABLE_CYCLES};
use vk::VerificationKey;

/// Default path to the airbender guest binary, relative to the project root.
const DEFAULT_GUEST_BIN: &str = "prover/guest_airbender/build/z6m_guest";

/// Default maximum cycles for the simulator. Proving clamps it to MAX_PROVABLE_CYCLES.
const DEFAULT_CYCLES: usize = 5_000_000_000;

#[derive(Parser, Debug)]
#[command(
    name = "z6m_prover_airbender",
    about = "Zilkworm prover on Airbender (zksync-airbender v3): RISC-V simulator, prover and verifier"
)]
struct Args {
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "command")]
    test_service: bool,

    /// Run as a continuous proving service (polls RPC for new blocks)
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "command")]
    service: bool,

    /// Root data directory containing a blocks/ subdirectory
    #[arg(long, default_value = "temp")]
    data_dir: PathBuf,

    #[arg(long)]
    start_block: Option<u64>,

    #[arg(long)]
    end_block: Option<u64>,

    /// Custom path for the execution log output (only used in --test-service mode)
    #[arg(long)]
    execution_log_file: Option<PathBuf>,

    /// Path to the guest binary (without .bin/.text extension)
    #[arg(long)]
    guest_bin: Option<PathBuf>,

    /// Maximum simulator cycles. Proving takes at most 1,073,741,822 (the prover's limit).
    #[arg(long, default_value_t = DEFAULT_CYCLES)]
    cycles: usize,

    /// CPU threads replaying the guest's execution into circuit traces while proving (the
    /// GPU backend's default is 8).
    #[arg(long, global = true, env = "Z6M_REPLAY_THREADS")]
    replay_threads: Option<usize>,

    /// RPC URL for fetching blocks (required for --service)
    #[arg(long)]
    rpc_url: Option<String>,

    /// WebSocket URL for newHeads push notifications (optional; the
    /// fetcher polls the RPC URL when unset)
    #[arg(long)]
    ws_url: Option<String>,

    /// Prove on the GPU in service mode (required with --prove-every)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    gpu: bool,

    /// Prove every N-th block (service mode)
    #[arg(long)]
    prove_every: Option<u64>,

    /// Execute (without proof) every N-th block (service mode)
    #[arg(long)]
    execute_every: Option<u64>,

    /// Post to ethproofs every N-th block (service mode)
    #[arg(long)]
    post_every: Option<u64>,

    /// Output directory for proofs (service mode)
    #[arg(long, default_value = "proofs")]
    output_dir: PathBuf,

    /// Save all RPC responses (service mode)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    save_all_responses: bool,

    /// Ethproofs API endpoint URL
    #[arg(long, env = "ETHPROOFS_ENDPOINT")]
    ethproofs_endpoint: Option<String>,

    /// Ethproofs API bearer token
    #[arg(long, env = "ETHPROOFS_TOKEN")]
    ethproofs_token: Option<String>,

    /// Ethproofs cluster ID
    #[arg(long, env = "ETHPROOFS_CLUSTER_ID")]
    ethproofs_cluster_id: Option<u64>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Execute a block on the simulator, without proving
    Execute {
        /// Block number (used to locate the input file in data_dir)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Direct path to the input file (MFBD flat witness bundle, or a SLIB envelope for a HashState guest)
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory override
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Input file is an EEST JSON test fixture (not an MFBD bundle)
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Generate a flamegraph SVG at this path (slower)
        #[arg(long)]
        flamegraph: Option<PathBuf>,
    },

    /// Write the guest's verification key (EVKEY001 v2), against which `verify` and the
    /// Ethproofs verifier check proofs
    Vk {
        /// Output file
        #[arg(long, default_value = "vk.bin")]
        output: PathBuf,
    },

    /// Prove a block to the final unified recursion layer and write proof.bin (gzip EPROOF01 v2)
    Prove {
        /// Block number (used to locate the input file in data_dir)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Direct path to the input file (MFBD flat witness bundle, or a SLIB envelope for a HashState guest)
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory override
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Input file is an EEST JSON test fixture (not an MFBD bundle)
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Proving backend; the CPU one is very slow and needs about 96 GB of RAM
        #[arg(long, value_enum, default_value = "gpu")]
        backend: ProverBackend,

        /// Same as --backend gpu
        #[arg(long, hide = true, action = clap::ArgAction::SetTrue, conflicts_with = "backend")]
        gpu: bool,

        /// Output directory for proof.bin
        #[arg(long, default_value = "proofs")]
        output_dir: PathBuf,
    },

    /// Benchmark: prove the same block repeatedly with a persistent prover
    Bench {
        /// Path to an MFBD input file
        #[arg(long)]
        file_name: PathBuf,

        /// Number of proving iterations
        #[arg(long, default_value_t = 5)]
        iterations: u32,

        /// Proving backend
        #[arg(long, value_enum, default_value = "gpu")]
        backend: ProverBackend,
    },

    /// Verify a proof file against a verification key and the block it must cover
    Verify {
        /// Path to proof.bin (gzip EPROOF01 v2)
        #[arg(long)]
        proof: PathBuf,

        /// Path to the guest's verification key (from `vk`)
        #[arg(long)]
        vk: PathBuf,

        /// Input the proof must cover (MFBD file): the proof's public output must equal the
        /// hash of its last valid block. A proof binds its block only through that output.
        #[arg(long, required_unless_present = "block_hash")]
        file_name: Option<PathBuf>,

        /// Hash of the block the proof must cover, when its input is not at hand
        #[arg(long, conflicts_with = "file_name")]
        block_hash: Option<alloy_primitives::B256>,
    },
}

#[derive(Clone, Debug, Serialize)]
struct ExecutionLog {
    block_number: u64,
    /// The input's gas used, once the guest's public output has matched the input; 0 when the
    /// guest did not finish successfully.
    gas_used: u64,
    /// The block hash the guest committed (checked against the input), if it finished successfully.
    block_hash: Option<alloy_primitives::B256>,
    cycle_count: u64,
    exec_time_secs: f64,
    freq_cycles_per_sec: u64,
    reached_end: bool,
    /// The run parked at the guest's exit point (finish_success). Every other way the guest
    /// stops (finish_error, fatal(), abort, the trap handler) is also a self-loop, which the
    /// VM reports as reached_end too.
    succeeded: bool,
    final_pc: u32,
    input_path: PathBuf,
}

/// Build the oracle data the guest reads from CSR 0x7C0.
///
/// Protocol:
///   word 0: num_bytes (u32, little-endian byte count)
///   words 1..N: input bytes packed into u32 words (LE, zero-padded tail)
// Mirrors zilk_core/core/types_zz/flat_bundle.hpp.
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45; // "EJSN"
const INPUT_VERSION_EJSN: u32 = 1;

pub(crate) fn build_oracle(input_file: &Path, is_test: bool) -> Result<Vec<u32>> {
    let bytes = fs::read(input_file)
        .map_err(|e| eyre!("failed to read input file '{}': {}", input_file.display(), e))?;

    // The guest dispatches on the envelope's leading 4-byte magic (MFBD/EJSN/SLIB).
    // MFBD files are already enveloped on disk by the flat-bundle converter;
    // EEST JSON test fixtures are minified and wrapped in an EJSN envelope here.
    let bytes = if is_test {
        let value: serde_json::Value = serde_json::from_str(
            std::str::from_utf8(&bytes).map_err(|e| eyre!("invalid UTF-8 in test file: {}", e))?,
        )
        .map_err(|e| eyre!("invalid JSON in test file: {}", e))?;
        let minified =
            serde_json::to_vec(&value).map_err(|e| eyre!("JSON re-serialize failed: {}", e))?;
        let mut envelope = Vec::with_capacity(8 + minified.len());
        envelope.extend_from_slice(&INPUT_MAGIC_EJSN.to_le_bytes());
        envelope.extend_from_slice(&INPUT_VERSION_EJSN.to_le_bytes());
        envelope.extend_from_slice(&minified);
        envelope
    } else {
        bytes
    };

    let num_bytes = bytes.len() as u32;
    let num_words = (bytes.len() + 3) / 4;
    // +1 capacity: byte count + data words
    let mut oracle = Vec::with_capacity(1 + num_words);
    oracle.push(num_bytes);
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        oracle.push(u32::from_le_bytes(word));
    }
    Ok(oracle)
}

/// Resolve the input file path from the CLI arguments.
fn resolve_input_path(
    block_number: u64,
    file_name: Option<PathBuf>,
    data_dir: &Path,
) -> Result<PathBuf> {
    if let Some(path) = file_name {
        return Ok(path);
    }
    if block_number == 0 {
        bail!("either --file-name or a nonzero --block-number is required");
    }
    let block_dir = data_dir.join("blocks").join(block_number.to_string());
    let mfbd = block_dir.join(format!("flatWitnessBundle{}.mfbd", block_number));
    if mfbd.exists() {
        return Ok(mfbd);
    }
    // Legacy pre-MFBD layout.
    Ok(block_dir.join(format!("unifiedBlockAndStateRlp{}.bin", block_number)))
}

/// The guest's files: --guest-bin, or the default build output under the project root.
fn guest_files(cli_override: Option<&Path>) -> Result<GuestFiles> {
    let base = cli_override.unwrap_or(Path::new(DEFAULT_GUEST_BIN));
    let files = GuestFiles::at(base).map_err(|e| {
        if cli_override.is_none() {
            eyre!("{e}; pass --guest-bin or run from the project root")
        } else {
            e
        }
    })?;
    println!("Guest binary base: {}", files.bin.with_extension("").display());
    Ok(files)
}

fn format_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// Run the simulator on a single block and return the execution log.
fn execute_block(
    guest: &Guest,
    input_path: &Path,
    block_number: u64,
    max_cycles: usize,
    is_test: bool,
    flamegraph_path: Option<&Path>,
) -> Result<ExecutionLog> {
    if !input_path.exists() {
        bail!(
            "input file for block {} not found at {}",
            block_number,
            input_path.display()
        );
    }

    let oracle = build_oracle(input_path, is_test)?;
    let run = guest.run(oracle, max_cycles, flamegraph_path)?;
    let succeeded = run.succeeded(guest.exit_pc);

    // A successful run parks in the exit sequence's self-loop with its public output in a0..a7;
    // a failed one parks in finish_error's loop and commits nothing. The gas used is the input's,
    // which the guest checks against the header; it is no longer read from the output registers.
    let expected = if succeeded {
        let expected = public_output::expected_for_file(input_path, is_test)?;
        public_output::check(&expected.block_hash, &run.output)?;
        Some(expected)
    } else {
        None
    };

    Ok(ExecutionLog {
        block_number,
        gas_used: expected.map_or(0, |e| e.gas_used),
        block_hash: expected.map(|e| e.block_hash),
        cycle_count: run.cycles,
        exec_time_secs: run.elapsed.as_secs_f64(),
        freq_cycles_per_sec: run.cycles_per_sec(),
        reached_end: run.reached_end,
        succeeded,
        final_pc: run.final_pc,
        input_path: input_path.to_path_buf(),
    })
}

fn persist_execution_log(log_file: &Path, log: &ExecutionLog) -> Result<()> {
    if let Some(parent) = log_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    let timestamp = format_timestamp();
    writeln!(
        &mut file,
        "{} block={} gas_used={} cycles={} time={:.2}s freq={} reached_end={} ok={}  input={}",
        timestamp,
        log.block_number,
        log.gas_used,
        log.cycle_count,
        log.exec_time_secs,
        log.freq_cycles_per_sec,
        log.reached_end,
        log.succeeded,
        log.input_path.display(),
    )?;
    Ok(())
}

/// Extract block number from an input file name like "flatWitnessBundle24522000.mfbd".
fn block_number_from_filename(path: &Path) -> u64 {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    // Try to extract the trailing digits from the stem.
    let digits: String = stem.chars().rev().take_while(|c| c.is_ascii_digit()).collect();
    let digits: String = digits.chars().rev().collect();
    digits.parse().unwrap_or(0)
}

fn run_test_service(
    start_block: u64,
    end_block: u64,
    data_dir: &Path,
    guest: &Guest,
    max_cycles: usize,
    execution_log_file: Option<&Path>,
) -> Result<()> {
    let log_file = execution_log_file
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| data_dir.join("executionLogs.log"));

    println!(
        "[{}] airbender test-service: blocks {}..{}, data_dir={}, log={}",
        format_timestamp(),
        start_block,
        end_block,
        data_dir.display(),
        log_file.display(),
    );

    for block_number in start_block..=end_block {
        let input_path = resolve_input_path(block_number, None, data_dir)?;
        if !input_path.exists() {
            eprintln!(
                "[{}] SKIP block {} — file not found: {}",
                format_timestamp(),
                block_number,
                input_path.display()
            );
            continue;
        }
        println!(
            "[{}] Executing block {}",
            format_timestamp(),
            block_number
        );
        match execute_block(guest, &input_path, block_number, max_cycles, false, None) {
            Ok(log) => {
                println!(
                    "[{}] block={} gas_used={} cycles={} time={:.2}s freq={:.2}GHz reached_end={} ok={} block_hash={}",
                    format_timestamp(),
                    log.block_number,
                    log.gas_used,
                    log.cycle_count,
                    log.exec_time_secs,
                    log.freq_cycles_per_sec as f64 / 1e9,
                    log.reached_end,
                    log.succeeded,
                    log.block_hash.map_or("none".to_string(), |h| h.to_string()),
                );
                if let Err(e) = persist_execution_log(&log_file, &log) {
                    eprintln!("warning: failed to write log: {}", e);
                }
            }
            Err(e) => {
                eprintln!(
                    "[{}] ERROR block {}: {}",
                    format_timestamp(),
                    block_number,
                    e
                );
            }
        }
    }
    Ok(())
}

/// Where the prover loads the recursion verifier programs from, for the logs.
fn fsv_dir_note() -> String {
    match std::env::var("FSV_DIR") {
        Ok(dir) => format!("FSV_DIR={dir}"),
        Err(_) => "FSV_DIR unset: tools/gkr_verifier of the zksync-airbender checkout the prover was built from".to_string(),
    }
}

/// The variable that controls the prover JIT's fusion of word load/store runs.
const MERGE_WINDOW_VAR: &str = "RISCV_MERGE_WINDOW";

fn main() -> Result<()> {
    // Airbender v3's JIT fuses runs of consecutive same-base word loads or stores (immediate
    // stride +4) into groups of RISCV_MERGE_WINDOW (default 4), on the assumption that no jump
    // lands inside a run. The guest breaks that assumption: keccak.c's buf_zero_state_from
    // (evmone) and mem_builtins.c's memset jump into the middle of runs of `sw`, and a jump past
    // a group's head would run the group from its head, storing below the target. 0 turns the
    // fusion off. The JIT reads the variable once, from any thread, so it is set here, before
    // the runtime or any other thread starts.
    if std::env::var_os(MERGE_WINDOW_VAR).is_none() {
        std::env::set_var(MERGE_WINDOW_VAR, "0");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Ok(window) = std::env::var(MERGE_WINDOW_VAR) {
        eyre::ensure!(
            window == "0",
            "{MERGE_WINDOW_VAR}={window}: the guest jumps into runs of word stores, which the \
             prover's JIT would then fuse, proving a wrong execution. Unset it or set it to 0."
        );
    }

    let args = Args::parse();

    // ── Service mode ────────────────────────────────────────────────────
    if args.service {
        let guest = guest_files(args.guest_bin.as_deref())?;
        let rpc_url = args
            .rpc_url
            .ok_or_else(|| eyre!("--service requires --rpc-url"))?;

        let ethproofs = match (
            args.ethproofs_endpoint,
            args.ethproofs_token,
            args.ethproofs_cluster_id,
        ) {
            (Some(endpoint), Some(token), Some(cluster_id)) => {
                Some(z6m_common::EthProofsConfig {
                    endpoint,
                    token,
                    cluster_id,
                })
            }
            _ => None,
        };

        let svc_config = service::ServiceConfig {
            start_block: args.start_block,
            end_block: args.end_block,
            prove_every: args.prove_every,
            execute_every: args.execute_every,
            post_every: args.post_every,
            rpc_url,
            ws_url: args.ws_url.clone(),
            save_all_responses: args.save_all_responses,
            data_dir: args.data_dir.clone(),
            output_dir: args.output_dir,
            guest,
            max_cycles: args.cycles,
            replay_threads: args.replay_threads,
            gpu: args.gpu,
            ethproofs,
        };

        let svc = tokio::task::block_in_place(|| service::AirbenderService::new(svc_config))?;
        return svc.run().await;
    }

    // ── Test-service mode (batch execution from disk) ───────────────────
    if args.test_service {
        let start = args
            .start_block
            .ok_or_else(|| eyre!("--test-service requires --start-block"))?;
        let end = args
            .end_block
            .ok_or_else(|| eyre!("--test-service requires --end-block"))?;
        let guest = Guest::load(guest_files(args.guest_bin.as_deref())?)?;
        return run_test_service(
            start,
            end,
            &args.data_dir,
            &guest,
            args.cycles,
            args.execution_log_file.as_deref(),
        );
    }

    match args.command {
        Some(Command::Execute {
            block_number,
            file_name,
            data_dir,
            is_test,
            flamegraph,
        }) => {
            let guest = Guest::load(guest_files(args.guest_bin.as_deref())?)?;
            let data_dir = data_dir.unwrap_or_else(|| args.data_dir.clone());
            let input_path = resolve_input_path(block_number, file_name, &data_dir)?;
            let block_num = if block_number > 0 {
                block_number
            } else {
                block_number_from_filename(&input_path)
            };

            let log = execute_block(
                &guest,
                &input_path,
                block_num,
                args.cycles,
                is_test,
                flamegraph.as_deref(),
            )?;

            let log_file = data_dir.join("executionLogs.log");
            persist_execution_log(&log_file, &log)?;

            if !log.succeeded {
                bail!(
                    "block {} did not finish successfully: final_pc=0x{:08x} reached_end={} cycles={}",
                    log.block_number,
                    log.final_pc,
                    log.reached_end,
                    log.cycle_count,
                );
            }
            println!(
                "Executed block {} (gas_used={}, cycles={}, time={:.2}s, freq={:.2} GHz, reached_end={})",
                log.block_number,
                log.gas_used,
                log.cycle_count,
                log.exec_time_secs,
                log.freq_cycles_per_sec as f64 / 1e9,
                log.reached_end,
            );
            match log.block_hash {
                Some(hash) => println!("Public output: block hash {} (matches the input)", hash),
                None => println!("Public output: none (the guest did not finish successfully)"),
            }
            if log.cycle_count > MAX_PROVABLE_CYCLES as u64 {
                println!(
                    "warning: {} cycles exceed the {} the prover takes; this input cannot be proved",
                    log.cycle_count, MAX_PROVABLE_CYCLES
                );
            }
        }

        Some(Command::Vk { output }) => {
            let guest = guest_files(args.guest_bin.as_deref())?;
            println!(
                "[{}] Computing the verification key ({})",
                format_timestamp(),
                fsv_dir_note()
            );
            let started = Instant::now();
            let key = tokio::task::block_in_place(|| VerificationKey::compute(&guest))?;
            if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output, key.encode()?)
                .map_err(|e| eyre!("failed to write {}: {e}", output.display()))?;
            println!(
                "[{}] Wrote the verification key to {} in {:.1}s",
                format_timestamp(),
                output.display(),
                started.elapsed().as_secs_f64()
            );
            println!("  app.bin keccak256  0x{}", hex(&key.app_bin_keccak));
            println!("  app.text keccak256 0x{}", hex(&key.app_text_keccak));
            for (layers, hash) in ["0", "1", ">=2"].iter().zip(&key.expected_chain_hashes) {
                println!("  chain hash ({layers:>3} unrolled layers) {}", hex_words(hash));
            }
        }

        Some(Command::Prove {
            block_number,
            file_name,
            data_dir,
            is_test,
            backend,
            gpu,
            output_dir,
        }) => {
            vk::check_recursion_environment()?;
            let backend = if gpu { ProverBackend::Gpu } else { backend };
            let guest = Guest::load(guest_files(args.guest_bin.as_deref())?)?;
            let data_dir = data_dir.unwrap_or_else(|| args.data_dir.clone());
            let input_path = resolve_input_path(block_number, file_name, &data_dir)?;
            let block_num = if block_number > 0 {
                block_number
            } else {
                block_number_from_filename(&input_path)
            };
            let settings = ProverSettings::new(
                guest.files.clone(),
                backend,
                args.cycles,
                args.replay_threads,
            )?;

            // The prover proves whatever the run did, wherever it stopped: a run that parked in
            // finish_error, or ran into the cycle bound, would yield a proof that commits no
            // block. Run it on the simulator first, as the service's preflight does.
            let preflight = execute_block(
                &guest,
                &input_path,
                block_num,
                settings.cycles_bound as usize,
                is_test,
                None,
            )?;
            // The simulator bounds its steps, the prover the timestamp, which a delegation call
            // advances by more than one cycle: check the cycle count as well.
            if !preflight.succeeded || preflight.cycle_count >= settings.cycles_bound as u64 {
                bail!(
                    "preflight: block {} did not finish successfully within {} cycles (final_pc=0x{:08x} reached_end={} cycles={}); not proving",
                    block_num,
                    settings.cycles_bound,
                    preflight.final_pc,
                    preflight.reached_end,
                    preflight.cycle_count,
                );
            }
            println!(
                "[{}] Preflight ok: block {} gas_used={} cycles={}",
                format_timestamp(),
                block_num,
                preflight.gas_used,
                preflight.cycle_count,
            );
            let expected = public_output::expected_for_file(&input_path, is_test)?;

            println!(
                "[{}] Proving block {} ({:?} backend, input={}, {})",
                format_timestamp(),
                block_num,
                backend,
                input_path.display(),
                fsv_dir_note(),
            );
            let wall_start = Instant::now();
            let proved = tokio::task::block_in_place(|| -> Result<_> {
                let mut prover = BlockProver::new(settings)?;
                prover.prove(build_oracle(&input_path, is_test)?)
            })?;
            prove::check_output(&expected, &proved.output())?;
            println!("Proof commits block hash {} (matches the input)", expected.block_hash);

            let proof_file = proof_format::proof_file_bytes(&proved.artifact)?;
            fs::create_dir_all(&output_dir)?;
            let proof_path = output_dir.join("proof.bin");
            fs::write(&proof_path, &proof_file)
                .map_err(|e| eyre!("failed to write {}: {e}", proof_path.display()))?;
            println!(
                "[{}] Proved block {} in {:.2}s (proving {:.2}s, cycles={}, proofs={}); wrote {} ({} bytes)",
                format_timestamp(),
                block_num,
                wall_start.elapsed().as_secs_f64(),
                proved.elapsed.as_secs_f64(),
                proved.program_cycles(),
                proved.proof_count(),
                proof_path.display(),
                proof_file.len(),
            );
        }

        Some(Command::Bench {
            file_name,
            iterations,
            backend,
        }) => {
            vk::check_recursion_environment()?;
            let guest = guest_files(args.guest_bin.as_deref())?;
            let settings = ProverSettings::new(guest, backend, args.cycles, args.replay_threads)?;
            let expected = public_output::expected_for_file(&file_name, false)?;
            let oracle = build_oracle(&file_name, false)?;
            tokio::task::block_in_place(|| -> Result<()> {
                let t = Instant::now();
                let mut prover = BlockProver::new(settings)?;
                println!("BENCH {:?} prover init in {:.2?}", backend, t.elapsed());

                let mut times = Vec::new();
                for i in 0..iterations {
                    let t = Instant::now();
                    match prover.prove(oracle.clone()) {
                        Ok(proved) => {
                            let ms = t.elapsed().as_millis();
                            prove::check_output(&expected, &proved.output())?;
                            times.push(ms);
                            println!(
                                "BENCH iter={} cycles={} proofs={} time_ms={}",
                                i,
                                proved.program_cycles(),
                                proved.proof_count(),
                                ms
                            );
                        }
                        Err(err) => println!("BENCH iter={} FAILED: {err}", i),
                    }
                }
                times.sort();
                println!(
                    "BENCH done iters={} ok={} min={}ms median={}ms max={}ms",
                    iterations,
                    times.len(),
                    times.first().unwrap_or(&0),
                    times.get(times.len() / 2).unwrap_or(&0),
                    times.last().unwrap_or(&0)
                );
                Ok(())
            })?;
        }

        Some(Command::Verify {
            proof,
            vk,
            file_name,
            block_hash,
        }) => {
            let key = VerificationKey::decode(
                &fs::read(&vk).map_err(|e| eyre!("failed to read {}: {e}", vk.display()))?,
            )?;
            let proof_file =
                fs::read(&proof).map_err(|e| eyre!("failed to read {}: {e}", proof.display()))?;

            let started = Instant::now();
            let output =
                tokio::task::block_in_place(|| vk::verify_proof_file(&proof_file, &key))
                    .map_err(|e| eyre!("VERIFIER REJECTED the proof: {e}"))?;
            println!("Verifier accepted in {:.2?}", started.elapsed());
            println!("verifier output[0..8]  = {:08x?}", &output[..8]);
            println!("verifier output[8..16] = {:08x?}", &output[8..]);
            // output[0..8] are the guest's x10..x17 (its own output), output[8..16] the
            // recursion chain over the end parameters: the setups, which include the guest
            // binary, and the final PC. Only the latter binds the proof to this guest.
            println!("CHAIN BINDING OK: output[8..16] is a chain hash of the key");

            // output[0..8] is the guest's public output: the hash of the last block the run
            // validated. The proof binds its block only through it.
            let expected = match (file_name, block_hash) {
                (Some(path), _) => public_output::expected_for_file(&path, false)?.block_hash,
                (None, Some(hash)) => hash,
                (None, None) => unreachable!("clap requires --file-name or --block-hash"),
            };
            public_output::check(&expected, &output[..8].try_into().unwrap())?;
            println!("PUBLIC OUTPUT OK: output[0..8] commits block hash {}", expected);
        }

        None => {
            bail!("no command provided; pass --test-service or a subcommand (e.g. execute, prove)");
        }
    }

    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_words(words: &[u32]) -> String {
    words.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(" ")
}
