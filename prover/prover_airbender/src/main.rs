#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(allocator_api)]

use clap::{Parser, Subcommand};
use eyre::{bail, eyre, Result};
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use riscv_transpiler::ir::{preprocess_bytecode, FullMachineDecoderConfig};
use riscv_transpiler::vm::{
    DelegationsCounters, FlamegraphConfig, RamWithRomRegion, SimpleTape, State,
    VmFlamegraphProfiler, VM,
};
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

mod prove;
mod service;

use prove::ProvingLimit;

/// Default path to the airbender guest binary, relative to the project root.
const DEFAULT_GUEST_BIN: &str = "prover/guest_airbender/build/z6m_guest";

/// Default maximum cycles for the simulator.
const DEFAULT_CYCLES: usize = 5_000_000_000;

/// Default RAM bound in bytes (1 GB).
const DEFAULT_RAM_BOUND: usize = 1 << 30;

#[derive(Parser, Debug)]
#[command(
    name = "z6m_prover_airbender",
    about = "Zilkworm prover using zksync-airbender RISC-V simulator"
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

    /// Maximum simulator cycles
    #[arg(long, default_value_t = DEFAULT_CYCLES)]
    cycles: usize,

    /// RPC URL for fetching blocks (required for --service)
    #[arg(long)]
    rpc_url: Option<String>,

    /// Use GPU (CUDA) for proving in service mode
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

    /// How far to prove (base, unrolled, or unified)
    #[arg(long, value_enum)]
    until: Option<ProvingLimit>,

    /// Save all RPC responses (service mode)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    save_all_responses: bool,

    /// Path to precomputed setup cache directory (from `setup` command)
    #[arg(long)]
    setup_dir: Option<PathBuf>,

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
    /// Execute a block without proving
    Execute {
        /// Block number (used to locate the input file in data_dir)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Direct path to the unified RLP input file
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory override
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Input file is an EEST JSON test fixture (not unified RLP)
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Generate a flamegraph SVG at this path (uses interpreted mode, slower)
        #[arg(long)]
        flamegraph: Option<PathBuf>,
    },

    /// Precompute circuit setup (cached to disk for reuse by prove/service)
    Setup {
        /// Output directory for the setup cache file
        #[arg(long, default_value = "temp")]
        setup_dir: PathBuf,

        /// How far to prove (base, unrolled, or unified)
        #[arg(long, value_enum, default_value = "base")]
        until: ProvingLimit,
    },

    /// Prove a block (generate ZK proof)
    Prove {
        /// Block number (used to locate the input file in data_dir)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Direct path to the unified RLP input file
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory override
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Input file is an EEST JSON test fixture (not unified RLP)
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Use GPU (CUDA) for proving
        #[arg(long, action = clap::ArgAction::SetTrue)]
        gpu: bool,

        /// Output directory for proof artifacts
        #[arg(long, default_value = "proofs")]
        output_dir: PathBuf,

        /// How far to prove (base, unrolled, or unified)
        #[arg(long, value_enum)]
        until: Option<ProvingLimit>,

        /// Path to precomputed setup cache (from `setup` command)
        #[arg(long)]
        setup_dir: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, Serialize)]
struct ExecutionLog {
    block_number: u64,
    gas_used: u64,
    cycle_count: u64,
    exec_time_secs: f64,
    freq_cycles_per_sec: u64,
    reached_end: bool,
    input_path: PathBuf,
}

/// Build the oracle data that the QuasiUARTSource feeds to the guest.
///
/// Protocol:
///   word 0: dispatch flag (0=unified RLP, 1=EEST JSON test)
///   word 1: num_bytes (u32, little-endian byte count)
///   words 2..N: file contents packed into u32 words (LE, zero-padded tail)
pub(crate) fn build_oracle(input_file: &Path, is_test: bool) -> Result<Vec<u32>> {
    let bytes = fs::read(input_file)
        .map_err(|e| eyre!("failed to read input file '{}': {}", input_file.display(), e))?;

    // If is_test, minify the JSON first
    let bytes = if is_test {
        let value: serde_json::Value = serde_json::from_str(
            std::str::from_utf8(&bytes).map_err(|e| eyre!("invalid UTF-8 in test file: {}", e))?,
        )
        .map_err(|e| eyre!("invalid JSON in test file: {}", e))?;
        serde_json::to_vec(&value).map_err(|e| eyre!("JSON re-serialize failed: {}", e))?
    } else {
        bytes
    };

    let num_bytes = bytes.len() as u32;
    let num_words = (bytes.len() + 3) / 4;
    // +2 capacity: dispatch word + byte count + data words
    let mut oracle = Vec::with_capacity(2 + num_words);
    // Dispatch word: 1 = test mode, 0 = unified RLP
    oracle.push(if is_test { 1u32 } else { 0u32 });
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
    let path = data_dir
        .join("blocks")
        .join(block_number.to_string())
        .join(format!("unifiedBlockAndStateRlp{}.bin", block_number));
    Ok(path)
}

/// Locate the guest binary base path (without .bin/.text extension).
fn resolve_guest_bin(cli_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = cli_override {
        // If user passed path ending in .bin, strip it
        let base = if p.extension().map_or(false, |e| e == "bin") {
            p.with_extension("")
        } else {
            p.to_path_buf()
        };
        let bin_path = PathBuf::from(format!("{}.bin", base.display()));
        if bin_path.exists() {
            return Ok(base);
        }
        bail!("guest binary not found at {}", bin_path.display());
    }
    let default = PathBuf::from(DEFAULT_GUEST_BIN);
    let bin_path = PathBuf::from(format!("{}.bin", default.display()));
    if bin_path.exists() {
        return Ok(default);
    }
    bail!(
        "guest binary not found at default path '{}'; pass --guest-bin or run from the project root",
        bin_path.display()
    );
}

fn format_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// Run the VM on a single block and return the execution log.
fn execute_block(
    guest_base: &Path,
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
    let source = QuasiUARTSource::new_with_reads(oracle);

    let bin_path = format!("{}.bin", guest_base.display());
    let text_path = format!("{}.text", guest_base.display());
    let elf_path = format!("{}.elf", guest_base.display());

    let (_, binary_u32) = execution_utils::setups::read_binary(Path::new(&bin_path));
    let (_, text_u32) = execution_utils::setups::read_binary(Path::new(&text_path));

    let instructions = preprocess_bytecode::<FullMachineDecoderConfig>(&text_u32);
    let tape = SimpleTape::new(&instructions);
    let mut ram =
        RamWithRomRegion::<{ prover::common_constants::rom::ROM_SECOND_WORD_BITS }>::from_rom_content(
            &binary_u32,
            DEFAULT_RAM_BOUND,
        );

    let mut state = State::initial_with_counters(DelegationsCounters::default());
    let mut non_determinism_source = source;

    let wall_start = Instant::now();
    let finished = if let Some(fg_path) = flamegraph_path {
        let config = FlamegraphConfig::new(PathBuf::from(&elf_path), fg_path.to_path_buf());
        let mut profiler = VmFlamegraphProfiler::new(config)
            .map_err(|e| eyre!("flamegraph init: {e}"))?;
        let result = VM::<DelegationsCounters>::run_basic_unrolled_with_flamegraph(
            &mut state,
            &mut ram,
            &mut (),
            &tape,
            max_cycles,
            &mut non_determinism_source,
            &mut profiler,
        )
        .map_err(|e| eyre!("flamegraph execution: {e}"))?;
        let stats = profiler.stats();
        eprintln!(
            "Flamegraph: {} samples collected / {} total, written to {}",
            stats.samples_collected, stats.samples_total, fg_path.display()
        );
        result
    } else {
        VM::<DelegationsCounters>::run_basic_unrolled(
            &mut state,
            &mut ram,
            &mut (),
            &tape,
            max_cycles,
            &mut non_determinism_source,
        )
    };
    let wall_elapsed = wall_start.elapsed();

    let cycles = (state.timestamp - riscv_transpiler::common_constants::INITIAL_TIMESTAMP)
        / riscv_transpiler::common_constants::TIMESTAMP_STEP;
    let exec_secs = wall_elapsed.as_secs_f64();
    let freq = if exec_secs > 0.0 {
        (cycles as f64 / exec_secs) as u64
    } else {
        0
    };

    // The guest stores gas_used in register a0 (x10) via finish_success.
    let gas_used = state.registers[10].value as u64;

    Ok(ExecutionLog {
        block_number,
        gas_used,
        cycle_count: cycles,
        exec_time_secs: wall_elapsed.as_secs_f64(),
        freq_cycles_per_sec: freq,
        reached_end: finished,
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
        "{} block={} gas_used={} cycles={} time={:.2}s freq={} reached_end={}  input={}",
        timestamp,
        log.block_number,
        log.gas_used,
        log.cycle_count,
        log.exec_time_secs,
        log.freq_cycles_per_sec,
        log.reached_end,
        log.input_path.display(),
    )?;
    Ok(())
}

/// Extract block number from a unified RLP file name like "unifiedBlockAndStateRlp24522000.bin".
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
    guest_base: &Path,
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
        match execute_block(guest_base, &input_path, block_number, max_cycles, false, None) {
            Ok(log) => {
                println!(
                    "[{}] block={} gas_used={} cycles={} time={:.2}s freq={:.2}GHz reached_end={}",
                    format_timestamp(),
                    log.block_number,
                    log.gas_used,
                    log.cycle_count,
                    log.exec_time_secs,
                    log.freq_cycles_per_sec as f64 / 1e9,
                    log.reached_end,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let guest_base = resolve_guest_bin(args.guest_bin.as_deref())?;
    println!("Guest binary base: {}", guest_base.display());

    // ── Service mode ────────────────────────────────────────────────────
    if args.service {
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
            save_all_responses: args.save_all_responses,
            data_dir: args.data_dir.clone(),
            output_dir: args.output_dir,
            guest_base: guest_base.clone(),
            max_cycles: args.cycles,
            gpu: args.gpu,
            until: args.until,
            setup_dir: args.setup_dir.clone(),
            ethproofs,
        };

        let svc = service::AirbenderService::new(svc_config)?;
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
        return run_test_service(
            start,
            end,
            &args.data_dir,
            &guest_base,
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
            let data_dir = data_dir.unwrap_or_else(|| args.data_dir.clone());
            let input_path = resolve_input_path(block_number, file_name, &data_dir)?;
            let block_num = if block_number > 0 {
                block_number
            } else {
                block_number_from_filename(&input_path)
            };

            let log = execute_block(
                &guest_base,
                &input_path,
                block_num,
                args.cycles,
                is_test,
                flamegraph.as_deref(),
            )?;

            println!(
                "Executed block {} (gas_used={}, cycles={}, time={:.2}s, freq={:.2} GHz, reached_end={})",
                log.block_number,
                log.gas_used,
                log.cycle_count,
                log.exec_time_secs,
                log.freq_cycles_per_sec as f64 / 1e9,
                log.reached_end,
            );

            let log_file = data_dir.join("executionLogs.log");
            persist_execution_log(&log_file, &log)?;
        }

        Some(Command::Setup {
            setup_dir,
            until,
        }) => {
            #[cfg(feature = "gpu")]
            {
                let guest_path = guest_base.display().to_string();
                println!(
                    "[{}] Computing setup (until={:?}, guest={})",
                    format_timestamp(), until, guest_path,
                );
                let start = Instant::now();
                let cache = prove::compute_setup(&guest_path, &until);
                println!(
                    "[{}] Setup computed in {:.2}s",
                    format_timestamp(), start.elapsed().as_secs_f64(),
                );
                fs::create_dir_all(&setup_dir)?;
                let setup_path = setup_dir.join("setup.bin");
                prove::save_setup(&cache, &setup_path)?;

                // If we computed up to Unified, also dump WASM-verifier-compatible
                // setup.bin + layout.bin (bincode 2.x standard config, unified layer only).
                if matches!(until, prove::ProvingLimit::Unified) {
                    let wasm_dir = setup_dir.join("wasm");
                    if let Err(e) = prove::save_for_wasm_verifier(&cache, &wasm_dir) {
                        eprintln!("[warn] WASM verifier files not written: {e}");
                    }
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                bail!("Compiled without GPU support. Rebuild with --features gpu");
            }
        }

        Some(Command::Prove {
            block_number,
            file_name,
            data_dir,
            is_test,
            gpu,
            output_dir,
            until,
            setup_dir,
        }) => {
            let data_dir = data_dir.unwrap_or_else(|| args.data_dir.clone());
            let input_path = resolve_input_path(block_number, file_name, &data_dir)?;
            let block_num = if block_number > 0 {
                block_number
            } else {
                block_number_from_filename(&input_path)
            };

            if !input_path.exists() {
                bail!(
                    "input file for block {} not found at {}",
                    block_num,
                    input_path.display()
                );
            }

            let until = until.unwrap_or(ProvingLimit::Base);

            println!(
                "[{}] Proving block {} (gpu={}, until={:?}, input={})",
                format_timestamp(),
                block_num,
                gpu,
                until,
                input_path.display(),
            );

            let oracle = build_oracle(&input_path, is_test)?;
            let wall_start = Instant::now();

            if gpu {
                #[cfg(feature = "gpu")]
                {
                    let prover = if let Some(dir) = setup_dir {
                        let setup_path = dir.join("setup.bin");
                        println!("Loading cached setup from {}", setup_path.display());
                        let cache = prove::load_setup(&setup_path)?;
                        prove::create_gpu_prover_from_cache(cache)
                    } else {
                        let guest_path = guest_base.display().to_string();
                        prove::create_gpu_prover(&guest_path, &until)
                    };
                    let (proof, cycles) = prove::gpu_prove(&prover, oracle, block_num);

                    fs::create_dir_all(&output_dir)?;
                    prove::serialize_proof_to_file(&proof, &output_dir.join("proof.bin"));

                    let total_wall = wall_start.elapsed();
                    println!(
                        "[{}] Proving complete for block {} in {:.2}s (cycles={})",
                        format_timestamp(),
                        block_num,
                        total_wall.as_secs_f64(),
                        cycles,
                    );
                }
                #[cfg(not(feature = "gpu"))]
                {
                    bail!("Compiled without GPU support. Rebuild with --features gpu");
                }
            } else {
                bail!("CPU proving not yet implemented in z6m. Use --gpu.");
            }
        }

        None => {
            bail!("no command provided; pass --test-service or a subcommand (e.g. execute, prove)");
        }
    }

    Ok(())
}
