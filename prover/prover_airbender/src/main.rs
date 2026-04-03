use clap::{Parser, Subcommand};
use eyre::{bail, eyre, Result};
use risc_v_simulator::abstractions::non_determinism::QuasiUARTSource;
use risc_v_simulator::runner::run_simple_with_entry_point_and_non_determimism_source;
use risc_v_simulator::sim::SimulatorConfig;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Default path to the airbender guest binary, relative to the project root.
const DEFAULT_GUEST_BIN: &str = "prover/guest_airbender/build/z6m_guest.bin";

/// Default maximum cycles for the simulator.
const DEFAULT_CYCLES: usize = 5_000_000_000;

#[derive(Parser, Debug)]
#[command(
    name = "z6m_prover_airbender",
    about = "Zilkworm prover using zksync-airbender RISC-V simulator"
)]
struct Args {
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "command")]
    test_service: bool,

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

    /// Path to the guest binary (ELF flat binary)
    #[arg(long)]
    guest_bin: Option<PathBuf>,

    /// Maximum simulator cycles
    #[arg(long, default_value_t = DEFAULT_CYCLES)]
    cycles: usize,

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
/// Protocol (matching runner.rs in zksync-airbender):
///   word 0: num_bytes (u32, little-endian byte count)
///   words 1..N: file contents packed into u32 words (LE, zero-padded tail)
fn build_oracle(input_file: &Path) -> Result<Vec<u32>> {
    let bytes = fs::read(input_file)
        .map_err(|e| eyre!("failed to read input file '{}': {}", input_file.display(), e))?;
    let num_bytes = bytes.len() as u32;
    let num_words = (bytes.len() + 3) / 4;
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
    let path = data_dir
        .join("blocks")
        .join(block_number.to_string())
        .join(format!("unifiedBlockAndStateRlp{}.bin", block_number));
    Ok(path)
}

/// Locate the guest binary: CLI override > DEFAULT_GUEST_BIN relative to cwd.
fn resolve_guest_bin(cli_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = cli_override {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        bail!("guest binary not found at {}", p.display());
    }
    let default = PathBuf::from(DEFAULT_GUEST_BIN);
    if default.exists() {
        return Ok(default);
    }
    bail!(
        "guest binary not found at default path '{}'; pass --guest-bin or run from the project root",
        DEFAULT_GUEST_BIN
    );
}

fn format_timestamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// Run the airbender simulator on a single block and return the execution log.
fn execute_block(
    guest_bin: &Path,
    input_path: &Path,
    block_number: u64,
    max_cycles: usize,
) -> Result<ExecutionLog> {
    if !input_path.exists() {
        bail!(
            "input file for block {} not found at {}",
            block_number,
            input_path.display()
        );
    }

    let oracle = build_oracle(input_path)?;
    let source = QuasiUARTSource::new_with_reads(oracle);

    let mut config = SimulatorConfig::simple(guest_bin);
    config.entry_point = 0;
    config.cycles = max_cycles;
    config.diagnostics = None;

    let wall_start = Instant::now();
    let output = run_simple_with_entry_point_and_non_determimism_source(config, source);
    let wall_elapsed = wall_start.elapsed();

    let cycles = output.measurements.time.exec_cycles as u64;
    let exec_secs = output.measurements.time.exec_time.as_secs_f64();
    let freq = if exec_secs > 0.0 {
        (cycles as f64 / exec_secs) as u64
    } else {
        0
    };

    // The guest stores gas_used in register a0 (x10) via finish_success.
    let gas_used = output.state.registers[10] as u64;

    Ok(ExecutionLog {
        block_number,
        gas_used,
        cycle_count: cycles,
        exec_time_secs: wall_elapsed.as_secs_f64(),
        freq_cycles_per_sec: freq,
        reached_end: output.reached_end,
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
    guest_bin: &Path,
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
        match execute_block(guest_bin, &input_path, block_number, max_cycles) {
            Ok(log) => {
                println!(
                    "[{}] block={} gas_used={} cycles={} time={:.2}s freq={} reached_end={}",
                    format_timestamp(),
                    log.block_number,
                    log.gas_used,
                    log.cycle_count,
                    log.exec_time_secs,
                    log.freq_cycles_per_sec,
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

fn main() -> Result<()> {
    let args = Args::parse();

    let guest_bin = resolve_guest_bin(args.guest_bin.as_deref())?;
    println!("Guest binary: {}", guest_bin.display());

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
            &guest_bin,
            args.cycles,
            args.execution_log_file.as_deref(),
        );
    }

    match args.command {
        Some(Command::Execute {
            block_number,
            file_name,
            data_dir,
        }) => {
            let data_dir = data_dir.unwrap_or_else(|| args.data_dir.clone());
            let input_path = resolve_input_path(block_number, file_name, &data_dir)?;
            let block_num = if block_number > 0 {
                block_number
            } else {
                block_number_from_filename(&input_path)
            };

            let log = execute_block(&guest_bin, &input_path, block_num, args.cycles)?;

            println!(
                "Executed block {} (gas_used={}, cycles={}, time={:.2}s, freq={} cycles/s, reached_end={})",
                log.block_number,
                log.gas_used,
                log.cycle_count,
                log.exec_time_secs,
                log.freq_cycles_per_sec,
                log.reached_end,
            );

            let log_file = data_dir.join("executionLogs.log");
            persist_execution_log(&log_file, &log)?;
        }
        None => {
            bail!("no command provided; pass --test-service or a subcommand (e.g. execute)");
        }
    }

    Ok(())
}
