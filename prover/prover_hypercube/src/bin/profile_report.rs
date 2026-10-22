// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Profiling helper: execute one input file through the guest and dump the full
//! SP1 ExecutionReport (opcode counts, per-syscall counts, cycle tracker) as JSON.
//! Not for benchmarking — stdout writes from the guest cost cycles themselves.

use clap::Parser;
use sp1_sdk::{include_elf, Prover, ProverClient, SP1Stdin};
use serde_json::json;
use std::path::PathBuf;

pub const Z6M_ELF: sp1_sdk::Elf = include_elf!("z6m_guest");

#[derive(Parser, Debug)]
struct Args {
    /// Input file (raw envelope bytes, written as a single Vec into the stdin).
    /// Omit (with --empty-stdin) for the calibration guest.
    #[arg(long)]
    file_name: Option<PathBuf>,
    /// Run with an empty stdin instead of an input file (calibration guest).
    #[arg(long, conflicts_with = "file_name")]
    empty_stdin: bool,
    /// Guest ELF path (default: the embedded z6m_guest build)
    #[arg(long)]
    elf: Option<PathBuf>,
    /// Optional output path for the JSON report (default: stdout)
    #[arg(long)]
    out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let mut stdin = SP1Stdin::new();
    if let Some(f) = &args.file_name {
        stdin.write_vec(std::fs::read(f)?);
    }

    let elf = match &args.elf {
        Some(p) => sp1_sdk::Elf::from(std::fs::read(p)?),
        None => Z6M_ELF,
    };
    let client = ProverClient::builder().cpu().build().await;
    let (mut output, report) = client.execute(elf, stdin).await?;

    let syscalls: serde_json::Map<String, serde_json::Value> = report
        .syscall_counts
        .iter()
        .filter(|(_, &c)| c > 0)
        .map(|(code, c)| (format!("{:?}", code), json!(c)))
        .collect();

    let opcodes: serde_json::Map<String, serde_json::Value> = report
        .opcode_counts
        .iter()
        .filter(|(_, &c)| c > 0)
        .map(|(op, c)| (format!("{:?}", op), json!(c)))
        .collect();

    let gas_used: Option<u64> = (!args.empty_stdin).then(|| output.read::<u64>());
    let doc = json!({
        "gas_used": gas_used,
        "total_cycles": report.total_instruction_count(),
        "prover_gas": report.gas().unwrap_or_default(),
        "total_syscalls": report.total_syscall_count(),
        "touched_memory_addresses": report.touched_memory_addresses,
        "exit_code": report.exit_code,
        "syscall_counts": syscalls,
        "opcode_counts": opcodes,
        "cycle_tracker": report.cycle_tracker,
    });

    match &args.out {
        Some(p) => std::fs::write(p, serde_json::to_string_pretty(&doc)?)?,
        None => println!("{}", serde_json::to_string_pretty(&doc)?),
    }
    Ok(())
}
