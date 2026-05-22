// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! EEST JSON → unified-RLP converter. Two modes:
//!   * `emit  --json <PATH> --index <N>` — single subtest → stdout, debug aid
//!   * `bulk-convert --input-dir <D> --output-dir <D'>` — produce a tree of `.rlp` files

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use rayon::prelude::*;
use walkdir::WalkDir;

use z6m_common::eest_json_to_unified_rlp::{
    eest_json_convert_subtest, eest_json_to_unified_rlp,
};
use z6m_common::rlp_methods::encode_rlp_bundle;

#[derive(Parser, Debug)]
#[command(about = "EEST JSON → unified RLP converter")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Convert the Nth accepted subtest of a JSON file; write RLP to stdout.
    Emit {
        #[arg(long)]
        json: PathBuf,
        #[arg(long)]
        index: usize,
    },
    /// Convert a whole EEST JSON tree into a mirror tree of `.rlp` files (see `docs/architecture.md` "Bundle format").
    /// Each input `<rel>.json` becomes `<rel>.rlp`. JSONs with zero accepted subtests are skipped (no output file written).
    BulkConvert {
        #[arg(long)]
        input_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
    },
}

fn bulk_convert_tree(input_root: &Path, output_root: &Path) -> Result<usize> {
    std::fs::create_dir_all(output_root)?;
    let mut json_files: Vec<PathBuf> = WalkDir::new(input_root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path().extension().map_or(false, |x| x == "json"))
        .map(|e| e.path().to_path_buf())
        .collect();
    json_files.sort();
    let total = json_files.len();

    let written = AtomicU64::new(0);
    let empty = AtomicU64::new(0);
    let failed = AtomicU64::new(0);

    json_files.par_iter().for_each(|json_path| {
        let rel = json_path.strip_prefix(input_root).unwrap_or(json_path);
        let out_path = output_root.join(rel).with_extension("rlp");
        let json_str = match std::fs::read_to_string(json_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("read error {}: {}", json_path.display(), e);
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let subtests = match eest_json_to_unified_rlp(&json_str) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("convert error {}: {}", json_path.display(), e);
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        if subtests.is_empty() {
            empty.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Some(parent) = out_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("mkdir error {}: {}", parent.display(), e);
                failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let blob_refs: Vec<&[u8]> = subtests.iter().map(|(_, b)| b.as_slice()).collect();
        if let Err(e) = std::fs::write(&out_path, encode_rlp_bundle(&blob_refs)) {
            eprintln!("write error {}: {}", out_path.display(), e);
            failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let n = written.fetch_add(1, Ordering::Relaxed) + 1;
        if n % 500 == 0 {
            eprintln!("[{}/{}] processed", n, total);
        }
    });

    let written = written.load(Ordering::Relaxed);
    let empty = empty.load(Ordering::Relaxed);
    let failed = failed.load(Ordering::Relaxed);
    println!(
        "Done: {} JSON files, {} .rlp written, {} empty, {} failed",
        total, written, empty, failed
    );
    if failed > 0 {
        bail!("{} JSON files failed to convert", failed);
    }
    Ok(written as usize)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Emit { json, index } => {
            let json_str = std::fs::read_to_string(&json)?;
            let (_name, bytes) = eest_json_convert_subtest(&json_str, index)?;
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            out.write_all(&bytes)?;
        }
        Cmd::BulkConvert { input_dir, output_dir } => {
            let input_root = input_dir.canonicalize()?;
            bulk_convert_tree(&input_root, &output_dir)?;
        }
    }
    Ok(())
}
