// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Byte-equality check: drive the pure-Rust MFBD encoder and the C++
//! `json_witness_to_flat_bundle` binary on the same input and assert their
//! output matches. Proves the determinism both sides buy (C++ `std::map` +
//! `std::stable_sort`, matching Rust `BTreeMap` + input-order).
//!
//! Two input modes:
//!   mfbd_parity_check <dir|fixture.json> [--cpp-bin <path>]
//!       ERE BenchmarkFixture(s) ({stateless_input, success}); a directory is
//!       swept, a single file is checked. Block RLP + fork are derived from the
//!       fixture.
//!   mfbd_parity_check --block-rlp <hex|@path> --witness <exec.json>
//!                     [--fork <Mainnet|Osaka|...>] [--expect-invalid] [--cpp-bin <path>]
//!       One ad-hoc input: raw block RLP + an alloy ExecutionWitness JSON
//!       (RPC envelope {"result":{...}} or bare).
//!
//! Exits 0 on byte-equal (all fixtures), 1 otherwise.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use alloy_consensus::BlockHeader;
use alloy_genesis::ChainConfig;
use alloy_primitives::{hex, Bytes};
use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use stateless::StatelessInput;
use z6m_stateless_validator::build_mfbd_from_parts;

const DEFAULT_CPP_BIN: &str = "../../build/zilk_core/dev/cli/json_witness_to_flat_bundle";

/// Everything the two encoders need for one comparison.
struct Parts {
    block_rlp: Vec<u8>,
    state: Vec<Bytes>,
    codes: Vec<Bytes>,
    keys: Vec<Bytes>,
    headers: Vec<Bytes>,
    fork: String,
    expect_invalid: bool,
}

// ---------- ERE BenchmarkFixture mode ----------

#[derive(Deserialize)]
struct Fixture {
    stateless_input: StatelessInput,
    success: bool,
}

// Mirror of the private lib.rs adapter fork mapping.
fn fork_base(cfg: &ChainConfig, timestamp: u64) -> String {
    if cfg.osaka_time.is_some_and(|t| timestamp >= t) {
        "Osaka".into()
    } else if cfg.prague_time.is_some_and(|t| timestamp >= t) {
        "Prague".into()
    } else if cfg.cancun_time.is_some_and(|t| timestamp >= t) {
        "Cancun".into()
    } else if cfg.shanghai_time.is_some_and(|t| timestamp >= t) {
        "Shanghai".into()
    } else {
        "Mainnet".into()
    }
}

fn parts_from_fixture(path: &Path) -> Result<Parts> {
    let fx: Fixture = serde_json::from_str(&fs::read_to_string(path)?)
        .with_context(|| format!("parsing fixture {}", path.display()))?;
    let si = fx.stateless_input;
    Ok(Parts {
        block_rlp: alloy_rlp::encode(&si.block),
        fork: fork_base(&si.chain_config, si.block.header.timestamp()),
        state: si.witness.state,
        codes: si.witness.codes,
        keys: si.witness.keys,
        headers: si.witness.headers,
        expect_invalid: !fx.success,
    })
}

// ---------- ad-hoc RPC-witness mode ----------

#[derive(Deserialize)]
struct WitnessRpc {
    result: Witness,
}

#[derive(Deserialize)]
struct Witness {
    state: Vec<String>,
    codes: Vec<String>,
    keys: Vec<String>,
    headers: Vec<String>,
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|e| anyhow!("hex decode: {}", e))
}

fn parts_from_adhoc(
    block_rlp_arg: &str,
    witness_path: &Path,
    fork: String,
    expect_invalid: bool,
) -> Result<Parts> {
    let block_rlp = if let Some(p) = block_rlp_arg.strip_prefix('@') {
        parse_hex(fs::read_to_string(p)?.trim().trim_matches('"'))?
    } else {
        parse_hex(block_rlp_arg)?
    };
    let raw = fs::read_to_string(witness_path)
        .with_context(|| format!("reading {}", witness_path.display()))?;
    let w: Witness = serde_json::from_str::<WitnessRpc>(&raw)
        .map(|e| e.result)
        .or_else(|_| serde_json::from_str::<Witness>(&raw))?;
    let to_bytes = |v: &[String]| -> Result<Vec<Bytes>> {
        v.iter().map(|s| Ok(Bytes::from(parse_hex(s)?))).collect()
    };
    Ok(Parts {
        block_rlp,
        state: to_bytes(&w.state)?,
        codes: to_bytes(&w.codes)?,
        keys: to_bytes(&w.keys)?,
        headers: to_bytes(&w.headers)?,
        fork,
        expect_invalid,
    })
}

// ---------- comparison ----------

fn cpp_bundle(cpp_bin: &Path, p: &Parts) -> Result<Vec<u8>> {
    let to_hex = |v: &[u8]| format!("0x{}", hex::encode(v));
    let payload = serde_json::json!({
        "block":          to_hex(&p.block_rlp),
        "headers":        p.headers.iter().map(|b| to_hex(b)).collect::<Vec<_>>(),
        "state":          p.state.iter().map(|b| to_hex(b)).collect::<Vec<_>>(),
        "codes":          p.codes.iter().map(|b| to_hex(b)).collect::<Vec<_>>(),
        "keys":           p.keys.iter().map(|b| to_hex(b)).collect::<Vec<_>>(),
        "fork":           p.fork,
        "expect_invalid": p.expect_invalid,
    });
    let mut child = Command::new(cpp_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", cpp_bin.display()))?;
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(&payload)?)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("C++ binary exited with {:?}", out.status);
    }
    Ok(out.stdout)
}

fn first_divergence(a: &[u8], b: &[u8]) -> String {
    match a.iter().zip(b).position(|(x, y)| x != y) {
        Some(i) => format!("first divergence at offset {i}"),
        None => format!("sizes differ: rust={} cpp={}", a.len(), b.len()),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cpp_bin = {
        let default = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_CPP_BIN);
        args.iter()
            .position(|a| a == "--cpp-bin")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or(default)
    };

    // Mode select: a leading non-flag arg is a fixture path (dir or file).
    let fixtures: Vec<(String, Parts)> = match args.first() {
        Some(a) if !a.starts_with("--") => {
            let path = PathBuf::from(a);
            let files: Vec<PathBuf> = if path.is_dir() {
                let mut v: Vec<PathBuf> = fs::read_dir(&path)?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect();
                v.sort();
                v
            } else {
                vec![path]
            };
            files
                .iter()
                .map(|f| {
                    Ok((f.file_name().unwrap().to_string_lossy().into_owned(), parts_from_fixture(f)?))
                })
                .collect::<Result<_>>()?
        }
        _ => {
            let get = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1));
            let block_rlp = get("--block-rlp").ok_or_else(|| anyhow!("--block-rlp required"))?;
            let witness = get("--witness").ok_or_else(|| anyhow!("--witness required"))?;
            let fork = get("--fork").cloned().unwrap_or_else(|| "Mainnet".into());
            let expect_invalid = args.iter().any(|a| a == "--expect-invalid");
            vec![("input".into(), parts_from_adhoc(block_rlp, Path::new(witness), fork, expect_invalid)?)]
        }
    };

    let total = fixtures.len();
    let mut ok = 0usize;
    let mut fails: Vec<String> = Vec::new();

    for (i, (label, p)) in fixtures.iter().enumerate() {
        let res = (|| -> Result<bool> {
            let rust = build_mfbd_from_parts(&p.block_rlp, &p.state, &p.codes, &p.keys, &p.headers, &p.fork, p.expect_invalid)?;
            let cpp = cpp_bundle(&cpp_bin, p)?;
            if total == 1 {
                println!("Rust: {} bytes  C++: {} bytes", rust.len(), cpp.len());
                if rust != cpp {
                    println!("byte-equal: NO — {}", first_divergence(&rust, &cpp));
                }
            }
            Ok(rust == cpp)
        })();
        match res {
            Ok(true) => ok += 1,
            Ok(false) => fails.push(format!("MISMATCH {label}")),
            Err(e) => fails.push(format!("ERROR    {label}: {e}")),
        }
        if total > 1 && ((i + 1) % 100 == 0 || i + 1 == total) {
            println!("  [{}/{}] byte-equal={ok} failed={}", i + 1, total, fails.len());
        }
    }

    println!("\n=== parity: {ok}/{total} byte-equal, {} failed ===", fails.len());
    for f in fails.iter().take(20) {
        println!("  {f}");
    }
    if fails.is_empty() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
