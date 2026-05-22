// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use sp1_sdk::SP1Stdin;
use std::fs;
use std::path::Path;

pub fn build_stdin_from_eth_tests(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    stdin.write(&true);
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let minified = serde_json::to_string(&value)?;
    stdin.write_slice(minified.as_bytes());
    Ok(stdin)
}

pub fn build_stdin_from_unified_rlp(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    stdin.write(&false);
    let raw = fs::read(path)?;
    stdin.write_slice(&raw);
    Ok(stdin)
}
