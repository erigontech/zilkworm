// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use sp1_sdk::SP1Stdin;
use std::fs;
use std::path::Path;

// Must match types_zz/input_envelope.hpp.
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45;
const INPUT_VERSION_EJSN: u32 = 1;

/// EJSN-wrapped EEST blockchain_test JSON; the guest reads it with a single `read_vec()`.
pub fn build_stdin_from_eth_tests(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let minified = serde_json::to_string(&value)?;
    let json_bytes = minified.as_bytes();

    let mut envelope = Vec::with_capacity(8 + json_bytes.len());
    envelope.extend_from_slice(&INPUT_MAGIC_EJSN.to_le_bytes());
    envelope.extend_from_slice(&INPUT_VERSION_EJSN.to_le_bytes());
    envelope.extend_from_slice(json_bytes);
    stdin.write_vec(envelope);
    Ok(stdin)
}

/// MFBD-wrapped FlatBundle read raw from disk as a single Vec.
pub fn build_stdin_from_mfbd(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read(path)?;
    stdin.write_vec(raw);
    Ok(stdin)
}
