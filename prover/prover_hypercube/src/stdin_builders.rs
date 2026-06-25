// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use sp1_sdk::SP1Stdin;
use std::fs;
use std::path::Path;

// Mirrors zilk_core/core/types_zz/input_envelope.hpp.
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45; // "EJSN"
const INPUT_VERSION_EJSN: u32 = 1;

/// Build an SP1Stdin carrying an EJSN-wrapped EEST blockchain_test JSON.
/// The guest does ONE `read_vec()` and feeds the bytes to StateTransition,
/// which dispatches on the leading 4-byte magic.
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

/// Build an SP1Stdin carrying an MFBD-wrapped FlatBundle. The on-disk file
/// is already MFBD-wrapped post-converter — we just slurp it raw and write
/// a single Vec into SP1Stdin.
pub fn build_stdin_from_unified_rlp(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read(path)?;
    stdin.write_vec(raw);
    Ok(stdin)
}
