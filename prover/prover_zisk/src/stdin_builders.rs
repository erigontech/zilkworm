// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use eyre::Result;
use std::fs;
use std::path::Path;
use zisk_sdk::ZiskStdin;

// Mirrors zilk_core/core/types_zz/input_envelope.hpp.
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45; // "EJSN"
const INPUT_VERSION_EJSN: u32 = 1;

pub fn envelope_from_eth_tests(path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)?;
    let value: serde_json::Value = serde_json::from_str(&raw)?;
    let minified = serde_json::to_string(&value)?;
    let json_bytes = minified.as_bytes();

    let mut envelope = Vec::with_capacity(8 + json_bytes.len());
    envelope.extend_from_slice(&INPUT_MAGIC_EJSN.to_le_bytes());
    envelope.extend_from_slice(&INPUT_VERSION_EJSN.to_le_bytes());
    envelope.extend_from_slice(json_bytes);
    Ok(envelope)
}

/// The converter already wrote the envelope.
pub fn envelope_from_mfbd(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

pub fn read_envelope(path: &Path, is_test: bool) -> Result<Vec<u8>> {
    if is_test {
        envelope_from_eth_tests(path)
    } else {
        envelope_from_mfbd(path)
    }
}

pub fn build_stdin(envelope: &[u8]) -> ZiskStdin {
    ZiskStdin::from_bytes(envelope.to_vec())
}

pub fn build_stdin_from_eth_tests(path: &Path) -> Result<ZiskStdin> {
    Ok(build_stdin(&envelope_from_eth_tests(path)?))
}

pub fn build_stdin_from_mfbd(path: &Path) -> Result<ZiskStdin> {
    Ok(build_stdin(&envelope_from_mfbd(path)?))
}
