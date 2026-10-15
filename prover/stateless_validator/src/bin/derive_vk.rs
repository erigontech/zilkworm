// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Derive the SP1 program verifying key for a guest ELF and write its 32-byte `bytes32_raw` digest,
//! the program VK form ere checks and ere-guests publishes.
//!
//! Usage: derive_vk <input.elf> <output.vk>

use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use sp1_sdk::{HashableKey, Prover, ProverClient, ProvingKey};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let elf_path = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("usage: derive_vk <input.elf> <output.vk>"))?,
    );
    let vk_path = PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow!("usage: derive_vk <input.elf> <output.vk>"))?,
    );

    let elf = fs::read(&elf_path)
        .with_context(|| format!("failed to read {}", elf_path.display()))?;

    let prover = ProverClient::from_env().await;
    let pk = prover
        .setup(elf.into())
        .await
        .map_err(|e| anyhow!("sp1 setup failed: {e}"))?;
    let vk = pk.verifying_key().bytes32_raw();

    if let Some(parent) = vk_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent dir for {}", vk_path.display()))?;
    }
    fs::write(&vk_path, vk).with_context(|| format!("failed to write {}", vk_path.display()))?;
    Ok(())
}
