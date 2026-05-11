// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Derive the SP1 verifying key from a guest ELF and write it as a bincode-encoded blob.
//! Usage: derive_vk <input.elf> <output.vk>

use std::env;
use std::fs::{self, File};
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use sp1_sdk::{Prover, ProverClient, ProvingKey};

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
    let elf = fs::read(&elf_path).with_context(|| format!("failed to read {}", elf_path.display()))?;
    let prover = ProverClient::from_env().await;
    let pk = prover
        .setup(elf.into())
        .await
        .map_err(|e| anyhow!("sp1 setup failed: {e}"))?;
    let vk = pk.verifying_key().clone();
    if let Some(parent) = vk_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let f = File::create(&vk_path)?;
    let mut w = BufWriter::new(f);
    bincode::serde::encode_into_std_write(&vk, &mut w, bincode::config::standard())
        .context("bincode-encode SP1VerifyingKey")?;
    Ok(())
}
