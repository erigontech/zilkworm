// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Host-side adapter that converts an Ethereum stateless-validation input into
//! the Zilkworm MFBD (Multiple Flat Bundles) envelope consumed by
//! the post-#90 zkEVM guest. The encoder is a pure-Rust port of the C++
//! `json_witness_to_flat_bundle` flow; see [`mfbd`] for the section layout.

#[cfg(feature = "download")]
pub mod download;
mod mfbd;

pub use mfbd::{build_mfbd_from_parts, stateless_input_to_mfbd};

use alloy_consensus::BlockHeader;
use alloy_genesis::ChainConfig;
use anyhow::Result;
use stateless::StatelessInput;

const MAINNET_FORK_NAME: &str = "Mainnet";

#[derive(Clone, Debug)]
pub struct StatelessValidatorZilkwormInput {
    /// MFBD-wrapped FlatBundle bytes, ready to feed the guest as-is via SP1Stdin.
    pub flat_bundle: Vec<u8>,
}

impl StatelessValidatorZilkwormInput {
    pub fn new(stateless_input: &StatelessInput, valid_block: bool) -> Result<Self> {
        let fork = fork_base_from_chain_config(
            &stateless_input.chain_config,
            stateless_input.block.header.timestamp(),
        );
        let flat_bundle = mfbd::stateless_input_to_mfbd(stateless_input, valid_block, &fork)?;
        Ok(Self { flat_bundle })
    }
}

/// Map alloy's `ChainConfig` + block timestamp to the network config name expected by Zilkworm.
fn fork_base_from_chain_config(cfg: &ChainConfig, timestamp: u64) -> String {
    if cfg.osaka_time.is_some_and(|t| timestamp >= t) {
        "Osaka".to_string()
    } else if cfg.prague_time.is_some_and(|t| timestamp >= t) {
        "Prague".to_string()
    } else if cfg.cancun_time.is_some_and(|t| timestamp >= t) {
        "Cancun".to_string()
    } else if cfg.shanghai_time.is_some_and(|t| timestamp >= t) {
        "Shanghai".to_string()
    } else {
        MAINNET_FORK_NAME.to_string()
    }
}
