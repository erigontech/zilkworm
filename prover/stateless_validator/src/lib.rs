// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Host-side adapter that converts an Ethereum stateless-validation input into
//! the Zilkworm MFBD (Multiple Flat Bundles) envelope consumed by
//! the post-#90 zkEVM guest. The encoder is a pure-Rust port of the C++
//! `json_witness_to_flat_bundle` flow; see [`mfbd`] for the section layout.

#[cfg(feature = "download")]
pub mod download;
pub mod ere_eest;
mod mfbd;

pub use mfbd::{
    build_mfbd_from_amsterdam_parts, build_mfbd_from_parts, stateless_input_to_mfbd,
    AmsterdamBlockParts, AmsterdamWithdrawal,
};

use alloy_consensus::BlockHeader;
use alloy_genesis::ChainConfig;
use alloy_primitives::Bytes;
use anyhow::{Context, Result};
use libssz::SszEncode;
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

    /// EEST canonical (SIOB) constructor: decode `statelessInputBytes`, extract
    /// the witness / block pieces / BAL, derive `keys` from BAL, and MFBD-encode.
    /// Amsterdam-only; assumes the block is expected to validate (`valid_block=true`).
    pub fn from_ere_eest(input_bytes: &[u8]) -> Result<Self> {
        let si = ere_eest::decode_stateless_input(input_bytes)
            .context("decode EEST statelessInputBytes")?;
        let fork = ere_eest::fork_name_from_ssz(&si.chain_config)?;

        // Witness pieces: SIOB's List<List<u8>> becomes Vec<Bytes>.
        let witness_state = ere_eest::ssz_bytes_list_to_bytes_vec(&si.witness.state);
        let witness_codes = ere_eest::ssz_bytes_list_to_bytes_vec(&si.witness.codes);
        let witness_headers = ere_eest::ssz_bytes_list_to_bytes_vec(&si.witness.headers);

        // Block pieces from the Amsterdam payload.
        let npr = &si.new_payload_request;
        let payload = &npr.execution_payload;

        let transactions: Vec<Bytes> = payload
            .transactions
            .iter()
            .map(|tx| Bytes::copy_from_slice(tx))
            .collect();

        let withdrawals: Vec<AmsterdamWithdrawal> = payload
            .withdrawals
            .iter()
            .map(|w| AmsterdamWithdrawal {
                index: w.index,
                validator_index: w.validator_index,
                address: w.address,
                amount: w.amount,
            })
            .collect();

        let extra_data: Vec<u8> = payload.extra_data.iter().copied().collect();
        let block_access_list: Vec<u8> = payload.block_access_list.iter().copied().collect();

        let execution_requests = collect_execution_requests(&npr.execution_requests)?;

        let parts = AmsterdamBlockParts {
            parent_hash: payload.parent_hash,
            beneficiary: payload.fee_recipient,
            state_root: payload.state_root,
            receipts_root: payload.receipts_root,
            logs_bloom: payload.logs_bloom,
            prev_randao: payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: &extra_data,
            base_fee_per_gas: payload.base_fee_per_gas,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            slot_number: payload.slot_number,
            parent_beacon_block_root: npr.parent_beacon_block_root,
            execution_requests: &execution_requests,
            transactions: &transactions,
            withdrawals: &withdrawals,
            block_access_list: &block_access_list,
        };

        let flat_bundle = build_mfbd_from_amsterdam_parts(
            &parts,
            &witness_state,
            &witness_codes,
            &witness_headers,
            fork,
            /* expect_invalid */ false,
        )?;
        Ok(Self { flat_bundle })
    }
}

/// Materialise EIP-7685 `ExecutionRequests` into `[type_byte, data...]` blobs,
/// as expected by `alloy_eips::eip7685::Requests::requests_hash()`.
fn collect_execution_requests(
    er: &stateless_validator_common::new_payload_request::ExecutionRequests,
) -> Result<Vec<Bytes>> {
    // EIP-7685 request type IDs.
    const REQ_TYPE_DEPOSIT: u8 = 0x00;
    const REQ_TYPE_WITHDRAWAL: u8 = 0x01;
    const REQ_TYPE_CONSOLIDATION: u8 = 0x02;

    fn encode_typed<T: SszEncode>(items: &[T], ty: u8) -> Option<Bytes> {
        if items.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        out.push(ty);
        for item in items {
            item.ssz_append(&mut out);
        }
        Some(Bytes::from(out))
    }

    let mut requests: Vec<Bytes> = Vec::new();
    // SszList<T,N> derefs to [T] so `&er.deposits` coerces to &[Deposit...].
    if let Some(b) = encode_typed(&er.deposits, REQ_TYPE_DEPOSIT) {
        requests.push(b);
    }
    if let Some(b) = encode_typed(&er.withdrawals, REQ_TYPE_WITHDRAWAL) {
        requests.push(b);
    }
    if let Some(b) = encode_typed(&er.consolidations, REQ_TYPE_CONSOLIDATION) {
        requests.push(b);
    }
    Ok(requests)
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
