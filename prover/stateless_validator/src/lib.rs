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

use alloy_consensus::{BlockHeader, Header};
use alloy_genesis::ChainConfig;
use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use anyhow::{bail, Context, Result};
use libssz::SszEncode;
use stateless::StatelessInput;
use stateless_validator_common::guest::input::{
    new_payload_request::NewPayloadRequest, ProtocolFork,
};

const MAINNET_FORK_NAME: &str = "Mainnet";

#[derive(Clone, Debug)]
pub struct StatelessValidatorZilkwormInput {
    /// MFBD-wrapped FlatBundle bytes, ready to feed the guest as-is via SP1Stdin.
    pub flat_bundle: Vec<u8>,
    /// Expected guest public values layout (see docs/architecture.md for details).
    pub public_values: Vec<u8>,
}

impl StatelessValidatorZilkwormInput {
    pub fn new(stateless_input: &StatelessInput, valid_block: bool) -> Result<Self> {
        let fork = fork_base_from_chain_config(
            &stateless_input.chain_config,
            stateless_input.block.header.timestamp(),
        );
        let flat_bundle = mfbd::stateless_input_to_mfbd(stateless_input, valid_block, &fork)?;
        Ok(Self { flat_bundle, public_values: Vec::new() })
    }

    /// EEST canonical statelessInputBytes constructor: decode, extract the witness / block pieces / BAL,
    /// derive `keys` from BAL, and MFBD-encode. Amsterdam-only. `valid_block` is the fixture's
    /// validity expectation (`statelessOutputBytes.successful_validation` / no `expectException`);
    /// it is not carried by statelessInputBytes itself.
    pub fn from_ere_eest(input_bytes: &[u8], valid_block: bool) -> Result<Self> {
        let (fork_id, si) = ere_eest::decode_stateless_input(input_bytes)
            .context("decode EEST statelessInputBytes")?;
        if fork_id != ProtocolFork::Amsterdam {
            bail!("statelessInputBytes fork {fork_id:?} unsupported (Amsterdam-only)");
        }
        // Network label carried in the MFBD; the guest maps it to a hardcoded chain config
        // (chain_id + blob schedule + fork activation) via its kNetworkConfig, so only
        // networks known on both sides are accepted. Selected by the input's chain id.
        let fork = match si.chain_id {
            1 => "Amsterdam", // generated EEST corpus (tests-zkevm-benchmark), Amsterdam from genesis
            0x1a62c8cb6 => "glamsterdam-devnet-7",
            0x1a6a8cc6e => "glamsterdam-devnet-8",
            id => bail!("unknown chain id {id:#x}: no guest-side network config"),
        };

        // Witness pieces: statelessInputBytes's List<List<u8>> becomes Vec<Bytes>.
        let witness_state: Vec<Bytes> =
            si.witness.state.iter().map(|n| Bytes::copy_from_slice(n)).collect();
        let witness_codes: Vec<Bytes> =
            si.witness.codes.iter().map(|c| Bytes::copy_from_slice(c)).collect();
        let witness_headers: Vec<Bytes> =
            si.witness.headers.iter().map(|h| Bytes::copy_from_slice(h)).collect();

        // Block pieces from the Amsterdam (Gloas) payload variant.
        let gloas = match &si.new_payload_request {
            NewPayloadRequest::Gloas(g) => g,
            _ => bail!("statelessInputBytes new_payload_request is not the Amsterdam (Gloas) variant"),
        };
        let payload = &gloas.execution_payload;

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

        // `base_fee_per_gas` is an SSZ uint256 (little-endian); the block-RLP
        // encoder wants big-endian. The other 32-byte payload fields are hashes
        // and thus endianness-neutral.
        let mut base_fee_be = payload.base_fee_per_gas;
        base_fee_be.reverse();

        let execution_requests = collect_execution_requests(&gloas.execution_requests)?;

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
            base_fee_per_gas: base_fee_be,
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            slot_number: payload.slot_number,
            parent_beacon_block_root: gloas.parent_beacon_block_root,
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
            /* expect_invalid */ !valid_block,
        )?;

        // Expected guest PV (#133 layout). pre_state_root is the parent header's
        // state root (witness lists headers ascending, so parent is last);
        // post_state_root / block_hash / gas_used are the payload's claimed
        // values the guest recomputes and commits.
        let pre_state_root: [u8; 32] = {
            let mut slice = witness_headers
                .last()
                .context("witness.headers empty; cannot read parent state root")?
                .as_ref();
            Header::decode(&mut slice)
                .context("decode parent header for pre_state_root")?
                .state_root
                .0
        };
        let mut public_values = Vec::with_capacity(112);
        public_values.extend_from_slice(&payload.gas_used.to_le_bytes());
        public_values.extend_from_slice(&pre_state_root);
        public_values.extend_from_slice(&payload.state_root);
        public_values.extend_from_slice(&payload.block_hash);
        public_values.extend_from_slice(&si.chain_id.to_le_bytes());

        Ok(Self { flat_bundle, public_values })
    }
}

/// Materialise EIP-7685 `ExecutionRequests` into `[type_byte, data...]` blobs,
/// as expected by `alloy_eips::eip7685::Requests::requests_hash()`.
///
/// All request types are emitted in ascending type order.
fn collect_execution_requests(
    er: &stateless_validator_common::guest::input::new_payload_request::ExecutionRequestsGloas,
) -> Result<Vec<Bytes>> {
    // EIP-7685 request type IDs.
    const REQ_TYPE_DEPOSIT: u8 = 0x00;
    const REQ_TYPE_WITHDRAWAL: u8 = 0x01;
    const REQ_TYPE_CONSOLIDATION: u8 = 0x02;
    const REQ_TYPE_BUILDER_DEPOSIT: u8 = 0x03;  // EIP-8282: Builder Execution Requests
    const REQ_TYPE_BUILDER_EXIT: u8 = 0x04;     // EIP-8282: Builder Execution Requests

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
    if let Some(b) = encode_typed(&er.builder_deposits, REQ_TYPE_BUILDER_DEPOSIT) {
        requests.push(b);
    }
    if let Some(b) = encode_typed(&er.builder_exits, REQ_TYPE_BUILDER_EXIT) {
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
