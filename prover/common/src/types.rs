// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use alloy_eips::eip4895::Withdrawals;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockchainTestCase {
    pub genesis_block_header: TestHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_rlp: Option<Bytes>,
    pub blocks: Vec<TestBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_state: Option<BTreeMap<Address, EthTestAccount>>,
    pub pre: BTreeMap<Address, EthTestAccount>,
    pub lastblockhash: B256,
    pub network: String,
    pub seal_engine: SealEngine,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestBlock {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_header: Option<TestHeader>,
    pub rlp: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expect_exception: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<EthTestTransaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncle_headers: Option<Vec<TestHeader>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_sequence: Option<Vec<TransactionSequence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Withdrawals>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestHeader {
    pub bloom: Bloom,
    pub coinbase: Address,
    pub difficulty: U256,
    pub extra_data: Bytes,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub hash: B256,
    pub mix_hash: B256,
    pub nonce: B64,
    pub number: U256,
    pub parent_hash: B256,
    pub receipt_trie: B256,
    pub state_root: B256,
    pub timestamp: U256,
    pub transactions_trie: B256,
    pub uncle_hash: B256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_beacon_block_root: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requests_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_blobs_per_block: Option<U256>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTestAccount {
    pub balance: U256,
    pub code: Bytes,
    pub nonce: U256,
    pub storage: BTreeMap<U256, U256>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTestTransaction {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U256>,
    pub data: Bytes,
    pub gas_limit: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    pub nonce: U256,
    pub r: U256,
    pub s: U256,
    pub v: U256,
    pub value: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<EthTestAccessListItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_blob_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_versioned_hashes: Option<Vec<B256>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_list: Option<Vec<EthTestAuthorization>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<B256>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTestAccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTestAuthorization {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: U256,
    pub y_parity: U256,
    pub r: U256,
    pub s: U256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSequence {
    pub exception: String,
    pub raw_bytes: Bytes,
    pub valid: String,
}

#[derive(Debug, Serialize)]
pub enum SealEngine {
    #[serde(rename = "NoProof")]
    NoProof,
}
