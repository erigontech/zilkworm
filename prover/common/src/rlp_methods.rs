// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/// RLP helpers for the network/RPC path. Bundle format primitives live in `z6m_unified_rlp` crate
/// and are re-exported here for backward compatibility with existing call sites.

pub use z6m_unified_rlp::{
    encode_pre_state_rlp, encode_pre_trie_rlp, encode_rlp_list, FlatAccount, MAINNET_FORK_NAME,
    RLP_FALSE, RLP_TRUE, VERSION_V1,
};

/// Encodes a sequence of RLP blobs into the bundle wire format (see `docs/architecture.md` "Bundle format").
pub fn encode_rlp_bundle(items: &[&[u8]]) -> Vec<u8> {
    let payload_len = 4 + items.iter().map(|b| 4 + b.len()).sum::<usize>();
    let mut out = Vec::with_capacity(payload_len);
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(item);
    }
    out
}

#[cfg(feature = "network")]
use std::collections::HashMap;

#[cfg(feature = "network")]
use alloy_consensus::{Block, BlockHeader, Header, TxEnvelope};
#[cfg(feature = "network")]
use alloy_eips::eip4895::Withdrawals;
#[cfg(feature = "network")]
use alloy_primitives::{Address, Bytes, B256, U256};
#[cfg(feature = "network")]
use alloy_rlp::{Decodable, Encodable};
#[cfg(feature = "network")]
use alloy_rpc_types::Block as RpcBlock;
#[cfg(feature = "network")]
use alloy_trie::{TrieAccount, KECCAK_EMPTY};
#[cfg(feature = "network")]
use eyre::Result;
#[cfg(feature = "network")]
use rsp_mpt::EthereumState;

/// Convert RPC block to RLP bytes with header only (empty transactions, uncles, withdrawals)
#[cfg(feature = "network")]
pub fn block_to_header_only_rlp(rpc_block: &RpcBlock) -> Result<Bytes> {
    let header = Header {
        parent_hash: rpc_block.header.parent_hash,
        ommers_hash: rpc_block.header.ommers_hash,
        beneficiary: rpc_block.header.beneficiary,
        state_root: rpc_block.header.state_root,
        transactions_root: rpc_block.header.transactions_root,
        receipts_root: rpc_block.header.receipts_root,
        logs_bloom: rpc_block.header.logs_bloom,
        difficulty: rpc_block.header.difficulty,
        number: rpc_block.header.number,
        gas_limit: rpc_block.header.gas_limit,
        gas_used: rpc_block.header.gas_used,
        timestamp: rpc_block.header.timestamp,
        extra_data: rpc_block.header.extra_data.clone(),
        mix_hash: rpc_block.header.mix_hash().unwrap_or_default(),
        nonce: rpc_block.header.nonce,
        base_fee_per_gas: rpc_block.header.base_fee_per_gas,
        withdrawals_root: rpc_block.header.withdrawals_root,
        blob_gas_used: rpc_block.header.blob_gas_used,
        excess_blob_gas: rpc_block.header.excess_blob_gas,
        parent_beacon_block_root: rpc_block.header.parent_beacon_block_root,
        requests_hash: rpc_block.header.requests_hash,
    };

    let block = Block {
        header,
        body: alloy_consensus::BlockBody {
            transactions: Vec::<TxEnvelope>::new(),
            ommers: Vec::<Header>::new(),
            withdrawals: Some(Withdrawals::new(Vec::new())),
        },
    };

    let mut buf = Vec::new();
    block.encode(&mut buf);
    Ok(Bytes::from(buf))
}

/// Walks trie in `state` and encodes the v1 `pre_state` RLP section.
#[cfg(feature = "network")]
pub fn build_pre_state_rlp(
    state: &EthereumState,
    code_map: &HashMap<B256, Bytes>,
    preimage_map: &HashMap<B256, Bytes>,
) -> Result<Bytes> {
    let mut accounts: Vec<FlatAccount> = Vec::new();

    state.state_trie.for_each_leaves(|key, value| {
        let hashed_address = B256::from_slice(key);
        let Some(address_bytes) = preimage_map.get(&hashed_address) else { return };
        if address_bytes.len() != Address::len_bytes() {
            return;
        }
        let address = Address::from_slice(address_bytes.as_ref());

        let mut bytes = value;
        let Ok(account) = TrieAccount::decode(&mut bytes) else { return };

        let code = if account.code_hash != KECCAK_EMPTY {
            code_map.get(&account.code_hash).cloned().unwrap_or_default()
        } else {
            Bytes::new()
        };

        // Walk the storage trie and convert each slot back to its preimage.
        let mut storage = std::collections::BTreeMap::new();
        if let Some(storage_trie) = state.storage_tries.get(&hashed_address) {
            storage_trie.for_each_leaves(|slot_key, slot_value| {
                let hashed_slot = B256::from_slice(slot_key);
                let Some(slot_preimage) = preimage_map.get(&hashed_slot) else { return };
                if slot_preimage.len() != 32 {
                    return;
                }
                let slot = U256::from_be_slice(slot_preimage.as_ref());
                let mut slot_bytes = slot_value;
                if let Ok(v) = U256::decode(&mut slot_bytes) {
                    if !v.is_zero() {
                        storage.insert(slot, v);
                    }
                }
            });
        }

        accounts.push(FlatAccount {
            address,
            nonce: account.nonce,
            balance: account.balance,
            code_hash: account.code_hash,
            storage_root: account.storage_root,
            code,
            storage,
        });
    });

    Ok(Bytes::from(encode_pre_state_rlp(&accounts)))
}

#[cfg(feature = "network")]
pub fn build_pre_trie_rlp(witness_state: &[Bytes]) -> Result<Bytes> {
    Ok(Bytes::from(encode_pre_trie_rlp(witness_state)))
}
