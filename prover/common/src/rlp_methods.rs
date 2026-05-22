//! RLP helpers shared across the prover + converter. The lightweight items
//! are feature-gate-free so the standalone `eest-convert` binary can use them
//! without pulling unneeded deps. The heavier RPC/state helpers below are
//! gated on `network`.

/// Unified-RLP v1 version byte. See `docs/architecture.md` "Per-subtest unified RLP".
pub const VERSION_V1: u8 = 0x01;

/// RLP encoding of `false` (the empty string).
pub const RLP_FALSE: u8 = 0x80;

/// RLP encoding of `true` (single-byte `0x01`).
pub const RLP_TRUE: u8 = 0x01;

/// Canonical Mainnet fork name used in v1 unified-RLP payloads.
pub const MAINNET_FORK_NAME: &str = "Mainnet";

/// Concatenates pre-encoded RLP items into an outer RLP list.
pub fn encode_rlp_list<T: AsRef<[u8]>>(items: &[T]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|i| i.as_ref().len()).sum();
    let mut out = Vec::with_capacity(payload_len + 9);
    if payload_len < 56 {
        out.push(0xc0 + payload_len as u8);
    } else {
        let len_bytes = payload_len.to_be_bytes();
        let len_bytes = &len_bytes[len_bytes.iter().position(|&b| b != 0).unwrap_or(7)..];
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(len_bytes);
    }
    for item in items {
        out.extend_from_slice(item.as_ref());
    }
    out
}

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
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
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

/// Build pre-state as RLP with structure:
/// [[{address, account}], [{address, storage}], [{codeHash, code}]]
#[cfg(feature = "network")]
pub fn build_pre_state_rlp(
    state: &EthereumState,
    code_map: &HashMap<B256, Bytes>,
    preimage_map: &HashMap<B256, Bytes>,
) -> Result<Bytes> {
    let mut accounts_list = Vec::new();
    let mut storage_list = Vec::new();
    let mut codes_list = Vec::new();

    // Track which code hashes we've already added
    let mut added_codes = std::collections::HashSet::new();

    state.state_trie.for_each_leaves(|key, value| {
        let hashed_address = B256::from_slice(key);
        if let Some(address_bytes) = preimage_map.get(&hashed_address) {
            if address_bytes.len() != Address::len_bytes() {
                return;
            }
            let address = Address::from_slice(address_bytes.as_ref());
            let mut bytes = value;

            if let Ok(account) = TrieAccount::decode(&mut bytes) {
                let addr_rlp = alloy_rlp::encode(&address);
                let nonce_rlp = alloy_rlp::encode(&account.nonce);
                let balance_rlp = alloy_rlp::encode(&account.balance);
                let code_hash_rlp = alloy_rlp::encode(&account.code_hash);
                let storage_root_rlp = alloy_rlp::encode(&account.storage_root);

                accounts_list.push(encode_rlp_list(&[
                    &addr_rlp,
                    &nonce_rlp,
                    &balance_rlp,
                    &code_hash_rlp,
                    &storage_root_rlp,
                ]));

                // Add code to codes list if not empty and not yet added
                if account.code_hash != KECCAK_EMPTY && !added_codes.contains(&account.code_hash) {
                    if let Some(code) = code_map.get(&account.code_hash) {
                        let mut code_entry = Vec::new();
                        account.code_hash.encode(&mut code_entry);
                        code.encode(&mut code_entry);
                        codes_list.push(code_entry);
                        added_codes.insert(account.code_hash);
                    }
                }

                // Process storage for this account
                if let Some(storage_trie) = state.storage_tries.get(&hashed_address) {
                    let mut storage_entries = Vec::new();

                    storage_trie.for_each_leaves(|slot_key, slot_value| {
                        let hashed_slot = B256::from_slice(slot_key);
                        if let Some(slot_preimage) = preimage_map.get(&hashed_slot) {
                            if slot_preimage.len() == 32 {
                                let slot = U256::from_be_slice(slot_preimage.as_ref());
                                let mut slot_bytes = slot_value;
                                if let Ok(value) = U256::decode(&mut slot_bytes) {
                                    if !value.is_zero() {
                                        let mut kv = Vec::new();
                                        slot.encode(&mut kv);
                                        value.encode(&mut kv);
                                        storage_entries.push(kv);
                                    }
                                }
                            }
                        }
                    });

                    if !storage_entries.is_empty() {
                        // Encode storage entry: [address, [[key, value], ...]]
                        let addr_rlp = alloy_rlp::encode(address);
                        let storage_entries_ref: Vec<&Vec<u8>> = storage_entries.iter().collect();
                        let storage_entries_rlp = encode_rlp_list(&storage_entries_ref);
                        let storage_rlp = encode_rlp_list(&[&addr_rlp, &storage_entries_rlp]);
                        storage_list.push(storage_rlp);
                    }
                }
            }
        }
    });

    // Encode the mega list: [accounts, storage, codes]
    let accounts_refs: Vec<&Vec<u8>> = accounts_list.iter().collect();
    let accounts_rlp = encode_rlp_list(&accounts_refs);

    let storage_refs: Vec<&Vec<u8>> = storage_list.iter().collect();
    let storage_rlp = encode_rlp_list(&storage_refs);

    let code_refs: Vec<&Vec<u8>> = codes_list.iter().collect();
    let codes_rlp = encode_rlp_list(&code_refs);

    let output = encode_rlp_list(&[&accounts_rlp, &storage_rlp, &codes_rlp]);

    Ok(Bytes::from(output))
}

#[cfg(feature = "network")]
pub fn build_pre_trie_rlp(witness_state: &Vec<Bytes>) -> Result<Bytes> {
    let mut mpt_node_list = Vec::new();

    witness_state.iter().for_each(|encoded_node| {
        let mut node_entry = Vec::new();
        let node_hash = keccak256(encoded_node);
        node_hash.encode(&mut node_entry);
        encoded_node.encode(&mut node_entry);
        mpt_node_list.push(node_entry);
    });
    let node_refs: Vec<&Vec<u8>> = mpt_node_list.iter().collect();
    let nodes_rlp_list = encode_rlp_list(&node_refs);
    Ok(Bytes::from(nodes_rlp_list))
}
