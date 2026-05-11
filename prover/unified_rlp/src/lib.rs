// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Bundle format primitives for the Zilkworm zkEVM guest's v1 unified-RLP input
//! (see `docs/architecture.md` "Bundle format").
//! This is used by every converter that targets the guest: the EEST JSON converter,
//! the Mainnet RPC-fetcher path, and the witness-based `StatelessInput` adapter.

use std::collections::{BTreeMap, HashSet};

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;

pub const VERSION_V1: u8 = 0x01;
pub const RLP_FALSE: u8 = 0x80;
pub const RLP_TRUE: u8 = 0x01;
pub const MAINNET_FORK_NAME: &str = "Mainnet";

/// Account record used as normalized input for `encode_pre_state_rlp`; each converter
/// walks its own source representation (EEST JSON / Mainnet `EthereumState` / witness
/// MPT) and produces a `Vec<FlatAccount>` before calling the encoder.
#[derive(Clone, Debug)]
pub struct FlatAccount {
    pub address: Address,
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub storage_root: B256,
    pub code: Bytes,
    pub storage: BTreeMap<U256, U256>,
}

/// Concatenates pre-encoded items into an outer RLP list. Items are appended verbatim.
/// If they are already RLP-encoded, they appear as separate elements in the resulting list;
/// if they are raw bytes, they appear as the list's flat payload.
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

/// Encodes the v1 `pre_state_rlp` section: `[accounts_list, storage_list, codes_list]`.
/// `accounts` is consumed in the order given; callers that need a deterministic
/// byte sequence should sort by `keccak256(address)` first.
pub fn encode_pre_state_rlp(accounts: &[FlatAccount]) -> Vec<u8> {
    // accounts section
    let mut account_entries: Vec<Vec<u8>> = Vec::with_capacity(accounts.len());
    for a in accounts {
        let addr_rlp = alloy_rlp::encode(&a.address);
        let nonce_rlp = alloy_rlp::encode(&a.nonce);
        let balance_rlp = alloy_rlp::encode(&a.balance);
        let code_hash_rlp = alloy_rlp::encode(&a.code_hash);
        let storage_root_rlp = alloy_rlp::encode(&a.storage_root);
        account_entries.push(encode_rlp_list(&[
            &addr_rlp,
            &nonce_rlp,
            &balance_rlp,
            &code_hash_rlp,
            &storage_root_rlp,
        ]));
    }
    let acct_refs: Vec<&[u8]> = account_entries.iter().map(|v| v.as_slice()).collect();
    let accounts_rlp = encode_rlp_list(&acct_refs);

    // storage section: list of [addr, [k, v, k, v, ...]]
    let mut storage_entries: Vec<Vec<u8>> = Vec::new();
    for a in accounts {
        if a.storage.is_empty() {
            continue;
        }
        let mut kvs: Vec<u8> = Vec::new();
        let mut sorted: Vec<(U256, U256)> = a.storage.iter().map(|(k, v)| (*k, *v)).collect();
        sorted.sort_by_key(|(k, _)| keccak256(k.to_be_bytes::<32>().as_slice()));
        for (k, v) in &sorted {
            k.encode(&mut kvs);
            v.encode(&mut kvs);
        }
        let kvs_list = encode_rlp_list(&[&kvs]);
        let addr_rlp = alloy_rlp::encode(&a.address);
        storage_entries.push(encode_rlp_list(&[&addr_rlp, &kvs_list]));
    }
    let stor_refs: Vec<&[u8]> = storage_entries.iter().map(|v| v.as_slice()).collect();
    let storage_rlp = encode_rlp_list(&stor_refs);

    // codes section: flat sequence of [code_hash, code] pairs wrapped in a list.
    let mut codes_flat: Vec<u8> = Vec::new();
    let mut seen: HashSet<B256> = HashSet::new();
    for a in accounts {
        if a.code_hash == KECCAK_EMPTY {
            continue;
        }
        if !seen.insert(a.code_hash) {
            continue;
        }
        a.code_hash.encode(&mut codes_flat);
        a.code.as_ref().encode(&mut codes_flat);
    }
    let codes_rlp = encode_rlp_list(&[&codes_flat]);

    encode_rlp_list(&[&accounts_rlp, &storage_rlp, &codes_rlp])
}

/// Encodes the v1 `pre_trie_rlp` section: outer list of alternating
/// `RLP(hash) RLP(node)` items, one pair per witness node.
pub fn encode_pre_trie_rlp<T: AsRef<[u8]>>(nodes: &[T]) -> Vec<u8> {
    let mut flat: Vec<u8> = Vec::new();
    for node in nodes {
        let h = keccak256(node.as_ref());
        h.encode(&mut flat);
        node.as_ref().encode(&mut flat);
    }
    encode_rlp_list(&[flat.as_slice()])
}

/// Same shape as [`encode_pre_trie_rlp`] but takes precomputed `(hash, node)` pairs
/// for callers that already have hashes.
pub fn encode_pre_trie_rlp_pairs<T: AsRef<[u8]>>(pairs: &[(B256, T)]) -> Vec<u8> {
    let mut flat: Vec<u8> = Vec::new();
    for (h, node) in pairs {
        h.encode(&mut flat);
        node.as_ref().encode(&mut flat);
    }
    encode_rlp_list(&[flat.as_slice()])
}

/// Hash of the empty Keccak-256 input. Inlined here to avoid adding alloy-trie as a dependency.
const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);
