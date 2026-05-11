// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Convert EEST JSON blockchain-test fixtures to the unified-RLP v1 bundle format.
//! See `docs/architecture.md` "Per-subtest unified RLP".
//!
//! EEST tests give us a flat pre-state (accounts with balance/nonce/code/slots),
//! so we build each account's storage trie and the global state trie to derive
//! the storage roots and to emit the MPT nodes needed by `check_root`.

use std::collections::BTreeMap;

use alloy_primitives::{hex, keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Encodable;
use alloy_trie::{
    proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY,
};
use eyre::{bail, eyre, Result};
use serde::Deserialize;

use z6m_unified_rlp::{
    encode_pre_state_rlp, encode_pre_trie_rlp_pairs, encode_rlp_list, FlatAccount, RLP_FALSE,
    RLP_TRUE, VERSION_V1,
};


#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EestTest {
    network: String,
    #[serde(rename = "genesisRLP")]
    genesis_rlp: String,
    pre: BTreeMap<String, EestPreAccount>,
    blocks: Vec<EestBlock>,
    #[serde(default)]
    post_state_hash: Option<String>,
    #[serde(default)]
    post_state: Option<BTreeMap<String, EestPreAccount>>,
}

#[derive(Deserialize, Debug)]
struct EestPreAccount {
    nonce: String,
    balance: String,
    code: String,
    #[serde(default)]
    storage: BTreeMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct EestBlock {
    rlp: String,
    #[serde(default, rename = "expectException")]
    expect_exception: Option<String>,
}


/// Parse an EEST JSON file and return one unified RLP binary per test.
/// Returns `Vec<(test_name, unified_rlp_bytes)>`.
/// Subtests kept after filtering (drops only the rare zero-block tests),
/// in the stable BTreeMap iteration order that `list` / `emit` share.
fn keep(test: &EestTest) -> bool {
    !test.blocks.is_empty()
}

pub fn eest_json_to_unified_rlp(json_str: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let outer: BTreeMap<String, EestTest> = serde_json::from_str(json_str)?;
    outer
        .into_iter()
        .filter(|(_, t)| keep(t))
        .map(|(name, test)| build_test(&test).map(|rlp| (name, rlp)))
        .collect()
}

/// Lightweight outline used by `eest_json_list_subtests` — parses only the
/// fields needed by the `keep` filter (block count), skipping pre-state /
/// block body to keep enumeration cheap.
#[derive(Deserialize, Debug)]
struct EestTestOutline {
    blocks: Vec<serde::de::IgnoredAny>,
}

/// Cheap enumeration: returns the names of subtests that would be converted,
/// in the same order `eest_json_to_unified_rlp` emits them.
pub fn eest_json_list_subtests(json_str: &str) -> Result<Vec<String>> {
    let outer: BTreeMap<String, EestTestOutline> = serde_json::from_str(json_str)?;
    Ok(outer.into_iter().filter(|(_, t)| !t.blocks.is_empty()).map(|(n, _)| n).collect())
}

/// Convert just the Nth accepted subtest. Index refers to the filtered order.
pub fn eest_json_convert_subtest(json_str: &str, index: usize) -> Result<(String, Vec<u8>)> {
    let outer: BTreeMap<String, EestTest> = serde_json::from_str(json_str)?;
    let mut n = 0usize;
    for (name, test) in outer {
        if !keep(&test) {
            continue;
        }
        if n == index {
            let rlp = build_test(&test)?;
            return Ok((name, rlp));
        }
        n += 1;
    }
    bail!("subtest index {} out of range (have {})", index, n);
}


fn build_test(test: &EestTest) -> Result<Vec<u8>> {
    let prev_rlp = decode_hex(&test.genesis_rlp)?;

    // 1) Parse pre-state into flat accounts, compute per-account storage_root.
    let mut accounts: Vec<FlatAccount> = Vec::with_capacity(test.pre.len());
    for (addr_hex, acct) in &test.pre {
        let address = parse_address(addr_hex)?;
        let nonce = parse_u64(&acct.nonce)?;
        let balance = parse_u256(&acct.balance)?;
        let code = Bytes::from(decode_hex(&acct.code)?);
        let code_hash = if code.is_empty() { KECCAK_EMPTY } else { keccak256(&code) };

        let mut storage: BTreeMap<U256, U256> = BTreeMap::new();
        for (k, v) in &acct.storage {
            let key = parse_u256(k)?;
            let value = parse_u256(v)?;
            if !value.is_zero() {
                storage.insert(key, value);
            }
        }

        let storage_root = storage_trie_root(&storage);

        accounts.push(FlatAccount {
            address,
            nonce,
            balance,
            code_hash,
            storage_root,
            code,
            storage,
        });
    }

    // Sort by hashed address for deterministic output.
    accounts.sort_by_key(|a| keccak256(a.address.as_slice()));

    // 2) Build the state trie and collect its nodes + every non-empty storage
    //    trie's nodes so `check_root` in C++ can verify the post-state root.
    let mut all_trie_nodes: Vec<(B256, Bytes)> = Vec::new();

    // State trie.
    let state_leaves: Vec<(Nibbles, Vec<u8>)> = accounts
        .iter()
        .map(|a| {
            let nibs = Nibbles::unpack(keccak256(a.address.as_slice()));
            let trie_account = TrieAccount {
                nonce: a.nonce,
                balance: a.balance,
                storage_root: a.storage_root,
                code_hash: a.code_hash,
            };
            let mut val = Vec::new();
            trie_account.encode(&mut val);
            (nibs, val)
        })
        .collect();
    all_trie_nodes.extend(hash_builder_nodes(&state_leaves));

    // Per-account storage tries.
    for a in &accounts {
        if a.storage.is_empty() {
            continue;
        }
        let mut sorted: Vec<(U256, U256)> = a.storage.iter().map(|(k, v)| (*k, *v)).collect();
        sorted.sort_by_key(|(k, _)| keccak256(k.to_be_bytes::<32>().as_slice()));
        let leaves: Vec<(Nibbles, Vec<u8>)> = sorted
            .iter()
            .map(|(k, v)| {
                let nibs = Nibbles::unpack(keccak256(k.to_be_bytes::<32>().as_slice()));
                let mut val = Vec::new();
                v.encode(&mut val);
                (nibs, val)
            })
            .collect();
        all_trie_nodes.extend(hash_builder_nodes(&leaves));
    }

    // Sort by node hash and dedup. Sorting first turns the encoded pre_trie
    // section into a canonical byte sequence — `HashBuilder::take_proof_nodes`
    // returns a `HashMap` whose iteration order is non-deterministic, and
    // without this the same JSON input can produce different RLP bytes across
    // runs (breaks content-addressed cache keys downstream).
    all_trie_nodes.sort_by_key(|(h, _)| *h);
    all_trie_nodes.dedup_by_key(|(h, _)| *h);

    // 3) Encode the pre-state RLP section.
    let pre_state_rlp = encode_pre_state_rlp(&accounts);

    // 4) Encode the pre-trie RLP section (flat sequence of (hash, node_bytes)
    //    pairs, wrapped in an outer RLP list). Hashes are precomputed.
    let pre_trie_rlp = encode_pre_trie_rlp_pairs(&all_trie_nodes);

    // 5) Historical headers: empty list for EEST tests.
    let headers_rlp: Vec<u8> = vec![0xc0];

    // Per-block `[block_rlp, expect_invalid_byte]` raw-concat lists, then the outer blocks_list.
    let mut block_entries_rlp: Vec<Vec<u8>> = Vec::with_capacity(test.blocks.len());
    for b in &test.blocks {
        let block_rlp = decode_hex(&b.rlp)?;
        let ei = [if b.expect_exception.is_some() { RLP_TRUE } else { RLP_FALSE }];
        block_entries_rlp.push(encode_rlp_list(&[block_rlp.as_slice(), &ei[..]]));
    }
    let entry_refs: Vec<&[u8]> = block_entries_rlp.iter().map(|v| v.as_slice()).collect();
    let blocks_list_rlp: Vec<u8> = encode_rlp_list(&entry_refs);

    // 32-byte `post_state_hash`, in order:
    // 1. the `postStateHash` JSON field (rare; EEST uses `postState` map)
    // 2. the `postState` per-account map computed at conversion time
    // 3. zero hash meaning "skip the check" (no post-state info)
    let post_state_hash_bytes: B256 = match (&test.post_state_hash, &test.post_state) {
        (Some(s), _) => {
            let v = decode_hex(s)?;
            if v.len() != 32 {
                bail!("postStateHash must be 32 bytes, got {}", v.len());
            }
            B256::from_slice(&v)
        }
        (None, Some(post_state)) => post_state_root(post_state)?,
        (None, None) => B256::ZERO,
    };
    let post_state_hash_rlp = alloy_rlp::encode(&post_state_hash_bytes);

    let version = [VERSION_V1];
    let items: Vec<&[u8]> = vec![
        &version,
        test.network.as_bytes(),
        &prev_rlp,
        &blocks_list_rlp,
        &pre_state_rlp,
        &headers_rlp,
        &pre_trie_rlp,
        &post_state_hash_rlp,
    ];
    Ok(alloy_rlp::encode(&items))
}

/// Compute the global state-trie root for a `postState`-shaped map. Same
/// algorithm as `build_test`'s pre-state trie, but only the root is needed
/// (no proof nodes), so the call is much cheaper.
fn post_state_root(post: &BTreeMap<String, EestPreAccount>) -> Result<B256> {
    if post.is_empty() {
        return Ok(EMPTY_ROOT_HASH);
    }
    let mut sorted: Vec<(B256, Vec<u8>)> = Vec::with_capacity(post.len());
    for (addr_hex, acct) in post {
        let address = parse_address(addr_hex)?;
        let nonce = parse_u64(&acct.nonce)?;
        let balance = parse_u256(&acct.balance)?;
        let code = decode_hex(&acct.code)?;
        let code_hash = if code.is_empty() { KECCAK_EMPTY } else { keccak256(&code) };

        let mut storage: BTreeMap<U256, U256> = BTreeMap::new();
        for (k, v) in &acct.storage {
            let key = parse_u256(k)?;
            let value = parse_u256(v)?;
            if !value.is_zero() {
                storage.insert(key, value);
            }
        }
        let storage_root = storage_trie_root(&storage);

        let trie_account = TrieAccount { nonce, balance, storage_root, code_hash };
        let mut val = Vec::new();
        trie_account.encode(&mut val);
        sorted.push((keccak256(address.as_slice()), val));
    }
    sorted.sort_by_key(|(k, _)| *k);

    let mut hb = HashBuilder::default();
    for (hashed_addr, val) in &sorted {
        hb.add_leaf(Nibbles::unpack(hashed_addr), val);
    }
    Ok(hb.root())
}

/// Compute the root of a single account's storage trie.
fn storage_trie_root(storage: &BTreeMap<U256, U256>) -> B256 {
    if storage.is_empty() {
        return EMPTY_ROOT_HASH;
    }
    let mut sorted: Vec<(U256, U256)> = storage.iter().map(|(k, v)| (*k, *v)).collect();
    sorted.sort_by_key(|(k, _)| keccak256(k.to_be_bytes::<32>().as_slice()));

    let mut hb = HashBuilder::default();
    for (k, v) in &sorted {
        let nibs = Nibbles::unpack(keccak256(k.to_be_bytes::<32>().as_slice()));
        let mut val = Vec::new();
        v.encode(&mut val);
        hb.add_leaf(nibs, &val);
    }
    hb.root()
}

/// Feed (nibble-path, value) leaves to `HashBuilder` with an all-targets
/// `ProofRetainer`; return the collected (hash, rlp_bytes) pairs for every
/// node on every path (effectively the entire trie).
fn hash_builder_nodes(leaves: &[(Nibbles, Vec<u8>)]) -> Vec<(B256, Bytes)> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let targets: Vec<Nibbles> = leaves.iter().map(|(k, _)| *k).collect();
    let retainer: ProofRetainer = targets.into_iter().collect();
    let mut hb = HashBuilder::default().with_proof_retainer(retainer);

    let mut sorted: Vec<&(Nibbles, Vec<u8>)> = leaves.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);
    for (key, val) in sorted {
        hb.add_leaf(*key, val);
    }
    let _root = hb.root();
    let proof_nodes = hb.take_proof_nodes();

    proof_nodes
        .into_inner()
        .into_iter()
        .map(|(_nibs, rlp)| (keccak256(&rlp), rlp))
        .collect()
}




fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).map_err(|e| eyre!("invalid hex: {e}"))
}

fn parse_address(s: &str) -> Result<Address> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 20 {
        bail!("address must be 20 bytes, got {}", bytes.len());
    }
    Ok(Address::from_slice(&bytes))
}

fn parse_u64(s: &str) -> Result<u64> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(stripped, 16).map_err(|e| eyre!("invalid u64 hex: {e}"))
}

fn parse_u256(s: &str) -> Result<U256> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(stripped, 16).map_err(|e| eyre!("invalid u256 hex: {e}"))
}
