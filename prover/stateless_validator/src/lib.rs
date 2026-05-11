// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Host-side adapter that converts an Ethereum stateless-validation input into the Zilkworm
//! unified-RLP v1 bundle format consumed by the zkEVM guest.
//!
//! Zilkworm's guest is the C++ `z6m_guest` binary built externally at
//! <https://github.com/erigontech/zilkworm>; this crate provides only the host-side
//! conversion from [`stateless::StatelessInput`] to the v1 unified-RLP wire format
//! that `z6m_guest::run_rlp` consumes.
//!
//! The optional `download` feature exposes a small downloader for the SP1 guest
//! ELF published on `erigontech/zilkworm` GitHub Releases.

#[cfg(feature = "download")]
pub mod download;

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::{Block, BlockBody, Header, TxEnvelope};
use alloy_genesis::ChainConfig;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::TrieNode, Nibbles, TrieAccount, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use anyhow::{anyhow, bail, Context, Result};
use stateless::StatelessInput;

use z6m_unified_rlp::{
    encode_pre_state_rlp, encode_pre_trie_rlp, encode_rlp_list, FlatAccount, MAINNET_FORK_NAME,
    RLP_FALSE, RLP_TRUE, VERSION_V1,
};

/// Host-side adapter exposing the Zilkworm guest's stateless-validation input as a unified-RLP blob.
#[derive(Clone, Debug)]
pub struct StatelessValidatorZilkwormInput {
    /// Zilkworm's v1 unified-RLP payload.
    pub unified_rlp: Vec<u8>,
}

/// Encode unified-RLP payloads as the batched-bundle wire format consumed by the Zilkworm guest.
pub fn encode_unified_rlp_bundle(items: &[&[u8]]) -> Vec<u8> {
    let payload_len: usize = items.iter().map(|item| 4 + item.len()).sum();
    let mut out = Vec::with_capacity(4 + payload_len);
    out.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(item);
    }
    out
}

impl StatelessValidatorZilkwormInput {
    /// Construct [`StatelessValidatorZilkwormInput`] from a [`stateless::StatelessInput`].
    pub fn new(stateless_input: &StatelessInput, valid_block: bool) -> Result<Self> {
        let unified_rlp = stateless_input_to_unified_rlp(stateless_input, valid_block)?;
        Ok(Self { unified_rlp })
    }
}

/// Convert a [`stateless::StatelessInput`] into the v1 unified-RLP blob the Zilkworm guest's entry point consumes.
fn stateless_input_to_unified_rlp(si: &StatelessInput, valid_block: bool) -> Result<Vec<u8>> {
    let block_rlp: Bytes = alloy_rlp::encode(&si.block).into();
    let block_timestamp = si.block.header.timestamp;
    let witness = &si.witness;
    let chain_config = &si.chain_config;

    let nodes: HashMap<B256, Vec<u8>> = witness
        .state
        .iter()
        .map(|b| (keccak256(b.as_ref()), b.to_vec()))
        .collect();

    let codes_by_hash: HashMap<B256, Vec<u8>> = witness
        .codes
        .iter()
        .map(|c| (keccak256(c.as_ref()), c.to_vec()))
        .collect();

    let mut preimages: HashMap<B256, &[u8]> = HashMap::with_capacity(witness.keys.len());
    for key in &witness.keys {
        preimages.insert(keccak256(key.as_ref()), key.as_ref());
    }

    // Parse parent header (witness.headers[0]) to get pre-state root.
    if witness.headers.is_empty() {
        bail!("witness.headers must contain at least the parent header");
    }
    let parent_header = {
        let mut slice = witness.headers[0].as_ref();
        Header::decode(&mut slice).context("decoding parent header")?
    };
    let pre_state_root: B256 = parent_header.state_root;

    // Walk the pre-state MPT nodes to extract the accounts touched during block execution.
    let mut accounts: Vec<FlatAccount> = Vec::new();
    let state_leaves = walk_all_leaves(pre_state_root, &nodes).context("walking state MPT")?;
    for (path_bytes, value_rlp) in state_leaves {
        if path_bytes.len() != 32 {
            continue; // Should never happen for a state trie, but skip if it does.
        }
        let hashed_addr = B256::from_slice(&path_bytes);
        let Some(addr_preimage) = preimages.get(&hashed_addr) else {
            continue; // Inline sibling of an accessed leaf, skip.
        };
        if addr_preimage.len() != 20 {
            continue;
        }
        let addr = Address::from_slice(addr_preimage);

        let trie_account = {
            let mut slice = value_rlp.as_slice();
            TrieAccount::decode(&mut slice).context("decoding TrieAccount leaf")?
        };
        // Code may be missing from witness.codes if the block never executed its code.
        let code: Bytes = if trie_account.code_hash == KECCAK_EMPTY {
            Bytes::new()
        } else {
            codes_by_hash
                .get(&trie_account.code_hash)
                .map(|v| Bytes::from(v.clone()))
                .unwrap_or_default()
        };

        let mut storage = BTreeMap::new();
        if trie_account.storage_root != EMPTY_ROOT_HASH {
            let storage_leaves = walk_all_leaves(trie_account.storage_root, &nodes)
                .with_context(|| format!("walking storage MPT for {addr}"))?;
            for (slot_path_bytes, slot_value_rlp) in storage_leaves {
                if slot_path_bytes.len() != 32 {
                    continue;
                }
                let hashed_slot = B256::from_slice(&slot_path_bytes);
                let Some(slot_preimage) = preimages.get(&hashed_slot) else {
                    continue; // Inline sibling of an accessed slot, skip.
                };
                if slot_preimage.len() != 32 {
                    continue;
                }
                let slot = U256::from_be_slice(slot_preimage);
                let value: U256 = {
                    let mut s = slot_value_rlp.as_slice();
                    Decodable::decode(&mut s).context("decoding storage slot value")?
                };
                storage.insert(slot, value);
            }
        }

        accounts.push(FlatAccount {
            address: addr,
            nonce: trie_account.nonce,
            balance: trie_account.balance,
            code_hash: trie_account.code_hash,
            storage_root: trie_account.storage_root,
            code,
            storage,
        });
    }
    // Sort by address bytes to match the prior BTreeMap<Address, _> iteration order.
    accounts.sort_by(|a, b| a.address.cmp(&b.address));

    // Derive fork_name from chain_config + block timestamp (suffix `!witness` so the guest selects its witness-based check_root).
    let fork_base = fork_base_from_chain_config(chain_config, block_timestamp);
    let fork_field = format!("{fork_base}!witness");

    let prev_block_rlp = encode_header_only_block(&parent_header);

    let expect_invalid = if valid_block { [RLP_FALSE] } else { [RLP_TRUE] };
    let block_entry_rlp = encode_rlp_list(&[block_rlp.as_ref(), &expect_invalid[..]]);
    let blocks_list_rlp = encode_rlp_list(&[block_entry_rlp.as_slice()]);

    let pre_state_rlp = encode_pre_state_rlp(&accounts);

    let mut headers_flat: Vec<u8> = Vec::new();
    for h in witness.headers.iter().skip(1) {
        headers_flat.extend_from_slice(h.as_ref());
    }
    let headers_rlp = encode_rlp_list(&[headers_flat.as_slice()]);

    let pre_trie_rlp = encode_pre_trie_rlp(&witness.state);

    // All-zero post-state hash because the guest uses witness-based check_root.
    let post_state_hash = [0u8; 32];

    let version = [VERSION_V1];
    let items: Vec<&[u8]> = vec![
        &version,
        fork_field.as_bytes(),
        &prev_block_rlp,
        &blocks_list_rlp,
        &pre_state_rlp,
        &headers_rlp,
        &pre_trie_rlp,
        &post_state_hash,
    ];
    Ok(alloy_rlp::encode(&items))
}

/// Walk an MPT exhaustively from `root`, returning every leaf the witness can reach as `(full_path_bytes, value_rlp)`.
fn walk_all_leaves(root: B256, nodes: &HashMap<B256, Vec<u8>>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    if root == EMPTY_ROOT_HASH {
        return Ok(out);
    }
    let Some(root_rlp) = nodes.get(&root).cloned() else {
        return Ok(out);
    };
    walk_subtree(&root_rlp, Nibbles::new(), nodes, &mut out)?;
    Ok(out)
}

/// Recursive walk helper: decode `node_rlp` and dispatch on the node variant.
/// `walked` is the prefix nibble-path already consumed from the root to reach this node.
fn walk_subtree(
    node_rlp: &[u8],
    walked: Nibbles,
    nodes: &HashMap<B256, Vec<u8>>,
    out: &mut Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<()> {
    let node = {
        let mut slice = node_rlp;
        TrieNode::decode(&mut slice).context("decoding trie node")?
    };
    match node {
        TrieNode::EmptyRoot => Ok(()),
        TrieNode::Leaf(leaf) => {
            let full = concat_nibbles(&walked, &leaf.key);
            out.push((nibbles_to_bytes(&full), leaf.value.clone()));
            Ok(())
        }
        TrieNode::Extension(ext) => {
            let new_walked = concat_nibbles(&walked, &ext.key);
            if let Some(child_rlp) = resolve_child(&ext.child, nodes)? {
                walk_subtree(&child_rlp, new_walked, nodes, out)?;
            }
            Ok(())
        }
        TrieNode::Branch(branch) => {
            let mut stack_idx = 0usize;
            for nib in 0u8..16 {
                if branch.state_mask.is_bit_set(nib) {
                    let child = branch
                        .stack
                        .get(stack_idx)
                        .ok_or_else(|| anyhow!("branch stack shorter than mask popcount"))?;
                    let mut new_walked = walked.clone();
                    new_walked.push(nib);
                    if let Some(child_rlp) = resolve_child(child, nodes)? {
                        walk_subtree(&child_rlp, new_walked, nodes, out)?;
                    }
                    stack_idx += 1;
                }
            }
            Ok(())
        }
    }
}

/// Pack an even-length nibble path back to bytes (high nibble first per byte).
fn nibbles_to_bytes(nib: &Nibbles) -> Vec<u8> {
    debug_assert_eq!(nib.len() % 2, 0, "expected even nibble count");
    let mut out = Vec::with_capacity(nib.len() / 2);
    let mut i = 0;
    while i + 1 < nib.len() {
        let hi = nib.get(i).expect("in-bounds");
        let lo = nib.get(i + 1).expect("in-bounds");
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Resolve a child reference (either inline RLP or a 32-byte hash reference) into the child node's RLP bytes.
/// Returns `None` for hash-referenced children that are absent from the witness.
fn resolve_child(
    child: &alloy_trie::nodes::RlpNode,
    nodes: &HashMap<B256, Vec<u8>>,
) -> Result<Option<Vec<u8>>> {
    let bytes: &[u8] = child.as_ref();
    // A 32-byte hash is encoded as a 33-byte RLP string starting with 0xa0 prefix.
    if bytes.len() == 33 && bytes[0] == 0xa0 {
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes[1..33]);
        let hash = B256::from(h);
        Ok(nodes.get(&hash).cloned())
    } else {
        Ok(Some(bytes.to_vec()))
    }
}

fn concat_nibbles(a: &Nibbles, b: &Nibbles) -> Nibbles {
    let mut out = a.clone();
    for i in 0..b.len() {
        out.push(b.get(i).unwrap());
    }
    out
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
        // Broad enough value to route pre-Shanghai blocks through the witness-based root check path.
        MAINNET_FORK_NAME.to_string()
    }
}

/// Encode `header` as the RLP of a block with an empty body.
fn encode_header_only_block(header: &Header) -> Vec<u8> {
    let block = Block { header: header.clone(), body: BlockBody::<TxEnvelope>::default() };
    alloy_rlp::encode(&block)
}

