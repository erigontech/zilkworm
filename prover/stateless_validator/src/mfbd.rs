// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust MFBD encoder. Ports the C++ `json_witness_to_flat_bundle` flow into a
//! self-contained library so the host-side adapter has no subprocess dependency.
//!
//! The encoder is deterministic and byte-equivalent to the C++ `json_witness_to_flat_bundle`
//! counterpart for the same witness: every MPHF is built over keys in ascending key8 order
//! (BTreeMap here, std::map in mphf_builder.cpp), and all other sections follow in sorted or
//! witness-input order.

use std::collections::{BTreeMap, HashMap};

use alloy_consensus::{Block, BlockBody, Header, TxEnvelope};
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::TrieNode, TrieAccount};
use anyhow::{anyhow, bail, Result};
use stateless::StatelessInput;

// ---------- Wire constants (docs/flat_witness_bundle.md) ----------

// MFBD outer wrapper.
pub const MFBD_MAGIC: u32 = 0x4442464D; // "MFBD"
pub const MFBD_VERSION: u32 = 1;
pub const MFBD_HEADER_SIZE: usize = 16;

// FlatBundle inner header.
const FLAT_BUNDLE_MAGIC: u32 = 0x444E4246; // "FBND"
const FLAT_BUNDLE_VERSION: u32 = 14;
const FLAT_BUNDLE_HEADER_SIZE: usize = 56;

// PreStateMeta.
// 9 u32 fields + 8 reserved u32 = 68 bytes (aligns up to 72).
const PRESTATE_MAGIC: u32 = 0x53455250; // "PRES"
const PRESTATE_VERSION: u32 = 4;
const PRESTATE_META_SIZE: usize = 68;

// MphfMapHeader.
const MPHF_MAP_VERSION: u32 = 3;
const MPHF_MAP_HEADER_SIZE: usize = 56;
const MPHF_ADDR_MAP_MAGIC: u32 = 0x4148504D; // "MPHA"
const MPHF_CODE_STORE_MAGIC: u32 = 0x4348504D; // "MPHC"
const MPHF_NODE_STORE_MAGIC: u32 = 0x4E48504D; // "MPHN"

// MphfBuilder tuning.
const MPHF_GOLDEN_RATIO: u64 = 0x9E3779B97F4A7C15;
const MPHF_LAMBDA: u32 = 4;
const MPHF_MAX_DISPLACEMENT: u32 = 1 << 20;
const MPHF_MAX_SEED_RETRIES: u32 = 32;

// Per-block flag bit.
const BLOCK_FLAG_EXPECT_INVALID: u8 = 0x01;

// Layout sizes — must match C++ static_asserts.
const ACCOUNT_SIZE: usize = 256;
const SLOT_SIZE: usize = 96;
const ADDR_HASH_ENTRY_SIZE: usize = 56;
const BLOCK_HASH_ENTRY_SIZE: usize = 40;
const MPHF_COLLISION_ENTRY_SIZE: usize = 16;

// FlatKv layout: [hash:32][payload]. Used for node_store + code_store bodies.
const FLAT_KV_KEY_SIZE: usize = 32;

const KECCAK_EMPTY: B256 = B256::new([
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
]);
const EMPTY_ROOT: B256 = B256::new([
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
]);

#[inline]
fn align8(v: usize) -> usize {
    (v + 7) & !7
}

#[inline]
fn align8_u32(v: u32) -> u32 {
    (v + 7) & !7
}

// ---------- key8 helpers ----------

/// 7 MSB bytes of the addr + byte[19] in the MSB slot of the u64 (precompile-friendly).
#[inline]
fn addr_key8(addr: &[u8; 20]) -> u64 {
    let mut k = u64::from_le_bytes([
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
    ]);
    k = (k & 0x00FF_FFFF_FFFF_FFFF) | ((addr[19] as u64) << 56);
    k
}

/// First 8 little-endian bytes of a 32-byte hash.
#[inline]
fn hash_key8(h: &[u8; 32]) -> u64 {
    u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

// ---------- MPHF builder (CHD with collision sidecar) ----------

#[inline]
fn mix64_body(z: u64) -> u64 {
    let z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z ^ (z >> 31)
}

#[inline]
fn fast_mod_u32(x: u32, n: u32) -> u32 {
    (((x as u64) * (n as u64)) >> 32) as u32
}

#[derive(Clone)]
struct CollisionEntry {
    key: u64,
    offset: u64,
}

/// CHD result. `idx_for_key[i]` is the slot for `distinct_keys[i]`; keys whose
/// bucket overflowed appear in `spilled_keys` (host-resolved via sidecar).
struct ChdSolution {
    n_buckets: u32,
    displacement_factors: Vec<u64>,
    seed: u64,
    seed_factor: u64,
    idx_for_key: Vec<u32>,
    spilled_keys: Vec<u32>,
}

fn chd_solve(distinct_keys: &[u64]) -> Result<ChdSolution> {
    let n = distinct_keys.len() as u32;
    if n == 0 {
        return Ok(ChdSolution {
            n_buckets: 1,
            displacement_factors: vec![0],
            seed: 0,
            seed_factor: 0,
            idx_for_key: Vec::new(),
            spilled_keys: Vec::new(),
        });
    }

    let n_buckets = ((n + MPHF_LAMBDA - 1) / MPHF_LAMBDA).max(1);

    let mut z1_cache = vec![0u64; n as usize];
    let mut buckets: Vec<Vec<u32>> = vec![Vec::new(); n_buckets as usize];
    let mut slot_used = vec![false; n as usize];
    let mut trial_positions: Vec<u32> = Vec::new();

    let mut best: Option<ChdSolution> = None;

    for seed_try in 0u64..MPHF_MAX_SEED_RETRIES as u64 {
        let seed_factor = seed_try.wrapping_mul(MPHF_GOLDEN_RATIO);

        for b in &mut buckets {
            b.clear();
        }
        for i in 0..n as usize {
            let z1 = distinct_keys[i].wrapping_add(seed_factor);
            z1_cache[i] = z1;
            let h1 = mix64_body(z1);
            let b = fast_mod_u32(h1 as u32, n_buckets);
            buckets[b as usize].push(i as u32);
        }

        // Largest buckets first; the sort must be stable so equal-sized buckets
        // keep ascending-index order (matches C++ std::stable_sort → deterministic
        // seed search). slice::sort_by is stable.
        let mut order: Vec<u32> = (0..n_buckets).collect();
        order.sort_by(|a, b| buckets[*b as usize].len().cmp(&buckets[*a as usize].len()));

        for s in slot_used.iter_mut() {
            *s = false;
        }
        let mut displacement_factors = vec![0u64; n_buckets as usize];
        let mut idx_for_key = vec![u32::MAX; n as usize];
        let mut spilled_this_try: Vec<u32> = Vec::new();

        for bi in &order {
            let bucket = &buckets[*bi as usize];
            if bucket.is_empty() {
                displacement_factors[*bi as usize] = 0;
                continue;
            }

            let mut placed = false;
            for d in 0..=MPHF_MAX_DISPLACEMENT {
                let d_factor = ((seed_try ^ d as u64 ^ MPHF_GOLDEN_RATIO)
                    .wrapping_sub(seed_try))
                .wrapping_mul(MPHF_GOLDEN_RATIO);

                trial_positions.clear();
                let mut collision = false;
                for &key_idx in bucket {
                    let h2 = mix64_body(z1_cache[key_idx as usize].wrapping_add(d_factor));
                    let pos = fast_mod_u32(h2 as u32, n);
                    if slot_used[pos as usize] {
                        collision = true;
                        break;
                    }
                    if trial_positions.contains(&pos) {
                        collision = true;
                        break;
                    }
                    trial_positions.push(pos);
                }
                if !collision {
                    for (pi, &pos) in trial_positions.iter().enumerate() {
                        slot_used[pos as usize] = true;
                        idx_for_key[bucket[pi] as usize] = pos;
                    }
                    displacement_factors[*bi as usize] = d_factor;
                    placed = true;
                    break;
                }
            }
            if !placed {
                displacement_factors[*bi as usize] = 0;
                for &key_idx in bucket {
                    let h2 = mix64_body(z1_cache[key_idx as usize]);
                    let pos = fast_mod_u32(h2 as u32, n);
                    idx_for_key[key_idx as usize] = pos;
                    spilled_this_try.push(key_idx);
                }
            }
        }

        if spilled_this_try.is_empty() {
            return Ok(ChdSolution {
                n_buckets,
                displacement_factors,
                seed: seed_try,
                seed_factor,
                idx_for_key,
                spilled_keys: spilled_this_try,
            });
        }
        let take_as_best = match &best {
            None => true,
            Some(b) => spilled_this_try.len() < b.spilled_keys.len(),
        };
        if take_as_best {
            best = Some(ChdSolution {
                n_buckets,
                displacement_factors,
                seed: seed_try,
                seed_factor,
                idx_for_key,
                spilled_keys: spilled_this_try,
            });
        }
    }

    best.ok_or_else(|| anyhow!("MphfBuilder: CHD solve failed within retry budget"))
}

/// Build an MPHF blob (MphfMapHeader + tables + data section). Mirrors the C++
/// `MphfBuilder<KeySize>::finalize`. The `entries` list of `(key8, body)` pairs
/// may contain duplicate `key8` values; the second and later are routed through
/// the collision sidecar.
fn build_mphf(magic: u32, entries: &[(u64, Vec<u8>)]) -> Result<Vec<u8>> {
    // BTreeMap mirrors std::map on the C++ side: iteration is ascending by key,
    // which keeps the MPHF layout deterministic and cross-encoder byte-equal.
    let mut unique: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut collision_keys: Vec<CollisionEntry> = Vec::new();
    let mut collision_bodies: Vec<Vec<u8>> = Vec::new();

    for (k, body) in entries {
        if let Some(existing) = unique.get_mut(k) {
            if !existing.is_empty() {
                collision_keys.push(CollisionEntry { key: *k, offset: 0 });
                collision_bodies.push(std::mem::take(existing));
            }
            collision_keys.push(CollisionEntry { key: *k, offset: 0 });
            collision_bodies.push(body.clone());
        } else {
            unique.insert(*k, body.clone());
        }
    }

    let distinct_keys: Vec<u64> = unique.keys().copied().collect();
    let mut sol = chd_solve(&distinct_keys)?;

    // CHD-spilled keys join the sidecar.
    for &i in &sol.spilled_keys {
        let k = distinct_keys[i as usize];
        if let Some(body) = unique.get_mut(&k) {
            if !body.is_empty() {
                collision_keys.push(CollisionEntry { key: k, offset: 0 });
                collision_bodies.push(std::mem::take(body));
            }
        }
    }
    sol.spilled_keys.clear();

    let entry_size = |body_len: usize| -> u32 { align8_u32((8 + body_len) as u32) };

    let n_keys = distinct_keys.len() as u32;
    let n_buckets = sol.n_buckets;

    // 8 bytes reserved at the start of `data` so `slot_offsets[idx]==0` means "sidecar".
    let mut data_size: u32 = 8;
    for (_, body) in &unique {
        if !body.is_empty() {
            data_size += entry_size(body.len());
        }
    }
    for body in &collision_bodies {
        data_size += entry_size(body.len());
    }

    let n_collisions = collision_keys.len() as u32;
    let collisions_size = n_collisions * MPHF_COLLISION_ENTRY_SIZE as u32;

    let mut off = align8_u32(MPHF_MAP_HEADER_SIZE as u32);
    let displacement_offset = off;
    off += align8_u32(n_buckets * 8);
    let slot_offsets_offset = off;
    off += align8_u32(n_keys * 4);
    let collisions_offset = off;
    off += align8_u32(collisions_size);
    let data_offset = off;
    off += align8_u32(data_size);
    let total_size = off as usize;

    let mut blob = vec![0u8; total_size];

    // Header.
    write_u32(&mut blob, 0, magic);
    write_u32(&mut blob, 4, MPHF_MAP_VERSION);
    write_u32(&mut blob, 8, n_keys);
    write_u32(&mut blob, 12, n_buckets);
    write_u64(&mut blob, 16, sol.seed);
    write_u64(&mut blob, 24, sol.seed_factor);
    write_u32(&mut blob, 32, collisions_offset);
    write_u32(&mut blob, 36, collisions_size);
    write_u32(&mut blob, 40, displacement_offset);
    write_u32(&mut blob, 44, slot_offsets_offset);
    write_u32(&mut blob, 48, data_offset);
    write_u32(&mut blob, 52, data_size);

    // Displacement factors.
    for (i, df) in sol.displacement_factors.iter().enumerate() {
        write_u64(&mut blob, displacement_offset as usize + i * 8, *df);
    }

    // Data section + slot_offsets for non-sidecar entries.
    let mut data_cur: u32 = 8;
    for (i, &k) in distinct_keys.iter().enumerate() {
        let idx = sol.idx_for_key[i];
        let body = unique.get(&k).expect("present");
        if body.is_empty() {
            continue;
        }
        let body_len = body.len() as u64;
        let slot_ofs = slot_offsets_offset as usize + (idx as usize) * 4;
        write_u32(&mut blob, slot_ofs, data_cur);
        let entry_off = data_offset as usize + data_cur as usize;
        write_u64(&mut blob, entry_off, body_len);
        blob[entry_off + 8..entry_off + 8 + body.len()].copy_from_slice(body);
        data_cur += entry_size(body.len());
    }

    // Collision-sidecar entries.
    for (i, body) in collision_bodies.iter().enumerate() {
        let body_len = body.len() as u64;
        collision_keys[i].offset = u64::from(data_cur);
        let entry_off = data_offset as usize + data_cur as usize;
        write_u64(&mut blob, entry_off, body_len);
        blob[entry_off + 8..entry_off + 8 + body.len()].copy_from_slice(body);
        data_cur += entry_size(body.len());
    }

    // Sort collisions by key (binary-search lookup at runtime).
    collision_keys.sort_by_key(|e| e.key);
    for (i, ce) in collision_keys.iter().enumerate() {
        let off = collisions_offset as usize + i * MPHF_COLLISION_ENTRY_SIZE;
        write_u64(&mut blob, off, ce.key);
        write_u64(&mut blob, off + 8, ce.offset);
    }

    Ok(blob)
}

// ---------- MPHF runtime lookup (host-side, used during PreState build) ----------

/// Look up the data offset for a `(addr, key8)` pair against an MPHF blob that
/// stores 20-byte-keyed entries (the prestate map). Returns 0 if not found.
fn mphf_addr_lookup(mphf: &[u8], addr20: &[u8; 20]) -> u32 {
    let n_keys = u32::from_le_bytes(mphf[8..12].try_into().unwrap());
    if n_keys == 0 {
        return 0;
    }
    let n_buckets = u32::from_le_bytes(mphf[12..16].try_into().unwrap());
    let seed_factor = u64::from_le_bytes(mphf[24..32].try_into().unwrap());
    let collisions_offset = u32::from_le_bytes(mphf[32..36].try_into().unwrap());
    let collisions_size = u32::from_le_bytes(mphf[36..40].try_into().unwrap());
    let displacement_offset = u32::from_le_bytes(mphf[40..44].try_into().unwrap());
    let slot_offsets_offset = u32::from_le_bytes(mphf[44..48].try_into().unwrap());
    let data_offset = u32::from_le_bytes(mphf[48..52].try_into().unwrap());

    let key8 = addr_key8(addr20);

    let z1 = key8.wrapping_add(seed_factor);
    let h1 = mix64_body(z1);
    let b = fast_mod_u32(h1 as u32, n_buckets);
    let df_offset = displacement_offset as usize + (b as usize) * 8;
    let df = u64::from_le_bytes(mphf[df_offset..df_offset + 8].try_into().unwrap());
    let h2 = mix64_body(z1.wrapping_add(df));
    let idx = fast_mod_u32(h2 as u32, n_keys);

    let slot_off = slot_offsets_offset as usize + (idx as usize) * 4;
    let slot_value = u32::from_le_bytes(mphf[slot_off..slot_off + 4].try_into().unwrap());

    // Direct singleton — verify by memcmp against the body's first 20 bytes (after the 8-byte length).
    if slot_value != 0 {
        let body_off = data_offset as usize + slot_value as usize + 8;
        if &mphf[body_off..body_off + 20] == addr20.as_slice() {
            return slot_value;
        }
    }

    // Sidecar.
    if collisions_size > 0 {
        let n_c = (collisions_size / MPHF_COLLISION_ENTRY_SIZE as u32) as usize;
        let base = collisions_offset as usize;
        // Binary search by key8.
        let mut lo = 0usize;
        let mut hi = n_c;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let ek = u64::from_le_bytes(
                mphf[base + mid * MPHF_COLLISION_ENTRY_SIZE
                    ..base + mid * MPHF_COLLISION_ENTRY_SIZE + 8]
                    .try_into()
                    .unwrap(),
            );
            if ek < key8 {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        // Linear scan the equal-key run, disambiguating duplicates by memcmp on the body's key bytes.
        let mut i = lo;
        while i < n_c {
            let off_i = base + i * MPHF_COLLISION_ENTRY_SIZE;
            let ek = u64::from_le_bytes(mphf[off_i..off_i + 8].try_into().unwrap());
            if ek != key8 {
                break;
            }
            let off_data = u64::from_le_bytes(mphf[off_i + 8..off_i + 16].try_into().unwrap());
            let off_data =
                u32::try_from(off_data).expect("mphf sidecar offset exceeds the u32 data arena");
            let body_off = data_offset as usize + off_data as usize + 8;
            if &mphf[body_off..body_off + 20] == addr20.as_slice() {
                return off_data;
            }
            i += 1;
        }
    }

    0
}

// ---------- MPT walker (alloy-trie node decode + local walk_tree) ----------
//
// Node RLP is decoded with `alloy_trie::nodes::TrieNode::decode` (bounds-checked,
// so a truncated node yields `Err` instead of a slice panic). The trie *walk*
// itself stays local: the encoder must enumerate every leaf, which reth/stateless
// cannot do. Leaf/extension keys arrive as `nybbles::Nibbles`; we expand them into
// the existing one-nibble-per-byte `[u8; 64]` buffer so `nibbles_to_bytes32` and the
// downstream account/U256 decode paths are unchanged.

fn walk_tree<F: FnMut(&[u8], &[u8])>(
    nodes: &HashMap<B256, Vec<u8>>,
    node_rlp: &[u8],
    path: &mut [u8; 64],
    depth: usize,
    cb: &mut F,
) -> Result<()> {
    // Fail-soft: the old hand-rolled walker early-returned `Ok(())` for a non-list
    // outer node. alloy's decode additionally rejects truncated/malformed input the
    // same way (`Err`); map both to the same graceful skip to preserve behavior and
    // byte parity. (A stricter `bail!` here is possible if callers want hard errors.)
    let node = match TrieNode::decode(&mut &node_rlp[..]) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };

    match node {
        // Empty-string node (`0x80`): nothing to walk (old code skipped non-lists).
        TrieNode::EmptyRoot => Ok(()),

        TrieNode::Branch(branch) => {
            // Guard against a chain of 65+ branch nodes overrunning the 64-nibble
            // path buffer (the ext/leaf arm already guards via `depth + plen > 64`).
            if depth >= 64 {
                return Ok(());
            }
            // `children()` yields (nibble, Option<&RlpNode>) over slots 0..16 in order.
            for (nibble, child) in branch.as_ref().children() {
                let Some(child) = child else { continue };
                path[depth] = nibble;
                if let Some(hash) = child.as_hash() {
                    // 32-byte hashref: resolve against the node store and recurse.
                    if let Some(child_rlp) = nodes.get(&hash) {
                        walk_tree(nodes, child_rlp, path, depth + 1, cb)?;
                    }
                } else {
                    // Embedded child: its bytes are the child's full RLP; recurse directly.
                    walk_tree(nodes, child.as_slice(), path, depth + 1, cb)?;
                }
            }
            Ok(())
        }

        TrieNode::Extension(ext) => {
            let key = ext.key.to_vec();
            let plen = key.len();
            if depth + plen > 64 {
                return Ok(());
            }
            path[depth..depth + plen].copy_from_slice(&key);
            let new_depth = depth + plen;
            if let Some(hash) = ext.child.as_hash() {
                if let Some(child_rlp) = nodes.get(&hash) {
                    walk_tree(nodes, child_rlp, path, new_depth, cb)?;
                }
            } else {
                // Embedded extension child: full RLP form; recurse directly.
                walk_tree(nodes, ext.child.as_slice(), path, new_depth, cb)?;
            }
            Ok(())
        }

        TrieNode::Leaf(leaf) => {
            let key = leaf.key.to_vec();
            let plen = key.len();
            if depth + plen > 64 {
                return Ok(());
            }
            path[depth..depth + plen].copy_from_slice(&key);
            let new_depth = depth + plen;
            // `leaf.value` is the unwrapped RLP-string payload — identical to the bytes
            // the old walker passed as `second` (account-RLP list / RLP-encoded U256).
            cb(&path[..new_depth], &leaf.value);
            Ok(())
        }
    }
}

fn for_each_leaf<F: FnMut(&[u8], &[u8])>(
    nodes: &HashMap<B256, Vec<u8>>,
    root: B256,
    mut cb: F,
) -> Result<()> {
    if root == EMPTY_ROOT || root == B256::ZERO {
        return Ok(());
    }
    let Some(root_rlp) = nodes.get(&root) else {
        return Ok(());
    };
    let mut path = [0u8; 64];
    walk_tree(nodes, root_rlp, &mut path, 0, &mut cb)
}

fn nibbles_to_bytes32(nibs: &[u8]) -> Option<B256> {
    if nibs.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nibs[2 * i] << 4) | (nibs[2 * i + 1] & 0x0F);
    }
    Some(B256::from(out))
}

// ---------- Account body builder (matches account_info_to_pre_account_bytes) ----------

struct AccountInfo {
    addr: [u8; 20],
    nonce: u64,
    /// little-endian (native) 32-byte representation of the U256.
    balance: [u8; 32],
    code_hash: [u8; 32],
    storage_root: [u8; 32],
    code_store_len: u32,
    /// (key, value) pairs; encoder sorts by key bytes.
    storage: Vec<([u8; 32], [u8; 32])>,
}

/// Account body layout: [Account (256 bytes)][Slot (96 bytes) * slot_count].
fn account_info_to_body(info: &mut AccountInfo) -> Vec<u8> {
    let slot_count = info.storage.len() as u32;
    let body_size = ACCOUNT_SIZE + (slot_count as usize) * SLOT_SIZE;
    let mut body = vec![0u8; body_size];

    // Offsets mirror the C++ Account struct. Unwritten fields stay 0: deleted@20,
    // acc_rlp_len@22, acc_rlp_sroot_off@23, modified@24, code_store_offset@128,
    // acc_rlp_buf@140..256 (the trailing buf+padding fills the fixed 256 bytes).
    body[0..20].copy_from_slice(&info.addr);
    body[24..32].copy_from_slice(&info.nonce.to_le_bytes());
    body[32..64].copy_from_slice(&info.balance);
    body[64..96].copy_from_slice(&info.code_hash);
    body[96..128].copy_from_slice(&info.storage_root);
    body[132..136].copy_from_slice(&info.code_store_len.to_le_bytes());
    body[136..140].copy_from_slice(&slot_count.to_le_bytes());

    // Slot layout [key][initial][current]; a pre-state slot has initial == current.
    info.storage.sort_by(|a, b| a.0.cmp(&b.0));
    for (i, (k, v)) in info.storage.iter().enumerate() {
        let slot_off = ACCOUNT_SIZE + i * SLOT_SIZE;
        body[slot_off..slot_off + 32].copy_from_slice(k);
        body[slot_off + 32..slot_off + 64].copy_from_slice(v);
        body[slot_off + 64..slot_off + 96].copy_from_slice(v);
    }
    body
}

// ---------- DirectState blob builder (build_blob_from_accounts) ----------

fn keccak_addr(addr: &[u8; 20]) -> [u8; 32] {
    let h = keccak256(addr);
    *h.as_ref()
}

fn build_direct_blob(
    mut accounts: Vec<AccountInfo>,
    mut block_hashes: Vec<(u64, [u8; 32])>,
    code_store_blob: Vec<u8>,
) -> Result<Vec<u8>> {
    accounts.sort_by(|a, b| a.addr.cmp(&b.addr));
    let n_accounts = accounts.len() as u32;

    let mut addr_key8_entries: Vec<u64> = Vec::with_capacity(n_accounts as usize);
    let mut addr_hashes_pre: Vec<([u8; 32], [u8; 20])> = Vec::with_capacity(n_accounts as usize);
    let mut acc_body_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_accounts as usize);

    for info in &mut accounts {
        addr_key8_entries.push(addr_key8(&info.addr));
        let ah = keccak_addr(&info.addr);
        addr_hashes_pre.push((ah, info.addr));
        acc_body_bytes.push(account_info_to_body(info));
    }

    let mphf_bytes = if n_accounts > 0 {
        let mut entries: Vec<(u64, Vec<u8>)> = Vec::with_capacity(n_accounts as usize);
        for i in 0..n_accounts as usize {
            entries.push((addr_key8_entries[i], acc_body_bytes[i].clone()));
        }
        build_mphf(MPHF_ADDR_MAP_MAGIC, &entries)?
    } else {
        Vec::new()
    };
    let mphf_size = mphf_bytes.len() as u32;
    let code_store_size = code_store_blob.len() as u32;

    block_hashes.sort_by_key(|e| e.0);
    let n_block_hashes = block_hashes.len() as u32;

    // Layout: meta | prestate-MphfMap | addr_hashes | block_hashes | code_store.
    let mut off = align8_u32(PRESTATE_META_SIZE as u32);
    let prestate_offset = off;
    off += align8_u32(mphf_size);
    let addr_hashes_offset = off;
    off += align8_u32(n_accounts * ADDR_HASH_ENTRY_SIZE as u32);
    let block_hashes_offset = off;
    off += align8_u32(n_block_hashes * BLOCK_HASH_ENTRY_SIZE as u32);
    let code_store_offset = off;
    off += align8_u32(code_store_size);
    let total_size = off as usize;

    let mut blob = vec![0u8; total_size];

    // PreStateMeta.
    write_u32(&mut blob, 0, PRESTATE_MAGIC);
    write_u32(&mut blob, 4, PRESTATE_VERSION);
    write_u32(&mut blob, 8, n_accounts);
    write_u32(&mut blob, 12, n_block_hashes);
    write_u32(&mut blob, 16, prestate_offset);
    write_u32(&mut blob, 20, addr_hashes_offset);
    write_u32(&mut blob, 24, block_hashes_offset);
    write_u32(&mut blob, 28, code_store_offset);
    write_u32(&mut blob, 32, code_store_size);
    // reserved[8] u32s at [36..68] stay 0.

    if code_store_size > 0 {
        blob[code_store_offset as usize..code_store_offset as usize + code_store_size as usize]
            .copy_from_slice(&code_store_blob);
    }
    for (i, (n, h)) in block_hashes.iter().enumerate() {
        let off = block_hashes_offset as usize + i * BLOCK_HASH_ENTRY_SIZE;
        write_u64(&mut blob, off, *n);
        blob[off + 8..off + 40].copy_from_slice(h);
    }
    if mphf_size > 0 {
        blob[prestate_offset as usize..prestate_offset as usize + mphf_size as usize]
            .copy_from_slice(&mphf_bytes);
    }

    // Fill AddrHashEntry table with entry_offset resolved via the just-built MPHF.
    let prestate_view = if mphf_size > 0 {
        &blob[prestate_offset as usize..prestate_offset as usize + mphf_size as usize]
    } else {
        &[][..]
    };
    let mut addr_hash_entries: Vec<([u8; 32], [u8; 20], u32)> =
        Vec::with_capacity(n_accounts as usize);
    for (ah, addr) in &addr_hashes_pre {
        let entry_offset = if !prestate_view.is_empty() {
            mphf_addr_lookup(prestate_view, addr)
        } else {
            0
        };
        addr_hash_entries.push((*ah, *addr, entry_offset));
    }
    addr_hash_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (i, (ah, addr, ofs)) in addr_hash_entries.iter().enumerate() {
        let off = addr_hashes_offset as usize + i * ADDR_HASH_ENTRY_SIZE;
        blob[off..off + 32].copy_from_slice(ah);
        blob[off + 32..off + 52].copy_from_slice(addr);
        write_u32(&mut blob, off + 52, *ofs);
    }

    Ok(blob)
}

// ---------- FlatBundle + MFBD envelope ----------

fn build_flat_bundle(
    genesis_rlp: &[u8],
    block_rlps: &[&[u8]],
    ancestors_rlp: &[u8],
    direct_state_blob: &[u8],
    node_store_blob: &[u8],
    network: &str,
    block_flags: &[u8],
) -> Vec<u8> {
    let mut blocks_payload = 0usize;
    for br in block_rlps {
        blocks_payload += align8(br.len());
    }
    let blocks_section_size = 8 + blocks_payload + block_flags.len();

    let hdr_size = align8(FLAT_BUNDLE_HEADER_SIZE);
    let genesis_off = hdr_size;
    let blocks_off = align8(genesis_off + genesis_rlp.len());
    let anc_off = align8(blocks_off + blocks_section_size);
    let direct_off = align8(anc_off + ancestors_rlp.len());
    let node_off = align8(direct_off + direct_state_blob.len());
    let network_off = align8(node_off + node_store_blob.len());
    let total = align8(network_off + network.len());

    let mut out = vec![0u8; total];

    // FlatBundleHeader.
    write_u32(&mut out, 0, FLAT_BUNDLE_MAGIC);
    write_u32(&mut out, 4, FLAT_BUNDLE_VERSION);
    write_u32(&mut out, 8, genesis_off as u32);
    write_u32(&mut out, 12, genesis_rlp.len() as u32);
    write_u32(&mut out, 16, blocks_off as u32);
    write_u32(&mut out, 20, blocks_section_size as u32);
    write_u32(&mut out, 24, anc_off as u32);
    write_u32(&mut out, 28, ancestors_rlp.len() as u32);
    write_u32(&mut out, 32, direct_off as u32);
    write_u32(&mut out, 36, direct_state_blob.len() as u32);
    write_u32(&mut out, 40, node_off as u32);
    write_u32(&mut out, 44, node_store_blob.len() as u32);
    write_u32(&mut out, 48, network_off as u32);
    write_u32(&mut out, 52, network.len() as u32);

    out[genesis_off..genesis_off + genesis_rlp.len()].copy_from_slice(genesis_rlp);

    let n_blocks = block_rlps.len() as u64;
    write_u64(&mut out, blocks_off, n_blocks);
    let mut cursor = blocks_off + 8;
    for br in block_rlps {
        if !br.is_empty() {
            out[cursor..cursor + br.len()].copy_from_slice(br);
        }
        cursor += align8(br.len());
    }
    if !block_flags.is_empty() {
        out[cursor..cursor + block_flags.len()].copy_from_slice(block_flags);
    }
    out[anc_off..anc_off + ancestors_rlp.len()].copy_from_slice(ancestors_rlp);
    out[direct_off..direct_off + direct_state_blob.len()].copy_from_slice(direct_state_blob);
    out[node_off..node_off + node_store_blob.len()].copy_from_slice(node_store_blob);
    out[network_off..network_off + network.len()].copy_from_slice(network.as_bytes());

    out
}

fn wrap_mfbd(bundle: &[u8]) -> Vec<u8> {
    let mut env = Vec::with_capacity(MFBD_HEADER_SIZE + bundle.len());
    env.extend_from_slice(&MFBD_MAGIC.to_le_bytes());
    env.extend_from_slice(&MFBD_VERSION.to_le_bytes());
    env.extend_from_slice(&1u64.to_le_bytes()); // n_bundles
    env.extend_from_slice(bundle);
    env
}

// ---------- Top-level entries ----------

/// Convert a `stateless::StatelessInput` directly into the MFBD envelope expected
/// by the post-#90 Zilkworm guest. Thin wrapper around [`build_mfbd_from_parts`].
pub fn stateless_input_to_mfbd(si: &StatelessInput, valid_block: bool, fork: &str) -> Result<Vec<u8>> {
    let current_block_rlp = alloy_rlp::encode(&si.block);
    build_mfbd_from_parts(
        &current_block_rlp,
        &si.witness.state,
        &si.witness.codes,
        &si.witness.keys,
        &si.witness.headers,
        fork,
        !valid_block,
    )
}

/// Build the MFBD envelope from raw witness components. Callable from any path
/// that has the pieces in hand (RPC fetcher, StatelessInput adapter, tests).
///
/// `witness_headers` must be a non-empty list of RLP-encoded block headers;
/// the *last* entry is the parent of `current_block_rlp` and its `state_root`
/// is used as the pre-state root for the trie walk.
pub fn build_mfbd_from_parts(
    current_block_rlp: &[u8],
    witness_state: &[Bytes],
    witness_codes: &[Bytes],
    witness_keys: &[Bytes],
    witness_headers: &[Bytes],
    fork: &str,
    expect_invalid: bool,
) -> Result<Vec<u8>> {
    if witness_headers.is_empty() {
        bail!("witness.headers must contain at least the parent header");
    }

    // Build the node-store hash → rlp map, plus the (hash, rlp) list we feed into
    // the MPHF. `ns_entries` retains witness.state's input order so MPHF input
    // ordering is deterministic and matches the C++ host.
    let mut nodes: HashMap<B256, Vec<u8>> = HashMap::with_capacity(witness_state.len());
    let mut ns_entries: Vec<(B256, Vec<u8>)> = Vec::with_capacity(witness_state.len());
    for n in witness_state {
        let h = keccak256(n.as_ref());
        let v: Vec<u8> = n.to_vec();
        nodes.insert(h, v.clone());
        ns_entries.push((h, v));
    }

    let mut code_map: HashMap<B256, Vec<u8>> = HashMap::with_capacity(witness_codes.len());
    for c in witness_codes {
        code_map.insert(keccak256(c.as_ref()), c.to_vec());
    }
    let mut preimage_map: HashMap<B256, Bytes> = HashMap::with_capacity(witness_keys.len());
    for k in witness_keys {
        preimage_map.insert(keccak256(k.as_ref()), k.clone());
    }

    // The parent header (last entry of `witness_headers`) furnishes the pre-state
    // root for the trie walk. Last because the witness lists headers in ascending
    // block-number order; the C++ `json_witness_to_flat_bundle` likewise treats
    // `ancestors.back()` as the parent.
    let parent_header = {
        let mut slice = witness_headers.last().unwrap().as_ref();
        Header::decode(&mut slice)?
    };
    let pre_state_root: B256 = parent_header.state_root;

    // Walk the state trie + each touched account's storage trie, building AccountInfos
    // for leaves whose 20-byte preimage is in keys[].
    let mut accounts: Vec<AccountInfo> = Vec::new();
    let state_leaves = collect_leaves(&nodes, pre_state_root)?;
    for (path_bytes, value_rlp) in state_leaves {
        let Some(hashed_addr) = nibbles_to_bytes32(&path_bytes) else { continue };
        let Some(addr_preimage) = preimage_map.get(&hashed_addr) else { continue };
        if addr_preimage.len() != 20 {
            continue;
        }
        let mut addr20 = [0u8; 20];
        addr20.copy_from_slice(addr_preimage.as_ref());

        let acc = match TrieAccount::decode(&mut value_rlp.as_slice()) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let mut code_store_len = 0u32;
        if acc.code_hash != KECCAK_EMPTY {
            if let Some(code) = code_map.get(&acc.code_hash) {
                code_store_len = code.len() as u32;
            }
        }

        let mut storage: Vec<([u8; 32], [u8; 32])> = Vec::new();
        if acc.storage_root != EMPTY_ROOT && acc.storage_root != B256::ZERO {
            let slot_leaves = collect_leaves(&nodes, acc.storage_root)?;
            for (slot_path, slot_rlp) in slot_leaves {
                let Some(hashed_slot) = nibbles_to_bytes32(&slot_path) else { continue };
                let Some(slot_preimage) = preimage_map.get(&hashed_slot) else { continue };
                if slot_preimage.len() != 32 {
                    continue;
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(slot_preimage.as_ref());

                let mut s = slot_rlp.as_slice();
                let v = match U256::decode(&mut s) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.is_zero() {
                    continue;
                }
                let v_be: [u8; 32] = v.to_be_bytes();
                storage.push((key, v_be));
            }
        }

        // balance: write the U256 as little-endian bytes (native layout matches
        // intx::uint256 memory order on LE hosts; guest runs RV64IM = LE too).
        let mut balance_le = [0u8; 32];
        let be = acc.balance.to_be_bytes::<32>();
        for i in 0..32 {
            balance_le[i] = be[31 - i];
        }

        accounts.push(AccountInfo {
            addr: addr20,
            nonce: acc.nonce,
            balance: balance_le,
            code_hash: *acc.code_hash.as_ref(),
            storage_root: *acc.storage_root.as_ref(),
            code_store_len,
            storage,
        });
    }

    // Block hashes for ancestor lookups (BLOCKHASH opcode service).
    let mut block_hashes: Vec<(u64, [u8; 32])> = Vec::with_capacity(witness_headers.len());
    for hdr_rlp in witness_headers {
        let mut slice = hdr_rlp.as_ref();
        let hdr = Header::decode(&mut slice)?;
        let h = hdr.hash_slow();
        block_hashes.push((hdr.number, *h.as_ref()));
    }

    // Code-store MPHF. Iterate witness_codes in input order (hash-dedup) so the
    // MPHF input sequence is deterministic and matches the C++ json_witness_to_flat_bundle.
    let code_store_blob = if !witness_codes.is_empty() {
        let mut entries: Vec<(u64, Vec<u8>)> = Vec::with_capacity(witness_codes.len());
        let mut seen: std::collections::HashSet<B256> =
            std::collections::HashSet::with_capacity(witness_codes.len());
        for c in witness_codes {
            let h = keccak256(c.as_ref());
            if !seen.insert(h) {
                continue;
            }
            let mut body = Vec::with_capacity(FLAT_KV_KEY_SIZE + c.len());
            body.extend_from_slice(h.as_ref());
            body.extend_from_slice(c.as_ref());
            entries.push((hash_key8(h.as_ref()), body));
        }
        if entries.is_empty() {
            Vec::new()
        } else {
            build_mphf(MPHF_CODE_STORE_MAGIC, &entries)?
        }
    } else {
        Vec::new()
    };

    let direct_blob = build_direct_blob(accounts, block_hashes, code_store_blob)?;

    // Node-store MPHF.
    let node_store_blob = if !ns_entries.is_empty() {
        let mut entries: Vec<(u64, Vec<u8>)> = Vec::with_capacity(ns_entries.len());
        for (h, rlp) in &ns_entries {
            let mut body = Vec::with_capacity(FLAT_KV_KEY_SIZE + rlp.len());
            body.extend_from_slice(h.as_ref());
            body.extend_from_slice(rlp);
            entries.push((hash_key8(h.as_ref()), body));
        }
        build_mphf(MPHF_NODE_STORE_MAGIC, &entries)?
    } else {
        Vec::new()
    };

    // Genesis slot in the bundle holds the header-only previous block; ancestors
    // section holds an RLP list of all witness headers (including parent).
    let prev_block_rlp = {
        let block = Block { header: parent_header.clone(), body: BlockBody::<TxEnvelope>::default() };
        alloy_rlp::encode(&block)
    };

    // ancestors_rlp = RLP list(header_rlp_0 || header_rlp_1 || ...).
    let mut ancestors_payload: Vec<u8> = Vec::new();
    let mut total_payload = 0usize;
    for h in witness_headers {
        total_payload += h.len();
    }
    let list_hdr = alloy_rlp::Header { list: true, payload_length: total_payload };
    list_hdr.encode(&mut ancestors_payload);
    for h in witness_headers {
        ancestors_payload.extend_from_slice(h.as_ref());
    }

    // Match the C++ host: only emit block_flags when expect_invalid is true.
    // (The guest treats an empty block_flags section as "all blocks are expected
    // valid"; emitting [0] would be a no-op semantically but breaks byte parity.)
    let block_flags_buf: &[u8] = if expect_invalid {
        const FLAGS: [u8; 1] = [BLOCK_FLAG_EXPECT_INVALID];
        &FLAGS
    } else {
        &[]
    };
    let bundle = build_flat_bundle(
        &prev_block_rlp,
        &[&current_block_rlp],
        &ancestors_payload,
        &direct_blob,
        &node_store_blob,
        fork,
        block_flags_buf,
    );

    Ok(wrap_mfbd(&bundle))
}

/// Walk an MPT exhaustively from `root` and return every leaf as `(path, value_rlp)`.
fn collect_leaves(
    nodes: &HashMap<B256, Vec<u8>>,
    root: B256,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for_each_leaf(nodes, root, |path, value| {
        out.push((path.to_vec(), value.to_vec()));
    })?;
    Ok(out)
}

// ---------- LE writers ----------

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    // RLP byte-string element with the given payload.
    fn rlp_str(payload: &[u8]) -> Vec<u8> {
        let mut o = Vec::new();
        alloy_rlp::Header { list: false, payload_length: payload.len() }.encode(&mut o);
        o.extend_from_slice(payload);
        o
    }

    // RLP list wrapping already-encoded elements.
    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload_len: usize = items.iter().map(Vec::len).sum();
        let mut o = Vec::new();
        alloy_rlp::Header { list: true, payload_length: payload_len }.encode(&mut o);
        for it in items {
            o.extend_from_slice(it);
        }
        o
    }

    // Hex-prefix (compact) encoding — inverse of hp_decode.
    fn hp_encode(nibs: &[u8], is_leaf: bool) -> Vec<u8> {
        let odd = nibs.len() % 2 == 1;
        let flag = (if is_leaf { 2u8 } else { 0 }) | (if odd { 1 } else { 0 });
        let mut o = Vec::new();
        let rest = if odd {
            o.push((flag << 4) | nibs[0]);
            &nibs[1..]
        } else {
            o.push(flag << 4);
            nibs
        };
        for pair in rest.chunks(2) {
            o.push((pair[0] << 4) | pair[1]);
        }
        o
    }

    fn nibbles(h: &[u8; 32]) -> Vec<u8> {
        let mut v = Vec::with_capacity(64);
        for b in h {
            v.push(b >> 4);
            v.push(b & 0x0f);
        }
        v
    }

    // EOA state-trie leaf for `addr` (path = the 63 nibbles below the root branch).
    fn eoa_leaf(addr: &[u8; 20]) -> (Vec<u8>, B256) {
        let account = rlp_list(&[
            alloy_rlp::encode(&7u64),
            alloy_rlp::encode(&U256::from(1_000u64)),
            alloy_rlp::encode(&EMPTY_ROOT),
            alloy_rlp::encode(&KECCAK_EMPTY),
        ]);
        let nibs = nibbles(keccak256(addr).as_ref());
        let leaf = rlp_list(&[rlp_str(&hp_encode(&nibs[1..], true)), rlp_str(&account)]);
        let h = keccak256(&leaf);
        (leaf, h)
    }

    fn addr_first_nibble(target: u8) -> [u8; 20] {
        for i in 1u64.. {
            let mut a = [0u8; 20];
            a[12..20].copy_from_slice(&i.to_be_bytes());
            if keccak256(a)[0] >> 4 == target {
                return a;
            }
        }
        unreachable!()
    }

    // Two-account state trie (root branch → two leaves) with a complete witness.
    // Encoding it twice must yield identical bytes: this proves its canonical form.
    #[test]
    fn encoder_is_deterministic_and_wellformed() {
        let addr_a = addr_first_nibble(0x3);
        let addr_b = addr_first_nibble(0xc);
        let (leaf_a, ha) = eoa_leaf(&addr_a);
        let (leaf_b, hb) = eoa_leaf(&addr_b);
        let nib_a = keccak256(addr_a)[0] >> 4;
        let nib_b = keccak256(addr_b)[0] >> 4;

        let mut items: Vec<Vec<u8>> = Vec::with_capacity(17);
        for slot in 0..16u8 {
            if slot == nib_a {
                items.push(rlp_str(ha.as_ref()));
            } else if slot == nib_b {
                items.push(rlp_str(hb.as_ref()));
            } else {
                items.push(rlp_str(&[]));
            }
        }
        items.push(rlp_str(&[])); // 17th (value) slot: empty
        let branch = rlp_list(&items);
        let state_root = keccak256(&branch);

        let state: Vec<Bytes> =
            vec![Bytes::from(branch), Bytes::from(leaf_a), Bytes::from(leaf_b)];
        let keys: Vec<Bytes> =
            vec![Bytes::from(addr_a.to_vec()), Bytes::from(addr_b.to_vec())];

        let mut parent = Header::default();
        parent.number = 100;
        parent.state_root = state_root;
        let headers: Vec<Bytes> = vec![Bytes::from(alloy_rlp::encode(&parent))];

        let mut child = Header::default();
        child.number = 101;
        child.parent_hash = parent.hash_slow();
        let block_rlp =
            alloy_rlp::encode(&Block { header: child, body: BlockBody::<TxEnvelope>::default() });

        let enc = || build_mfbd_from_parts(&block_rlp, &state, &[], &keys, &headers, "Cancun", false);
        let out1 = enc().unwrap();
        let out2 = enc().unwrap();
        assert_eq!(out1, out2, "encoder output must be deterministic");

        // Well-formed envelope: MFBD wrapper + single FlatBundle.
        assert_eq!(out1[0..4], MFBD_MAGIC.to_le_bytes());
        assert_eq!(u64::from_le_bytes(out1[8..16].try_into().unwrap()), 1);
        assert_eq!(out1[16..20], FLAT_BUNDLE_MAGIC.to_le_bytes());

        // Both accounts were recovered from the witness (PreStateMeta.n_accounts).
        let direct_off = 16 + u32::from_le_bytes(out1[48..52].try_into().unwrap()) as usize;
        let n_accounts = u32::from_le_bytes(out1[direct_off + 8..direct_off + 12].try_into().unwrap());
        assert_eq!(n_accounts, 2);
    }
}
