// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! EEST canonical stateless-input adapter — decodes `statelessInputBytes` (SIOB)
//! into the pieces our MFBD encoder consumes.
//!
//! Wire format (Amsterdam, per [EIP-8025 / execution-specs `projects/zkevm`]):
//!   `[schema_id: 2B big-endian = 0x0001] || SSZ(SszStatelessInput)`
//!
//! The `keys` list our MFBD encoder needs (20-byte address preimages + 32-byte
//! slot preimages for touched trie leaves) is not present in SIOB directly.
//! We derive it from the Block Access List (BAL, EIP-7928) which is embedded
//! as opaque RLP bytes inside `ExecutionPayloadV4.block_access_list` and
//! records every account/slot the block execution touched.
//!
//! [EIP-8025 / execution-specs `projects/zkevm`]:
//!   https://github.com/ethereum/execution-specs/tree/projects/zkevm

use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use anyhow::{anyhow, bail, Context, Result};

use libssz::SszDecode;
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;

use stateless_validator_common::new_payload_request::NewPayloadRequestAmsterdam;

// ---------- Wire framing ----------

/// SIOB schema identifier for Amsterdam (2 bytes, big-endian).
pub const STATELESS_INPUT_SCHEMA_ID: u16 = 0x0001;

// ---------- SSZ bounds (must match execution-specs `stateless_ssz.py`) ----------

const MAX_WITNESS_NODES: usize = 1 << 22;
const MAX_WITNESS_CODES: usize = 1 << 18;
const MAX_WITNESS_HEADERS: usize = 256;
const MAX_BYTES_PER_WITNESS_NODE: usize = 1 << 10;
const MAX_BYTES_PER_CODE: usize = 1 << 16;
const MAX_BYTES_PER_HEADER: usize = 1 << 10;
const MAX_OPTIONAL_FORK_ACTIVATION_VALUES: usize = 1;
const MAX_BLOB_SCHEDULES_PER_FORK: usize = 1;
const MAX_PUBLIC_KEYS: usize = 1 << 15;
const PUBLIC_KEY_BYTES: usize = 65;

// ---------- SSZ container types ----------
//
// These mirror the containers defined in
// `execution-specs/src/ethereum/forks/amsterdam/stateless_ssz.py`. Only the
// pieces not already exposed by `stateless-validator-common` are declared here.

/// SSZ container mirroring `ExecutionWitness` — the pre-state trie nodes,
/// contract codes, and ancestor headers needed to run the block statelessly.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszExecutionWitness {
    pub state: SszList<SszList<u8, MAX_BYTES_PER_WITNESS_NODE>, MAX_WITNESS_NODES>,
    pub codes: SszList<SszList<u8, MAX_BYTES_PER_CODE>, MAX_WITNESS_CODES>,
    pub headers: SszList<SszList<u8, MAX_BYTES_PER_HEADER>, MAX_WITNESS_HEADERS>,
}

/// SSZ container mirroring `ForkActivation`. Each field is a
/// zero-or-one-element list to encode Python's `Optional[U64]` in SSZ.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszForkActivation {
    pub block_number: SszList<u64, MAX_OPTIONAL_FORK_ACTIVATION_VALUES>,
    pub timestamp: SszList<u64, MAX_OPTIONAL_FORK_ACTIVATION_VALUES>,
}

/// SSZ container mirroring `BlobSchedule` (EIP-4844 blob params).
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszBlobSchedule {
    pub target: u64,
    pub max: u64,
    pub base_fee_update_fraction: u64,
}

/// SSZ container mirroring `ForkConfig` — the currently-active fork plus its
/// activation point and (optional) blob schedule.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszForkConfig {
    /// `ProtocolFork` enum value — see `stateless_ssz.py::PROTOCOL_FORKS`.
    pub fork: u64,
    pub activation: SszForkActivation,
    pub blob_schedule: SszList<SszBlobSchedule, MAX_BLOB_SCHEDULES_PER_FORK>,
}

/// SSZ container mirroring `ChainConfig` — chain id + active fork.
///
/// Compact single-fork descriptor; NOT the full history that
/// `alloy_genesis::ChainConfig` carries. Translation to alloy's shape is
/// straightforward because the encoder only needs the active fork name.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszChainConfig {
    pub chain_id: u64,
    pub active_fork: SszForkConfig,
}

/// Top-level SIOB container mirroring `SszStatelessInput`.
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszStatelessInput {
    pub new_payload_request: NewPayloadRequestAmsterdam,
    pub witness: SszExecutionWitness,
    pub chain_config: SszChainConfig,
    pub public_keys: SszList<[u8; PUBLIC_KEY_BYTES], MAX_PUBLIC_KEYS>,
}

/// SSZ container mirroring `SszStatelessValidationResult` — the output blob
/// the workload compares against `sha256(statelessOutputBytes)`.
///
/// Only decoded on the host as an optional cross-check (1c-relaxed: our guest
/// commits `gas_used`, not this container).
#[derive(Debug, Clone, SszEncode, SszDecode)]
pub struct SszStatelessValidationResult {
    pub new_payload_request_root: [u8; 32],
    pub successful_validation: bool,
    pub chain_config: SszChainConfig,
}

// ---------- Decode entry points ----------

/// Strip the 2-byte schema-id prefix and SSZ-decode the SIOB input container.
pub fn decode_stateless_input(bytes: &[u8]) -> Result<SszStatelessInput> {
    if bytes.len() < 2 {
        bail!("SIOB input too short for schema id (got {} bytes)", bytes.len());
    }
    let schema_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    if schema_id != STATELESS_INPUT_SCHEMA_ID {
        bail!(
            "unsupported SIOB schema id: 0x{:04x} (expected 0x{:04x})",
            schema_id,
            STATELESS_INPUT_SCHEMA_ID,
        );
    }
    SszStatelessInput::from_ssz_bytes(&bytes[2..])
        .map_err(|e| anyhow!("SSZ decode of SszStatelessInput failed: {:?}", e))
}

/// SSZ-decode the SIOB output container (no schema prefix, per spec).
pub fn decode_stateless_output(bytes: &[u8]) -> Result<SszStatelessValidationResult> {
    SszStatelessValidationResult::from_ssz_bytes(bytes)
        .map_err(|e| anyhow!("SSZ decode of SszStatelessValidationResult failed: {:?}", e))
}

// ---------- Block Access List (EIP-7928) — RLP payload ----------
//
// The BAL is stored inside `ExecutionPayloadV4.block_access_list` as opaque
// SSZ bytes; the actual encoding is RLP (per execution-specs
// `block_access_lists.py`). Field order and types below match the Python
// dataclasses in that file. Only fields we need for keys derivation are
// populated with strict types; leaf change data we opaquely skip (RLP list
// count check only) to keep code compact.

/// EIP-7928 `StorageChange` entry — one per (tx-index, slot) write.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalStorageChange {
    pub block_access_index: u64,
    /// New slot value after this change (U256, RLP-encoded).
    pub new_value: U256,
}

/// EIP-7928 `SlotChanges` — one per written storage slot.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalSlotChanges {
    /// 32-byte slot preimage.
    pub slot: U256,
    /// Ordered per-tx-index writes.
    pub changes: Vec<BalStorageChange>,
}

/// EIP-7928 `BalanceChange`.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalBalanceChange {
    pub block_access_index: u64,
    pub new_balance: U256,
}

/// EIP-7928 `NonceChange`.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalNonceChange {
    pub block_access_index: u64,
    pub new_nonce: u64,
}

/// EIP-7928 `CodeChange`.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalCodeChange {
    pub block_access_index: u64,
    pub new_code: Bytes,
}

/// EIP-7928 `AccountChanges` entry — one per touched account.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalAccountChanges {
    /// 20-byte address preimage.
    pub address: Address,
    /// Per-slot writes.
    pub storage_changes: Vec<BalSlotChanges>,
    /// Slots that were read but not written (32-byte slot preimages).
    pub storage_reads: Vec<U256>,
    pub balance_changes: Vec<BalBalanceChange>,
    pub nonce_changes: Vec<BalNonceChange>,
    pub code_changes: Vec<BalCodeChange>,
}

/// Decode the raw BAL RLP blob into the strongly-typed structure.
pub fn decode_bal(bal_rlp: &[u8]) -> Result<Vec<BalAccountChanges>> {
    let mut slice = bal_rlp;
    let list: Vec<BalAccountChanges> = <Vec<BalAccountChanges> as Decodable>::decode(&mut slice)
        .context("BAL RLP decode failed")?;
    if !slice.is_empty() {
        bail!("BAL RLP trailing bytes: {} left over after decode", slice.len());
    }
    Ok(list)
}

/// Derive the `witness.keys` preimage list from a decoded BAL. Contains every
/// 20-byte address the block touched (read or written) and every 32-byte slot
/// (both `storage_changes` and `storage_reads`). This is exactly what the
/// MFBD encoder ([`crate::mfbd::build_mfbd_from_parts`]) consumes via the
/// `witness_keys` slice to reconstruct trie-leaf preimages.
pub fn keys_from_bal(bal: &[BalAccountChanges]) -> Vec<Bytes> {
    let mut keys: Vec<Bytes> = Vec::with_capacity(bal.len() * 4);
    for ac in bal {
        // 20-byte address preimage.
        keys.push(Bytes::copy_from_slice(ac.address.as_slice()));
        // 32-byte slot preimages: writes then reads.
        for sc in &ac.storage_changes {
            keys.push(Bytes::from(sc.slot.to_be_bytes::<32>().to_vec()));
        }
        for slot in &ac.storage_reads {
            keys.push(Bytes::from(slot.to_be_bytes::<32>().to_vec()));
        }
    }
    keys
}

/// Convenience: end-to-end BAL → keys given the raw payload bytes.
pub fn keys_from_bal_bytes(bal_rlp: &[u8]) -> Result<Vec<Bytes>> {
    let bal = decode_bal(bal_rlp)?;
    Ok(keys_from_bal(&bal))
}

// ---------- Chain config translation ----------

/// Map a `SszChainConfig` to the fork-name string our MFBD encoder consumes
/// via [`crate::fork_base_from_chain_config`]-style dispatch.
///
/// Amsterdam is the only fork with SIOB coverage today; the ProtocolFork
/// enum values below mirror `stateless_ssz.py::PROTOCOL_FORKS` ordering.
pub fn fork_name_from_ssz(cfg: &SszChainConfig) -> Result<&'static str> {
    // Python `enum.IntEnum` value ordering per stateless_ssz.py PROTOCOL_FORKS.
    // Only Amsterdam is expected in practice (SIOB is Amsterdam-only).
    match cfg.active_fork.fork {
        // Osaka / earlier forks won't ship SIOB; if we ever see them, surface loudly.
        18 => Ok("Amsterdam"),
        n => bail!("unsupported SIOB active_fork enum value: {n} (Amsterdam=18 expected)"),
    }
}

// ---------- Cursor helpers exposed for the top-level constructor ----------

/// Flatten a nested `SszList<SszList<u8, _>, _>` into `Vec<Bytes>` — the shape
/// the MFBD encoder wants for `witness.state`, `witness.codes`, `witness.headers`.
pub fn ssz_bytes_list_to_bytes_vec<const OUTER: usize, const INNER: usize>(
    list: &SszList<SszList<u8, INNER>, OUTER>,
) -> Vec<Bytes> {
    // SszList<T,N> derefs to `[T]`; SszList<u8,INNER> derefs to `[u8]`.
    list.iter().map(|inner| Bytes::copy_from_slice(inner)).collect()
}
