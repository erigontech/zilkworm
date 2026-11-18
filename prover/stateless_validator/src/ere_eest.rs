// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! EEST canonical stateless-input adapter: decodes `statelessInputBytes` and derives the MFBD `keys` preimages from the EIP-7928 BAL.

use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Decodable, RlpDecodable};
use anyhow::{anyhow, bail, Context, Result};

use stateless_validator_common::guest::input::{ProtocolFork, StatelessInput};

/// The active fork is carried in the 2-byte schema-id prefix.
pub fn decode_stateless_input(bytes: &[u8]) -> Result<(ProtocolFork, StatelessInput)> {
    StatelessInput::from_schema_prefixed_ssz(bytes)
        .map_err(|e| anyhow!("StatelessInput decode failed: {e:?}"))
}

// The BAL is opaque RLP in `ExecutionPayloadV4.block_access_list`; only key-derivation fields are strictly typed.

#[derive(Debug, Clone, RlpDecodable)]
pub struct BalStorageChange {
    pub block_access_index: u64,
    /// New slot value after this change (U256, RLP-encoded).
    pub new_value: U256,
}

#[derive(Debug, Clone, RlpDecodable)]
pub struct BalSlotChanges {
    /// 32-byte slot preimage.
    pub slot: U256,
    pub changes: Vec<BalStorageChange>,
}

#[derive(Debug, Clone, RlpDecodable)]
pub struct BalBalanceChange {
    pub block_access_index: u64,
    pub new_balance: U256,
}

#[derive(Debug, Clone, RlpDecodable)]
pub struct BalNonceChange {
    pub block_access_index: u64,
    pub new_nonce: u64,
}

#[derive(Debug, Clone, RlpDecodable)]
pub struct BalCodeChange {
    pub block_access_index: u64,
    pub new_code: Bytes,
}

/// Accounts read but not modified appear with empty change lists, so their address preimage is always present.
#[derive(Debug, Clone, RlpDecodable)]
pub struct BalAccountChanges {
    /// 20-byte address preimage.
    pub address: Address,
    pub storage_changes: Vec<BalSlotChanges>,
    /// Slots read but not written (32-byte slot preimages).
    pub storage_reads: Vec<U256>,
    pub balance_changes: Vec<BalBalanceChange>,
    pub nonce_changes: Vec<BalNonceChange>,
    pub code_changes: Vec<BalCodeChange>,
}

pub fn decode_bal(bal_rlp: &[u8]) -> Result<Vec<BalAccountChanges>> {
    let mut slice = bal_rlp;
    let list: Vec<BalAccountChanges> = <Vec<BalAccountChanges> as Decodable>::decode(&mut slice)
        .context("BAL RLP decode failed")?;
    if !slice.is_empty() {
        bail!("BAL RLP trailing bytes: {} left over after decode", slice.len());
    }
    Ok(list)
}

/// Every 20-byte address and 32-byte slot (changed or read) the block touched, as `witness.keys`.
pub fn keys_from_bal(bal: &[BalAccountChanges]) -> Vec<Bytes> {
    let mut keys: Vec<Bytes> = Vec::with_capacity(bal.len() * 4);
    for ac in bal {
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

pub fn keys_from_bal_bytes(bal_rlp: &[u8]) -> Result<Vec<Bytes>> {
    let bal = decode_bal(bal_rlp)?;
    Ok(keys_from_bal(&bal))
}

#[cfg(all(test, feature = "parity-check"))]
mod smoke {
    //! Smoke test on a canonical EEST fixture: set `Z6M_SIB_FIXTURE=<blockchain_tests/*.json>`; no-op when unset.

    #[test]
    fn from_ere_eest_smoke() {
        let Ok(path) = std::env::var("Z6M_SIB_FIXTURE") else {
            eprintln!("Z6M_SIB_FIXTURE unset; skipping");
            return;
        };
        let raw = std::fs::read(&path).expect("read fixture");
        let json: serde_json::Value = serde_json::from_slice(&raw).expect("parse fixture");
        let case = json.as_object().unwrap().values().next().unwrap();
        let block = case["blocks"].as_array().unwrap().last().unwrap();
        let hex = block["statelessInputBytes"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x");
        let bytes = alloy_primitives::hex::decode(hex).expect("hex");
        eprintln!(
            "network={} statelessInputBytes={} prefix=0x{:02x}{:02x}",
            case["network"], bytes.len(), bytes[0], bytes[1]
        );

        let prepared = crate::StatelessValidatorZilkwormInput::from_ere_eest(&bytes, true)
            .expect("from_ere_eest");
        assert_eq!(prepared.public_values.len(), 112, "PV must be 112 bytes");
        assert!(!prepared.flat_bundle.is_empty(), "flat_bundle empty");
        let pv = &prepared.public_values;
        eprintln!(
            "flat_bundle={} gas_used={} chain_id={}",
            prepared.flat_bundle.len(),
            u64::from_le_bytes(pv[0..8].try_into().unwrap()),
            u64::from_le_bytes(pv[104..112].try_into().unwrap()),
        );
    }

    /// Set `Z6M_SIB_DIR=<dir of *.json>`: prints block#, tx count, max tx gas_limit and gas_used (EIP-7825 caps a tx at 2**24).
    #[test]
    fn tx_gas_limits() {
        use alloy_consensus::{Transaction, TxEnvelope};
        use alloy_eips::eip2718::Decodable2718;
        use stateless_validator_common::guest::input::new_payload_request::NewPayloadRequest;

        let Ok(dir) = std::env::var("Z6M_SIB_DIR") else {
            eprintln!("Z6M_SIB_DIR unset; skipping");
            return;
        };
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        const CAP: u64 = 0x1000000;
        for path in files {
            let raw = std::fs::read(&path).expect("read fixture");
            let json: serde_json::Value = serde_json::from_slice(&raw).expect("parse");
            let case = json.as_object().unwrap().values().next().unwrap();
            let block = case["blocks"].as_array().unwrap().last().unwrap();
            let hex = block["statelessInputBytes"].as_str().unwrap().trim_start_matches("0x");
            let bytes = alloy_primitives::hex::decode(hex).expect("hex");
            let (_fork, si) = crate::ere_eest::decode_stateless_input(&bytes).expect("decode");
            if std::env::var("Z6M_TX_DETAIL").is_ok() {
                eprintln!(
                    "  witness: state_nodes={} codes={} (code_lens={:?}) headers={}",
                    si.witness.state.len(),
                    si.witness.codes.len(),
                    si.witness.codes.iter().map(|c| c.len()).collect::<Vec<_>>(),
                    si.witness.headers.len(),
                );
            }
            if std::env::var("Z6M_DUMP_CODES").is_ok() {
                for (ci, c) in si.witness.codes.iter().enumerate() {
                    let bytes: Vec<u8> = c.iter().copied().collect();
                    eprintln!("  code[{ci}] len={} hex={}", bytes.len(), alloy_primitives::hex::encode(&bytes));
                }
            }
            let NewPayloadRequest::Gloas(g) = &si.new_payload_request else { panic!("not Gloas") };
            let p = &g.execution_payload;
            if std::env::var("Z6M_DUMP_CALLDATA").is_ok() {
                use alloy_consensus::Transaction as _;
                for (ti, tx) in p.transactions.iter().enumerate().take(2) {
                    let raw: Vec<u8> = tx.iter().copied().collect();
                    let env = TxEnvelope::decode_2718(&mut raw.as_slice()).expect("decode tx");
                    eprintln!("  calldata[{ti}] len={} hex={}", env.input().len(),
                        alloy_primitives::hex::encode(env.input()));
                }
            }
            if std::env::var("Z6M_DUMP_T8N").is_ok() {
                use alloy_consensus::transaction::SignerRecoverable as _;
                use alloy_consensus::Transaction as _;
                let mut base_fee_be = p.base_fee_per_gas;
                base_fee_be.reverse();
                eprintln!(
                    "  env: number={} timestamp={} gas_limit={} coinbase=0x{} prev_randao=0x{} base_fee=0x{} beacon_root=0x{}",
                    p.block_number, p.timestamp, p.gas_limit,
                    alloy_primitives::hex::encode(p.fee_recipient),
                    alloy_primitives::hex::encode(p.prev_randao),
                    alloy_primitives::hex::encode(base_fee_be),
                    alloy_primitives::hex::encode(g.parent_beacon_block_root),
                );
                for (ti, tx) in p.transactions.iter().enumerate() {
                    let raw: Vec<u8> = tx.iter().copied().collect();
                    let env = TxEnvelope::decode_2718(&mut raw.as_slice()).expect("decode tx");
                    let sender = env.recover_signer().expect("recover sender");
                    eprintln!(
                        "  tx[{ti}]: sender={sender} nonce={} rawhex={}",
                        env.nonce(),
                        alloy_primitives::hex::encode(&raw),
                    );
                }
            }
            if let Ok(target) = std::env::var("Z6M_BAL_ADDR") {
                let bal_bytes: Vec<u8> = p.block_access_list.iter().copied().collect();
                let bal = crate::ere_eest::decode_bal(&bal_bytes).expect("decode bal");
                let want = target.trim_start_matches("0x").to_lowercase();
                for ac in &bal {
                    if alloy_primitives::hex::encode(ac.address.as_slice()) == want {
                        let writes: Vec<String> = ac.storage_changes.iter()
                            .map(|s| format!("0x{:x}", s.slot)).collect();
                        let reads: Vec<String> = ac.storage_reads.iter()
                            .map(|s| format!("0x{:x}", s)).collect();
                        eprintln!("  BAL[{target}] storage_changes={writes:?} storage_reads={reads:?}");
                    }
                }
                eprintln!("  BAL total accounts={}", bal.len());
            }
            let mut max_gl = 0u64;
            for (i, tx) in p.transactions.iter().enumerate() {
                let env = TxEnvelope::decode_2718(&mut tx.as_ref()).expect("decode tx");
                max_gl = max_gl.max(env.gas_limit());
                if std::env::var("Z6M_TX_DETAIL").is_ok() && i < 4 {
                    use alloy_consensus::Transaction as _;
                    let to = match env.to() {
                        Some(a) => format!("{a}"),
                        None => "CREATE".to_string(),
                    };
                    let input = env.input();
                    let zeros = input.iter().filter(|b| **b == 0).count();
                    let nonzeros = input.len() - zeros;
                    eprintln!(
                        "  tx[{i}] ty={} gas_limit={} to={} value>0={} input_len={} (z={} nz={}) access_list={}",
                        env.tx_type() as u8,
                        env.gas_limit(),
                        to,
                        env.value() > alloy_primitives::U256::ZERO,
                        input.len(),
                        zeros,
                        nonzeros,
                        env.access_list().map_or(0, |a| a.len()),
                    );
                }
            }
            eprintln!(
                "block={:>6} txs={:>3} max_tx_gas_limit={:>12} block_gas_used={:>12} over_7825_cap={}",
                p.block_number,
                p.transactions.len(),
                max_gl,
                p.gas_used,
                max_gl > CAP,
            );
        }
    }
}
