// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use crate::rlp_methods::{block_to_header_only_rlp, build_pre_state_rlp, build_pre_trie_rlp};
use crate::types::{
    BlockchainTestCase, EthTestAccessListItem, EthTestAccount, EthTestAuthorization,
    EthTestTransaction, SealEngine, TestBlock, TestHeader,
};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{BlockHeader, Header as ConsensusHeader, Transaction};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_provider::{ext::DebugApi, Provider, ProviderBuilder};
use alloy_rlp::Decodable;
use alloy_rpc_types::{Block as RpcBlock, BlockTransactions, Transaction as RPCTransaction};
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_trie::{TrieAccount, KECCAK_EMPTY};
use eyre::{bail, eyre, Context, Result};
use serde::Deserialize;
use rsp_mpt::EthereumState;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};
use url::Url;

/// Geth's `debug_executionWitness` response format.
/// Headers are JSON objects, codes/state can be maps (hash→hex) or lists.
#[derive(Deserialize, Debug)]
struct GethExecutionWitness {
    #[serde(default)]
    headers: Vec<serde_json::Value>,
    #[serde(default)]
    codes: serde_json::Value,
    #[serde(default)]
    state: serde_json::Value,
    #[serde(default)]
    keys: serde_json::Value,
}

/// Convert a geth witness response into the alloy `ExecutionWitness` format.
fn convert_geth_witness(geth: GethExecutionWitness) -> Result<ExecutionWitness> {
    // Headers: JSON objects → RLP-encoded bytes
    let headers: Vec<Bytes> = geth
        .headers
        .into_iter()
        .map(|h| {
            let header: ConsensusHeader =
                serde_json::from_value(h).wrap_err("failed to parse geth header")?;
            let mut buf = Vec::new();
            alloy_rlp::Encodable::encode(&header, &mut buf);
            Ok(Bytes::from(buf))
        })
        .collect::<Result<Vec<_>>>()?;

    let codes = extract_bytes_from_value(&geth.codes)
        .wrap_err("failed to convert geth codes")?;
    let state = extract_bytes_from_value(&geth.state)
        .wrap_err("failed to convert geth state")?;

    // Geth doesn't provide key preimages
    let keys = match &geth.keys {
        serde_json::Value::Array(arr) if !arr.is_empty() => {
            extract_bytes_from_value(&geth.keys)?
        }
        _ => {
            warn!("geth witness has no key preimages; preimage-dependent features will be limited");
            Vec::new()
        }
    };

    Ok(ExecutionWitness {
        state,
        codes,
        keys,
        headers,
    })
}

/// Extract a flat list of `Bytes` from a JSON value that is either:
/// - a map (`{"hash": "0xdata", ...}`) → take the values
/// - an array (`["0xdata", ...]`) → take each element
/// - null → empty vec
fn extract_bytes_from_value(value: &serde_json::Value) -> Result<Vec<Bytes>> {
    match value {
        serde_json::Value::Object(map) => map
            .values()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| eyre!("expected hex string in map value"))?;
                Ok(Bytes::from(
                    alloy_primitives::hex::decode(s.strip_prefix("0x").unwrap_or(s))
                        .wrap_err_with(|| format!("invalid hex: {}", s))?,
                ))
            })
            .collect(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or_else(|| eyre!("expected hex string in array"))?;
                Ok(Bytes::from(
                    alloy_primitives::hex::decode(s.strip_prefix("0x").unwrap_or(s))
                        .wrap_err_with(|| format!("invalid hex: {}", s))?,
                ))
            })
            .collect(),
        serde_json::Value::Null => Ok(Vec::new()),
        _ => bail!("unexpected JSON type for witness field: expected object, array, or null"),
    }
}

/// Fetch execution witness from a geth node using a raw JSON-RPC call.
async fn fetch_geth_execution_witness(
    rpc_url: &str,
    block_number: u64,
) -> Result<GethExecutionWitness> {
    let client = reqwest::Client::new();
    let block_hex = format!("0x{:x}", block_number);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "debug_executionWitness",
        "params": [block_hex],
        "id": 1
    });
    let resp: serde_json::Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .wrap_err("failed to send geth RPC request")?
        .json()
        .await
        .wrap_err("failed to parse geth RPC response")?;

    if let Some(error) = resp.get("error") {
        bail!("geth RPC error: {}", error);
    }

    let result = resp
        .get("result")
        .ok_or_else(|| eyre!("missing 'result' in geth RPC response"))?;
    serde_json::from_value(result.clone()).wrap_err("failed to deserialize geth ExecutionWitness")
}

/// Fetch geth execution witness with retry logic, converting to alloy format.
async fn fetch_geth_execution_witness_with_retry(
    rpc_url: &str,
    block_number: u64,
    max_retries: u32,
) -> Result<ExecutionWitness> {
    let mut attempts = 0;
    loop {
        match fetch_geth_execution_witness(rpc_url, block_number).await {
            Ok(geth_witness) => return convert_geth_witness(geth_witness),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err);
                }
                let delay = Duration::from_secs(2_u64.pow(attempts.min(5)));
                warn!(
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_secs = delay.as_secs(),
                    block_number = block_number,
                    error = %err,
                    "Failed to get geth execution witness, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

pub struct FetchRequest<'a> {
    pub rpc_url: &'a str,
    pub block_number: Option<u64>,
    pub data_dir: PathBuf,
    pub save_all_responses: bool,
    pub build_eth_test: bool,
    pub geth: bool,
}

pub struct FetchOutcome {
    pub block_number: u64,
    pub block_directory: PathBuf,
    pub unified_rlp_path: PathBuf,
}

pub async fn fetch_block_and_witness(request: FetchRequest<'_>) -> Result<FetchOutcome> {
    let url = Url::parse(request.rpc_url)?;
    let provider = ProviderBuilder::new().connect_http(url);

    let mut block_number = if let Some(num) = request.block_number {
        num
    } else {
        get_block_number_with_retry(&provider, 3).await?
    };

    if block_number == 0 {
        block_number = get_block_number_with_retry(&provider, 3).await?;
    }
    if block_number == 0 {
        bail!("cannot fetch block 0 without a parent");
    }

    let blocks_dir: PathBuf = request.data_dir.join("blocks");
    let block_dir: PathBuf = blocks_dir.join(block_number.to_string());
    std::fs::create_dir_all(&block_dir)?;

    let block_path = block_dir.join(format!("block{}.json", block_number));
    let block_rlp_path = block_dir.join(format!("blockRlp{}.json", block_number));
    let prev_number = block_number
        .checked_sub(1)
        .ok_or_else(|| eyre!("block {} has no parent", block_number))?;
    let prev_block_path = block_dir.join(format!("block{}.json", prev_number));
    let witness_path = block_dir.join(format!("executionWitness{}.json", block_number));
    let tests_path = block_dir.join(format!("ethTests{}.json", block_number));
    // let unified_map_path = block_dir.join(format!("inputRlpUnified{}.json", block_number));
    let unified_rlp_only_path =
        block_dir.join(format!("unifiedBlockAndStateRlp{}.bin", block_number));
    if unified_rlp_only_path.exists() {
        return Ok(FetchOutcome {
            block_number,
            block_directory: block_dir,
            unified_rlp_path: unified_rlp_only_path,
        });
    }

    let current_block: RpcBlock = if block_path.exists() {
        let block_json = fs::read_to_string(&block_path)?;
        serde_json::from_str(&block_json)?
    } else {
        let fetched = get_block_by_number_with_retry(&provider, block_number, 3)
            .await?
            .ok_or_else(|| eyre!("block {} not found", block_number))?;
        if request.save_all_responses {
            write_json(&block_path, &fetched)?;
        }
        fetched
    };

    let current_block_rlp: Bytes = if block_rlp_path.exists() {
        let block_rlp_json = fs::read_to_string(&block_rlp_path)?;
        serde_json::from_str(&block_rlp_json)?
    } else {
        let rlp = debug_get_raw_block_with_retry(&provider, block_number, 3).await?;
        if request.save_all_responses {
            write_json(&block_rlp_path, &rlp)?;
        }
        rlp
    };

    let prev_block: RpcBlock = if prev_block_path.exists() {
        let block_json = fs::read_to_string(&prev_block_path)?;
        serde_json::from_str(&block_json)?
    } else {
        let fetched = get_block_by_number_with_retry(&provider, prev_number, 3)
            .await?
            .ok_or_else(|| eyre!("block {} not found", prev_number))?;
        if request.save_all_responses {
            write_json(&prev_block_path, &fetched)?;
        }
        fetched
    };

    let prev_block_rlp = block_to_header_only_rlp(&prev_block)?;

    let execution_witness: ExecutionWitness = if witness_path.exists() {
        let witness_json = fs::read_to_string(&witness_path)?;
        match serde_json::from_str::<ExecutionWitness>(&witness_json) {
            Ok(w) => w,
            Err(e) if request.geth => {
                debug!("alloy format parse failed ({}), trying geth format...", e);
                let geth: GethExecutionWitness = serde_json::from_str(&witness_json)
                    .wrap_err("failed to parse witness file as geth format")?;
                convert_geth_witness(geth)?
            }
            Err(e) => {
                return Err(e).wrap_err(
                    "failed to parse witness file; if using geth, pass --geth flag",
                );
            }
        }
    } else if request.geth {
        let witness = fetch_geth_execution_witness_with_retry(request.rpc_url, block_number, 3)
            .await
            .wrap_err("failed to fetch geth execution witness after retries")?;
        if request.save_all_responses {
            write_json(&witness_path, &witness)?;
        }
        witness
    } else {
        let witness = debug_execution_witness_with_retry(&provider, block_number, 3)
            .await
            .wrap_err("failed to fetch execution witness after retries")?;
        if request.save_all_responses {
            write_json(&witness_path, &witness)?;
        }
        witness
    };

    if request.save_all_responses && !tests_path.exists() && request.build_eth_test {
        let eth_tests = build_eth_tests_case(
            block_number,
            &current_block,
            &current_block_rlp,
            &prev_block,
            &prev_block_rlp,
            &execution_witness,
        )?;
        write_json(&tests_path, &eth_tests)?;
    }

    let unified_rlp_map = build_unified_rlp_map(
        block_number,
        &current_block,
        &current_block_rlp,
        &prev_block,
        &prev_block_rlp,
        &execution_witness,
    )?;

    // if request.save_all_responses {
    //     write_json(&unified_map_path, &unified_rlp_map)?;
    // }

    if let Some(unified_rlp_bytes) = unified_rlp_map.get("unifiedBlockAndStateRlp") {
        fs::write(&unified_rlp_only_path, unified_rlp_bytes)?;
    } else {
        bail!("missing unifiedBlockAndStateRlp entry");
    }

    debug!(
        %block_number,
        "fetched block data and wrote unified rlp to {:?}",
        unified_rlp_only_path
    );

    Ok(FetchOutcome {
        block_number,
        block_directory: block_dir,
        unified_rlp_path: unified_rlp_only_path,
    })
}

// Helper functions for network retry logic
async fn get_block_number_with_retry<P>(provider: &P, max_retries: u32) -> Result<u64>
where
    P: Provider,
{
    let mut attempts = 0;

    loop {
        match provider.get_block_number().await {
            Ok(block_number) => return Ok(block_number),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err.into());
                }

                let delay = Duration::from_secs(2_u64.pow(attempts.min(5))); // Exponential backoff, max 32 seconds
                warn!(
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_secs = delay.as_secs(),
                    error = %err,
                    "Failed to get block number, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

async fn get_block_by_number_with_retry<P>(
    provider: &P,
    block_number: u64,
    max_retries: u32,
) -> Result<Option<RpcBlock>>
where
    P: Provider,
{
    let mut attempts = 0;

    loop {
        match provider.get_block_by_number(block_number.into()).await {
            Ok(block) => return Ok(block),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err.into());
                }

                let delay = Duration::from_secs(2_u64.pow(attempts.min(5)));
                warn!(
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_secs = delay.as_secs(),
                    block_number = block_number,
                    error = %err,
                    "Failed to get block by number, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

async fn debug_get_raw_block_with_retry<P>(
    provider: &P,
    block_number: u64,
    max_retries: u32,
) -> Result<Bytes>
where
    P: Provider + DebugApi,
{
    let mut attempts = 0;

    loop {
        match provider.debug_get_raw_block(block_number.into()).await {
            Ok(rlp) => return Ok(rlp),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err.into());
                }

                let delay = Duration::from_secs(2_u64.pow(attempts.min(5)));
                warn!(
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_secs = delay.as_secs(),
                    block_number = block_number,
                    error = %err,
                    "Failed to get raw block, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

async fn debug_execution_witness_with_retry<P>(
    provider: &P,
    block_number: u64,
    max_retries: u32,
) -> Result<ExecutionWitness>
where
    P: Provider + DebugApi,
{
    let mut attempts = 0;

    loop {
        match provider.debug_execution_witness(block_number.into()).await {
            Ok(witness) => return Ok(witness),
            Err(err) => {
                attempts += 1;
                if attempts >= max_retries {
                    return Err(err.into());
                }

                let delay = Duration::from_secs(2_u64.pow(attempts.min(5)));
                warn!(
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_secs = delay.as_secs(),
                    block_number = block_number,
                    error = %err,
                    "Failed to get execution witness, retrying..."
                );
                sleep(delay).await;
            }
        }
    }
}

pub fn write_json<T: ?Sized + Serialize>(path: &Path, value: &T) -> Result<()> {
    let file = fs::File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, value)?;
    Ok(())
}

fn build_unified_rlp_map(
    _block_number: u64,
    _current_block: &RpcBlock,
    block_rlp: &Bytes,
    previous_block: &RpcBlock,
    prev_block_rlp: &Bytes,
    witness: &ExecutionWitness,
) -> Result<BTreeMap<String, Bytes>> {
    let pre_state_root = previous_block.header.state_root;
    let state = EthereumState::from_execution_witness(witness, pre_state_root);

    let code_map: HashMap<B256, Bytes> = witness
        .codes
        .iter()
        .cloned()
        .map(|code| (keccak256(&code), code))
        .collect();

    let preimage_map: HashMap<B256, Bytes> = witness
        .keys
        .iter()
        .cloned()
        .map(|preimage| (keccak256(&preimage), preimage))
        .collect();

    let pre_state_rlp = build_pre_state_rlp(&state, &code_map, &preimage_map)?;

    let headers_rlp_list = alloy_rlp::encode(witness.headers.clone());

    let pre_trie_map = build_pre_trie_rlp(&witness.state)?;

    // Wrap the single block as a one-element v1 blocks-list.
    use crate::rlp_methods::{encode_rlp_list, MAINNET_FORK_NAME, RLP_FALSE, VERSION_V1};
    let ei = [RLP_FALSE];
    let block_entry: Vec<u8> = encode_rlp_list(&[block_rlp.as_ref(), &ei[..]]);
    let blocks_list_rlp: Vec<u8> = encode_rlp_list(&[block_entry.as_slice()]);

    let version = [VERSION_V1];
    let items: Vec<&[u8]> = vec![
        &version,
        MAINNET_FORK_NAME.as_bytes(),
        prev_block_rlp.as_ref(),
        blocks_list_rlp.as_ref(),
        pre_state_rlp.as_ref(),
        headers_rlp_list.as_ref(),
        pre_trie_map.as_ref(),
    ];
    let unified_rlp = alloy_rlp::encode(&items);

    let mut input_map = BTreeMap::<String, Bytes>::new();
    input_map.insert(
        "unifiedBlockAndStateRlp".to_string(),
        Bytes::from(unified_rlp),
    );

    Ok(input_map)
}

fn build_eth_tests_case(
    block_number: u64,
    current_block: &RpcBlock,
    block_rlp: &Bytes,
    previous_block: &RpcBlock,
    prev_block_rlp: &Bytes,
    witness: &ExecutionWitness,
) -> Result<BTreeMap<String, BlockchainTestCase>> {
    let pre_state_root = previous_block.header.state_root;
    let state = EthereumState::from_execution_witness(witness, pre_state_root);

    let code_map: HashMap<B256, Bytes> = witness
        .codes
        .iter()
        .cloned()
        .map(|code| (keccak256(&code), code))
        .collect();

    let preimage_map: HashMap<B256, Bytes> = witness
        .keys
        .iter()
        .cloned()
        .map(|preimage| (keccak256(&preimage), preimage))
        .collect();

    let pre = build_pre_state(&state, &code_map, &preimage_map);

    let transactions = match &current_block.transactions {
        BlockTransactions::Full(txs) => {
            let mut converted = Vec::with_capacity(txs.len());
            for tx in txs.iter() {
                converted.push(convert_transaction(tx)?);
            }
            Some(converted)
        }
        _ => None,
    };

    let block_case = TestBlock {
        block_header: Some(convert_header(&current_block.header)),
        rlp: block_rlp.clone(),
        expect_exception: None,
        transactions,
        uncle_headers: None,
        transaction_sequence: None,
        withdrawals: current_block.withdrawals.clone(),
    };

    let mut cases = BTreeMap::new();
    cases.insert(
        format!("block_{block_number}"),
        BlockchainTestCase {
            genesis_block_header: convert_header(&previous_block.header),
            genesis_rlp: Some(prev_block_rlp.clone()),
            blocks: vec![block_case],
            post_state: None,
            pre,
            lastblockhash: current_block.header.hash,
            network: "Cancun".to_string(),
            seal_engine: SealEngine::NoProof,
        },
    );

    Ok(cases)
}

fn build_pre_state(
    state: &EthereumState,
    code_map: &HashMap<B256, Bytes>,
    preimage_map: &HashMap<B256, Bytes>,
) -> BTreeMap<Address, EthTestAccount> {
    let mut accounts = BTreeMap::new();

    state.state_trie.for_each_leaves(|key, value| {
        let hashed_address = B256::from_slice(key);
        if let Some(address_bytes) = preimage_map.get(&hashed_address) {
            if address_bytes.len() != Address::len_bytes() {
                return;
            }
            let address = Address::from_slice(address_bytes.as_ref());
            let mut bytes = value;
            if let Ok(account) = TrieAccount::decode(&mut bytes) {
                let code = if account.code_hash == KECCAK_EMPTY {
                    Bytes::default()
                } else {
                    code_map
                        .get(&account.code_hash)
                        .cloned()
                        .unwrap_or_default()
                };

                let mut storage = BTreeMap::new();
                if let Some(storage_trie) = state.storage_tries.get(&hashed_address) {
                    storage_trie.for_each_leaves(|slot_key, slot_value| {
                        let hashed_slot = B256::from_slice(slot_key);
                        if let Some(slot_preimage) = preimage_map.get(&hashed_slot) {
                            if slot_preimage.len() == 32 {
                                let slot = U256::from_be_slice(slot_preimage.as_ref());
                                let mut slot_bytes = slot_value;
                                if let Ok(value) = U256::decode(&mut slot_bytes) {
                                    if !value.is_zero() {
                                        storage.insert(slot, value);
                                    }
                                }
                            }
                        }
                    });
                }

                accounts.insert(
                    address,
                    EthTestAccount {
                        balance: account.balance,
                        code,
                        nonce: U256::from(account.nonce),
                        storage,
                    },
                );
            }
        }
    });

    accounts
}

fn convert_transaction(tx: &RPCTransaction) -> Result<EthTestTransaction> {
    let from = tx.inner.recover_signer()?;
    let hash = Some(*tx.inner.hash());
    let ty = match tx.inner.tx_type() {
        alloy_consensus::TxType::Legacy => 0,
        alloy_consensus::TxType::Eip2930 => 1,
        alloy_consensus::TxType::Eip1559 => 2,
        alloy_consensus::TxType::Eip4844 => 3,
        alloy_consensus::TxType::Eip7702 => 4,
    };
    let transaction_type = if ty == 0 { None } else { Some(U256::from(ty)) };
    let gas_price = tx.gas_price().map(U256::from);
    let max_fee_per_gas = Some(U256::from(tx.max_fee_per_gas()));
    let max_priority_fee_per_gas = tx.max_priority_fee_per_gas().map(U256::from);
    let max_fee_per_blob_gas = tx.max_fee_per_blob_gas().map(U256::from);

    let access_list: Option<Vec<EthTestAccessListItem>> = tx.access_list().as_ref().map(|list| {
        list.0
            .iter()
            .map(|item| EthTestAccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect()
    });

    let authorization_list: Option<Vec<EthTestAuthorization>> =
        tx.authorization_list().as_ref().map(|list| {
            list.iter()
                .map(|auth| EthTestAuthorization {
                    chain_id: U256::from(auth.chain_id),
                    address: auth.address,
                    nonce: U256::from(auth.nonce),
                    y_parity: U256::from(if auth.y_parity() != 0 { 1u64 } else { 0u64 }),
                    r: auth.r(),
                    s: auth.s(),
                })
                .collect()
        });

    let blob_versioned_hashes = tx.blob_versioned_hashes().map(|hashes| hashes.to_vec());

    let (r, s, v) = {
        let sig = tx.inner.signature();
        (sig.r(), sig.s(), U256::from(sig.v()))
    };

    Ok(EthTestTransaction {
        transaction_type,
        data: tx.input().clone(),
        gas_limit: U256::from(tx.gas_limit()),
        gas_price,
        nonce: U256::from(tx.nonce()),
        r,
        s,
        v,
        value: tx.value(),
        chain_id: tx.chain_id().map(U256::from),
        access_list,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        max_fee_per_blob_gas,
        blob_versioned_hashes,
        authorization_list,
        to: tx.to(),
        from: Some(from),
        hash,
    })
}

fn convert_header(header: &alloy_rpc_types::Header) -> TestHeader {
    TestHeader {
        bloom: header.logs_bloom,
        coinbase: header.beneficiary,
        difficulty: header.difficulty,
        extra_data: header.extra_data.clone(),
        gas_limit: U256::from(header.gas_limit),
        gas_used: U256::from(header.gas_used),
        hash: header.hash,
        mix_hash: header.mix_hash().unwrap_or_default(),
        nonce: header.nonce,
        number: U256::from(header.number),
        parent_hash: header.parent_hash,
        receipt_trie: header.receipts_root,
        state_root: header.state_root,
        timestamp: U256::from(header.timestamp),
        transactions_trie: header.transactions_root,
        uncle_hash: header.ommers_hash,
        base_fee_per_gas: header.base_fee_per_gas.map(U256::from),
        withdrawals_root: header.withdrawals_root,
        blob_gas_used: header.blob_gas_used.map(U256::from),
        excess_blob_gas: header.excess_blob_gas.map(U256::from),
        parent_beacon_block_root: header.parent_beacon_block_root,
        requests_hash: header.requests_hash,
        target_blobs_per_block: None,
    }
}
