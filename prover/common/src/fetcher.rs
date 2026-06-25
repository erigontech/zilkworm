// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use alloy_consensus::Header as ConsensusHeader;
use alloy_provider::{ext::DebugApi, Provider, ProviderBuilder};
use alloy_primitives::Bytes;
use alloy_rpc_types::Block as RpcBlock;
use alloy_rpc_types_debug::ExecutionWitness;
use eyre::{bail, eyre, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
    pub geth: bool,
    /// When true, regenerate the flat bundle even if a cached
    /// `flatWitnessBundle<N>.mfbd` already exists on disk. Also drops the
    /// cached block / block-RLP / witness JSON intermediates so the bundle
    /// is rebuilt from a fresh RPC fetch. Used by the live prover service so
    /// `--execute-every 1` always operates on a freshly-built bundle.
    pub force_rebuild: bool,
}

pub struct FetchOutcome {
    pub block_number: u64,
    pub block_directory: PathBuf,
    pub flat_bundle_path: PathBuf,
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
    let witness_path = block_dir.join(format!("executionWitness{}.json", block_number));
    let flat_bundle_path =
        block_dir.join(format!("flatWitnessBundle{}.mfbd", block_number));
    if request.force_rebuild {
        for stale in [&flat_bundle_path, &block_path, &block_rlp_path, &witness_path] {
            if stale.exists() {
                if let Err(err) = fs::remove_file(stale) {
                    warn!(
                        path = %stale.display(),
                        error = %err,
                        "force_rebuild: failed to remove stale cache file"
                    );
                }
            }
        }
    } else if flat_bundle_path.exists() {
        return Ok(FetchOutcome {
            block_number,
            block_directory: block_dir,
            flat_bundle_path,
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
    let block_ts_ms: u64 = u64::from(current_block.header.timestamp) * 1000;

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

    let payload = serde_json::json!({
        "block":   alloy_primitives::hex::encode_prefixed(&current_block_rlp),
        "headers": execution_witness.headers,
        "state":   execution_witness.state,
        "codes":   execution_witness.codes,
        "keys":    execution_witness.keys,
    });
    let witness_input = serde_json::to_vec(&payload)
        .wrap_err("failed to serialize witness JSON")?;
    {
        let now_ms: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        println!(
            "BEGIN_BUNDLE block={} block_ts_ms={} now_ms={}",
            block_number, block_ts_ms, now_ms
        );
    }
    let bundle_bytes = run_json_witness_to_flat_bundle(&witness_input)
        .wrap_err("json_witness_to_flat_bundle subprocess failed")?;
    fs::write(&flat_bundle_path, &bundle_bytes)?;

    debug!(
        %block_number,
        "fetched block data and wrote flat bundle to {:?}",
        flat_bundle_path,
    );

    Ok(FetchOutcome {
        block_number,
        block_directory: block_dir,
        flat_bundle_path,
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

/// Path to the C++ json_witness_to_flat_bundle binary built by the top-level
/// Makefile (`make json_witness_to_flat_bundle`).
const BUILDER_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../build/zilk_core/dev/cli/json_witness_to_flat_bundle"
);

/// Spawn json_witness_to_flat_bundle, pipe `input` to its stdin, and return
/// the stdout bytes.
fn run_json_witness_to_flat_bundle(input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(BUILDER_PATH)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .wrap_err_with(|| {
            format!(
                "spawn {} (run `make json_witness_to_flat_bundle` to build it)",
                BUILDER_PATH
            )
        })?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| eyre!("subprocess stdin not piped"))?;
        stdin.write_all(input)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("json_witness_to_flat_bundle exited with {:?}", out.status);
    }
    Ok(out.stdout)
}
