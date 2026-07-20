// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

mod service;
mod stdin_builders;

use z6m_common::EthProofsConfig;
use z6m_common::{fetch_block_and_witness, FetchRequest};
use crate::service::{
    AppConfig, ExecuteOptions, ProveOptions, ServiceConfig,
    Z6mProverService,
};
use clap::{Parser, Subcommand};
use eyre::{bail, eyre, Result};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "z6m_prover", about = "Zilkworm prover service")]
struct Args {
    /// Run the continuous prover service (requires --rpc-url)
    ///
    /// Processes blocks from --start-block (default: chain head + 1) to
    /// --end-block (default: follow the chain head), fetching block + witness
    /// and proving/executing per --prove-every / --execute-every.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    service: bool,

    /// Run offline test mode (conflicts with --service)
    ///
    /// With --test-dir, executes EEST fixtures from that directory. Otherwise
    /// requires --start-block/--end-block and executes already-downloaded
    /// bundles from --data-dir. No RPC access, no proving.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "service")]
    test_service: bool,

    /// Ethereum JSON-RPC endpoint (must expose debug_getRawBlock and debug_executionWitness)
    #[arg(long)]
    rpc_url: Option<String>,

    /// Root data directory (e.g. /mnt/data, not /mnt/data/blocks)
    ///
    /// Block artifacts are written to <data-dir>/blocks/<N>/; execution and
    /// proving logs are appended at the root.
    #[arg(long, default_value = "temp")]
    data_dir: PathBuf,

    /// Also save raw RPC JSON responses next to each block's flat bundle
    ///
    /// Writes block<N>.json, blockRlp<N>.json and executionWitness<N>.json;
    /// the flatWitnessBundle<N>.mfbd bundle is always written regardless. In
    /// service mode this also fetches blocks that match no prove/execute
    /// interval.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    save_all_responses: bool,

    /// Service mode: fetch block + witness bundles only, skip proving and executing
    ///
    /// Continuously downloads each block's flat bundle into
    /// <data-dir>/blocks/<N>/, taking precedence over --prove-every and
    /// --execute-every.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    download_only: bool,

    /// Service mode: prove blocks whose number is divisible by N (0 or unset: never)
    #[arg(long)]
    prove_every: Option<u64>,

    /// Execute (without proving) blocks whose number is divisible by N (0 or unset: never)
    ///
    /// Skipped for blocks that also match --prove-every. Also used by
    /// --test-service without --test-dir, where it defaults to 1 (every block).
    #[arg(long)]
    execute_every: Option<u64>,

    /// Reserved posting interval; currently unused
    #[arg(long)]
    post_every: Option<u64>,

    /// First block to process (service default: chain head + 1; required by --test-service without --test-dir)
    #[arg(long)]
    start_block: Option<u64>,

    /// Last block to process, inclusive; the service exits after it (default: follow the chain head)
    #[arg(long)]
    end_block: Option<u64>,

    /// Execution log path for --test-service (default: executionLogs.log in --data-dir or --test-dir)
    #[arg(long)]
    execution_log_file: Option<PathBuf>,

    /// Directory of EEST fixtures for --test-service, scanned recursively for .mfbd/.json files
    #[arg(long)]
    test_dir: Option<PathBuf>,

    /// Skip EEST test files larger than this many bytes (0 = no limit)
    #[arg(long, default_value = "20971520")]
    max_file_size: u64,

    /// Proving key path; currently unused (the key is generated in-process at startup)
    #[arg(long, default_value = "pk.bin")]
    pk_path: PathBuf,

    /// Proof mode for service proving: core, compressed, groth16 or plonk (unknown values fall back to compressed)
    #[arg(long, default_value = "compressed")]
    proof_type: String,

    /// EthProofs API endpoint; reporting is enabled only when endpoint, token and cluster id are all set
    #[arg(long)]
    ethproofs_endpoint: Option<String>,

    /// EthProofs API token (see --ethproofs-endpoint)
    #[arg(long)]
    ethproofs_token: Option<String>,

    /// EthProofs cluster id to report under (see --ethproofs-endpoint)
    #[arg(long)]
    ethproofs_cluster_id: Option<u64>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate proving and verifying keys (currently a no-op)
    Setup {
        /// File path to save the proving key
        #[arg(long, default_value = "pk.bin")]
        pk_path: PathBuf,
        /// File path to save the verifying key
        #[arg(long, default_value = "vk.bin")]
        vk_path: PathBuf,
    },
    /// Fetch a block and its witness over RPC and write the flat bundle
    ///
    /// Writes <data-dir>/blocks/<N>/flatWitnessBundle<N>.mfbd, reusing a
    /// cached bundle if one already exists (unlike service mode, which
    /// force-rebuilds).
    Fetch {
        /// RPC endpoint URL (falls back to the top-level --rpc-url)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Block number to fetch (unset or 0: latest chain head)
        #[arg(long)]
        block_number: Option<u64>,

        /// Output root directory (falls back to the top-level --data-dir)
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Also save raw RPC JSON responses next to the bundle
        #[arg(long, action = clap::ArgAction::SetTrue)]
        save_all_responses: bool,

        /// Use geth's debug_executionWitness format instead of reth/alloy
        #[arg(long, action = clap::ArgAction::SetTrue)]
        geth: bool,
    },
    /// Execute the guest program for one block without proving
    Execute {
        /// Block number to execute; input read from <data-dir>/blocks/<N>/ (required unless --file-name is set)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Explicit input file path, overriding block-number resolution
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Treat the input as an ethereum/tests JSON fixture instead of an .mfbd bundle
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Root data directory (falls back to the top-level --data-dir)
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Generate a proof for one block
    ///
    /// Current implementation proves in compressed mode via the CUDA prover
    /// and does not write the proof to disk.
    Prove {
        /// Block number to prove; input read from <data-dir>/blocks/<N>/ (required unless --file-name is set)
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Explicit input file path, overriding block-number resolution
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Treat the input as an ethereum/tests JSON fixture instead of an .mfbd bundle
        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Root data directory (falls back to the top-level --data-dir)
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Proving key path (currently unused)
        #[arg(long, default_value = "pk.bin")]
        pk_path: PathBuf,

        /// Proof output path (currently unused)
        #[arg(long)]
        proof_path: Option<PathBuf>,

        /// Proof mode: core, compressed, groth16 or plonk (currently ignored by this subcommand)
        #[arg(long, default_value = "compressed")]
        proof_type: String,
    },
    /// Verify a proof against a verifying key (currently a no-op)
    Verify {
        /// Proof file path
        #[arg(long, default_value = "proof.bin")]
        proof_path: PathBuf,
        /// Verifying key path
        #[arg(long, default_value = "vk.bin")]
        vk_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // // Set up tracing with info level by default
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
    dotenv::dotenv().ok();
    let args = Args::parse();

    if args.test_service {
        if args.command.is_some() {
            bail!("--test-service cannot be combined with a subcommand");
        }
        if let Some(test_dir) = args.test_dir {
            Z6mProverService::run_test_service_eest(
                test_dir,
                args.execution_log_file.clone(),
                args.max_file_size,
            )
            .await?;
        } else {
            let start = args.start_block.ok_or_else(|| eyre!("--test-service requires --start-block (or --test-dir for EEST tests)"))?;
            let end = args.end_block.ok_or_else(|| eyre!("--test-service requires --end-block (or --test-dir for EEST tests)"))?;
            Z6mProverService::run_test_service(
                start,
                end,
                args.execute_every,
                args.data_dir.clone(),
                args.execution_log_file.clone(),
            )
            .await?;
        }
        return Ok(());
    }

    if args.service || matches!(args.command, Some(Command::Prove { .. })) {
        let ethproofs = match (
            args.ethproofs_endpoint.clone(),
            args.ethproofs_token.clone(),
            args.ethproofs_cluster_id,
        ) {
            (Some(endpoint), Some(token), Some(cluster_id)) => Some(EthProofsConfig {
                endpoint,
                token,
                cluster_id,
            }),
            _ => None,
        };

        let app_config = AppConfig {
            data_dir: args.data_dir.clone(),
            rpc_url: args.rpc_url.clone(),
            save_all_responses: args.save_all_responses,
            ethproofs,
        };

        let mut app = Z6mProverService::new(app_config).await?;

        if args.service {
            let rpc_url = args.rpc_url.clone().or_else(|| {
                args.command.as_ref().and_then(|cmd| match cmd {
                    Command::Fetch { rpc_url, .. } => rpc_url.clone(),
                    _ => None,
                })
            });
            let rpc_url = rpc_url.ok_or_else(|| eyre!("--service requires --rpc-url"))?;

            let service_config = ServiceConfig {
                start_block: args.start_block,
                end_block: args.end_block,
                prove_every: args.prove_every,
                execute_every: args.execute_every,
                post_every: args.post_every,
                rpc_url,
                save_all_responses: args.save_all_responses,
                download_only: args.download_only,
                proving_key_path: Some(args.pk_path.clone()),
                proof_type: args.proof_type.clone(),
            };
            app.run_service(service_config).await?;
        } else if let Some(Command::Prove {
            block_number,
            file_name,
            is_test,
            data_dir,
            pk_path: _,
            proof_path,
            proof_type,
        }) = args.command
        {
            let log = app
                .prove_block(&ProveOptions {
                    block_number,
                    file_name,
                    is_test,
                    data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                    proof_path,
                    proof_type,
                })
                .await?;
            println!(
                "Proved block {} (gas_used={}, proof={})",
                log.block_number,
                log.gas_used,
                log.proof_path.display()
            );
        }
        return Ok(());
    }

    match args.command {
        Some(Command::Setup { pk_path: _, vk_path: _ }) => {
            // app.setup_keys(SetupOptions { pk_path, vk_path }).await?;
        }
        Some(Command::Fetch {
            rpc_url,
            block_number,
            data_dir,
            save_all_responses,
            geth,
        }) => {
            let rpc = rpc_url
                .or_else(|| args.rpc_url.clone())
                .ok_or_else(|| eyre!("fetch requires --rpc-url"))?;
            let outcome = fetch_block_and_witness(FetchRequest {
                block_number,
                rpc_url: &rpc,
                save_all_responses: save_all_responses || args.save_all_responses,
                data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                geth,
                force_rebuild: false,
            })
            .await?;
            println!(
                "Fetched block {} into {}",
                outcome.block_number,
                outcome.block_directory.display()
            );
        }
        Some(Command::Execute {
            block_number,
            file_name,
            is_test,
            data_dir,
        }) => {
            let opts = ExecuteOptions {
                block_number,
                file_name,
                is_test,
                data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
            };
            let log = Z6mProverService::execute_block_static(opts).await.unwrap();

            if log.gas_used == 0 {
                // execute_block_static already emitted the FAILED block + error! line.
                std::process::exit(1);
            }
            println!(
                "Executed block {} (gas_used={}, cycles={}, prover_gas={}, syscall_count={})",
                log.block_number, log.gas_used, log.cycle_count, log.prover_gas, log.syscall_count
            );
        }
        Some(Command::Prove { .. }) => {
            unreachable!("Prove is handled by the service path above");
        }
        Some(Command::Verify {
            proof_path: _,
            vk_path: _,
        }) => {
            //     app.verify_proof(VerifyOptions {
            //         proof_path,
            //         vk_path,
            //     })
            //     .await?;
        }
        None => {
            bail!("no command provided; pass --service or a subcommand");
        }
    }

    Ok(())
}
