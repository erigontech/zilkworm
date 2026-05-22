mod ethproofs_client;
mod service;
mod stdin_builders;

use crate::ethproofs_client::EthProofsConfig;
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
    #[arg(long, action = clap::ArgAction::SetTrue)]
    service: bool,

    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "service")]
    test_service: bool,

    #[arg(long)]
    rpc_url: Option<String>,

    /// Root data directory containing a blocks/ subdirectory (e.g. /mnt/data, not /mnt/data/blocks)
    #[arg(long, default_value = "temp")]
    data_dir: PathBuf,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    save_all_responses: bool,

    #[arg(long)]
    prove_every: Option<u64>,

    #[arg(long)]
    execute_every: Option<u64>,

    #[arg(long)]
    post_every: Option<u64>,

    #[arg(long)]
    start_block: Option<u64>,

    #[arg(long)]
    end_block: Option<u64>,

    /// Custom path for the execution log output (only used in --test-service mode)
    #[arg(long)]
    execution_log_file: Option<PathBuf>,

    /// If set, write one log file per input fixture under this directory (mirrors --test-dir layout).
    /// Mutually exclusive with --execution-log-file.
    #[arg(long, conflicts_with = "execution_log_file")]
    execution_log_dir: Option<PathBuf>,

    /// Directory of pre-converted batched-RLP EEST fixtures to run in test-service mode.
    #[arg(long)]
    test_dir: Option<PathBuf>,

    /// Max test file size in bytes (default 20MB, 0 = no limit)
    #[arg(long, default_value = "20971520")]
    max_file_size: u64,

    #[arg(long, default_value = "pk.bin")]
    pk_path: PathBuf,

    #[arg(long, default_value = "compressed")]
    proof_type: String,

    #[arg(long)]
    ethproofs_endpoint: Option<String>,

    #[arg(long)]
    ethproofs_token: Option<String>,

    #[arg(long)]
    ethproofs_cluster_id: Option<u64>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run setup to generate proving and verifying keys
    Setup {
        #[arg(long, default_value = "pk.bin")]
        pk_path: PathBuf,
        /// File path to save verifying key
        #[arg(long, default_value = "vk.bin")]
        vk_path: PathBuf,
    },
    /// Fetch block and witness from RPC
    Fetch {
        /// RPC endpoint URL
        #[arg(long)]
        rpc_url: Option<String>,

        /// Block number to fetch
        #[arg(long)]
        block_number: Option<u64>,

        /// Output directory
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Whether to save all the json files to disk after download
        #[arg(long, action = clap::ArgAction::SetTrue)]
        save_all_responses: bool,

        /// Whether to create an ethereum/tests format json file too
        #[arg(long, action = clap::ArgAction::SetTrue)]
        build_eth_test: bool,

        /// Use geth's debug_executionWitness format instead of reth/alloy format
        #[arg(long, action = clap::ArgAction::SetTrue)]
        geth: bool,
    },
    /// Execute the guest program without proving
    Execute {
        /// Block number to execute
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Path to the unified RLP input file (overrides --block-number lookup)
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Generate a proof for a block
    Prove {
        /// Block number to prove
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Path to the unified RLP input file (overrides --block-number lookup)
        #[arg(long)]
        file_name: Option<PathBuf>,

        /// Data directory
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Proving key path
        #[arg(long, default_value = "pk.bin")]
        pk_path: PathBuf,

        /// Proof output path
        #[arg(long)]
        proof_path: Option<PathBuf>,

        /// Proof type: core, compressed, groth16, plonk
        #[arg(long, default_value = "compressed")]
        proof_type: String,
    },
    /// Verify a proof using a verification key
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
                args.execution_log_dir.clone(),
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
                proving_key_path: Some(args.pk_path.clone()),
                proof_type: args.proof_type.clone(),
            };
            app.run_service(service_config).await?;
        } else if let Some(Command::Prove {
            block_number,
            file_name,
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
            build_eth_test,
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
                build_eth_test,
                geth,
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
            data_dir,
        }) => {
            let opts = ExecuteOptions {
                block_number,
                file_name,
                data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
            };
            let log = Z6mProverService::execute_block_static(opts).await.unwrap();

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
