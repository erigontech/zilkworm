// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

mod ethproofs_client;
mod service;
mod stdin_builders;

use crate::ethproofs_client::EthProofsConfig;
use crate::service::{
    AppConfig, ExecuteOptions, FetchOptions, ProveOptions, ServiceConfig, SetupOptions,
    VerifyOptions, Z6mProverService,
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

    #[arg(long)]
    rpc_url: Option<String>,

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
    },
    /// Execute the guest program without proving
    Execute {
        /// Block number to execute
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Whether the input file is an Ethereum/tests file
        #[arg(long)]
        file_name: Option<PathBuf>,

        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

        /// Data directory
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Generate a proof for a block
    Prove {
        /// JSON file to load ethereum/tests format test from
        #[arg(long, default_value_t = 0)]
        block_number: u64,

        /// Whether the input file is an Ethereum/tests file
        #[arg(long)]
        file_name: Option<PathBuf>,

        #[arg(long, action = clap::ArgAction::SetTrue)]
        is_test: bool,

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
    // let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    // fmt().with_env_filter(filter).init();

    // dotenv::dotenv().ok();

    let args = Args::parse();

    // let ethproofs = match (
    //     args.ethproofs_endpoint.clone(),
    //     args.ethproofs_token.clone(),
    //     args.ethproofs_cluster_id,
    // ) {
    //     (Some(endpoint), Some(token), Some(cluster_id)) => Some(EthProofsConfig {
    //         endpoint,
    //         token,
    //         cluster_id,
    //     }),
    //     _ => None,
    // };

    // let app_config = AppConfig {
    //     data_dir: args.data_dir.clone(),
    //     rpc_url: args.rpc_url.clone(),
    //     save_all_responses: args.save_all_responses,
    //     ethproofs,
    // };

    let app = Z6mProverService::new(app_config)?;

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
        return Ok(());
    }

    match args.command {
        Some(Command::Setup { pk_path, vk_path }) => {
            app.setup_keys(SetupOptions { pk_path, vk_path }).await?;
        }
        Some(Command::Fetch {
            rpc_url,
            block_number,
            data_dir,
            save_all_responses,
            build_eth_test,
        }) => {
            let rpc = rpc_url
                .or_else(|| args.rpc_url.clone())
                .ok_or_else(|| eyre!("fetch requires --rpc-url"))?;
            let outcome = app
                .fetch_block(FetchOptions {
                    block_number,
                    rpc_url: rpc,
                    save_all_responses: save_all_responses || args.save_all_responses,
                    data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                    build_eth_test,
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
            let log = app.execute_block(ExecuteOptions {
                block_number,
                file_name,
                is_test,
                data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
            })?;
            println!(
                "Executed block {} (gas_used={}, cycles={}, prover_gas={}, syscall_count={})",
                log.block_number, log.gas_used, log.cycle_count, log.prover_gas, log.syscall_count
            );
        }
        Some(Command::Prove {
            block_number,
            file_name,
            is_test,
            data_dir,
            pk_path,
            proof_path,
            proof_type,
        }) => {
            let pk = pk_path.clone();

            let log = app
                .prove_block(&ProveOptions {
                    block_number,
                    file_name,
                    is_test,
                    data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                    pk_path: pk,
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
        Some(Command::Verify {
            proof_path,
            vk_path,
        }) => {
            app.verify_proof(VerifyOptions {
                proof_path,
                vk_path,
            })
            .await?;
        }
        None => {
            bail!("no command provided; pass --service or a subcommand");
        }
    }

    Ok(())
}
