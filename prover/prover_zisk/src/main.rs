// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

mod service;
mod stdin_builders;

use crate::service::{
    execute_block, load_program, parse_proof_kind, prove_block, run_service, run_test_service,
    run_test_service_eest, verify_proof, Engine, ExecMode, ExecuteOptions, Outcome, ProveOptions,
    ProverOpts, ServiceConfig, ZiskExecutor, ZiskProver,
};
use clap::{Parser, Subcommand, ValueEnum};
use eyre::{bail, eyre, Result};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};
use z6m_common::{fetch_block_and_witness, FetchRequest};
use zisk_sdk::ExecutorKind;

/// ZisK executor backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Executor {
    /// zisk-sdk Rust emulator (emulate on 16 threads + plan; no memlock, no install)
    Emulator,
    /// zisk-sdk ASM emulator (needs ziskup's emulator-asm tree and unlimited memlock)
    Assembly,
    /// One-thread ziskemu engine, in-process; execute-only, 20-30x less CPU
    Ziskemu,
}

impl Executor {
    fn exec_mode(self) -> ExecMode {
        match self {
            Executor::Emulator => ExecMode::Sdk(ExecutorKind::Emulator),
            Executor::Assembly => ExecMode::Sdk(ExecutorKind::Assembly),
            Executor::Ziskemu => ExecMode::Ziskemu,
        }
    }

    fn prover_kind(self) -> Result<ExecutorKind> {
        match self.exec_mode() {
            ExecMode::Sdk(kind) => Ok(kind),
            ExecMode::Ziskemu => {
                bail!("--executor ziskemu is execute-only; use emulator or assembly")
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "z6m_prover_zisk", about = "Zilkworm prover service (ZisK)")]
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
    #[arg(long, action = clap::ArgAction::SetTrue)]
    save_all_responses: bool,

    /// Service mode: fetch block + witness bundles only, skip proving and executing
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

    /// Proof mode for service proving: compressed (= vadcop), minimal or plonk
    #[arg(long, default_value = "compressed")]
    proof_type: String,

    /// Guest ELF to run instead of the one embedded at build time
    #[arg(long)]
    elf: Option<PathBuf>,

    /// ZisK executor backend
    #[arg(long, value_enum, env = "Z6M_ZISK_EXECUTOR", default_value_t = Executor::Emulator)]
    executor: Executor,

    /// Proving key directory (default: $ZISK_HOME/provingKey or ~/.zisk/provingKey)
    #[arg(long)]
    proving_key: Option<PathBuf>,

    /// Prove on a ZisK coordinator at this URL instead of in-process
    #[arg(long)]
    remote: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run program setup (ROM merkle + ASM build) and print the program VK; needs the proving key or --remote
    Setup,
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

        /// Also write the framed stdin to this path (a `ziskemu -i` input)
        #[arg(long)]
        save_input: Option<PathBuf>,
    },
    /// Generate, verify and save a proof for one block (needs the proving key or --remote)
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

        /// Proof output path (default: <data-dir>/<N>/proof<N>.bin)
        #[arg(long)]
        proof_path: Option<PathBuf>,

        /// Proof mode: compressed (= vadcop), minimal or plonk (default: the top-level --proof-type)
        #[arg(long)]
        proof_type: Option<String>,
    },
    /// Verify a saved proof against this guest's program VK (run `setup` once first)
    Verify {
        /// Proof file path
        #[arg(long, default_value = "proof.bin")]
        proof_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
    dotenv::dotenv().ok();
    let args = Args::parse();
    let exec_mode = args.executor.exec_mode();

    if args.test_service {
        if args.command.is_some() {
            bail!("--test-service cannot be combined with a subcommand");
        }
        let program = load_program(args.elf.as_deref())?;
        let mut zisk = ZiskExecutor::new(program, exec_mode)?;
        if let Some(test_dir) = args.test_dir {
            run_test_service_eest(
                &mut zisk,
                test_dir,
                args.execution_log_file,
                args.max_file_size,
            )?;
        } else {
            let start = args.start_block.ok_or_else(|| {
                eyre!("--test-service requires --start-block (or --test-dir for EEST tests)")
            })?;
            let end = args.end_block.ok_or_else(|| {
                eyre!("--test-service requires --end-block (or --test-dir for EEST tests)")
            })?;
            run_test_service(
                &mut zisk,
                start,
                end,
                args.execute_every,
                args.data_dir.clone(),
                args.execution_log_file,
            )?;
        }
        return Ok(());
    }

    let prover_opts = |proof_type: &str| -> Result<ProverOpts> {
        Ok(ProverOpts {
            executor: args.executor.prover_kind()?,
            proving_key: args.proving_key.clone(),
            remote: args.remote.clone(),
            proof_kind: parse_proof_kind(proof_type)?,
        })
    };

    if args.service {
        let rpc_url = args.rpc_url.clone().or_else(|| match &args.command {
            Some(Command::Fetch { rpc_url, .. }) => rpc_url.clone(),
            _ => None,
        });
        let rpc_url = rpc_url.ok_or_else(|| eyre!("--service requires --rpc-url"))?;
        let program = load_program(args.elf.as_deref())?;
        let proves = args.prove_every.is_some_and(|n| n > 0) && !args.download_only;
        let mut engine = if proves {
            Engine::Prove(ZiskProver::new(program, &prover_opts(&args.proof_type)?).await?)
        } else {
            Engine::Execute(ZiskExecutor::new(program, exec_mode)?)
        };
        let service_config = ServiceConfig {
            start_block: args.start_block,
            end_block: args.end_block,
            prove_every: args.prove_every,
            execute_every: args.execute_every,
            post_every: args.post_every,
            rpc_url,
            save_all_responses: args.save_all_responses,
            download_only: args.download_only,
            data_dir: args.data_dir.clone(),
            proof_type: args.proof_type.clone(),
        };
        return run_service(&mut engine, service_config).await;
    }

    match args.command {
        Some(Command::Setup) => {
            let program = load_program(args.elf.as_deref())?;
            let prover = ZiskProver::new(program, &prover_opts(&args.proof_type)?).await?;
            match prover.program().vk() {
                Ok(vk) => println!("Setup complete; program VK: {:?}", vk.vk),
                Err(e) => println!("Setup complete; program VK not cached locally ({e})"),
            }
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
            save_input,
        }) => {
            let program = load_program(args.elf.as_deref())?;
            let mut engine = Engine::Execute(ZiskExecutor::new(program, exec_mode)?);
            let opts = ExecuteOptions {
                block_number,
                file_name,
                is_test,
                data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                save_input,
            };
            let (_, outcome) = execute_block(&mut engine, opts).await?;
            if matches!(outcome, Outcome::Failed | Outcome::Aborted) {
                std::process::exit(1);
            }
        }
        Some(Command::Prove {
            block_number,
            file_name,
            is_test,
            data_dir,
            proof_path,
            proof_type,
        }) => {
            let proof_type = proof_type.unwrap_or_else(|| args.proof_type.clone());
            let program = load_program(args.elf.as_deref())?;
            let prover = ZiskProver::new(program, &prover_opts(&proof_type)?).await?;
            let log = prove_block(
                &prover,
                &ProveOptions {
                    block_number,
                    file_name,
                    is_test,
                    data_dir: data_dir.unwrap_or_else(|| args.data_dir.clone()),
                    proof_path,
                    proof_type,
                },
            )
            .await?;
            println!(
                "Proved block {} (gas_used={}, proof={})",
                log.block_number,
                log.gas_used,
                log.proof_path.display()
            );
        }
        Some(Command::Verify { proof_path }) => {
            let program = load_program(args.elf.as_deref())?;
            let pv = verify_proof(&program, &proof_path)?;
            println!(
                "Verified {}: gas_used={} pre_root={} post_root={} block_hash={} chain_id={}",
                proof_path.display(),
                pv.gas_used,
                pv.pre_state_root,
                pv.post_state_root,
                pv.block_hash,
                pv.chain_id
            );
        }
        None => {
            bail!("no command provided; pass --service, --test-service or a subcommand");
        }
    }

    Ok(())
}
