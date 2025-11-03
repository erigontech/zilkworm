//! SP1 prover CLI with 4 modes using bincode v2.0.1 (serde)

use clap::Parser;
use sp1_sdk::{
    include_elf, ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use std::{
    fs,
    io::{BufReader, BufWriter},
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const SILK_ST_ELF: &[u8] = include_elf!("z6m_guest");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run setup only: produce pk/vk and save to disk.
    #[arg(long)]
    setup: bool,

    /// Execute the guest program without proving.
    #[arg(long)]
    execute: bool,

    /// Prove using an existing pk (reads pk_path) and save proof to disk.
    #[arg(long)]
    prove: bool,

    /// Verify a proof from disk against a vk from disk.
    #[arg(long)]
    verify: bool,

    /// First input written to SP1Stdin.
    #[arg(long, default_value = "1")]
    n: u32,

    /// JSON file to read, minify, and pass as bytes to the guest (second input).
    #[arg(long, default_value = "test.json")]
    file_name: String,

    /// File path to persist/read proving key.
    #[arg(long, default_value = "pk.bin")]
    pk_path: String,

    /// File path to persist/read verifying key.
    #[arg(long, default_value = "vk.bin")]
    vk_path: String,

    /// File path to persist/read proof.
    #[arg(long, default_value = "proof.bin")]
    proof_path: String,
}

fn exactly_one_true(flags: &[bool]) -> bool {
    flags.iter().filter(|&&b| b).count() == 1
}

fn build_stdin(n: u32, json_path: &str) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(&n);

    let raw = fs::read_to_string(json_path).expect("failed to read JSON file");
    let value: serde_json::Value = serde_json::from_str(&raw).expect("invalid JSON");
    let minified = serde_json::to_string(&value).expect("failed to minify JSON");
    stdin.write_slice(minified.as_bytes());

    println!("n: {}", n);
    println!("Input JSON bytes: {}", minified.len());
    stdin
}

fn main() {
    // Logger + env
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    if !exactly_one_true(&[args.setup, args.execute, args.prove, args.verify]) {
        eprintln!("Error: you must specify exactly one of --setup, --execute, --prove, or --verify.");
        std::process::exit(1);
    }

    // Prover client
    let client = ProverClient::from_env();

    // bincode v2 config (use defaults; keep consistent across read/write!)
    let cfg = bincode::config::standard();

    if args.setup {
        // --- SETUP: produce pk/vk and persist with bincode v2 (serde) ---
        let (pk, vk) = client.setup(SILK_ST_ELF);

        std::fs::create_dir_all(".").unwrap();

        let mut fpk = BufWriter::new(fs::File::create(&args.pk_path).expect("create pk file"));
        bincode::serde::encode_into_std_write(&pk, &mut fpk, cfg).expect("write pk");
        let mut fvk = BufWriter::new(fs::File::create(&args.vk_path).expect("create vk file"));
        bincode::serde::encode_into_std_write(&vk, &mut fvk, cfg).expect("write vk");

        println!("Setup completed. Saved pk -> {}, vk -> {}", args.pk_path, args.vk_path);
        return;
    }

    if args.execute {
        // --- EXECUTE: run without proving ---
        let stdin = build_stdin(args.n, &args.file_name);
        let (mut output, report) = client.execute(SILK_ST_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("Cumulative Gas Used: {}", output.read::<u64>());
        println!("Number of cycles: {}", report.total_instruction_count());
        return;
    }

    if args.prove {
        // --- PROVE: load pk from disk, run prove, save proof with bincode v2 ---
        let pk: SP1ProvingKey = {
            let mut r = BufReader::new(fs::File::open(&args.pk_path).expect("open pk file"));
            bincode::serde::decode_from_std_read(&mut r, cfg).expect("read pk")
        };

        let stdin = build_stdin(args.n, &args.file_name);

        let mut proof = client.prove(&pk, &stdin).run().expect("failed to generate proof");
        println!("Successfully generated proof!");
        println!(
            "Cumulative Gas Used: {}",
            proof.public_values.read::<u64>()
        );

        let mut fp = BufWriter::new(fs::File::create(&args.proof_path).expect("create proof file"));
        bincode::serde::encode_into_std_write(&proof, &mut fp, cfg).expect("write proof");
        println!("Saved proof -> {}", args.proof_path);
        return;
    }

    if args.verify {
        // --- VERIFY: load proof + vk from disk and verify ---
        let mut proof: SP1ProofWithPublicValues = {
            let mut r = BufReader::new(fs::File::open(&args.proof_path).expect("open proof"));
            bincode::serde::decode_from_std_read(&mut r, cfg).expect("read proof")
        };
        let vk: SP1VerifyingKey = {
            let mut r = BufReader::new(fs::File::open(&args.vk_path).expect("open vk"));
            bincode::serde::decode_from_std_read(&mut r, cfg).expect("read vk")
        };

        ProverClient::from_env()
            .verify(&proof, &vk)
            .expect("failed to verify proof");

        println!("Successfully verified proof!");

        println!("Cumulative Gas Used: {}", proof.public_values.read::<u64>());
        return;
    }
}
