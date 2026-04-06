#![allow(unused_imports)]

use eyre::{bail, eyre, Result};
use execution_utils::{
    generate_oracle_data_for_universal_verifier, get_padded_binary, Machine, ProofList,
    ProofMetadata, ProgramProof, RecursionStrategy, UNIVERSAL_CIRCUIT_VERIFIER,
};
use prover::prover_stages::Proof;
use prover::risc_v_simulator::abstractions::non_determinism::QuasiUARTSource;
use prover::transcript::Blake2sBufferingTranscript;
use std::alloc::Global;
use std::path::Path;
use std::time::Instant;
use trace_and_split::fs_transform_for_memory_and_delegation_arguments;
use verifier_common::parse_field_els_as_u32_from_u16_limbs_checked;

#[cfg(feature = "gpu")]
use gpu_prover::circuit_type::MainCircuitType;
#[cfg(feature = "gpu")]
use gpu_prover::execution::prover::{ExecutableBinary, ExecutionProver};

/// Proving depth control.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ProvingLimit {
    /// Base proofs only (no recursion).
    Base,
    /// Base + 1st recursion layer.
    FinalRecursion,
    /// Base + both recursion layers (full proof).
    FinalProof,
}

// ─── GPU shared state ───────────────────────────────────────────────────────

#[cfg(feature = "gpu")]
pub struct GpuSharedState {
    pub prover: ExecutionProver<usize>,
}

#[cfg(feature = "gpu")]
impl GpuSharedState {
    const MAIN_BINARY_KEY: usize = 0;
    const RECURSION_BINARY_KEY: usize = 1;

    pub fn new(binary: &Vec<u32>, recursion_circuit_type: MainCircuitType) -> Self {
        assert!(
            recursion_circuit_type == MainCircuitType::ReducedRiscVMachine
                || recursion_circuit_type == MainCircuitType::ReducedRiscVLog23Machine,
            "Only ReducedRiscVMachine and ReducedRiscVLog23Machine are supported on GPU"
        );

        let main_binary = ExecutableBinary {
            key: Self::MAIN_BINARY_KEY,
            circuit_type: MainCircuitType::RiscVCycles,
            bytecode: binary.clone(),
        };
        let recursion_binary = ExecutableBinary {
            key: Self::RECURSION_BINARY_KEY,
            circuit_type: recursion_circuit_type,
            bytecode: get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER),
        };
        let prover = ExecutionProver::new(1, vec![main_binary, recursion_binary]);
        Self { prover }
    }
}

#[cfg(not(feature = "gpu"))]
#[allow(dead_code)]
pub struct GpuSharedState;

// ─── Core proving logic ─────────────────────────────────────────────────────

pub fn create_proofs_for_block(
    binary: &Vec<u32>,
    non_determinism_data: Vec<u32>,
    num_instances: usize,
    use_gpu: bool,
) -> Result<(ProofList, ProofMetadata)> {
    let worker = worker::Worker::new();

    let mut non_determinism_source = QuasiUARTSource::default();
    for entry in non_determinism_data {
        non_determinism_source.oracle.push_back(entry);
    }

    let (basic_proofs, delegation_proofs, register_values) = if use_gpu {
        #[cfg(feature = "gpu")]
        {
            println!("**** Proving using GPU (CUDA) ****");
            let recursion_circuit_type = MainCircuitType::ReducedRiscVMachine;
            let gpu_state = GpuSharedState::new(binary, recursion_circuit_type);

            let timer = Instant::now();
            let (final_register_values, basic_proofs, delegation_proofs) =
                gpu_state.prover.commit_memory_and_prove(
                    0,
                    &GpuSharedState::MAIN_BINARY_KEY,
                    num_instances,
                    non_determinism_source,
                );
            let elapsed = timer.elapsed().as_secs_f64();
            println!("**** GPU proofs generated in {:.3}s ****", elapsed);
            (basic_proofs, delegation_proofs, final_register_values.into())
        }
        #[cfg(not(feature = "gpu"))]
        {
            bail!("Compiled without GPU support. Rebuild with --features gpu");
        }
    } else {
        println!("**** Proving using CPU ****");
        let main_circuit_precomputations =
            setups::get_main_riscv_circuit_setup::<Global, Global>(binary, &worker);
        let delegation_precomputations =
            setups::all_delegation_circuits_precomputations::<Global, Global>(&worker);

        prover_examples::prove_image_execution(
            num_instances,
            binary,
            non_determinism_source,
            &main_circuit_precomputations,
            &delegation_precomputations,
            &worker,
        )
    };

    let proof_list = ProofList {
        basic_proofs,
        reduced_proofs: vec![],
        reduced_log_23_proofs: vec![],
        delegation_proofs,
    };

    let last_proof = proof_list.get_last_proof();
    let (end_params, prev_end_params_output) = get_end_params_output(last_proof, None);

    let prev_end_params_output_hash = prev_end_params_output.map(|data| {
        let mut tmp_hash = Blake2sBufferingTranscript::new();
        tmp_hash.absorb(&data);
        tmp_hash.finalize().0
    });

    let proof_metadata = ProofMetadata {
        basic_proof_count: proof_list.basic_proofs.len(),
        reduced_proof_count: 0,
        reduced_log_23_proof_count: 0,
        deprecated_final_proof_count: 0,
        delegation_proof_count: proof_list
            .delegation_proofs
            .iter()
            .map(|(i, x)| (*i, x.len()))
            .collect(),
        register_values,
        end_params,
        prev_end_params_output_hash,
        prev_end_params_output,
    };

    let total_delegation: usize = proof_list
        .delegation_proofs
        .iter()
        .map(|(_, x)| x.len())
        .sum();
    println!(
        "Created {} basic proofs and {} delegation proofs.",
        proof_list.basic_proofs.len(),
        total_delegation,
    );

    Ok((proof_list, proof_metadata))
}

// ─── Recursion ──────────────────────────────────────────────────────────────

pub fn create_recursion_proofs(
    proof_list: ProofList,
    proof_metadata: ProofMetadata,
    use_gpu: bool,
) -> Result<(ProofList, ProofMetadata)> {
    assert!(
        proof_metadata.basic_proof_count > 0,
        "Recursion proofs can be created only for basic proofs."
    );

    let binary = get_padded_binary(UNIVERSAL_CIRCUIT_VERIFIER);
    let worker = worker::Worker::new();
    let recursion_mode = RecursionStrategy::UseReducedLog23Machine;

    #[cfg(feature = "gpu")]
    let gpu_state = if use_gpu {
        Some(GpuSharedState::new(
            &binary,
            MainCircuitType::ReducedRiscVMachine,
        ))
    } else {
        None
    };

    let mut current_proof_list = proof_list;
    let mut current_proof_metadata = proof_metadata;
    let mut recursion_level = 0;

    loop {
        if recursion_mode.skip_first_layer() {
            println!("Skipping recursion.");
            break;
        }

        println!("*** Starting recursion level {} ***", recursion_level);
        let non_determinism_data = generate_oracle_data_for_universal_verifier(
            &current_proof_metadata,
            &current_proof_list,
        );

        let num_instances = current_proof_metadata.total_proofs();

        let mut non_determinism_source = QuasiUARTSource::default();
        for entry in non_determinism_data {
            non_determinism_source.oracle.push_back(entry);
        }

        let (reduced_proofs, delegation_proofs, register_values) = if use_gpu {
            #[cfg(feature = "gpu")]
            {
                let gpu_state = gpu_state.as_ref().unwrap();
                let timer = Instant::now();
                let (final_register_values, proofs, delegation_proofs) =
                    gpu_state.prover.commit_memory_and_prove(
                        0,
                        &GpuSharedState::RECURSION_BINARY_KEY,
                        num_instances,
                        non_determinism_source,
                    );
                let elapsed = timer.elapsed().as_secs_f64();
                println!(
                    "**** GPU recursion proofs generated in {:.3}s ****",
                    elapsed
                );
                (proofs, delegation_proofs, final_register_values.into())
            }
            #[cfg(not(feature = "gpu"))]
            {
                bail!("Compiled without GPU support. Rebuild with --features gpu");
            }
        } else {
            let main_circuit_precomputations =
                setups::get_reduced_riscv_circuit_setup::<Global, Global>(&binary, &worker);
            let delegation_precomputations =
                setups::all_delegation_circuits_precomputations::<Global, Global>(&worker);

            prover_examples::prove_image_execution_on_reduced_machine(
                num_instances,
                &binary,
                non_determinism_source,
                &main_circuit_precomputations,
                &delegation_precomputations,
                &worker,
            )
        };

        let new_proof_list = ProofList {
            basic_proofs: vec![],
            reduced_proofs,
            reduced_log_23_proofs: vec![],
            delegation_proofs,
        };

        let last_proof = new_proof_list.get_last_proof();
        let (end_params, prev_end_params_output) = get_end_params_output(
            last_proof,
            Some(current_proof_metadata.create_prev_metadata()),
        );

        let prev_end_params_output_hash = prev_end_params_output.map(|data| {
            let mut tmp_hash = Blake2sBufferingTranscript::new();
            tmp_hash.absorb(&data);
            tmp_hash.finalize().0
        });

        current_proof_metadata = ProofMetadata {
            basic_proof_count: 0,
            reduced_proof_count: new_proof_list.reduced_proofs.len(),
            reduced_log_23_proof_count: 0,
            deprecated_final_proof_count: 0,
            delegation_proof_count: new_proof_list
                .delegation_proofs
                .iter()
                .map(|(i, x)| (*i, x.len()))
                .collect(),
            register_values,
            end_params,
            prev_end_params_output_hash,
            prev_end_params_output,
        };
        current_proof_list = new_proof_list;

        recursion_level += 1;

        if recursion_mode.switch_to_second_recursion_layer(&current_proof_metadata) {
            println!("Stopping 1st recursion layer.");
            break;
        }
    }

    Ok((current_proof_list, current_proof_metadata))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn get_end_params_output(
    last_proof: &Proof,
    prev_end_params_output: Option<([u32; 8], Option<[u32; 16]>)>,
) -> ([u32; 8], Option<[u32; 16]>) {
    let end_params_output_suffix = get_end_params_output_suffix_from_proof(last_proof).unwrap();
    let end_params = end_params_output_suffix.0;

    let new_preimage = match prev_end_params_output {
        Some((prev_bin, prev_params)) => match prev_params {
            Some(prev_params) => {
                if prev_params[8..16] == prev_bin {
                    Some(prev_params)
                } else {
                    let mut end_params_output = [0u32; 16];
                    let mut hasher = Blake2sBufferingTranscript::new();
                    hasher.absorb(&prev_params);
                    let prev_params_hash = hasher.finalize().0;
                    for i in 0..8 {
                        end_params_output[i] = prev_params_hash[i];
                    }
                    for i in 8..16 {
                        end_params_output[i] = prev_bin[i - 8];
                    }
                    Some(end_params_output)
                }
            }
            None => {
                let mut end_params_output = [0u32; 16];
                for i in 8..16 {
                    end_params_output[i] = prev_bin[i - 8];
                }
                Some(end_params_output)
            }
        },
        None => None,
    };

    (end_params, new_preimage)
}

fn get_end_params_output_suffix_from_proof(
    last_proof: &Proof,
) -> Option<prover::transcript::Seed> {
    if last_proof.public_inputs.len() != 4 {
        return None;
    }

    let end_pc = parse_field_els_as_u32_from_u16_limbs_checked([
        last_proof.public_inputs[2],
        last_proof.public_inputs[3],
    ]);

    let mut hasher = Blake2sBufferingTranscript::new();
    hasher.absorb(&[end_pc]);

    for cap in &last_proof.setup_tree_caps {
        for entry in cap.cap.iter() {
            hasher.absorb(entry);
        }
    }
    Some(hasher.finalize_reset())
}

pub fn serialize_to_file<T: serde::Serialize>(el: &T, path: &Path) {
    let mut dst = std::fs::File::create(path).unwrap();
    serde_json::to_writer_pretty(&mut dst, el).unwrap();
}
