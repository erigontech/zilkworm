#![allow(unused_imports)]

use eyre::{bail, eyre, Result};
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;

#[cfg(feature = "gpu")]
use execution_utils::unrolled_gpu::{
    UnrolledProver, UnrolledProverLevel, UnrolledProverLevelData,
    RECURSION_UNIFIED_BIN, RECURSION_UNIFIED_TXT,
    RECURSION_UNROLLED_BIN, RECURSION_UNROLLED_TXT,
};
#[cfg(feature = "gpu")]
use execution_utils::unrolled::{
    compute_setup_for_machine_configuration, UnrolledProgramProof, UnrolledProgramSetup,
};
#[cfg(feature = "gpu")]
use execution_utils::unified_circuit::compute_unified_setup_for_machine_configuration;
#[cfg(feature = "gpu")]
use execution_utils::setups::{
    binary_u8_to_u32, get_unified_circuit_artifact_for_machine_type,
    get_unrolled_circuits_artifacts_for_machine_type, pad_bytecode_bytes_for_proving,
    pad_bytecode_for_proving, read_binary,
};
#[cfg(feature = "gpu")]
use gpu_prover::execution::prover::{
    ExecutionKind, ExecutionProver, ExecutionProverConfiguration,
};
#[cfg(feature = "gpu")]
use gpu_prover::machine_type::MachineType;
#[cfg(feature = "gpu")]
use riscv_transpiler::cycle::{
    IMStandardIsaConfig, IWithoutByteAccessIsaConfigWithDelegation,
};
#[cfg(feature = "gpu")]
use std::collections::BTreeMap;

#[cfg(not(feature = "gpu"))]
use execution_utils::unrolled::UnrolledProgramProof;

/// Proving depth control.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ProvingLimit {
    /// Base proofs only (no recursion).
    Base,
    /// Base + unrolled recursion layer.
    FinalRecursion,
    /// Base + unrolled + unified recursion (full proof).
    FinalProof,
}

/// Create an UnrolledProver for z6m's guest binary.
/// Uses MachineType::Full (with signed mul/div) for the base layer,
/// unlike the default CLI which uses FullUnsigned.
#[cfg(feature = "gpu")]
pub fn create_gpu_prover(
    path_without_ext: &str,
    until: &ProvingLimit,
) -> UnrolledProver {
    let mut config = ExecutionProverConfiguration::default();
    config.replay_worker_threads_count = 8;
    // Reduce host memory allocation to fit in ~8GB pinned memory
    config.host_allocators_per_job_count = 96;      // 6 GB
    config.host_allocators_per_device_count = 32;    // 2 GB
    config.min_free_host_allocators_per_job = 16;    // 1 GB

    let max_level = match until {
        ProvingLimit::Base => UnrolledProverLevel::Base,
        ProvingLimit::FinalRecursion => UnrolledProverLevel::RecursionUnrolled,
        ProvingLimit::FinalProof => UnrolledProverLevel::RecursionUnified,
    };

    let mut prover = ExecutionProver::with_configuration(config);
    let mut level_data = BTreeMap::new();

    // ── Base layer: z6m guest with Full machine (signed mul/div) ───────
    {
        let bin_path = format!("{}.bin", path_without_ext);
        let text_path = format!("{}.text", path_without_ext);
        let (binary, binary_u32) = read_binary(Path::new(&bin_path));
        let (text, text_u32) = read_binary(Path::new(&text_path));
        prover.add_binary(
            UnrolledProverLevel::Base as usize,
            ExecutionKind::Unrolled,
            MachineType::Full,  // z6m guest uses signed mul/div
            binary_u32.clone(),
            text_u32.clone(),
            None,
        );
        log::info!("Computing base layer setup (Full machine)");
        let mut padded_binary = binary.clone();
        pad_bytecode_bytes_for_proving(&mut padded_binary);
        let mut padded_text = text.clone();
        pad_bytecode_bytes_for_proving(&mut padded_text);
        let mut padded_binary_u32 = binary_u32.clone();
        pad_bytecode_for_proving(&mut padded_binary_u32);
        let setup = compute_setup_for_machine_configuration::<IMStandardIsaConfig>(
            &padded_binary, &padded_text,
        );
        let compiled_layouts =
            get_unrolled_circuits_artifacts_for_machine_type::<IMStandardIsaConfig>(
                &padded_binary_u32,
            );
        let (hash_chain, preimage) =
            UnrolledProgramSetup::begin_recursion_chain(&setup.end_params);
        level_data.insert(
            UnrolledProverLevel::Base,
            UnrolledProverLevelData {
                binary,
                text,
                binary_u32,
                text_u32,
                setup,
                compiled_layouts,
                hash_chain,
                preimage,
            },
        );
    }

    // ── Unrolled recursion layer ───────────────────────────────────────
    if max_level >= UnrolledProverLevel::RecursionUnrolled {
        let binary = RECURSION_UNROLLED_BIN.to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = RECURSION_UNROLLED_TXT.to_vec();
        let text_u32 = binary_u8_to_u32(&text);
        prover.add_binary(
            UnrolledProverLevel::RecursionUnrolled as usize,
            ExecutionKind::Unrolled,
            MachineType::Reduced,
            binary_u32.clone(),
            text_u32.clone(),
            None,
        );
        log::info!("Computing recursion in unrolled layer setup");
        let mut padded_binary = binary.clone();
        pad_bytecode_bytes_for_proving(&mut padded_binary);
        let mut padded_text = text.clone();
        pad_bytecode_bytes_for_proving(&mut padded_text);
        let mut padded_binary_u32 = binary_u32.clone();
        pad_bytecode_for_proving(&mut padded_binary_u32);
        let setup = compute_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_binary, &padded_text);
        let compiled_layouts = get_unrolled_circuits_artifacts_for_machine_type::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_binary_u32);
        let previous_level_data = &level_data[&UnrolledProverLevel::Base];
        let (hash_chain, preimage) = UnrolledProgramSetup::continue_recursion_chain(
            &setup.end_params,
            &previous_level_data.hash_chain,
            &previous_level_data.preimage,
        );
        level_data.insert(
            UnrolledProverLevel::RecursionUnrolled,
            UnrolledProverLevelData {
                binary,
                text,
                binary_u32,
                text_u32,
                setup,
                compiled_layouts,
                hash_chain,
                preimage,
            },
        );
    }

    // ── Unified recursion layer ────────────────────────────────────────
    if max_level == UnrolledProverLevel::RecursionUnified {
        let binary = RECURSION_UNIFIED_BIN.to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = RECURSION_UNIFIED_TXT.to_vec();
        let text_u32 = binary_u8_to_u32(&text);
        prover.add_binary(
            UnrolledProverLevel::RecursionUnified as usize,
            ExecutionKind::Unified,
            MachineType::Reduced,
            binary_u32.clone(),
            text_u32.clone(),
            None,
        );
        log::info!("Computing recursion in unified layer setup");
        let mut padded_binary = binary.clone();
        pad_bytecode_bytes_for_proving(&mut padded_binary);
        let mut padded_text = text.clone();
        pad_bytecode_bytes_for_proving(&mut padded_text);
        let mut padded_binary_u32 = binary_u32.clone();
        pad_bytecode_for_proving(&mut padded_binary_u32);
        let setup = compute_unified_setup_for_machine_configuration::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_binary, &padded_text);
        let compiled_layouts = get_unified_circuit_artifact_for_machine_type::<
            IWithoutByteAccessIsaConfigWithDelegation,
        >(&padded_binary_u32);
        let previous_level_data = &level_data[&UnrolledProverLevel::RecursionUnrolled];
        let (hash_chain, preimage) = UnrolledProgramSetup::continue_recursion_chain(
            &setup.end_params,
            &previous_level_data.hash_chain,
            &previous_level_data.preimage,
        );
        level_data.insert(
            UnrolledProverLevel::RecursionUnified,
            UnrolledProverLevelData {
                binary,
                text,
                binary_u32,
                text_u32,
                setup,
                compiled_layouts,
                hash_chain,
                preimage,
            },
        );
    }

    UnrolledProver {
        max_level,
        level_data,
        prover,
    }
}

/// Prove a block using GPU. Returns (proof, cycles).
#[cfg(feature = "gpu")]
pub fn gpu_prove(
    prover: &UnrolledProver,
    non_determinism_data: Vec<u32>,
    batch_id: u64,
) -> (UnrolledProgramProof, u64) {
    let source = QuasiUARTSource::new_with_reads(non_determinism_data);
    prover.prove(batch_id, source)
}

pub fn serialize_to_file<T: serde::Serialize>(el: &T, path: &Path) {
    let mut dst = std::fs::File::create(path).unwrap();
    serde_json::to_writer_pretty(&mut dst, el).unwrap();
}
