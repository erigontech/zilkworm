#![allow(unused_imports)]

use eyre::{bail, eyre, Result};
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

#[cfg(feature = "gpu")]
impl ProvingLimit {
    pub fn to_unrolled_level(&self) -> UnrolledProverLevel {
        match self {
            ProvingLimit::Base => UnrolledProverLevel::Base,
            ProvingLimit::FinalRecursion => UnrolledProverLevel::RecursionUnrolled,
            ProvingLimit::FinalProof => UnrolledProverLevel::RecursionUnified,
        }
    }
}

// ─── Cached setup data ─────────────────────────────────────────────────────

/// Serializable setup cache: everything needed to construct an UnrolledProver
/// without recomputing circuit setups.
#[cfg(feature = "gpu")]
#[derive(Serialize, Deserialize)]
pub struct SetupCache {
    pub max_level: UnrolledProverLevel,
    pub level_data: BTreeMap<UnrolledProverLevel, UnrolledProverLevelData>,
}

// ─── Setup computation ─────────────────────────────────────────────────────

/// Compute all level data for a given guest binary and proof target.
/// This is the expensive part (~75s) that we want to cache.
#[cfg(feature = "gpu")]
pub fn compute_setup(
    path_without_ext: &str,
    until: &ProvingLimit,
) -> SetupCache {
    let max_level = until.to_unrolled_level();
    let mut level_data = BTreeMap::new();

    // ── Base layer: z6m guest with Full machine (signed mul/div) ───────
    {
        let bin_path = format!("{}.bin", path_without_ext);
        let text_path = format!("{}.text", path_without_ext);
        let (binary, binary_u32) = read_binary(Path::new(&bin_path));
        let (text, text_u32) = read_binary(Path::new(&text_path));
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
                binary, text, binary_u32, text_u32,
                setup, compiled_layouts, hash_chain, preimage,
            },
        );
    }

    // ── Unrolled recursion layer ───────────────────────────────────────
    if max_level >= UnrolledProverLevel::RecursionUnrolled {
        let binary = RECURSION_UNROLLED_BIN.to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = RECURSION_UNROLLED_TXT.to_vec();
        let text_u32 = binary_u8_to_u32(&text);
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
        let previous = &level_data[&UnrolledProverLevel::Base];
        let (hash_chain, preimage) = UnrolledProgramSetup::continue_recursion_chain(
            &setup.end_params, &previous.hash_chain, &previous.preimage,
        );
        level_data.insert(
            UnrolledProverLevel::RecursionUnrolled,
            UnrolledProverLevelData {
                binary, text, binary_u32, text_u32,
                setup, compiled_layouts, hash_chain, preimage,
            },
        );
    }

    // ── Unified recursion layer ────────────────────────────────────────
    if max_level == UnrolledProverLevel::RecursionUnified {
        let binary = RECURSION_UNIFIED_BIN.to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = RECURSION_UNIFIED_TXT.to_vec();
        let text_u32 = binary_u8_to_u32(&text);
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
        let previous = &level_data[&UnrolledProverLevel::RecursionUnrolled];
        let (hash_chain, preimage) = UnrolledProgramSetup::continue_recursion_chain(
            &setup.end_params, &previous.hash_chain, &previous.preimage,
        );
        level_data.insert(
            UnrolledProverLevel::RecursionUnified,
            UnrolledProverLevelData {
                binary, text, binary_u32, text_u32,
                setup, compiled_layouts, hash_chain, preimage,
            },
        );
    }

    SetupCache { max_level, level_data }
}

/// Save a setup cache to disk using bincode.
#[cfg(feature = "gpu")]
pub fn save_setup(cache: &SetupCache, path: &Path) -> Result<()> {
    let data = bincode::serialize(cache)
        .map_err(|e| eyre!("failed to serialize setup: {}", e))?;
    std::fs::write(path, &data)
        .map_err(|e| eyre!("failed to write setup to {}: {}", path.display(), e))?;
    log::info!("Setup saved to {} ({:.1} MB)", path.display(), data.len() as f64 / 1e6);
    Ok(())
}

/// Load a setup cache from disk.
#[cfg(feature = "gpu")]
pub fn load_setup(path: &Path) -> Result<SetupCache> {
    let data = std::fs::read(path)
        .map_err(|e| eyre!("failed to read setup from {}: {}", path.display(), e))?;
    let cache: SetupCache = bincode::deserialize(&data)
        .map_err(|e| eyre!("failed to deserialize setup: {}", e))?;
    log::info!("Setup loaded from {} ({:.1} MB)", path.display(), data.len() as f64 / 1e6);
    Ok(cache)
}

// ─── GPU prover construction ───────────────────────────────────────────────

/// Build an UnrolledProver from cached setup data.
/// Only creates the ExecutionProver (GPU init) and registers binaries.
#[cfg(feature = "gpu")]
pub fn create_gpu_prover_from_cache(cache: SetupCache) -> UnrolledProver {
    let mut config = ExecutionProverConfiguration::default();
    config.replay_worker_threads_count = 8;
    config.host_allocators_per_job_count = 96;
    config.host_allocators_per_device_count = 32;
    config.min_free_host_allocators_per_job = 16;

    let mut prover = ExecutionProver::with_configuration(config);

    // Register each level's binary with the GPU prover
    for (&level, data) in &cache.level_data {
        let (kind, machine) = match level {
            UnrolledProverLevel::Base => (ExecutionKind::Unrolled, MachineType::Full),
            UnrolledProverLevel::RecursionUnrolled => (ExecutionKind::Unrolled, MachineType::Reduced),
            UnrolledProverLevel::RecursionUnified => (ExecutionKind::Unified, MachineType::Reduced),
        };
        prover.add_binary(
            level as usize,
            kind,
            machine,
            data.binary_u32.clone(),
            data.text_u32.clone(),
            None,
        );
    }

    UnrolledProver {
        max_level: cache.max_level,
        level_data: cache.level_data,
        prover,
    }
}

/// Create an UnrolledProver from scratch (computes setup + GPU init).
#[cfg(feature = "gpu")]
pub fn create_gpu_prover(path_without_ext: &str, until: &ProvingLimit) -> UnrolledProver {
    let cache = compute_setup(path_without_ext, until);
    create_gpu_prover_from_cache(cache)
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
