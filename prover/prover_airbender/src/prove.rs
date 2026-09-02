#![allow(unused_imports)]

use eyre::{bail, eyre, Result};
use riscv_transpiler::abstractions::non_determinism::QuasiUARTSource;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

#[cfg(feature = "gpu")]
use execution_utils::unrolled_gpu::{
    RuntimeExecutionProver, UnrolledProver, UnrolledProverLevel, UnrolledProverLevelData,
};
#[cfg(feature = "gpu")]
use execution_utils::verifier_binaries;
#[cfg(feature = "gpu")]
use execution_utils::{RecursionArtifact, RecursionLayer};
#[cfg(feature = "gpu")]
use verifier_common::{
    security_100::Security100Marker, security_80::Security80Marker, SecurityMarker, SecurityModel,
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

/// Proving depth control — matches the CLI's ProofTarget naming.
#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ProvingLimit {
    /// Base proofs only (no recursion).
    Base,
    /// Base + unrolled recursion.
    Unrolled,
    /// Base + unrolled + unified recursion.
    Unified,
}

#[cfg(feature = "gpu")]
impl ProvingLimit {
    pub fn to_unrolled_level(&self) -> UnrolledProverLevel {
        match self {
            ProvingLimit::Base => UnrolledProverLevel::Base,
            ProvingLimit::Unrolled => UnrolledProverLevel::RecursionUnrolled,
            ProvingLimit::Unified => UnrolledProverLevel::RecursionUnified,
        }
    }
}

// ─── Cached setup data ─────────────────────────────────────────────────────

/// Serializable setup cache: everything needed to construct an UnrolledProver
/// without recomputing circuit setups.
///
/// `security_100` records which security model the recursion-layer verifier
/// binaries were selected for; the GPU prover must be constructed with the
/// same model (SecurityModel has no serde impls, hence the bool).
#[cfg(feature = "gpu")]
#[derive(Serialize, Deserialize)]
pub struct SetupCache {
    pub max_level: UnrolledProverLevel,
    pub level_data: BTreeMap<UnrolledProverLevel, UnrolledProverLevelData>,
    pub security_100: bool,
}

#[cfg(feature = "gpu")]
impl SetupCache {
    pub fn security(&self) -> SecurityModel {
        if self.security_100 {
            SecurityModel::Security100
        } else {
            SecurityModel::Security80
        }
    }
}

// ─── Setup computation ─────────────────────────────────────────────────────

/// Compute all level data for a given guest binary and proof target.
/// This is the expensive part (~75s) that we want to cache.
#[cfg(feature = "gpu")]
pub fn compute_setup(
    path_without_ext: &str,
    until: &ProvingLimit,
    security: SecurityModel,
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
        let binary = verifier_binaries::recursion_artifact(
            security, RecursionLayer::Unrolled, RecursionArtifact::Bin,
        ).to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = verifier_binaries::recursion_artifact(
            security, RecursionLayer::Unrolled, RecursionArtifact::Txt,
        ).to_vec();
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
        let binary = verifier_binaries::recursion_artifact(
            security, RecursionLayer::Unified, RecursionArtifact::Bin,
        ).to_vec();
        let binary_u32 = binary_u8_to_u32(&binary);
        let text = verifier_binaries::recursion_artifact(
            security, RecursionLayer::Unified, RecursionArtifact::Txt,
        ).to_vec();
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

    SetupCache {
        max_level,
        level_data,
        security_100: matches!(security, SecurityModel::Security100),
    }
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

/// Save the unified-layer setup and layouts in the format expected by the
/// matter-labs/ethereum-prover WASM verifier.
///
/// The verifier (proof_verifier_js/wasm/src/lib.rs) expects:
///   setup.bin  = bincode-2.x(standard) of UnrolledProgramSetup
///   layout.bin = bincode-2.x(standard) of CompiledCircuitsSet
///
/// Both are decoded with `bincode::serde::decode_from_slice(.., bincode::config::standard())`.
/// Only the unified recursion layer is used by the WASM verifier
/// (`verify_proof_in_unified_layer(.., input_is_unrolled=false)`).
#[cfg(feature = "gpu")]
pub fn save_for_wasm_verifier(cache: &SetupCache, dir: &Path) -> Result<()> {
    use bincode2::config;
    use bincode2::serde::encode_to_vec;

    let unified = cache
        .level_data
        .get(&UnrolledProverLevel::RecursionUnified)
        .ok_or_else(|| eyre!("setup cache does not contain unified recursion level"))?;

    std::fs::create_dir_all(dir)
        .map_err(|e| eyre!("failed to create {}: {}", dir.display(), e))?;

    let setup_path = dir.join("setup.bin");
    let setup_bytes = encode_to_vec(&unified.setup, config::standard())
        .map_err(|e| eyre!("failed to encode UnrolledProgramSetup: {}", e))?;
    std::fs::write(&setup_path, &setup_bytes)
        .map_err(|e| eyre!("failed to write {}: {}", setup_path.display(), e))?;
    log::info!(
        "WASM verifier setup saved to {} ({:.1} MB)",
        setup_path.display(),
        setup_bytes.len() as f64 / 1e6
    );

    let layout_path = dir.join("layout.bin");
    let layout_bytes = encode_to_vec(&unified.compiled_layouts, config::standard())
        .map_err(|e| eyre!("failed to encode CompiledCircuitsSet: {}", e))?;
    std::fs::write(&layout_path, &layout_bytes)
        .map_err(|e| eyre!("failed to write {}: {}", layout_path.display(), e))?;
    log::info!(
        "WASM verifier layout saved to {} ({:.1} MB)",
        layout_path.display(),
        layout_bytes.len() as f64 / 1e6
    );

    // Single-file verification key in the security-tagged envelope format
    // (EVKEY001): the only key format that carries the security level, and
    // required for 100-bit proofs (the legacy split key is assumed 80-bit).
    let vk_path = dir.join("vk.bin");
    let mut vk_bytes =
        Vec::with_capacity(setup_bytes.len() + layout_bytes.len() + 10);
    vk_bytes.extend_from_slice(VK_ENVELOPE_MAGIC);
    vk_bytes.push(ENVELOPE_FORMAT_VERSION);
    vk_bytes.push(security_wire_bits(cache.security()));
    vk_bytes.extend_from_slice(&setup_bytes);
    vk_bytes.extend_from_slice(&layout_bytes);
    std::fs::write(&vk_path, &vk_bytes)
        .map_err(|e| eyre!("failed to write {}: {}", vk_path.display(), e))?;
    log::info!(
        "WASM verifier key saved to {} ({:.1} MB)",
        vk_path.display(),
        vk_bytes.len() as f64 / 1e6
    );

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

/// Register each level's binary with the GPU prover.
#[cfg(feature = "gpu")]
fn register_binaries<S: SecurityMarker>(prover: &mut ExecutionProver<S>, cache: &SetupCache) {
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
}

/// Build an UnrolledProver from cached setup data.
/// Only creates the ExecutionProver (GPU init) and registers binaries.
#[cfg(feature = "gpu")]
pub fn create_gpu_prover_from_cache(cache: SetupCache) -> UnrolledProver {
    let mut config = ExecutionProverConfiguration::default();
    config.replay_worker_threads_count = 8;
    config.host_allocators_per_job_count = 96;
    config.host_allocators_per_device_count = 32;
    config.min_free_host_allocators_per_job = 16;

    let prover = match cache.security() {
        SecurityModel::Security80 => {
            let mut prover =
                ExecutionProver::<Security80Marker>::with_configuration_80(config);
            register_binaries(&mut prover, &cache);
            RuntimeExecutionProver::Security80(prover)
        }
        SecurityModel::Security100 => {
            let mut prover =
                ExecutionProver::<Security100Marker>::with_configuration_100(config);
            register_binaries(&mut prover, &cache);
            RuntimeExecutionProver::Security100(prover)
        }
    };

    UnrolledProver {
        max_level: cache.max_level,
        level_data: cache.level_data,
        prover,
        base_is_full_machine: true,
    }
}

/// Create an UnrolledProver from scratch (computes setup + GPU init).
#[cfg(feature = "gpu")]
pub fn create_gpu_prover(
    path_without_ext: &str,
    until: &ProvingLimit,
    security: SecurityModel,
) -> UnrolledProver {
    let cache = compute_setup(path_without_ext, until, security);
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

/// Security-tagged envelope magics used by the matter-labs WASM verifier
/// (proof_verifier_js): proofs and verification keys carry an 8-byte magic,
/// a format version, and the security level in bits. Legacy un-enveloped
/// artifacts are assumed to be 80-bit by the verifier, so 100-bit proofs
/// MUST be enveloped.
pub const PROOF_ENVELOPE_MAGIC: &[u8; 8] = b"EPROOF01";
pub const VK_ENVELOPE_MAGIC: &[u8; 8] = b"EVKEY001";
const ENVELOPE_FORMAT_VERSION: u8 = 1;

fn security_wire_bits(security: verifier_common::SecurityModel) -> u8 {
    match security {
        verifier_common::SecurityModel::Security80 => 80,
        verifier_common::SecurityModel::Security100 => 100,
    }
}

/// Serialize proof in the format expected by the matter-labs WASM verifier:
/// gzip(EPROOF01 envelope + bincode 2.x standard config). This is what the
/// proof_verifier_js WASM verifier's `deserialize_proof_bytes` consumes,
/// and what ethproofs.org / dApps that use that verifier expect.
pub fn serialize_proof_to_bytes_enveloped<T: serde::Serialize>(
    el: &T,
    security: verifier_common::SecurityModel,
) -> Vec<u8> {
    use std::io::Write;
    let bin2 = bincode2::serde::encode_to_vec(el, bincode2::config::standard())
        .expect("failed to encode proof (bincode 2.x)");
    let mut enveloped = Vec::with_capacity(bin2.len() + 10);
    enveloped.extend_from_slice(PROOF_ENVELOPE_MAGIC);
    enveloped.push(ENVELOPE_FORMAT_VERSION);
    enveloped.push(security_wire_bits(security));
    enveloped.extend_from_slice(&bin2);
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&enveloped).expect("failed to gzip proof");
    enc.finish().expect("failed to finish gzip stream")
}

/// Legacy format: gzip(bincode) without the security envelope. The WASM
/// verifier treats these as 80-bit proofs.
pub fn serialize_proof_to_bytes<T: serde::Serialize>(el: &T) -> Vec<u8> {
    use std::io::Write;
    let bin2 = bincode2::serde::encode_to_vec(el, bincode2::config::standard())
        .expect("failed to encode proof (bincode 2.x)");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&bin2).expect("failed to gzip proof");
    enc.finish().expect("failed to finish gzip stream")
}

/// Serialize proof to disk in the same gzipped enveloped format as
/// `serialize_proof_to_bytes_enveloped` so `proof.bin` files are directly
/// verifiable by the standard WASM verifier without any conversion step.
pub fn serialize_proof_to_file_enveloped<T: serde::Serialize>(
    el: &T,
    security: verifier_common::SecurityModel,
    path: &Path,
) {
    let data = serialize_proof_to_bytes_enveloped(el, security);
    std::fs::write(path, &data).expect("failed to write proof");
}

/// Legacy on-disk format without the security envelope.
pub fn serialize_proof_to_file<T: serde::Serialize>(el: &T, path: &Path) {
    let data = serialize_proof_to_bytes(el);
    std::fs::write(path, &data).expect("failed to write proof");
}
