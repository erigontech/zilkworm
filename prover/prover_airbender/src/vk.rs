//! The verification key (EVKEY001 v2) and proof verification against it.
//!
//! A key binds proofs to one guest: a proof is accepted only if the recursion chain hash its
//! final verifier outputs (output[8..16]) is one of the key's three expected chain hashes, for
//! zero, one, or two and more unrolled recursion layers. Those hashes are recomputed from the
//! guest binary and the fsv recursion verifier binaries in FSV_DIR, with the Blake modes of the
//! RECURSION_*_BLAKE variables, never taken from a proof.
//!
//! Adapted from matter-labs/ethereum-prover ethereum_prover/src/verification_key_format.rs,
//! verifier_artifacts.rs and verification.rs (MIT OR Apache-2.0).

use crate::guest::GuestFiles;
use crate::proof_format::proof_words_from_file;
use alloy_primitives::keccak256;
use eyre::{ensure, eyre, Result};
use full_statement_verifier::unified_circuit_statement::verify_unified_circuit_recursion_layer_sec_100;
use full_statement_verifier::verifier_common::errors::DebugErrorCreator;
use full_statement_verifier::verifier_common::fsv_binaries::BlakeMode;
use full_statement_verifier::verifier_common::USE_REDUCED_BLAKE2_ROUNDS;
use prover_pipeline::{unified_verification_chain_hashes, ProgramSource};

pub const VERIFICATION_KEY_MAGIC: [u8; 8] = *b"EVKEY001";
const VERIFICATION_KEY_FORMAT_VERSION: u8 = 2;
const VERIFICATION_KEY_SECURITY: u8 = 100;

/// Stack of the threads that recompute setups (the key) and run the unified verifier.
const SETUPS_STACK_SIZE: usize = 1 << 30;
const VERIFIER_STACK_SIZE: usize = 1 << 27;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerificationKey {
    magic: [u8; 8],
    version: u8,
    security: u8,
    /// keccak256 of the guest's .bin file
    pub app_bin_keccak: [u8; 32],
    /// keccak256 of the guest's .text file
    pub app_text_keccak: [u8; 32],
    pub expected_chain_hashes: [[u32; 8]; 3],
}

impl VerificationKey {
    pub fn new(
        app_bin_keccak: [u8; 32],
        app_text_keccak: [u8; 32],
        expected_chain_hashes: [[u32; 8]; 3],
    ) -> Self {
        Self {
            magic: VERIFICATION_KEY_MAGIC,
            version: VERIFICATION_KEY_FORMAT_VERSION,
            security: VERIFICATION_KEY_SECURITY,
            app_bin_keccak,
            app_text_keccak,
            expected_chain_hashes,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode2::serde::encode_to_vec(self, bincode2::config::standard())
            .map_err(|e| eyre!("failed to encode the verification key: {e}"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 10 && bytes[..8] == VERIFICATION_KEY_MAGIC,
            "not an EVKEY001 verification key"
        );
        ensure!(
            bytes[8] == VERIFICATION_KEY_FORMAT_VERSION && bytes[9] == VERIFICATION_KEY_SECURITY,
            "unsupported verification key version {} / security {}",
            bytes[8],
            bytes[9]
        );
        let (key, read): (Self, usize) =
            bincode2::serde::decode_from_slice(bytes, bincode2::config::standard())
                .map_err(|e| eyre!("failed to decode the verification key: {e}"))?;
        ensure!(
            read == bytes.len(),
            "trailing bytes after the verification key"
        );
        Ok(key)
    }

    /// Computes the key of the guest. Recomputes the setups of the guest and of the fsv
    /// verifier programs, which takes a while.
    pub fn compute(guest: &GuestFiles) -> Result<Self> {
        check_recursion_environment()?;
        let app_bin_keccak = keccak256(std::fs::read(&guest.bin)?).0;
        let app_text_keccak = keccak256(std::fs::read(&guest.text)?).0;
        let source = ProgramSource::from_paths(guest.bin_str()?, Some(guest.text_str()?));
        let hashes = std::thread::Builder::new()
            .name("verification key".to_string())
            .stack_size(SETUPS_STACK_SIZE)
            .spawn(move || unified_verification_chain_hashes(&source))?
            .join()
            .map_err(|p| {
                eyre!(
                    "computing the chain hashes panicked: {}",
                    crate::guest::panic_message(p.as_ref())
                )
            })?
            .map_err(|e| eyre!("failed to compute the trusted chain hashes: {e}"))?;
        Ok(Self::new(app_bin_keccak, app_text_keccak, hashes))
    }
}

/// Verifies a proof file against the key and returns the verifier's output: output[0..8] is the
/// guest's public output, output[8..16] the recursion chain, one the key trusts.
pub fn verify_proof_file(proof_file: &[u8], key: &VerificationKey) -> Result<[u32; 16]> {
    let words = proof_words_from_file(proof_file)?;
    let output = std::thread::Builder::new()
        .name("unified verifier".to_string())
        .stack_size(VERIFIER_STACK_SIZE)
        .spawn(move || -> Result<[u32; 16]> {
            let mut words = words.into_iter();
            let output = verify_unified_circuit_recursion_layer_sec_100::<
                _,
                DebugErrorCreator,
                USE_REDUCED_BLAKE2_ROUNDS,
            >(&mut words)
            .map_err(|err| eyre!("the proof does not verify: {err:?}"))?;
            ensure!(words.next().is_none(), "words left after the proof");
            Ok(output)
        })?
        .join()
        .map_err(|_| eyre!("the verifier panicked on this proof"))??;
    ensure!(
        key.expected_chain_hashes
            .iter()
            .any(|hash| output[8..] == hash[..]),
        "the proof verifies but its recursion chain {:08x?} is not one the key trusts",
        &output[8..]
    );
    Ok(output)
}

/// The variables that select the recursion verifier programs, and with them the chain hashes:
/// anything but their default (Blake2s with compression) makes proofs that no published key
/// accepts.
const RECURSION_BLAKE_VARS: [&str; 4] = [
    "RECURSION_UNROLLED_BLAKE",
    "RECURSION_BRIDGE_BLAKE",
    "RECURSION_FINAL_BLAKE",
    "RECURSION_UNIFIED_BLAKE",
];

/// Fails unless every RECURSION_*_BLAKE variable is unset or names the default mode.
pub fn check_recursion_environment() -> Result<()> {
    for var in RECURSION_BLAKE_VARS {
        if let Ok(value) = std::env::var(var) {
            ensure!(
                BlakeMode::parse(&value) == Some(BlakeMode::Compression),
                "{var}={value}: the verification key is defined for the default recursion \
                 verifiers ({}); unset it",
                BlakeMode::Compression.tag()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_format::tests::hex;

    #[test]
    fn key_matches_golden_vector() {
        let bytes = VerificationKey::new([0x11; 32], [0x22; 32], [[1; 8], [300; 8], [0; 8]])
            .encode()
            .unwrap();
        let expected = format!(
            "{}{}{}{}{}{}",
            "45564b4559303031", // magic
            "0264",             // version 2, security 100
            "11".repeat(32),
            "22".repeat(32),
            "01".repeat(8) + &"fb2c01".repeat(8),
            "00".repeat(8),
        );
        assert_eq!(hex(&bytes), expected);
    }

    #[test]
    fn key_round_trips() {
        let key = VerificationKey::new(
            [1; 32],
            [2; 32],
            [[1, 2, 3, 4, 5, 6, 7, 8], [9; 8], [u32::MAX; 8]],
        );
        let bytes = key.encode().unwrap();
        assert_eq!(VerificationKey::decode(&bytes).unwrap(), key);

        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut v1 = bytes.clone();
        v1[8] = 1;
        let mut sec80 = bytes.clone();
        sec80[9] = 80;
        for bad in [
            &trailing[..],
            &v1,
            &sec80,
            &bytes[..bytes.len() - 1],
            b"EPROOF01xx",
        ] {
            assert!(VerificationKey::decode(bad).is_err());
        }
    }

    #[test]
    fn default_recursion_modes_are_accepted() {
        assert_eq!(
            BlakeMode::parse("compression"),
            Some(BlakeMode::Compression)
        );
        assert_eq!(
            BlakeMode::parse("blake2_with_compression"),
            Some(BlakeMode::Compression)
        );
        assert_ne!(
            BlakeMode::parse("special_opcodes"),
            Some(BlakeMode::Compression)
        );
    }
}
