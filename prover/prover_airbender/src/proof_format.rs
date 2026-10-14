//! The proof file: gzip of the EPROOF01 v2 envelope that Ethproofs and its JS/WASM verifier take.
//!
//! Adapted from matter-labs/ethereum-prover ethereum_prover/src/prover/proof_format.rs and
//! proof_output.rs (MIT OR Apache-2.0).

use eyre::{bail, ensure, eyre, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use prover_pipeline::{ProofArtifact, ProofTarget, SecurityLevel};
use std::io::{Read, Write};

pub const PROOF_MAGIC: [u8; 8] = *b"EPROOF01";
const PROOF_FORMAT_VERSION: u8 = 2;
const PROOF_SECURITY: u8 = 100;

/// Largest proof the verifier decompresses (a unified proof is about 1 MB).
pub const MAX_DECOMPRESSED_PROOF_BYTES: u64 = 64 << 20;

/// Version 2 carries the word stream the final unified full-statement verifier consumes
/// (`build_unified_stream` of the final recursion layer), not a native proof structure.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EncodedProof {
    magic: [u8; 8],
    version: u8,
    security: u8,
    proof_words: Vec<u32>,
}

/// The proof file of a final unified recursion proof: gzip(bincode2 EncodedProof).
pub fn proof_file_bytes(artifact: &ProofArtifact) -> Result<Vec<u8>> {
    ensure!(
        artifact.target == ProofTarget::RecursionUnified,
        "only final unified recursion proofs have a proof file, got {:?}",
        artifact.target
    );
    ensure!(
        artifact.security_level == SecurityLevel::Sec100,
        "the proof file is for 100-bit proofs, got {:?}",
        artifact.security_level
    );
    let words = full_statement_verifier::host_utils::build_unified_stream(
        &artifact.setups,
        &artifact.proof,
    );
    gzip(&encode_envelope(words)?)
}

/// The unified verifier's word stream in a proof file.
pub fn proof_words_from_file(file: &[u8]) -> Result<Vec<u32>> {
    decode_proof_words(&gunzip(file, MAX_DECOMPRESSED_PROOF_BYTES)?)
}

fn encode_envelope(proof_words: Vec<u32>) -> Result<Vec<u8>> {
    let encoded = EncodedProof {
        magic: PROOF_MAGIC,
        version: PROOF_FORMAT_VERSION,
        security: PROOF_SECURITY,
        proof_words,
    };
    bincode2::serde::encode_to_vec(&encoded, bincode2::config::standard())
        .map_err(|e| eyre!("failed to encode the proof envelope: {e}"))
}

/// Decodes an uncompressed envelope: the fixed prefix is checked before the body, and the bytes
/// must be consumed exactly.
fn decode_proof_words(bytes: &[u8]) -> Result<Vec<u32>> {
    ensure!(
        bytes.len() >= 10 && bytes[..8] == PROOF_MAGIC,
        "not an EPROOF01 proof envelope"
    );
    ensure!(
        bytes[8] == PROOF_FORMAT_VERSION,
        "unsupported proof envelope version {} (expected {PROOF_FORMAT_VERSION})",
        bytes[8]
    );
    ensure!(
        bytes[9] == PROOF_SECURITY,
        "unsupported proof security {} (expected {PROOF_SECURITY})",
        bytes[9]
    );
    let (decoded, read): (EncodedProof, usize) =
        bincode2::serde::decode_from_slice(bytes, bincode2::config::standard())
            .map_err(|e| eyre!("failed to decode the proof envelope: {e}"))?;
    ensure!(
        read == bytes.len(),
        "trailing bytes after the proof envelope"
    );
    Ok(decoded.proof_words)
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

/// Decompresses at most `limit` bytes; a longer stream is an error.
pub fn gunzip(bytes: &[u8], limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    GzDecoder::new(bytes)
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| eyre!("failed to decompress: {e}"))?;
    if out.len() as u64 > limit {
        bail!("decompresses to more than {limit} bytes");
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // ethereum-prover's golden vector: magic, version 2, security 100, then three words: 1, 300
    // and u32::MAX cover the one-, three- and five-byte varint forms.
    const THREE_WORD_ENVELOPE_HEX: &str = "4550524f4f46303102640301fb2c01fcffffffff";

    #[test]
    fn envelope_matches_golden_vector() {
        let bytes = encode_envelope(vec![1, 300, u32::MAX]).unwrap();
        assert_eq!(hex(&bytes), THREE_WORD_ENVELOPE_HEX);
    }

    #[test]
    fn envelope_round_trips() {
        let bytes = encode_envelope(vec![7, 8, 9]).unwrap();
        assert_eq!(decode_proof_words(&bytes).unwrap(), vec![7, 8, 9]);
        let file = gzip(&bytes).unwrap();
        assert_eq!(&file[..2], &[0x1f, 0x8b]);
        assert_eq!(proof_words_from_file(&file).unwrap(), vec![7, 8, 9]);
    }

    #[test]
    fn bad_envelopes_are_rejected() {
        let good = encode_envelope(vec![1, 2]).unwrap();
        let mut wrong_version = good.clone();
        wrong_version[8] = 1;
        let mut wrong_security = good.clone();
        wrong_security[9] = 80;
        let mut trailing = good.clone();
        trailing.push(0);
        for bad in [
            &b"EPROOF02.."[..],
            &wrong_version,
            &wrong_security,
            &trailing,
            &good[..9],
        ] {
            assert!(decode_proof_words(bad).is_err());
        }
    }

    #[test]
    fn oversized_streams_are_rejected() {
        let file = gzip(&[0u8; 1000]).unwrap();
        assert!(gunzip(&file, 999).is_err());
        assert_eq!(gunzip(&file, 1000).unwrap().len(), 1000);
    }

    pub(crate) fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
