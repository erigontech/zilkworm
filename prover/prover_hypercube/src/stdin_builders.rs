use eyre::Result;
use sp1_sdk::SP1Stdin;
use std::fs;
use std::path::Path;
use z6m_common::rlp_methods::encode_rlp_bundle;

/// Wraps a batch of per-subtest RLP blobs as SP1 stdin.
/// See `docs/architecture.md` "Bundle format" and "Transport variants".
pub fn build_stdin_from_batch(items: &[&[u8]]) -> SP1Stdin {
    build_stdin_from_bundle(&encode_rlp_bundle(items))
}

/// Pass already-bundled bytes (e.g. read from a `.rlp` file produced by
/// `z6m_eest_convert bulk-convert`) into SP1Stdin verbatim.
pub fn build_stdin_from_bundle(bundle: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(bundle);
    stdin
}

pub fn build_stdin_from_bytes(rlp: &[u8]) -> SP1Stdin {
    build_stdin_from_batch(&[rlp])
}

pub fn build_stdin_from_unified_rlp(path: &Path) -> Result<SP1Stdin> {
    Ok(build_stdin_from_bytes(&fs::read(path)?))
}
