//! The guest's public output, and the host's check of it against the input.
//!
//! The guest commits one 32-byte value in its output registers a0..a7: the hash of the last
//! block it validated, its bytes in order as little-endian words, or zero when it validated
//! none (EJSN tests, envelopes without a valid block). StateTransition anchors a bundle's
//! pre-state at the state root of the header that its first block's parent hash names,
//! requires every later block of the bundle to extend the one before it, and checks each
//! header's state root and gas used against the execution, so that hash binds the state
//! transition of its bundle. The host derives the expected value from the input alone and
//! refuses any run or proof that commits another.

use alloy_primitives::{keccak256, B256};
use eyre::{bail, eyre, Result};
use std::fs;
use std::path::Path;

/// What an honest run of the guest commits for an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    /// Hash of the last block the guest validates; zero when it validates none.
    pub block_hash: B256,
    /// Gas used by the validated blocks together: their header values, summed as the guest
    /// sums them for its "gas used" line.
    pub gas_used: u64,
}

// The envelope and flat-bundle layout of zilk_core/core/types_zz/flat_bundle.{hpp,cpp}.
const INPUT_MAGIC_MFBD: u32 = 0x4442_464D; // "MFBD"
const INPUT_VERSION_MFBD: u32 = 1;
const INPUT_HEADER_SIZE_MFBD: usize = 16;
const FLAT_BUNDLE_MAGIC: u32 = 0x444E_4246; // "FBND"
const FLAT_BUNDLE_VERSION: u32 = 14;
const FLAT_BUNDLE_HEADER_SIZE: usize = 56;
/// Byte offsets of the blocks section's (offset, size) pair in the flat-bundle header.
const BLOCKS_SECTION_FIELD: usize = 16;
const BLOCK_FLAG_EXPECT_INVALID: u8 = 0x01;
/// Position of gas_used in an RLP block header, the same in every fork.
const HEADER_GAS_USED: usize = 10;

/// The expected public output for an input file, read as `build_oracle` reads it.
pub fn expected_for_file(input_file: &Path, is_test: bool) -> Result<Expected> {
    if is_test {
        // EJSN tests run through blockchain_test, which validates no block of the run.
        return Ok(Expected { block_hash: B256::ZERO, gas_used: 0 });
    }
    let bytes = fs::read(input_file)
        .map_err(|e| eyre!("failed to read input file '{}': {}", input_file.display(), e))?;
    expected_for_mfbd(&bytes)
}

/// Walks an MFBD envelope as StateTransition::run_mfbd does. A successful run validated every
/// block without the expect-invalid flag (and rejected the flagged ones), so the committed
/// hash is that of the last unflagged block.
pub fn expected_for_mfbd(envelope: &[u8]) -> Result<Expected> {
    if read_u32(envelope, 0)? != INPUT_MAGIC_MFBD || read_u32(envelope, 4)? != INPUT_VERSION_MFBD {
        bail!("input is not an MFBD v{} envelope", INPUT_VERSION_MFBD);
    }
    let n_bundles = read_u64(envelope, 8)?;
    let mut expected = Expected { block_hash: B256::ZERO, gas_used: 0 };
    let mut cursor = INPUT_HEADER_SIZE_MFBD;
    for i in 0..n_bundles {
        let bundle = envelope
            .get(cursor..)
            .ok_or_else(|| eyre!("MFBD bundle {} starts past the end of the input", i))?;
        let size = add_bundle_blocks(bundle, &mut expected)
            .map_err(|e| eyre!("MFBD bundle {}: {}", i, e))?;
        cursor = align8(cursor + size);
    }
    Ok(expected)
}

/// Folds one flat bundle's blocks into `expected` and returns the bundle's size.
fn add_bundle_blocks(bundle: &[u8], expected: &mut Expected) -> Result<usize> {
    if read_u32(bundle, 0)? != FLAT_BUNDLE_MAGIC || read_u32(bundle, 4)? != FLAT_BUNDLE_VERSION {
        bail!("bad flat bundle magic or version");
    }
    // Six (offset, size) sections follow magic and version; the bundle ends at the last one.
    let mut size = FLAT_BUNDLE_HEADER_SIZE;
    for field in (8..FLAT_BUNDLE_HEADER_SIZE).step_by(8) {
        let end = read_u32(bundle, field)? as usize + read_u32(bundle, field + 4)? as usize;
        if end > bundle.len() {
            bail!("section out of range");
        }
        size = size.max(end);
    }

    let blocks_off = read_u32(bundle, BLOCKS_SECTION_FIELD)? as usize;
    let section_end = blocks_off + read_u32(bundle, BLOCKS_SECTION_FIELD + 4)? as usize;
    let section = &bundle[..section_end];
    let n_blocks = read_u64(section, blocks_off)? as usize;
    let mut cursor = blocks_off + 8;
    let mut blocks = Vec::new();
    for _ in 0..n_blocks {
        let item = rlp_item(section.get(cursor..).unwrap_or_default())?;
        if !item.is_list {
            bail!("block {} is not an RLP list", blocks.len());
        }
        blocks.push(&section[cursor..cursor + item.len]);
        cursor = align8(cursor + item.len);
    }
    // Optional trailing flag bytes, one per block.
    let flags = if n_blocks > 0 && cursor + n_blocks <= section_end {
        &section[cursor..cursor + n_blocks]
    } else {
        &[][..]
    };

    for (i, block) in blocks.iter().enumerate() {
        if flags.get(i).is_some_and(|f| f & BLOCK_FLAG_EXPECT_INVALID != 0) {
            continue;
        }
        let (hash, gas_used) = block_hash_and_gas(block).map_err(|e| eyre!("block {}: {}", i, e))?;
        expected.block_hash = hash;
        expected.gas_used = expected.gas_used.wrapping_add(gas_used);
    }
    Ok(size)
}

/// The block's hash (keccak256 of its RLP header, the block's first item) and its gas used.
fn block_hash_and_gas(block: &[u8]) -> Result<(B256, u64)> {
    let body = rlp_item(block)?.payload;
    let header = rlp_item(body)?;
    if !header.is_list {
        bail!("header is not an RLP list");
    }
    let mut fields = header.payload;
    for _ in 0..HEADER_GAS_USED {
        fields = &fields[rlp_item(fields)?.len..];
    }
    let gas = rlp_item(fields)?;
    if gas.is_list || gas.payload.len() > 8 {
        bail!("header gas_used is not a 64-bit integer");
    }
    let gas_used = gas.payload.iter().fold(0u64, |acc, &b| acc << 8 | b as u64);
    Ok((keccak256(&body[..header.len]), gas_used))
}

/// The output words an honest guest leaves in a0..a7 for `hash`.
#[cfg(test)]
fn words(hash: &B256) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_le_bytes(hash[4 * i..4 * i + 4].try_into().unwrap()))
}

/// The 32-byte value that output words a0..a7 commit.
pub fn committed(output: &[u32; 8]) -> B256 {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(output) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    B256::from(bytes)
}

/// Fails unless the guest's output words commit exactly `block_hash`.
pub fn check(block_hash: &B256, output: &[u32; 8]) -> Result<()> {
    let got = committed(output);
    if got != *block_hash {
        bail!(
            "public output mismatch: the guest committed {}, but the expected block hash is {}",
            got,
            block_hash
        );
    }
    Ok(())
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| eyre!("input truncated at byte {}", off))
}

fn read_u64(buf: &[u8], off: usize) -> Result<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| eyre!("input truncated at byte {}", off))
}

/// One RLP item at the start of a buffer.
struct RlpItem<'a> {
    is_list: bool,
    payload: &'a [u8],
    /// Encoded length: prefix plus payload.
    len: usize,
}

fn rlp_item(buf: &[u8]) -> Result<RlpItem<'_>> {
    let &first = buf.first().ok_or_else(|| eyre!("RLP item past the end of its input"))?;
    let (is_list, prefix, payload_len) = match first {
        0x00..=0x7f => (false, 0, 1),
        0x80..=0xb7 => (false, 1, (first - 0x80) as usize),
        0xc0..=0xf7 => (true, 1, (first - 0xc0) as usize),
        _ => {
            let (is_list, n) = if first < 0xc0 { (false, first - 0xb7) } else { (true, first - 0xf7) };
            let n = n as usize;
            let len_bytes = buf.get(1..1 + n).ok_or_else(|| eyre!("RLP length truncated"))?;
            if n > 4 || len_bytes[0] == 0 {
                bail!("RLP length not canonical or too large");
            }
            (is_list, 1 + n, len_bytes.iter().fold(0usize, |acc, &b| acc << 8 | b as usize))
        }
    };
    let payload = buf
        .get(prefix..prefix + payload_len)
        .ok_or_else(|| eyre!("RLP item overruns its input"))?;
    Ok(RlpItem { is_list, payload, len: prefix + payload_len })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rlp_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return b.to_vec();
        }
        let mut out = rlp_prefix(0x80, b.len());
        out.extend_from_slice(b);
        out
    }

    fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.concat();
        let mut out = rlp_prefix(0xc0, payload.len());
        out.extend_from_slice(&payload);
        out
    }

    fn rlp_prefix(base: u8, len: usize) -> Vec<u8> {
        if len < 56 {
            return vec![base + len as u8];
        }
        let be = len.to_be_bytes();
        let be = &be[be.iter().position(|&b| b != 0).unwrap()..];
        let mut out = vec![base + 55 + be.len() as u8];
        out.extend_from_slice(be);
        out
    }

    fn rlp_uint(v: u64) -> Vec<u8> {
        let be = v.to_be_bytes();
        rlp_bytes(&be[be.iter().position(|&b| b != 0).unwrap_or(8)..])
    }

    /// A 15-field (pre-London) header; `tag` makes headers of equal number and gas distinct.
    fn header(number: u64, gas_used: u64, tag: u8) -> Vec<u8> {
        rlp_list(&[
            rlp_bytes(&[tag; 32]),         // parent_hash
            rlp_bytes(&[0x1d; 32]),        // ommers_hash
            rlp_bytes(&[0xbe; 20]),        // beneficiary
            rlp_bytes(&[0x5a; 32]),        // state_root
            rlp_bytes(&[0x7a; 32]),        // transactions_root
            rlp_bytes(&[0x4e; 32]),        // receipts_root
            rlp_bytes(&[0u8; 256]),        // logs_bloom
            rlp_uint(0),                   // difficulty
            rlp_uint(number),              // number
            rlp_uint(30_000_000),          // gas_limit
            rlp_uint(gas_used),            // gas_used
            rlp_uint(1_000 + number),      // timestamp
            rlp_bytes(b"z6m"),             // extra_data
            rlp_bytes(&[0u8; 32]),         // mix_hash
            rlp_bytes(&[0u8; 8]),          // nonce
        ])
    }

    fn block(header: &[u8]) -> Vec<u8> {
        rlp_list(&[header.to_vec(), rlp_list(&[]), rlp_list(&[])])
    }

    /// A flat bundle as build_flat_bundle lays it out (empty witness sections).
    fn bundle(blocks: &[Vec<u8>], flags: &[u8]) -> Vec<u8> {
        let genesis = block(&header(0, 0, 0));
        let mut blocks_section = (blocks.len() as u64).to_le_bytes().to_vec();
        for b in blocks {
            blocks_section.extend_from_slice(b);
            blocks_section.resize(align8(blocks_section.len()), 0);
        }
        blocks_section.extend_from_slice(flags);
        let network = b"Mainnet";

        let genesis_off = align8(FLAT_BUNDLE_HEADER_SIZE);
        let blocks_off = align8(genesis_off + genesis.len());
        let rest_off = align8(blocks_off + blocks_section.len());
        let sections = [
            (genesis_off, genesis.len()),
            (blocks_off, blocks_section.len()),
            (rest_off, 0), // ancestors
            (rest_off, 0), // direct state
            (rest_off, 0), // node store
            (rest_off, network.len()),
        ];
        let mut out = vec![0u8; align8(rest_off + network.len())];
        out[0..4].copy_from_slice(&FLAT_BUNDLE_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&FLAT_BUNDLE_VERSION.to_le_bytes());
        for (i, (off, size)) in sections.iter().enumerate() {
            out[8 + 8 * i..12 + 8 * i].copy_from_slice(&(*off as u32).to_le_bytes());
            out[12 + 8 * i..16 + 8 * i].copy_from_slice(&(*size as u32).to_le_bytes());
        }
        out[genesis_off..genesis_off + genesis.len()].copy_from_slice(&genesis);
        out[blocks_off..blocks_off + blocks_section.len()].copy_from_slice(&blocks_section);
        out[rest_off..rest_off + network.len()].copy_from_slice(network);
        out
    }

    fn envelope(bundles: &[Vec<u8>]) -> Vec<u8> {
        let mut out = INPUT_MAGIC_MFBD.to_le_bytes().to_vec();
        out.extend_from_slice(&INPUT_VERSION_MFBD.to_le_bytes());
        out.extend_from_slice(&(bundles.len() as u64).to_le_bytes());
        for b in bundles {
            out.extend_from_slice(b);
            out.resize(align8(out.len()), 0);
        }
        out
    }

    #[test]
    fn single_block_commits_its_header_hash() {
        let h = header(7, 1_234_567, 0xaa);
        let expected = expected_for_mfbd(&envelope(&[bundle(&[block(&h)], &[])])).unwrap();
        assert_eq!(expected.block_hash, keccak256(&h));
        assert_eq!(expected.gas_used, 1_234_567);
        check(&expected.block_hash, &words(&expected.block_hash)).unwrap();
    }

    #[test]
    fn words_are_the_hash_bytes_as_little_endian_words() {
        let hash = B256::from(std::array::from_fn::<u8, 32, _>(|i| i as u8));
        let w = words(&hash);
        assert_eq!(w[0], 0x0302_0100);
        assert_eq!(w[7], 0x1f1e_1d1c);
        assert_eq!(committed(&w), hash);
    }

    #[test]
    fn any_tampered_output_bit_fails() {
        let h = header(7, 21_000, 0xaa);
        let expected = expected_for_mfbd(&envelope(&[bundle(&[block(&h)], &[])])).unwrap();
        let honest = words(&expected.block_hash);
        for word in 0..8 {
            for bit in 0..32 {
                let mut out = honest;
                out[word] ^= 1 << bit;
                assert!(check(&expected.block_hash, &out).is_err(), "word {} bit {}", word, bit);
            }
        }
    }

    #[test]
    fn output_for_another_block_fails() {
        let input = envelope(&[bundle(&[block(&header(7, 21_000, 0xaa))], &[])]);
        let expected = expected_for_mfbd(&input).unwrap();
        // Same number and gas used, different parent: a valid proof of that block must not pass.
        let other = keccak256(header(7, 21_000, 0xbb));
        assert!(check(&expected.block_hash, &words(&other)).is_err());
        // Nor may the old gas-only output, or an all-zero one.
        assert!(check(&expected.block_hash, &[21_000, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(check(&expected.block_hash, &[0; 8]).is_err());
    }

    #[test]
    fn expect_invalid_blocks_are_not_committed() {
        let a = header(7, 100, 0xaa);
        let b = header(8, 200, 0xbb);
        let input = envelope(&[bundle(&[block(&a), block(&b)], &[0, BLOCK_FLAG_EXPECT_INVALID])]);
        let expected = expected_for_mfbd(&input).unwrap();
        assert_eq!(expected.block_hash, keccak256(&a));
        assert_eq!(expected.gas_used, 100);
    }

    #[test]
    fn last_valid_block_of_the_run_is_committed() {
        let a = header(7, 100, 0xaa);
        let b = header(8, 200, 0xbb);
        let c = header(9, 400, 0xcc);
        let input = envelope(&[
            bundle(&[block(&a), block(&b)], &[]),
            bundle(&[block(&c)], &[BLOCK_FLAG_EXPECT_INVALID]),
        ]);
        let expected = expected_for_mfbd(&input).unwrap();
        assert_eq!(expected.block_hash, keccak256(&b));
        assert_eq!(expected.gas_used, 300);

        let input = envelope(&[bundle(&[block(&a)], &[]), bundle(&[block(&b), block(&c)], &[])]);
        let expected = expected_for_mfbd(&input).unwrap();
        assert_eq!(expected.block_hash, keccak256(&c));
        assert_eq!(expected.gas_used, 700);
    }

    #[test]
    fn runs_without_a_valid_block_commit_zero() {
        let expected = expected_for_mfbd(&envelope(&[])).unwrap();
        assert_eq!(expected, Expected { block_hash: B256::ZERO, gas_used: 0 });
        let flagged = bundle(&[block(&header(7, 100, 0xaa))], &[BLOCK_FLAG_EXPECT_INVALID]);
        assert_eq!(expected_for_mfbd(&envelope(&[flagged])).unwrap().block_hash, B256::ZERO);
        let ejsn = expected_for_file(Path::new("not read for EJSN"), true).unwrap();
        assert_eq!(ejsn.block_hash, B256::ZERO);
        check(&ejsn.block_hash, &[0; 8]).unwrap();
        assert!(check(&ejsn.block_hash, &[1, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let good = envelope(&[bundle(&[block(&header(7, 100, 0xaa))], &[])]);
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 1;
        assert!(expected_for_mfbd(&bad_magic).is_err());
        let mut bad_bundle_version = good.clone();
        bad_bundle_version[INPUT_HEADER_SIZE_MFBD + 4] ^= 1;
        assert!(expected_for_mfbd(&bad_bundle_version).is_err());
        assert!(expected_for_mfbd(&good[..good.len() - 16]).is_err());
        let mut two_bundles = good.clone();
        two_bundles[8] = 2;
        assert!(expected_for_mfbd(&two_bundles).is_err());
    }

    /// Mainnet block 24,491,136 from the 200-block corpus: its RLP header, its hash as a separate
    /// keccak implementation computes it, and the output words the guest commits for that block.
    #[test]
    fn mainnet_header_hash() {
        let header = alloy_primitives::hex::decode(MAINNET_24491136_HEADER).unwrap();
        let block = block(&header);
        let (hash, gas_used) = block_hash_and_gas(&block).unwrap();
        assert_eq!(
            hash,
            "0x361dc453212495d7cb6f48b21cadfd8f22bcd56b70b76185dc0683f9f0b0694d"
                .parse::<B256>()
                .unwrap()
        );
        assert_eq!(gas_used, 43_315_900);
        assert_eq!(
            words(&hash),
            [0x53c41d36, 0xd7952421, 0xb2486fcb, 0x8ffdad1c, 0x6bd5bc22, 0x8561b770, 0xf98306dc, 0x4d69b0f0]
        );
    }

    const MAINNET_24491136_HEADER: &str = concat!(
        "f90284a03395e22c0b070c57717976419d8955adcd83e60bc145cea350ca2a67442a27daa01dcc4de8dec75d",
        "7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794dadb0d80178819f2319190d340ce9a924f78",
        "3711a0fa0f9609162a72faa279d11f7abe75caa6386fbe69e172387404c766ac3c412ba0b9b68462fece7c55",
        "8174f979a28d80a89d556cf63428af528f15e0a29bc14e44a036dfd5fd97d1d7f420ca555fed9114ae23c6ff",
        "ae3b03eaba95724c41ba4364a2b901007fff5df7efeffbf6f6ef37fffbf7bf9fdfff8ffdbf7f7fffbfbd93bf",
        "ffffffa3fdffeffdfbefffef93bfffeeffffff2fff77ff7bbf3feebb97fbbfef7effadffbfff7ecdafdbdbfe",
        "7dfcf7afffebfef2fffff5bfddf77f3effb3feefbffff6ff7f3fb7f7b37f7beff7bf9ffddf7faf6fefebf72f",
        "ff9ffffed2ffffff9dfbffffbbffefeffbfb7ffb5b7ffbef7f7ef1eedefdbf75ffefffffb7ffd37efef5feff",
        "7fffbfee7ffffdfffdffdfffbdfbbefc7ebedfdfbff7b1fabfffbdffbfeafffffffffbffffdebf7d7f3baffc",
        "e7ffffdf7ffdffffffad7ffedf7fe7ef9fffbfef7b9fffff7bbffdfabeefffffdffdfdd7fff7df3fcff8fbfb",
        "7f5effbf9fddff7f80840175b4808403938700840294f2bc8469970d4b964275696c6465724e65742028466c",
        "617368626f747329a0c5b9908e5439206caf88d2ba421d5fccbd2206ce1f32e24f93d55ed6cddd8add880000",
        "0000000000008408dd1065a048f644604a4474da13a87a357b559bd7d3519df2b92d5dc6898b9544bceacda4",
        "830a0000840b26400da07f3beb81503dbe0dbf796adfa39936bab5d1d35ffd784d6ae9930d4a3da711cfa0e3",
        "b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}
