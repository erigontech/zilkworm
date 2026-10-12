// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Index keys: the 64-bit values ("key8") the MPHF maps (MphfMap, MphfBuilder) and HashIndex
// place and look up full keys by. Each function folds one kind of full key into 64 bits.
// The containers confirm every hit by comparing the full key, so two keys with the same key8
// cost an extra probe, never a wrong result. Both containers also mix the key8 before
// choosing a slot or bucket (MphfMapHeader::index_lookup, HashIndex::index_of), so a key8
// only has to tell keys apart, not be uniformly distributed.
//
// The Rust MFBD encoder (prover/stateless_validator/src/mfbd.rs) has its own addr_key8 and
// hash_key8, which must stay in step with these.

#pragma once

#include <cstdint>
#include <cstring>

#include <evmc/evmc.hpp>

namespace zilkworm {

/// Index key of a 32-byte keccak hash: its first 8 bytes, loaded in native byte order.
///
/// Used for code hashes (code store), trie node hashes (node store) and account hashes
/// (HashState's account index). Keccak output is uniform, so the prefix needs no further
/// mixing to tell hashes apart.
///
/// @param hash  the full 32-byte hash
[[gnu::always_inline]] inline uint64_t hash_key8(const uint8_t (&hash)[32]) noexcept {
    uint64_t k;
    std::memcpy(&k, hash, 8);
    return k;
}

/// Index key of a 32-byte keccak hash; see hash_key8(const uint8_t (&)[32]).
///
/// @param hash  the full 32-byte hash
[[gnu::always_inline]] inline uint64_t hash_key8(const evmc::bytes32& hash) noexcept {
    return hash_key8(hash.bytes);
}

/// Index key of a 20-byte account address: its first 7 bytes as the low 7 bytes of the key,
/// and its last byte (byte 19) as the top byte.
///
/// Used for DirectState's address map. A plain 8-byte prefix would give every precompile
/// the same key, because precompile addresses are zero in every byte but the last; taking
/// byte 19 in place of byte 7 keeps them apart.
///
/// @param addr  the full 20-byte address
[[gnu::always_inline]] inline uint64_t addr_key8(const uint8_t (&addr)[20]) noexcept {
    uint64_t k;
    std::memcpy(&k, addr, 8);
    return (k & 0x00FFFFFFFFFFFFFFull) | (uint64_t{addr[19]} << 56);
}

/// Index key of a 20-byte account address; see addr_key8(const uint8_t (&)[20]).
///
/// @param addr  the full 20-byte address
[[gnu::always_inline]] inline uint64_t addr_key8(const evmc::address& addr) noexcept {
    return addr_key8(addr.bytes);
}

/// Index key of a storage slot in HashState's storage index, whose full key is the 64-byte
/// concatenation addr_hash || slot_hash: the XOR of the first 8 bytes of each half.
///
/// Both halves are keccak outputs, so each prefix is uniform. XORing them makes the key
/// depend on the slot as well as the account; keying on the addr_hash prefix alone would give
/// every slot of an account the same key, and so the same home bucket.
///
/// @param key  the full 64-byte key: keccak256(address) followed by keccak256(slot key)
[[gnu::always_inline]] inline uint64_t storage_key8(const uint8_t (&key)[64]) noexcept {
    uint64_t addr_prefix;
    uint64_t slot_prefix;
    std::memcpy(&addr_prefix, key, 8);
    std::memcpy(&slot_prefix, key + 32, 8);
    return addr_prefix ^ slot_prefix;
}

}  // namespace zilkworm
