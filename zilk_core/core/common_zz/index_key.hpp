// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// key8 folds a full key into 64 bits; containers confirm hits by full-key compare, so it need only tell keys apart. The Rust MFBD encoder's addr_key8 / hash_key8 must stay in step.

#pragma once

#include <cstdint>
#include <cstring>

#include <evmc/evmc.hpp>

namespace zilkworm {

[[gnu::always_inline]] inline uint64_t hash_key8_at(const uint8_t* hash) noexcept {
    uint64_t k;
    std::memcpy(&k, hash, 8);
    return k;
}

/// First 8 bytes of a keccak hash in native byte order (uniform, so no mixing needed).
[[gnu::always_inline]] inline uint64_t hash_key8(const uint8_t (&hash)[32]) noexcept {
    return hash_key8_at(hash);
}

[[gnu::always_inline]] inline uint64_t hash_key8(const evmc::bytes32& hash) noexcept {
    return hash_key8_at(hash.bytes);
}

/// Address bytes 0..6 in the low 7 bytes, byte 19 on top: a plain 8-byte prefix would give every precompile the same key.
[[gnu::always_inline]] inline uint64_t addr_key8_at(const uint8_t* addr) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    // Word-aligned fast path: the memcpy below is eight byte loads under strict alignment.
    if ((reinterpret_cast<uintptr_t>(addr) & 3) == 0) [[likely]] {
        typedef uint32_t __attribute__((may_alias)) w32;
        const w32* const w = reinterpret_cast<const w32*>(addr);
        return w[0] | (uint64_t{(w[1] & 0x00FFFFFFu) | (uint32_t{addr[19]} << 24)} << 32);
    }
#endif
    uint64_t k; std::memcpy(&k, addr, 8);
    k = (k & 0x00FFFFFFFFFFFFFFull) | (uint64_t(addr[19]) << 56); return k;
}

[[gnu::always_inline]] inline uint64_t addr_key8(const uint8_t (&addr)[20]) noexcept {
    return addr_key8_at(addr);
}

[[gnu::always_inline]] inline uint64_t addr_key8(const evmc::address& addr) noexcept {
    return addr_key8_at(addr.bytes);
}

[[gnu::always_inline]] inline uint64_t storage_key8_at(const uint8_t* key) noexcept {
    uint64_t addr_prefix;
    uint64_t slot_prefix;
    std::memcpy(&addr_prefix, key, 8);
    std::memcpy(&slot_prefix, key + 32, 8);
    return addr_prefix ^ slot_prefix;
}

/// XOR of the first 8 bytes of addr_hash and slot_hash: the addr_hash prefix alone would give every slot of an account one home bucket.
[[gnu::always_inline]] inline uint64_t storage_key8(const uint8_t (&key)[64]) noexcept {
    return storage_key8_at(key);
}

}  // namespace zilkworm
