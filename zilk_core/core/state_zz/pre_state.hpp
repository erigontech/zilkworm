// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types_zz/account.hpp>

namespace zilkworm {

using ::silkworm::ByteView;
using ::silkworm::Bytes;

// Equality-only compare: 20-byte addrs need a 8-aligned for the 20-byte loads.
[[gnu::always_inline]] inline bool eq_addr20(const uint8_t* a, const uint8_t* b) noexcept {
    uint64_t a0, a1, b0, b1;
    uint32_t a2, b2;
    std::memcpy(&a0, a + 0,  8);  std::memcpy(&b0, b + 0,  8);
    std::memcpy(&a1, a + 8,  8);  std::memcpy(&b1, b + 8,  8);
    std::memcpy(&a2, a + 16, 4);  std::memcpy(&b2, b + 16, 4);
    return ((a0 ^ b0) | (a1 ^ b1) | static_cast<uint64_t>(a2 ^ b2)) == 0;
}

[[gnu::always_inline]] inline bool eq_hash32(const uint8_t* a, const uint8_t* b) noexcept {
    uint64_t a0, a1, a2, a3, b0, b1, b2, b3;
    std::memcpy(&a0, a + 0,  8);  std::memcpy(&b0, b + 0,  8);
    std::memcpy(&a1, a + 8,  8);  std::memcpy(&b1, b + 8,  8);
    std::memcpy(&a2, a + 16, 8);  std::memcpy(&b2, b + 16, 8);
    std::memcpy(&a3, a + 24, 8);  std::memcpy(&b3, b + 24, 8);
    return ((a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3)) == 0;
}

inline constexpr uint32_t kMagic = 0x53455250u;  // 'PRES' little-endian
inline constexpr uint32_t kVersion = 4u;

inline constexpr uint32_t align8(uint32_t v) noexcept { return (v + 7u) & ~uint32_t{7u}; }

struct PreStateMeta {
    uint32_t magic;
    uint32_t version;
    uint32_t n_accounts;
    uint32_t n_block_hashes;

    uint32_t prestate_offset;
    uint32_t addr_hashes_offset;
    uint32_t block_hashes_offset;

    uint32_t code_store_offset;
    uint32_t code_store_size;

    uint32_t reserved[8];
};

struct alignas(8) Slot {
    uint8_t key[32];
    uint8_t initial[32];
    uint8_t current[32];
};

struct alignas(8) AddrHashEntry {
    uint8_t  addr_hash[32];
    uint8_t  addr[20];
    uint32_t entry_offset;

    bool operator<(const AddrHashEntry& other) const {
        return std::memcmp(addr_hash, other.addr_hash, 32) < 0;
    }
};

struct alignas(8) BlockHashEntry {
    uint64_t block_number;
    uint8_t  block_hash[32];
};

inline constexpr uint32_t inline_account_entry_size(uint32_t slot_count) noexcept {
    return 8u + static_cast<uint32_t>(sizeof(Account)) +
           slot_count * static_cast<uint32_t>(sizeof(Slot));
}

static_assert(std::is_trivially_copyable_v<PreStateMeta>);
static_assert(std::is_trivially_copyable_v<Slot>);
static_assert(std::is_trivially_copyable_v<AddrHashEntry>);
static_assert(std::is_trivially_copyable_v<BlockHashEntry>);

static_assert(alignof(Slot) == 8);
static_assert(alignof(AddrHashEntry) == 8);
static_assert(alignof(BlockHashEntry) == 8);

static_assert(sizeof(Slot) % 8 == 0);
static_assert(sizeof(AddrHashEntry) % 8 == 0);
static_assert(sizeof(BlockHashEntry) % 8 == 0);

static_assert(sizeof(Slot) == 96);
static_assert(sizeof(AddrHashEntry) == 56);
static_assert(sizeof(BlockHashEntry) == 40);

}  // namespace zilkworm
