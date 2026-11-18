// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>

// Invariant: tag_orig[i] != null means pool[i] holds the Keccak state after 136 * tag_sb[i] verified bytes of the witness node at tag_orig[i]; every writer clears the tag first and sets it only once the node hashed to its lookup hash.
namespace zilkworm::kprefix {

inline constexpr size_t kRows = 128;
static_assert((kRows & (kRows - 1)) == 0, "rows are picked by masking a grid depth");
inline constexpr size_t kNodeSize = 3 + 16 * 33 + 1;
inline constexpr size_t kBlock = 136;
inline constexpr unsigned kNoSlot = 16;
/// SnapRequest::row value: save into DirectState's address table instead of the pool.
inline constexpr size_t kAddrRow = ~size_t{0};
inline constexpr unsigned kAddrBits = 12;
inline constexpr size_t kAddrRows = size_t{1} << kAddrBits;

struct alignas(256) StateRow {
    uint64_t lanes[32];
};
static_assert(sizeof(StateRow) == 256);

/// Multiplicative hash of the node address (bodies are 8-aligned).
[[gnu::always_inline]] inline size_t addr_row(const uint8_t* node) noexcept {
    return (static_cast<uint32_t>(reinterpret_cast<uintptr_t>(node) >> 3) * 0x9E3779B1u) >> (32 - kAddrBits);
}

struct Resume {
    uint64_t* state;
    unsigned blocks;
};

#if defined(__cpp_threadsafe_static_init) && !defined(NO_THREAD_LOCAL) && !defined(SP1) && !defined(QEMU_DEBUG) && !defined(AIRBENDER)
#define ZILK_KPREFIX_TLS thread_local
#else
#define ZILK_KPREFIX_TLS
#endif

// 32 lanes a row: the delegation reads and writes 31 and wants the state 256-byte aligned.
alignas(256) inline ZILK_KPREFIX_TLS uint64_t pool[kRows][32];
inline ZILK_KPREFIX_TLS const uint8_t* tag_orig[kRows];
inline ZILK_KPREFIX_TLS uint8_t tag_sb[kRows];
#undef ZILK_KPREFIX_TLS

// Unrolled: as a loop it becomes a memset call, and the guest's memset is the BigInt delegation.
inline void clear_tags() noexcept {
#pragma GCC unroll 128
    for (size_t i = 0; i < kRows; ++i) tag_orig[i] = nullptr;
}

struct SnapRequest {
    unsigned slot;
    size_t row;
};

/// Whole blocks before slot j's hash bytes (4 + 33 j); a slot straddling a block boundary counts as the block it starts in.
[[gnu::always_inline]] inline unsigned first_blocks(unsigned j) noexcept {
    static constexpr uint8_t kTable[17] = {0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 0};
    return kTable[j];
}

/// The node is unverified here: the count only picks how many leading blocks the saved state covers, and a fold re-checks before resuming.
inline unsigned blocks_before_slot(const uint8_t* node, size_t size, unsigned j) noexcept {
    if (size == kNodeSize) return first_blocks(j);
    if (j >= 16) return 0;
    const uint8_t b0 = node[0];
    if (b0 != 0xf8 && b0 != 0xf9) return 0;
    size_t off = b0 == 0xf8 ? 2 : 3;
    for (unsigned i = 0; i < j && off < size; ++i) {
        const unsigned c = node[off];
        off += c == 0xa0u ? 33u : (c >= 0xc0u && c <= 0xf7u) ? 1u + (c - 0xc0u) : 1u;
    }
    return static_cast<unsigned>((off < size ? off : size) / kBlock);
}

/// Slots (bit i = slot i) whose hash bytes begin inside the first `blocks` blocks.
inline constexpr uint16_t kHeadSlots[4] = {0, 0x000f, 0x01ff, 0x1fff};
static_assert([] {
    for (unsigned blocks = 1; blocks <= 3; ++blocks) {
        unsigned first = 0;
        while (4 + 33 * first < kBlock * blocks) ++first;
        if (kHeadSlots[blocks] != (1u << first) - 1) return false;
    }
    return true;
}());

/// True iff keccak of the `size` bytes at `node` (8-aligned, >= 136 * blocks) equals `want`; the state and tag are saved only then.
[[gnu::noinline]] inline bool verify_and_snap(const uint8_t* node, size_t size, uint64_t* state, const uint8_t*& tag,
                                              uint8_t& sb, unsigned blocks, const uint8_t* want) noexcept {
    // Clear the tag first: a failed compare must not leave the previous node's tag over this state.
    tag = nullptr;
    const auto h = ethash_keccak256_snap(node, size, blocks, state);
    if (!bytes_equal<32>(h.bytes, want)) [[unlikely]] return false;
    tag = node;
    sb = static_cast<uint8_t>(blocks);
    return true;
}

inline bool verify_and_snap(const uint8_t* node, size_t row, unsigned blocks, const uint8_t* want) noexcept {
    return verify_and_snap(node, kNodeSize, pool[row], tag_orig[row], tag_sb[row], blocks, want);
}

}  // namespace zilkworm::kprefix
