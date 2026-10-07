// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>

// Keccak states of the leading blocks of full trie branches, saved while a witness node is verified
// and resumed when the same branch is hashed again after an update. A branch of 16 hash children
// is 532 bytes: three 136-byte blocks and a last one of 124. An update rewrites the 32 hash bytes of
// some slots, and the blocks before the first one it rewrites are the witness bytes still.
//
// Invariant: while tag_orig[i] is not null, pool[i] holds the Keccak state after the first
// 136 * tag_sb[i] bytes of the 532-byte witness node at tag_orig[i] (rows 0..24; the delegation's
// scratch lanes after them are meaningless), those bytes being verified against their hash, and
// tag_sb[i] is 1..3 (take_resumable_blocks() masks it with 3 all the same, see there).
// Everything that writes a pool row clears its tag first and sets it again only once the node
// hashed to the hash it was looked up by, and a resume clears the tag as it permutes the row in
// place. Witness bytes do not change, so a tag never goes stale, and it names the node by its
// bytes' address, not by where the node sits in the grid: whatever row a tag is found in, the
// state is that of the node it names.
namespace zilkworm::kprefix {

inline constexpr size_t kRows = 128;
static_assert((kRows & (kRows - 1)) == 0, "rows are picked by masking a grid depth");
inline constexpr size_t kNodeSize = 3 + 16 * 33 + 1;  // A full branch with an empty value.
inline constexpr size_t kBlock = 136;
inline constexpr unsigned kNoSlot = 16;  // For first_blocks(): no snapshot wanted.

// The same condition as rlp_sw.hpp's static_buffer: one pool per thread on the host, a plain
// global on the guests.
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

/// What a lookup asks for when it verifies a full branch: the lowest slot of it the caller will change
/// (kNoSlot if none), and the pool row for the state saved before that slot's blocks.
struct SnapRequest {
    unsigned slot;
    size_t row;
};

/// The whole blocks before slot `j` of a full branch: its hash bytes start at 4 + 33 j. A slot
/// that straddles a block boundary (8 and 12) counts as the block it starts in. kNoSlot gives 0.
[[gnu::always_inline]] inline unsigned first_blocks(unsigned j) noexcept {
    static constexpr uint8_t kTable[17] = {0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 0};
    return kTable[j];
}

/// The slots of a full branch whose hash bytes begin inside the first `blocks` blocks (136 bytes each): slot i
/// has its bytes from 4 + 33 i, so the slots before the first with 4 + 33 i >= 136 * blocks, a slot that
/// straddles the boundary (8 for 2 blocks, 12 for 3) included. A state saved for `blocks` blocks is good for a
/// node as long as none of them changed.
inline constexpr uint16_t kHeadSlots[4] = {0, 0x000f, 0x01ff, 0x1fff};
static_assert([] {
    for (unsigned blocks = 1; blocks <= 3; ++blocks) {
        unsigned first = 0;
        while (4 + 33 * first < kBlock * blocks) ++first;
        if (kHeadSlots[blocks] != (1u << first) - 1) return false;
    }
    return true;
}());

/// Whether the keccak of the full branch at `node` (8-byte aligned) is `want`, saving the state
/// after its first `blocks` blocks in row `row` when it is. Out of line: its tag stores would
/// otherwise add to the registers unfold_slot() keeps live around the lookup.
[[gnu::noinline]] inline bool verify_and_snap(const uint8_t* node, size_t row, unsigned blocks,
                                              const uint8_t* want) noexcept {
    // The row is about to be overwritten, whatever the compare says: a node that fails it must not
    // leave the tag of the node before it over its bytes' state.
    tag_orig[row] = nullptr;
    const auto h = ethash_keccak256_snap(node, kNodeSize, blocks, pool[row]);
    if (!bytes_equal<32>(h.bytes, want)) [[unlikely]] return false;
    tag_orig[row] = node;
    tag_sb[row] = static_cast<uint8_t>(blocks);
    return true;
}

}  // namespace zilkworm::kprefix
