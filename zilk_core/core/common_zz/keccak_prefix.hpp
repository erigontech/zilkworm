// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>

// Keccak states of the leading blocks of trie branches, saved while a witness node is verified
// and resumed when the same branch is hashed again after an update. A branch of 16 hash children
// is 532 bytes: three 136-byte blocks and a last one of 124. An update rewrites the 32 hash bytes of
// some slots, and the blocks before the first one it rewrites are the witness bytes still. A branch
// with empty or embedded slots (136 to 531 bytes) is hashed as a copy of the witness node with the
// items of its dirty slots rewritten, and the blocks before the first such item are the node's too.
//
// Invariant: while tag_orig[i] is not null, pool[i] holds the Keccak state after the first
// 136 * tag_sb[i] bytes of the witness node at tag_orig[i], of 136 to 532 bytes (rows 0..24; the
// delegation's scratch lanes after them are meaningless), those bytes being verified against their
// hash, and tag_sb[i] is 1..3 (take_resumable_blocks() masks it with 3 all the same, see there).
// Everything that writes a pool row clears its tag first and sets it again only once the node
// hashed to the hash it was looked up by, and a resume clears the tag as it permutes the row in
// place. Witness bytes do not change, so a tag never goes stale, and it names the node by its
// bytes' address, not by where the node sits in the grid: whatever row a tag is found in, the
// state is that of the node it names.
//
// The pool holds the states saved while check_root's walks verify nodes, in the row of the grid line a node
// is unfolded to. The node-store walks of USE_HASH_KEY run during execution, before any grid exists: they save
// in a table of DirectState's instead (kAddrRow), a row per node address, which lives as long as the node store
// it names nodes of. Both keep the invariant above: verify_and_snap() writes every row, and a fold that finds
// a node in neither hashes it in full.
namespace zilkworm::kprefix {

inline constexpr size_t kRows = 128;
static_assert((kRows & (kRows - 1)) == 0, "rows are picked by masking a grid depth");
inline constexpr size_t kNodeSize = 3 + 16 * 33 + 1;  // A full branch with an empty value.
inline constexpr size_t kBlock = 136;
inline constexpr unsigned kNoSlot = 16;  // For first_blocks(): no snapshot wanted.
/// SnapRequest::row of a node-store walk: the state goes to DirectState's table, in the row of the node's address.
inline constexpr size_t kAddrRow = ~size_t{0};
/// DirectState's table: 4096 rows of 256 bytes. A block's walks verify a few thousand full branches, and the folds
/// of check_root come after all of them; a much smaller table would lose most states before they are used.
inline constexpr unsigned kAddrBits = 12;
inline constexpr size_t kAddrRows = size_t{1} << kAddrBits;

/// A row of DirectState's table, laid out as one of the pool.
struct alignas(256) StateRow {
    uint64_t lanes[32];
};
static_assert(sizeof(StateRow) == 256);

/// The table row of the node at `node`: a multiplicative hash of its address (bodies are 8-aligned).
[[gnu::always_inline]] inline size_t addr_row(const uint8_t* node) noexcept {
    return (static_cast<uint32_t>(reinterpret_cast<uintptr_t>(node) >> 3) * 0x9E3779B1u) >> (32 - kAddrBits);
}

/// A saved state a fold resumes from: the first `blocks` blocks (0: none) of a node, in `state`.
struct Resume {
    uint64_t* state;
    unsigned blocks;
};

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

/// The whole blocks of the branch node at `node` (`size` bytes, at least kBlock) before the first byte an update of
/// slot `j` can rewrite (0 for kNoSlot): for a full branch the slot's hash, first_blocks(); for any other branch the
/// slot's item, at the offset the items before it take (a hash reference 33 bytes, an empty slot 1, an embedded node
/// its own length), as encode_branch() rewrites a slot of a copy of the node. At most size / kBlock.
/// The node is not verified when this runs. That is harmless: the count only picks how many of the node's leading
/// blocks the state saved while hashing it covers, the state is that of those bytes whatever they hold, and a fold
/// resumes from it only when its own test, on the verified node, allows that many blocks.
inline unsigned blocks_before_slot(const uint8_t* node, size_t size, unsigned j) noexcept {
    if (size == kNodeSize) return first_blocks(j);
    if (j >= 16) return 0;
    const uint8_t b0 = node[0];
    if (b0 != 0xf8 && b0 != 0xf9) return 0;  // a list of 136 to 65535 bytes has one or two length bytes
    size_t off = b0 == 0xf8 ? 2 : 3;
    for (unsigned i = 0; i < j && off < size; ++i) {
        const unsigned c = node[off];
        off += c == 0xa0u ? 33u : (c >= 0xc0u && c <= 0xf7u) ? 1u + (c - 0xc0u) : 1u;
    }
    return static_cast<unsigned>((off < size ? off : size) / kBlock);
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

/// Whether the keccak of the `size` bytes at `node` (8-byte aligned, at least 136 * `blocks` of them) is
/// `want`, saving the state after its first `blocks` blocks in `state`, and the tag `tag` and `sb` of that
/// row, when it is. Out of line: its tag stores would otherwise add to the registers unfold_slot() keeps
/// live around the lookup.
#if defined(Z6M_GUEST_PROFILE) || defined(Z6M_HOST_PROFILE)
// Fold-side counters, defined in evmone_precompiles/keccak.c.
extern "C" uint64_t z6mprof_verify_snap;
extern "C" uint64_t z6mprof_verify_snap_bytes;
#endif

[[gnu::noinline]] inline bool verify_and_snap(const uint8_t* node, size_t size, uint64_t* state, const uint8_t*& tag,
                                              uint8_t& sb, unsigned blocks, const uint8_t* want) noexcept {
#if defined(Z6M_GUEST_PROFILE) || defined(Z6M_HOST_PROFILE)
    ++z6mprof_verify_snap;
    z6mprof_verify_snap_bytes += size;
#endif
    // The row is about to be overwritten, whatever the compare says: a node that fails it must not
    // leave the tag of the node before it over its bytes' state.
    tag = nullptr;
    const auto h = ethash_keccak256_snap(node, size, blocks, state);
    if (!bytes_equal<32>(h.bytes, want)) [[unlikely]] return false;
    tag = node;
    sb = static_cast<uint8_t>(blocks);
    return true;
}

/// verify_and_snap() of the full branch at `node` into row `row` of the pool.
inline bool verify_and_snap(const uint8_t* node, size_t row, unsigned blocks, const uint8_t* want) noexcept {
    return verify_and_snap(node, kNodeSize, pool[row], tag_orig[row], tag_sb[row], blocks, want);
}

}  // namespace zilkworm::kprefix
