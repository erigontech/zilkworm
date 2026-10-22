// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/bytes_cmp.hpp>
#include <zilk_core/core/common_zz/keccak_prefix.hpp>
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/print.hpp>

namespace zilkworm {
using ::silkworm::kEmptyRoot;
using ::silkworm::ByteView;
using ::silkworm::Bytes;

// The node-store backend is selected at compile time via the defaulted GridMPT template parameter
// StateT (default ActiveState, from active_state.hpp above). Node-store lookups go through
// StateT::find_node_rlp, whose signature is identical on both backends (DirectState / HashState).
using bytes32 = evmc::bytes32;
inline bytes32 keccak_bytes(const ByteView x) noexcept {
    return std::bit_cast<bytes32>(silkworm::keccak256(x).bytes);
}
inline bytes32 keccak_bytes32(const bytes32& x) noexcept {
    return std::bit_cast<bytes32>(silkworm::keccak256({x.bytes, 32}).bytes);
}
}  // namespace zilkworm

namespace silkworm {
using ::zilkworm::bytes32;
using ::zilkworm::keccak_bytes;
using ::zilkworm::keccak_bytes32;
}  // namespace silkworm

namespace zilkworm {
// Nibble i: bits 4*(i%16) of word i/16.
[[gnu::always_inline]] inline uint64_t nib_swap64(uint64_t x) noexcept {
    constexpr uint64_t M = 0x0F0F0F0F0F0F0F0Full;
    return ((x & M) << 4) | ((x >> 4) & M);
}

// Requires off <= 63; 64 would read s[4].
[[gnu::always_inline]] inline uint64_t nib_word(const uint64_t* s, size_t off) noexcept {
    const uint64_t lo = s[off >> 4];
    const unsigned sh = 4u * static_cast<unsigned>(off & 15u);
    if (sh == 0) return lo;
    const uint64_t hi = (off >> 4) + 1 < 4 ? s[(off >> 4) + 1] : 0;
    return (lo >> sh) | (hi << (64 - sh));
}

// Requires off + max <= 64.
[[gnu::always_inline]] inline size_t lcp_packed(const uint64_t* a, const uint64_t* s, size_t off,
                                                size_t max) noexcept {
    size_t k = 0;
    for (; k + 16 <= max; k += 16) {
        const uint64_t diff = a[k >> 4] ^ nib_word(s, off + k);
        if (diff != 0) return k + (static_cast<size_t>(__builtin_ctzll(diff)) >> 2);
    }
    if (k != max) {
        const uint64_t diff = a[k >> 4] ^ nib_word(s, off + k);
        const size_t rem = max - k;
        const size_t t = diff != 0 ? static_cast<size_t>(__builtin_ctzll(diff)) >> 2 : rem;
        return k + (t < rem ? t : rem);
    }
    return k;
}

struct nibbles64 {
    uint8_t len{};
    // len leads the ext/leaf union; zero past len.
    alignas(8) std::array<uint64_t, 4> w{};

    uint8_t at(size_t i) const noexcept { return static_cast<uint8_t>((w[i >> 4] >> (4u * (i & 15u))) & 0xFu); }

    void set(size_t i, uint8_t v) noexcept {
        uint64_t& x = w[i >> 4];
        const unsigned sh = 4u * static_cast<unsigned>(i & 15u);
        x = (x & ~(uint64_t{0xF} << sh)) | (uint64_t{v} << sh);
    }

    void push(unsigned nib) noexcept {  // the host trie walks only
        set(len, static_cast<uint8_t>(nib & 0xF));
        ++len;
    }

    static nibbles64 single(unsigned nib) noexcept {
        nibbles64 out;
        out.len = 1;
        out.w[0] = nib & 0xF;
        return out;
    }

    static nibbles64 from_bytes32(const bytes32& k) {
        nibbles64 out;
        out.assign_bytes32(k);
        return out;
    }

    // from_bytes32 in place: that one value-initializes its result for the caller to copy.
    void assign_bytes32(const bytes32& k) noexcept {
        len = 64;
        if (alignof(void*) == 8 && (reinterpret_cast<uintptr_t>(k.bytes) & 7) == 0) [[likely]] {
            // One swap per key word.
            typedef uint64_t __attribute__((may_alias)) w64;
            const w64* const s = reinterpret_cast<const w64*>(std::assume_aligned<8>(k.bytes));
#pragma GCC unroll 4
            for (unsigned i = 0; i < 4; ++i) w[i] = nib_swap64(s[i]);
            return;
        }
        for (unsigned i = 0; i < 4; ++i) {
            uint64_t x = 0;
            for (unsigned j = 0; j < 8; ++j) x |= uint64_t{k.bytes[8 * i + j]} << (8 * j);
            w[i] = nib_swap64(x);
        }
    }

    // assign_bytes32 for a source that may be misaligned
    void assign_bytes32_unaligned(const uint8_t* bytes) noexcept {
        len = 64;
        for (unsigned i = 0; i < 4; ++i) {
            uint64_t x = 0;
            for (unsigned j = 0; j < 8; ++j) x |= uint64_t{bytes[8 * i + j]} << (8 * j);
            w[i] = nib_swap64(x);
        }
    }

    // Requires off + n <= 64.
    nibbles64 slice(size_t off, size_t n) const noexcept {
        [[assume(off + n <= 64)]];
        nibbles64 out;
        out.len = static_cast<uint8_t>(n);
        size_t i = 0;
        for (; i + 16 <= n; i += 16) out.w[i >> 4] = nib_word(w.data(), off + i);
        if (i != n) {  // Mask keeps zero past len.
            const uint64_t v = nib_word(w.data(), off + i);
            out.w[i >> 4] = v & ((uint64_t{1} << (4 * (n - i))) - 1);
        }
        return out;
    }

    void append(const nibbles64& other) {
        [[assume(len + other.len <= 64)]];
        size_t i = 0;
        for (; i + 16 <= other.len; i += 16) or_word(len + i, nib_word(other.w.data(), i));
        for (; i < other.len; ++i) set(len + i, other.at(i));
        len = static_cast<uint8_t>(len + other.len);
    }

  private:
    // Destination bits must be zero.
    void or_word(size_t off, uint64_t v) noexcept {
        const unsigned sh = 4u * static_cast<unsigned>(off & 15u);
        w[off >> 4] |= v << sh;
        if (sh != 0 && (off >> 4) + 1 < 4) w[(off >> 4) + 1] |= v >> (64 - sh);
    }
};

struct BranchNode {
    // child/child_ptr intentionally left uninitialized: every read is gated by
    // child_len (set slots only), and decode/set_child write them before any
    // read
    std::array<bytes32, 16> child;
    std::array<const uint8_t*, 16> child_ptr;
    alignas(8) std::array<uint8_t, 16> child_len{};
    // Aliased so one sd sets all four.
    union {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
        struct {
            uint64_t mask : 16;
            uint64_t orig_size : 16;
            uint64_t dirty : 16;
            uint64_t spare : 16;
        };
#pragma GCC diagnostic pop
        uint64_t mask_word;
    };
    ByteView value{};
    // Orig witness RLP; null when built in-grid.
    const uint8_t* orig{nullptr};
    alignas(8) std::array<uint8_t, 16> orig_child_len{};

    // Unchanged iff no slot changed length class.
    inline bool same_layout_as_orig() const noexcept {
        // Through data() the 8-byte alignment is lost, and a strict-alignment target then
        // copies both arrays byte-wise (two memcpy calls per encode); read them as words.
        typedef uint64_t __attribute__((may_alias)) w64;
        const w64* a = reinterpret_cast<const w64*>(std::assume_aligned<8>(child_len.data()));
        const w64* b = reinterpret_cast<const w64*>(std::assume_aligned<8>(orig_child_len.data()));
        return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
    }

    inline uint8_t child_count() const noexcept {
        return static_cast<uint8_t>(std::popcount(mask));
    }

    inline uint8_t first_set_bit() const noexcept {
        return static_cast<uint8_t>(std::countr_zero(mask));
    }

    inline bool has_single_child() const noexcept {
        return std::has_single_bit(mask);
    }

    BranchNode() : child_len{}, mask_word{0}, value{} {}

    inline void set_child(unsigned slot, ByteView b) noexcept {
        [[assume(slot < 16)]];
        mask_word |= (uint64_t{1} << slot) | (uint64_t{1} << (32 + slot));
        if (b.size() == 0) {
            child_len[slot] = 1;
            child_ptr[slot] = nullptr;
            return;
        }
        std::memcpy(child[slot].bytes, b.data(), b.size());
        child_len[slot] = static_cast<uint8_t>(b.size());
        child_ptr[slot] = nullptr;  // recomputed hash reads own inline storage
    }

    // set_child() for a hash reference: the keccak of `rlp`, a child's encoding of 32 bytes or more.
    inline void set_child_hash(unsigned slot, ByteView rlp) noexcept {
        [[assume(slot < 16)]];
        mask_word |= (uint64_t{1} << slot) | (uint64_t{1} << (32 + slot));
        child_len[slot] = 32;
        child_ptr[slot] = nullptr;
        // The keccak returns its hash straight into the slot, with no copy out of a temporary: the
        // bytes array provides storage for it, suitably aligned as child[] leads this 8-aligned
        // struct. The hash bytes of child[] are only ever read through memcpy, byte loads or
        // may_alias words, never through a typed access to the bytes array.
        ::new (static_cast<void*>(child[slot].bytes)) ethash::hash256(silkworm::keccak256(rlp));
    }

    // set_child_hash() resumed from `r`, a state of the first r.blocks blocks of `rlp` (none if 0), which it consumes.
    inline void set_child_hash(unsigned slot, ByteView rlp, kprefix::Resume r) noexcept {
        if (r.blocks == 0) {
            set_child_hash(slot, rlp);
            return;
        }
        [[assume(slot < 16)]];
        mask_word |= (uint64_t{1} << slot) | (uint64_t{1} << (32 + slot));
        child_len[slot] = 32;
        child_ptr[slot] = nullptr;
        ::new (static_cast<void*>(child[slot].bytes))
            ethash::hash256(ethash_keccak256_resume(r.state, r.blocks, rlp.data(), rlp.size()));
    }

    // The keccak of the encoding of this branch, which hashes_from_witness() (rlp_sw.hpp) must accept:
    // read from the witness node and the new hashes of the dirty slots, with no copy. With `blocks`
    // nonzero, `state` holds the state of the node's first blocks (see take_resumable_blocks()),
    // which the call consumes.
    inline ethash::hash256 full_branch_hash(uint64_t* state, unsigned blocks) const noexcept {
        return ethash_keccak256_full_branch(state, blocks, orig, static_cast<uint16_t>(mask_word >> 32), child[0].bytes, child_ptr.data());
    }

    // set_child_hash() for the full branch `node`: its full_branch_hash().
    inline void set_child_hash_of(unsigned slot, const BranchNode& node, uint64_t* state, unsigned blocks) noexcept {
        [[assume(slot < 16)]];
        mask_word |= (uint64_t{1} << slot) | (uint64_t{1} << (32 + slot));
        child_len[slot] = 32;
        child_ptr[slot] = nullptr;
        ::new (static_cast<void*>(child[slot].bytes)) ethash::hash256(node.full_branch_hash(state, blocks));
    }

    inline void delete_child(unsigned slot) noexcept {
        [[assume(slot < 16)]];
        mask_word = (mask_word | (uint64_t{1} << (32 + slot))) & ~(uint64_t{1} << slot);
        child_len[slot] = 0;
        child_ptr[slot] = nullptr;
    }
};

struct ExtensionNode {
    nibbles64 path;
    bytes32 child{};
    uint8_t child_len;

    inline void set_child(ByteView b) noexcept {
        std::memcpy(child.bytes, b.data(), b.size());
        child_len = static_cast<uint8_t>(b.size());
    }

    // set_child() for a hash reference: the keccak of `rlp`, a child's encoding of 32 bytes or more.
    inline void set_child_hash(ByteView rlp) noexcept {
        const ethash::hash256 h = silkworm::keccak256(rlp);
        // the 8-aligned nibbles64 leaves child 8-aligned
        typedef uint64_t __attribute__((may_alias)) w64;
        w64* const d = reinterpret_cast<w64*>(std::assume_aligned<8>(child.bytes));
        for (size_t i = 0; i < 4; ++i) d[i] = h.word64s[i];
        child_len = 32;
    }

    // set_child_hash() resumed from `r`, as BranchNode's.
    inline void set_child_hash(ByteView rlp, kprefix::Resume r) noexcept {
        if (r.blocks == 0) {
            set_child_hash(rlp);
            return;
        }
        const ethash::hash256 h = ethash_keccak256_resume(r.state, r.blocks, rlp.data(), rlp.size());
        typedef uint64_t __attribute__((may_alias)) w64;
        w64* const d = reinterpret_cast<w64*>(std::assume_aligned<8>(child.bytes));
        for (size_t i = 0; i < 4; ++i) d[i] = h.word64s[i];
        child_len = 32;
    }

    // set_child_hash() for the full branch `node`, as BranchNode::set_child_hash_of().
    inline void set_child_hash_of(const BranchNode& node, uint64_t* state, unsigned blocks) noexcept {
        const ethash::hash256 h = node.full_branch_hash(state, blocks);
        typedef uint64_t __attribute__((may_alias)) w64;
        w64* const d = reinterpret_cast<w64*>(std::assume_aligned<8>(child.bytes));
        for (size_t i = 0; i < 4; ++i) d[i] = h.word64s[i];
        child_len = 32;
    }

    inline void delete_child() noexcept {
        child_len = 0;
    }
};

// BranchNode::set_child_hash places an ethash::hash256 into child[slot].bytes; ExtensionNode::set_child_hash
// stores whole words into child.
static_assert(offsetof(BranchNode, child) == 0 && alignof(BranchNode) >= 8);
static_assert(offsetof(nibbles64, w) == 8 && alignof(nibbles64) == 8);
static_assert(offsetof(ExtensionNode, child) % 8 == 0);
static_assert(sizeof(BranchNode) == (sizeof(void*) == 4 ? 632 : 704));  // 4-byte ptrs/ByteView on ilp32

struct LeafNode {
    nibbles64 path;
    uint8_t parent_slot;
    ByteView value{};
};

inline bool is_zero_quick(const bytes32& h) noexcept {
    auto words = std::bit_cast<std::array<std::uint32_t, 8>>(h);
    return (words[0] | words[1] | words[2] | words[3] |
            words[4] | words[5] | words[6] | words[7]) == 0;
}
inline bool is_zero_quick(const ByteView b) noexcept {
    return std::all_of(b.begin(), b.end(), [](uint8_t byte) { return byte == 0; });
}
inline void zero(bytes32& h) noexcept { std::memset(h.bytes, 0, 32); }

enum Kind : uint8_t {
    kInvalid = 0,
    kBranch = 1,
    kExt = 2,
    kLeaf = 3,
    kExtOrLeaf = 4
};

// Result of an unfold attempt against a branch slot.
// kEmpty - The RLP indicates empty
// kMissing - The RLP indicates non-empty but the target RLP not found
// kUndefined - Error occurred
enum class UnfoldResult : uint8_t {
    kSuccess,
    kEmpty,
    kMissing,
    kUndefined
};

struct GridLine {
    Kind kind;          // Kind
    uint8_t parent_slot;   // parent child index (0..15) or 16 = branch value
    uint8_t parent_depth;  // Depth in the stack the current line's parent is at
    uint8_t consumed;      // path nibbles consumed till this node (cumulative)
    bool modified;
    // Word-aligned (free: the union below is 8-aligned) so zeroing it is 4 word stores on a
    // strict-alignment target rather than a call to memset for 16 unaligned bytes.
    alignas(4) std::array<uint8_t, 16> child_depth{};

    // Parent pointer: kills index mul on climbs
    GridLine* parent;

    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), parent_slot(0), parent_depth(0), consumed(0), modified(false), parent(nullptr), branch{} {}
    GridLine(Kind k, unsigned pslot, unsigned pdepth, unsigned c, GridLine* p) : parent(p) {
        // header+child_depth as three word stores
        typedef uint64_t __attribute__((may_alias)) w64;
        *reinterpret_cast<w64*>(std::assume_aligned<8>(this)) =
            static_cast<uint64_t>(static_cast<uint8_t>(k)) |
            (static_cast<uint64_t>(static_cast<uint8_t>(pslot)) << 8) |
            (static_cast<uint64_t>(static_cast<uint8_t>(pdepth)) << 16) |
            (static_cast<uint64_t>(static_cast<uint8_t>(c)) << 24);
        w64* const cd = reinterpret_cast<w64*>(std::assume_aligned<8>(child_depth.data()));
        cd[0] = 0;
        cd[1] = 0;
    }
};

static_assert(offsetof(GridLine, kind) == 0);
static_assert(offsetof(GridLine, parent_slot) == 1);
static_assert(offsetof(GridLine, parent_depth) == 2);
static_assert(offsetof(GridLine, consumed) == 3);
static_assert(offsetof(GridLine, modified) == 4);
static_assert(offsetof(GridLine, child_depth) == 8);
static_assert(offsetof(GridLine, parent) == 24);
static_assert(offsetof(GridLine, branch) == 32);
static_assert(sizeof(GridLine) == (sizeof(void*) == 4 ? 664 : 736) && alignof(GridLine) == 8);  // ilp32 child shrink

struct TrieNodeFlat {
    bytes32 key;
    // self_initial_len > 0 means initial RLP lives in buf[0..]; else use ext_initial.
    ByteView ext_initial{};
    uint8_t self_initial_len{0};
    uint8_t current_off{0};
    uint8_t current_len{0};

    TrieNodeFlat() = default;
    // buf[] left uninit; callers must write before reading.
    [[gnu::always_inline]] explicit TrieNodeFlat(const bytes32& k) noexcept : key{k} {}
    // Sized to match silkworm::kAccRlpBufSize; smaller variants violate the bound.
    uint8_t buf[112];

    ByteView initial_value() const noexcept {
        return self_initial_len > 0 ? ByteView{buf, self_initial_len} : ext_initial;
    }
    ByteView current_value() const noexcept {
        return {buf + current_off, current_len};
    }

    bool operator<(const TrieNodeFlat& other) const {
        return lt_bytes32(key.bytes, other.key.bytes);  // TrieNodeFlat is 4-aligned, key first
    }
};

// Leading nibbles two keys share, read from the keys themselves: equal to lcp_packed over their packed
// expansions. Word compares need the 4-byte alignment of TrieNodeFlat::key, which a bytes32 elsewhere (in a
// witness node, say) need not have; no ctz, which rv32im lacks (ctzll is a __ctzdi2 call).
[[gnu::always_inline]] inline unsigned key_lcp_nibbles(const TrieNodeFlat& a, const TrieNodeFlat& b) noexcept {
    static_assert(offsetof(TrieNodeFlat, key) == 0 && alignof(TrieNodeFlat) >= 4);
    typedef uint32_t __attribute__((may_alias)) w32;
    const w32* const wa = reinterpret_cast<const w32*>(std::assume_aligned<4>(a.key.bytes));
    const w32* const wb = reinterpret_cast<const w32*>(std::assume_aligned<4>(b.key.bytes));
    unsigned i = 0;
    while (i < 8 && wa[i] == wb[i]) ++i;
    if (i == 8) return 64;
    unsigned j = 4 * i;  // the first differing byte is in word i
    while (a.key.bytes[j] == b.key.bytes[j]) ++j;
    return 2 * j + (((a.key.bytes[j] ^ b.key.bytes[j]) & 0xF0) == 0);
}

/// Sorts n pointers to nodes by the nodes' keys: a walk that reads the nodes through them leaves
/// the nodes in place (sort_trie_nodes() moves each out-of-place node once).
inline void sort_trie_node_ptrs(const TrieNodeFlat** order, size_t n) {
    if (n < 2) return;
    const auto less = [](const TrieNodeFlat* a, const TrieNodeFlat* b) noexcept {
        return lt_bytes32(a->key.bytes, b->key.bytes);
    };
    if (n <= 16) {
        for (size_t i = 1; i < n; ++i) {
            const TrieNodeFlat* const k = order[i];
            size_t j = i;
            while (j > 0 && less(k, order[j - 1])) {
                order[j] = order[j - 1];
                --j;
            }
            order[j] = k;
        }
    } else {
        std::sort(order, order + n, less);
    }
}

/// Sorts n nodes by key. A node is 155 bytes, so a sort that moves nodes (n^2/4 moves for the
/// insertion sort below 17, n log n for std::sort) spends most of its time copying; this sorts
/// indices and then applies the permutation, moving each node at most once (cycle following).
inline void sort_trie_nodes(TrieNodeFlat* data, size_t n) {
    if (n < 2) return;
    uint32_t local_idx[64];
    std::vector<uint32_t> heap_idx;
    uint32_t* idx = local_idx;
    if (n > 64) {
        heap_idx.resize(n);
        idx = heap_idx.data();
    }
    for (size_t i = 0; i < n; ++i) idx[i] = static_cast<uint32_t>(i);
    const auto less = [data](uint32_t a, uint32_t b) noexcept {
        return lt_bytes32(data[a].key.bytes, data[b].key.bytes);
    };
    if (n <= 16) {
        for (size_t i = 1; i < n; ++i) {
            const uint32_t k = idx[i];
            size_t j = i;
            while (j > 0 && less(k, idx[j - 1])) {
                idx[j] = idx[j - 1];
                --j;
            }
            idx[j] = k;
        }
    } else {
        std::sort(idx, idx + n, less);
    }
    // data[i] must become the node idx[i] held before; follow each cycle with one node in hand.
    for (size_t i = 0; i < n; ++i) {
        if (idx[i] == i) continue;
        TrieNodeFlat held = data[i];
        size_t j = i;
        while (true) {
            const size_t k = idx[j];
            idx[j] = static_cast<uint32_t>(j);
            if (k == i) {
                data[j] = held;
                break;
            }
            data[j] = data[k];
            j = k;
        }
    }
}

// A class holding the data for the Trie root calculation
// Proceeds as follows:
// Search a key by going down the tree (unfolding)
// When you find a position to insert, insert there and
// recalculate the hash of that node all the way up (folding)
// If there are more keys to insert, find a common divergence point
// and insert the new key there before folding further.
// More unfolding and folding needed for this or more keys
template <bool DeletionEnabled = false, class StateT = ActiveState>
class GridMPT {
    uint64_t depth_{0};             // The current depth we are visiting
    uint64_t search_nib_cursor_{0};  // The position in the current search key
    // Previous root of the trie
    bytes32 prev_root_;
    // A stack of grid-lines consisting of TrieNodes. Lines name each other by uint8_t depth, 0xFF marking a
    // deleted line, so there are at most kMaxLines; and references to lines are held across the appends of
    // unfolds and insertions, so the grid is allocated at that size once and never moves. Honest tries take
    // it far past a path's length: each branch on the path of the current key keeps the children the walk
    // unfolded under it until it leaves the branch, so a path of D branches that each have 15 such children
    // holds 16 D + 1 lines (76 keys ground to share prefixes of up to 4 nibbles make 81).
    static constexpr size_t kMaxLines = 255;
    std::vector<GridLine> grid_;
    size_t grid_n_ = 0;  // cached count; kills size()'s div-by-728 in loops
    nibbles64 search_nibbles_;  // The current key being searched for/inserted

    bool last_was_delete_{false};
    // grid_[0] is the node find_node_rlp() verified to hash to prev_root_ (unchanged while unmodified).
    bool root_unfolded_{false};
    // Set by the constructor and reset(): prev_root_ is looked up and unfolded by calc_root_impl(), which knows
    // the first slot of the root its updates change, so that the lookup saves the right keccak state of the root.
    bool root_pending_{false};
    // Whether the walk's updates write anything, set with root_pending_: a walk that only reads changes no node,
    // and its lookups save no keccak state (unfold_slot()).
    bool snap_{false};

    bool light_ro_{false};

    // Node-store lookups go through StateT::find_node_rlp (DirectState owns
    // the cached MphfMapHeader pointer + slot_offsets, returns the FlatKv payload
    // slice directly, and lets us drop the bundle blob span from GridMPT.
    const StateT* state_{nullptr};
    // Owned copies of the embedded node RLPs unfolded during the walk: an embedded leaf's value is a view
    // into its copy until the leaf is folded, so the copies must not move as more are added (a deque).
    std::deque<bytes32> embedded_rlp_copies_;

    // Diagnostic — incremented every time unfold_slot or the ext-child path
    // hits a 32-byte hash ref absent from the node store (witness incomplete).
    unsigned missing_count_{0};

    // Set by every path that cannot go on with the witness it was given (a missing or malformed node, a
    // pre-value that does not match): the root calc_root_from_updates() then returns means nothing, and
    // the caller must reject. A failed walk returns a zero root, which a root compare alone would accept
    // against a header that commits to a zero root.
    bool failed_{false};

    LeafNode make_cur_leaf(ByteView value_rlp);

    // Run by calc_root_impl() before its walk, for the root the constructor or reset() named: if
    // previous_root_hash is non-empty, look it up via DirectState::find_node_rlp and unfold onto grid_[0].
    // A full branch verified there keeps the keccak state of its blocks before `first_slot`, the first slot of
    // it the updates change (kNoSlot: none), for the final root to resume from. Defined in grid_mpt.cpp to keep
    // the DirectState include out of mpt.hpp.
    void init_from_root(bytes32 previous_root_hash, unsigned first_slot);

    // parent is grid_[parent_depth]; null at root.
    void link_to_parent(GridLine& line, unsigned depth, unsigned parent_slot, GridLine* parent);

    // emplace_back a grid_line of `kind`, set the `depth_` to it and `link_to_parent()`.
    GridLine* emplace_line(Kind kind, unsigned parent_slot, unsigned parent_depth, GridLine* parent,
                           unsigned consumed_init);

    // Whether `lines` more lines fit the grid (see kMaxLines); the walk cannot go on if not.
    bool has_room(unsigned lines);

    // The keccak state a fold of the full branch `b` of pool row `row` resumes from (fold_unfold.hpp).
    kprefix::Resume take_resume_full(const BranchNode& b, size_t row);
    // The same for a branch encode_branch() copies from its witness node and patches (fold_unfold.hpp).
    kprefix::Resume take_resume_encoded(const BranchNode& b, size_t row);

  public:
    GridMPT(const StateT& state, bytes32 previous_root_hash)
        : prev_root_{previous_root_hash},
          grid_{},
          state_{&state} {
        grid_.reserve(kMaxLines);
        // Not in reset(): the witness does not change from one trie to the next, so a state saved while
        // verifying a node stays that node's. A new instance may have a witness at the old one's
        // addresses (a host test), whose tags would then name other bytes.
        kprefix::clear_tags();
        root_pending_ = true;
    }
    // A copy would allocate its grid at the size it has, and its leaves would still view this one's copies.
    GridMPT(const GridMPT&) = delete;
    GridMPT& operator=(const GridMPT&) = delete;

    // Re-initialise this instance for a new previous-root, reusing the
    // already-allocated grid_/embedded_rlp_copies_ capacity. Used to hoist a
    // single GridMPT<true> out of the per-account merge-walk loop in
    // check_root: ~100-300 modified accounts/block × ~167 KB grid_ buffer adds
    // up to a lot of malloc+free that this avoids.
    void reset(bytes32 new_prev_root) {
        depth_ = 0;
        search_nib_cursor_ = 0;
        last_was_delete_ = false;
        missing_count_ = 0;
        failed_ = false;
        prev_root_ = new_prev_root;
        grid_.clear();
        grid_n_ = 0;
        embedded_rlp_copies_.clear();   // keeps capacity
        // search_nibbles_ is overwritten on each insert by the main algorithm
        // (calc_root_from_updates seeds it from the first update); no need to
        // zero it here.
        root_pending_ = true;
    }

    // Helper methods
    bool unfold_node_from_rlp(ByteView rlp, unsigned parent_slot_index, unsigned parent_depth,
                              GridLine* parent);
    void delete_line(unsigned depth);
    void fold_line(unsigned depth);
    void pop_back();
    unsigned move_line(unsigned from_depth);
    UnfoldResult unfold_slot(unsigned slot);
    UnfoldResult unfold_slot(unsigned slot, GridLine& grid_line);
    void seek_with_last_insert(const TrieNodeFlat& cur, const TrieNodeFlat* prev);
    // Whether update `u`, whose key the walk is about to insert, claims the key absent; flags the walk
    // failed if not.
    bool claims_absent(const TrieNodeFlat& u);

    // Main algorithm
    bytes32 calc_root_from_updates(std::span<const TrieNodeFlat> updates_sorted);
    // The same walk over an order of pointers (see sort_trie_node_ptrs()): the nodes stay where they are.
    bytes32 calc_root_from_updates(std::span<const TrieNodeFlat* const> updates_sorted);

// all-read walks bind light, not grid
    void enable_light_read_only() noexcept { light_ro_ = true; }

    template <typename NodeType>
    bool insert_line(unsigned parent_slot, unsigned parent_depth, NodeType&& node, GridLine* parent);

    template <typename NodeType>
    bool insert_line_at(unsigned target_depth, unsigned parent_slot, unsigned parent_depth, NodeType&& node,
                        GridLine* parent);

    void delete_leaf(unsigned depth);

    template <typename NodeType>
    bool transform_line(GridLine& line, NodeType&& node);

    // Compile-time check for deletion support
    static constexpr bool supports_deletion() noexcept { return DeletionEnabled; }

    unsigned missing_count() const noexcept { return missing_count_; }

    // Whether anything since construction or the last reset() failed; see failed_.
    bool failed() const noexcept { return failed_; }

    unsigned cascade_delete(unsigned depth);

  private:
    // The walk of both calc_root_from_updates(), over the nodes or pointers to them (grid_mpt.cpp).
    template <typename It>
    bytes32 calc_root_impl(It updates_it, It updates_end);

// cells whose single-child fold is pending
    struct RoFoldEntry {
        unsigned depth;
        Bytes cell;
    };
    template <typename It>
    bytes32 calc_root_read_only_impl(It updates_it, It updates_end);
    bool ro_descend(const TrieNodeFlat* u, ByteView node, unsigned consumed, std::vector<RoFoldEntry>* pend,
                    bool from_ext);
// sorted writes: lcp neighbours for reads
    std::vector<const TrieNodeFlat*> light_writes_;
};

}  // namespace zilkworm

// Backward-compat bridge for silkworm::mpt:: callers (witness_trie.cpp etc.)
// and unqualified uses inside `namespace silkworm { ... }` consumer TUs.
namespace silkworm {
namespace mpt {
    using ::zilkworm::nibbles64;
    using ::zilkworm::BranchNode;
    using ::zilkworm::ExtensionNode;
    using ::zilkworm::LeafNode;
    using ::zilkworm::Kind;
    using ::zilkworm::kBranch;
    using ::zilkworm::kExt;
    using ::zilkworm::kLeaf;
    using ::zilkworm::UnfoldResult;
    using ::zilkworm::GridLine;
    using ::zilkworm::TrieNodeFlat;
    template <bool DeletionEnabled> using GridMPT = ::zilkworm::GridMPT<DeletionEnabled>;
    using ::zilkworm::is_zero_quick;
    using ::zilkworm::zero;
}  // namespace mpt
}  // namespace silkworm
