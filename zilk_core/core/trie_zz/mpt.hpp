// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/print.hpp>

namespace zilkworm {
using ::silkworm::kEmptyRoot;
using ::silkworm::ByteView;
using ::silkworm::Bytes;

class DirectState;  // node-store lookups go through DirectState::find_node_rlp
using bytes32 = evmc::bytes32;
inline bytes32 keccak_bytes(const ByteView x) noexcept {
    return std::bit_cast<bytes32>(ethash_keccak256(x.data(), x.size()).bytes);
}
inline bytes32 keccak_bytes32(const bytes32& x) noexcept {
    return std::bit_cast<bytes32>(ethash_keccak256_32(x.bytes));
}
}  // namespace zilkworm

namespace silkworm {
using ::zilkworm::bytes32;
using ::zilkworm::keccak_bytes;
using ::zilkworm::keccak_bytes32;
}  // namespace silkworm

// Witness-bug guard: when an accessed account's leaf is in the node-store but
// its address preimage is missing from `keys`, the addr-keyed prestate map
// misses and balance reads as 0. With USE_HASH_KEY=1, DirectState falls back to
// a hashed-key node-store lookup. Default OFF -> compiled away, zero overhead.
#ifndef USE_HASH_KEY
#define USE_HASH_KEY 0
#endif

namespace zilkworm {
struct nibbles64 {
    uint8_t len{};
    std::array<uint8_t, 64> nib{};  // max trie path is 64 nibbles

    uint8_t& operator[](size_t index) { return nib[index]; }
    const uint8_t& operator[](size_t index) const { return nib[index]; }

    static nibbles64 from_bytes32(const bytes32& k) {
        nibbles64 out;
        out.len = 64;
        for (size_t i = 0; i < 32; ++i) {
            uint8_t b = k.bytes[i];
            out[2 * i] = (b >> 4) & 0x0F;
            out[2 * i + 1] = b & 0x0F;
        }
        return out;
    }

    void append(const nibbles64& other) {
        [[assume(len + other.len <= 64)]];
        std::memcpy(nib.data() + len, other.nib.data(), other.len);
        len += other.len;
    }
};

struct BranchNode {
    // child/child_ptr intentionally left uninitialized: every read is gated by
    // child_len (set slots only), and decode/set_child write them before any
    // read
    std::array<bytes32, 16> child;
    std::array<const uint8_t*, 16> child_ptr;
    std::array<uint8_t, 16> child_len{};
    uint16_t mask{};
    ByteView value{};

    inline uint8_t child_count() const noexcept {
        return static_cast<uint8_t>(std::popcount(mask));
    }

    inline uint8_t first_set_bit() const noexcept {
        return static_cast<uint8_t>(std::countr_zero(mask));
    }

    inline bool has_single_child() const noexcept {
        return std::has_single_bit(mask);
    }

    BranchNode() : child_len{}, mask{}, value{} {}

    inline void set_child(unsigned slot, ByteView b) noexcept {
        [[assume(slot < 16)]];
        mask |= 1 << slot;
        if (b.size() == 0) {
            child_len[slot] = 1;
            child_ptr[slot] = nullptr;
            return;
        }
        std::memcpy(child[slot].bytes, b.data(), b.size());
        child_len[slot] = static_cast<uint8_t>(b.size());
        child_ptr[slot] = nullptr;  // recomputed hash reads own inline storage
    }

    inline void delete_child(unsigned slot) noexcept {
        [[assume(slot < 16)]];
        child_len[slot] = 0;
        child_ptr[slot] = nullptr;
        mask &= ~(1 << slot);
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

    inline void delete_child() noexcept {
        child_len = 0;
    }
};

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
    std::array<uint8_t, 16> child_depth{};

    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), parent_slot(0), parent_depth(0), consumed(0), modified(false), branch{} {}
    GridLine(Kind k, unsigned pslot, unsigned pdepth, unsigned c) : kind{k}, parent_slot{static_cast<uint8_t>(pslot)}, parent_depth{static_cast<uint8_t>(pdepth)}, consumed{static_cast<uint8_t>(c)}, modified{false}, child_depth{} {}
};

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
        return std::memcmp(key.bytes, other.key.bytes, 32) < 0;
    }
};

// A class holding the data for the Trie root calculation
// Proceeds as follows:
// Search a key by going down the tree (unfolding)
// When you find a position to insert, insert there and
// recalculate the hash of that node all the way up (folding)
// If there are more keys to insert, find a common divergence point
// and insert the new key there before folding further.
// More unfolding and folding needed for this or more keys
template <bool DeletionEnabled = false>
class GridMPT {
    unsigned depth_{0};              // The current depth we are visiting
    unsigned search_nib_cursor_{0};  // The position in the current search key
    // Previous root of the trie
    bytes32 prev_root_;
    // A stack of grid-lines consisting of TrieNodes
    std::vector<GridLine> grid_;
    nibbles64 search_nibbles_;  // The current key being searched for/inserted

    bool last_was_delete_{false};

    // Node-store lookups go through DirectState::find_node_rlp, which owns
    // the cached MphfMapHeader pointer + slot_offsets, returns the FlatKv payload
    // slice directly, and lets us drop the bundle blob span from GridMPT.
    const DirectState* state_{nullptr};
    std::vector<bytes32> embedded_rlp_copies_;  // To store owned copies of embedded node RLPs to survive next loop

    // Diagnostic — incremented every time unfold_slot or the ext-child path
    // hits a 32-byte hash ref absent from the node store (witness incomplete).
    unsigned missing_count_{0};

    LeafNode make_cur_leaf(ByteView value_rlp);

    // Shared by the constructor and reset(): if previous_root_hash is
    // non-empty, look it up via DirectState::find_node_rlp and unfold onto
    // grid_[0]. Defined in grid_mpt.cpp to keep the DirectState include out
    // of mpt.hpp.
    void init_from_root(bytes32 previous_root_hash);

    // Update the grid_line's parent-child bookkeeping
    void link_to_parent(GridLine& line, unsigned depth, unsigned parent_slot, unsigned parent_depth);

    // emplace_back a grid_line of `kind`, set the `depth_` to it and `link_to_parent()`.
    GridLine* emplace_line(Kind kind, unsigned parent_slot, unsigned parent_depth, unsigned consumed_init);

  public:
    GridMPT(const DirectState& state, bytes32 previous_root_hash)
        : prev_root_{previous_root_hash},
          grid_{},
          state_{&state} {
        grid_.reserve(66);  // Reserve max depth to avoid reallocations - 66 is a good compromise for average-bad cases
        init_from_root(previous_root_hash);
    }

    // Re-initialise this instance for a new previous-root, reusing the
    // already-allocated grid_/embedded_rlp_copies_ capacity. Used to hoist a
    // single GridMPT<true> out of the per-account merge-walk loop in
    // check_root: ~100-300 modified accounts/block × ~38 KB grid_ buffer adds
    // up to a lot of malloc+free that this avoids.
    void reset(bytes32 new_prev_root) {
        depth_ = 0;
        search_nib_cursor_ = 0;
        last_was_delete_ = false;
        missing_count_ = 0;
        prev_root_ = new_prev_root;
        grid_.clear();                  
        embedded_rlp_copies_.clear();   // keeps capacity
        // search_nibbles_ is overwritten on each insert by the main algorithm
        // (calc_root_from_updates seeds it from the first update); no need to
        // zero it here.
        init_from_root(new_prev_root);
    }

    // Helper methods
    bool unfold_node_from_rlp(ByteView rlp, unsigned parent_slot_index, unsigned parent_depth);
    void delete_line(unsigned depth);
    void fold_line(unsigned depth);
    void pop_back();
    unsigned move_line(unsigned from_depth);
    UnfoldResult unfold_slot(unsigned slot);
    void seek_with_last_insert(nibbles64& new_nibbles);

    // Main algorithm
    bytes32 calc_root_from_updates(std::span<const TrieNodeFlat> updates_sorted);

    template <typename NodeType>
    bool insert_line(unsigned parent_slot, unsigned parent_depth, NodeType&& node);

    template <typename NodeType>
    bool insert_line_at(unsigned target_depth, unsigned parent_slot, unsigned parent_depth, NodeType&& node);

    void delete_leaf(unsigned depth);

    template <typename NodeType>
    bool transform_line(GridLine& line, NodeType&& node);

    // Compile-time check for deletion support
    static constexpr bool supports_deletion() noexcept { return DeletionEnabled; }

    unsigned missing_count() const noexcept { return missing_count_; }
    unsigned cascade_delete(unsigned depth);
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
