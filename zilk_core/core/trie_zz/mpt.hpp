// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/print.hpp>

#include "node_store_i.hpp"

namespace silkworm {
using bytes32 = evmc::bytes32;
inline bytes32 keccak_bytes(const ByteView x) noexcept {
    return std::bit_cast<bytes32>(ethash_keccak256(x.data(), x.size()).bytes);
}
inline bytes32 keccak_bytes32(const bytes32& x) noexcept {
    return std::bit_cast<bytes32>(ethash_keccak256_32(x.bytes));
}
}  // namespace silkworm

namespace silkworm::mpt {

struct nibbles64 {
    uint8_t len{};                  // Upto what point it holds the path, could be a sub-path
    std::array<uint8_t, 64> nib{};  // each 0..15   // Maximum path a TrieNode can have is 64 nibbles

    // Operator overloads for direct array access
    uint8_t& operator[](size_t index) { return nib[index]; }
    const uint8_t& operator[](size_t index) const { return nib[index]; }

    // Convert a 32-byte key into 64 hex nibbles (0..15 per entry).
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

    // Append another nibbles64 object to this one
    void append(const nibbles64& other) {
        [[assume(len + other.len <= 64)]];
        std::memcpy(nib.data() + len, other.nib.data(), other.len);
        len += other.len;
    }
};

struct BranchNode {
    std::array<bytes32, 16> child{};
    std::array<uint8_t, 16> child_len{};
    uint16_t mask{};
    ByteView value{};  // RLP "value" payload view (empty if none)

    // Bit operations on mask
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

    // sets the branch's child at the slot with b.size() <= 32
    inline void set_child(unsigned slot, ByteView b) noexcept {
        [[assume(slot < 16)]];
        mask |= 1 << slot;
        if (b.size() == 0) {
            child_len[slot] = 1;
            return;
        }
        std::memcpy(child[slot].bytes, b.data(), b.size());
        child_len[slot] = static_cast<uint8_t>(b.size());
    }

    inline void delete_child(unsigned slot) noexcept {
        [[assume(slot < 16)]];
        child_len[slot] = 0;
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
    kBranch = 0,
    kExt = 1,
    kLeaf = 2
};

struct GridLine {
    uint8_t kind;          // Kind
    uint8_t parent_slot;   // parent child index (0..15) or 16 = branch value
    uint8_t parent_depth;  // Depth in the stack the current line's parent is at
    uint8_t consumed;      // path nibbles consumed till this node (cumulative)
    std::array<uint8_t, 16> child_depth{};

    union {
        BranchNode branch;
        ExtensionNode ext;
        LeafNode leaf;
    };

    GridLine() : kind(kBranch), parent_slot(0), parent_depth(0), consumed(0), branch{} {}
    GridLine(unsigned k, unsigned pslot, unsigned pdepth, unsigned c) : kind{static_cast<uint8_t>(k)}, parent_slot{static_cast<uint8_t>(pslot)}, parent_depth{static_cast<uint8_t>(pdepth)}, consumed{static_cast<uint8_t>(c)}, child_depth{} {}
};

struct TrieNodeFlat {
    bytes32 key;
    Bytes value_rlp;

    // Lexicographic comparison for sorting
    bool operator<(const TrieNodeFlat& other) const {
        return key < other.key;
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

    // A store containing the set of keys to be inserted
    NodeStore& node_store_;
    std::vector<bytes32> embedded_rlp_copies_;  // To store owned copies of embedded node RLPs to survive next loop

    LeafNode make_cur_leaf(ByteView value_rlp);

  public:
    GridMPT(NodeStore& node_store, bytes32 previous_root_hash)
        : prev_root_{previous_root_hash},
          grid_{},
          node_store_{node_store} {
        grid_.reserve(66);  // Reserve max depth to avoid reallocations - 66 is a good compromise for average-bad cases
        if (previous_root_hash != kEmptyRoot) {
            // Load root on to first line
            auto rlp = node_store.get_rlp(previous_root_hash);
            if (!rlp) [[unlikely]] {
                sys_println(std::format("{{\"err\":\"no_rlp\",\"hash\":\"{}\"}}", hex(previous_root_hash)));
                return;
            }
            unfold_node_from_rlp(*rlp, 0, 0);
        }
    }

    // Helper methods
    bool unfold_node_from_rlp(ByteView rlp, unsigned parent_slot_index, unsigned parent_depth);
    void delete_line(unsigned depth);
    void fold_line(unsigned depth);
    void pop_back();
    unsigned move_line(unsigned from_depth);
    bool unfold_slot(unsigned slot);
    void seek_with_last_insert(nibbles64& new_nibbles);

    // Main algorithm
    bytes32 calc_root_from_updates(const std::vector<TrieNodeFlat>& updates_sorted);

    template <typename NodeType>
    bool insert_line(unsigned parent_slot, unsigned parent_depth, NodeType&& node);

    template <typename NodeType>
    bool insert_line_at(unsigned target_depth, unsigned parent_slot, unsigned parent_depth, NodeType&& node);

    void delete_leaf(unsigned depth);

    template <typename NodeType>
    bool transform_line(GridLine& line, NodeType&& node);

    // Compile-time check for deletion support
    static constexpr bool supports_deletion() noexcept { return DeletionEnabled; }
};

}  // namespace silkworm::mpt
