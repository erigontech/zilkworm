// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/print.hpp>

#include "mpt.hpp"
#include "rlp_sw.hpp"

namespace zilkworm {

// rlp helpers live in silkworm::rlp; alias for local readability.
namespace rlp = ::silkworm::rlp;

[[gnu::always_inline]] inline rlp::Header fast_decode_header(ByteView& from) noexcept {
    if (from.size() < 8) [[unlikely]] {
        return {false, from.size()};
    }
    uint64_t word;
    std::memcpy(&word, from.data(), 8);
    uint8_t first = word & 0xFF;

    if (first < 0x80) return {false, 1};

    bool is_list = first >= 0xC0;
    uint8_t offset = first & 0x3Fu;

    from.remove_prefix(1);
    if (offset <= 55) return {is_list, offset};

    size_t len_bytes = offset - 55;
    size_t length = ((word >> 8) & 0xFF) << 16 | ((word >> 16) & 0xFF) << 8 | ((word >> 24) & 0xFF);
    length >>= (8 * (3 - len_bytes));
    from.remove_prefix(len_bytes);
    return {is_list, length};
}

// Here lies an optimized code for stateless Merkle Patricia Trie
// The core idea is processing nodes in a stack/grid where
// a node is inserted, processed and moved on to the next slot/node
// The core idea is based on the fact that if updates are sorted
// by keys, you never have to visit the left sub-tree at any height
// of any branch once you are done processing that.

// Decode an MPT node from its into a GridLine and push onto grid
// Returns false on failure and true on success
template <bool DeletionEnabled>
bool GridMPT<DeletionEnabled>::unfold_node_from_rlp(ByteView payload, unsigned parent_slot_index, unsigned parent_depth) {
    // Use the inline fast_decode_header — every ext-child unfold and every
    // direct unfold call lands here, so an out-of-line .cpp call would charge
    // ~256 (3T+C) of jal/jalr per node read.
    auto hh{fast_decode_header(payload)};
    if (!hh.list) [[unlikely]] {
        sys_println(("ERROR: unfold_node_from_rlp Invalid Payload Header, parent_slot_index: " 
            + std::to_string(parent_slot_index) 
            + " parent_depth: " + std::to_string(parent_depth)).c_str());
        return false;
    }
    auto list{payload.substr(0, hh.payload_length)};

    bool is_leaf = false;
    std::array<uint8_t, 64> path;
    uint8_t plen = 0;
    ByteView second{};

    GridLine* line_ptr = emplace_line(kBranch, parent_slot_index, parent_depth, 1u);
    if (!line_ptr) [[unlikely]] return false;
    GridLine& line = *line_ptr;

    Kind kind = decode_node(list, line.branch, is_leaf, path, plen, second);
    if (kind == kBranch) {
        return true;
    }
    if (kind == kInvalid) [[unlikely]] {
        pop_back();
        return false;
    }
    if (is_leaf) {
        LeafNode l{nibbles64{plen, path}, static_cast<uint8_t>(parent_slot_index), second};
        transform_line(line, std::move(l));
    } else {
        ExtensionNode ext{nibbles64{plen, path}, {}};
        // Reject an oversized child that would overflow child (a 32-byte bytes32).
        if (second.size() > sizeof(ext.child.bytes)) return false;
        std::copy(second.cbegin(), second.cend(), ext.child.bytes);
        ext.child_len = static_cast<uint8_t>(second.size());
        transform_line(line, std::move(ext));
    }
    return true;
}

// Deletes leaf towards the end of the stack at the given depth
// Swaps the last child with this position, if of the same parent
// Use it only if grid_.back() has the current parent
template <bool DeletionEnabled>
void GridMPT<DeletionEnabled>::delete_leaf(unsigned depth) {
    if (depth > 0) {
        GridLine& grid_line = grid_[depth];
        GridLine& parent = grid_[grid_line.parent_depth];
        unsigned parent_slot = grid_line.parent_slot;
        parent.branch.delete_child(parent_slot);
        parent.child_depth[parent_slot] = 0;  // clear

        // Compact easily if it's in the middle and shares parent with the last one
        if (depth != grid_.size() - 1 && grid_.back().parent_depth == grid_line.parent_depth) {
            grid_line = grid_.back();  // TODO: Use smaller copy for leaf
            parent.child_depth[grid_line.parent_slot] = depth;
            depth = grid_.size() - 1;
        }
    }
    delete_line(depth);
}

template <bool DeletionEnabled>
void GridMPT<DeletionEnabled>::pop_back() {
    grid_.pop_back();
    depth_ = grid_.size() - 1;
}

// Soft delete a line in the middle, hard-delete from the end
template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::delete_line(unsigned depth) {
    if (depth == grid_.size() - 1) {
        grid_.pop_back();
    } else {
        grid_[depth].parent_depth = 0xff;
    }
}
template <bool DeletionEnabled>
inline unsigned GridMPT<DeletionEnabled>::cascade_delete(unsigned depth) {
    while (is_empty(grid_[depth])) {
        auto& grid_line = grid_[depth];
        if (grid_.size() > 1 && depth > 0) {
            auto parent_depth = grid_line.parent_depth;
            auto& parent = grid_[parent_depth];
            switch (parent.kind) {
                case kBranch:
                    parent.branch.delete_child(grid_line.parent_slot);
                    parent.child_depth[grid_line.parent_slot] = 0;  // clear
                    parent.modified = true;
                    break;
                case kExt:
                    parent.ext.delete_child();
                    parent.child_depth[grid_line.parent_slot] = 0;  // clear
                    parent.modified = true;
                    break;
                default:
                    std::unreachable();
            }
            delete_line(depth);
            depth = parent_depth;
        } else {
            delete_line(depth);
            return 0;
        }
    }
    return depth;
}

// Fold line at a given depth and make it phantom or deleted
template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::fold_line(unsigned depth) {
    auto& grid_line = grid_[depth];
    if (grid_line.parent_depth == 0xFF) {
        grid_.pop_back();  // depth musth be at the end as otherwise already popped, see delete_line
        return;            // Phantom line
    }
    if constexpr (DeletionEnabled) {
        if (is_empty(grid_line)) {
            cascade_delete(depth);
            return;
        }
        if (grid_line.kind == kBranch && grid_line.branch.has_single_child()) {  // Should get absorbed into an extension
            unsigned non_empty_nib = grid_line.branch.first_set_bit();
            depth_ = depth;
            // TODO optimize by checking it's a branch or not
            if (unfold_slot(non_empty_nib) != UnfoldResult::kSuccess) {  // Needed because if it's a leaf this will get extended.
                sys_println("Error: fold_line unexpected error unfolding non_emtpy_nib");
            }
            ExtensionNode ext{nibbles64{1, {static_cast<uint8_t>(non_empty_nib)}}};
            if (grid_.back().kind == kBranch) {
                auto clen = grid_line.branch.child_len[non_empty_nib];
                const uint8_t* src = (clen == 32 && grid_line.branch.child_ptr[non_empty_nib])
                                         ? grid_line.branch.child_ptr[non_empty_nib]
                                         : grid_line.branch.child[non_empty_nib].bytes;
                ext.child_len = clen;
                ext.set_child(ByteView{src, clen});
                transform_line(grid_line, std::move(ext));
                grid_line.modified = true;
                grid_line.child_depth[non_empty_nib] = 0;
                grid_.pop_back();
                return;
            }
            transform_line(grid_line, std::move(ext));

            fold_line(grid_line.child_depth[non_empty_nib]);  // The extension would get absorbed, if needed, in the next recursion
        }

        if (grid_.size() > 1) {
            GridLine& parent = grid_[grid_line.parent_depth];

            // Note: the following isn't code duplication
            // We are applying parent br transformation here to avoid having to store hashed entry to be unfolded again
            // single-child br -> ext
            if (parent.kind == kBranch && parent.branch.has_single_child()) {
                ExtensionNode ext{
                    nibbles64{1, {parent.branch.first_set_bit()}}};
                transform_line(parent, std::move(ext));
                parent.modified = true;
            }

            // ext -> ext = ext
            if (grid_line.kind == kExt && parent.kind == kExt) {
                parent.ext.path.append(grid_line.ext.path);
                parent.ext.child = grid_line.ext.child;  // Todo only copy up to child_len
                parent.ext.child_len = grid_line.ext.child_len;
                parent.child_depth[grid_line.parent_slot] = 0;
                parent.modified = true;
                delete_line(depth);
                return;
            }

            // ext -> leaf = leaf
            if (grid_line.kind == kLeaf && parent.kind == kExt) {
                nibbles64 new_path{parent.ext.path};
                new_path.append(grid_line.leaf.path);
                grid_line.leaf.path = new_path;
                grid_line.leaf.parent_slot = parent.parent_slot;
                transform_line(parent, std::move(grid_line.leaf));
                parent.modified = true;
                delete_line(depth);
                return;
            }
        }
    }

    if (!grid_line.modified) {
        if (grid_.size() > 1) {
            // Clear parent's pointer; otherwise restructures follow a dangling depth.
            grid_[grid_line.parent_depth].child_depth[grid_line.parent_slot] = 0;
            delete_line(depth);
        }
        return;
    }

    const auto& encoded = encode_line(grid_line);
    bytes32 hash;
    ByteView node_ref;
    if (encoded.size() >= 32) {
        hash = keccak_bytes(encoded);
        node_ref = ByteView{hash.bytes, 32};
    } else {
        node_ref = encoded;
    }
    if (grid_.size() > 1) {
        auto& parent = grid_[grid_line.parent_depth];
        parent.modified = true;
        switch (parent.kind) {
            case kBranch:
                parent.branch.set_child(grid_line.parent_slot, node_ref);
                parent.child_depth[grid_line.parent_slot] = 0;  // clear
                break;
            case kExt:
                parent.ext.set_child(node_ref);
                parent.child_depth[grid_line.parent_slot] = 0;  // clear
                break;
            default:
                std::unreachable();
        }
        delete_line(depth);
    }
}

// Make a leaf of path after cursor of current search key
template <bool DeletionEnabled>
inline LeafNode GridMPT<DeletionEnabled>::make_cur_leaf(ByteView value_rlp) {
    LeafNode l{};
    l.parent_slot = search_nibbles_[search_nib_cursor_];
    l.path.len = 64 - (search_nib_cursor_ + 1);
    std::memcpy(l.path.nib.data(),
                &search_nibbles_[search_nib_cursor_ + 1],
                l.path.len);
    l.value = value_rlp;
    return l;
}

// Displaces the subtree chain starting at from_depth by cascading swaps along
// first-child pointers. Frees the slot at from_depth (marked phantom) and
// returns the new depth where the original node ended up.
template <bool DeletionEnabled>
unsigned GridMPT<DeletionEnabled>::move_line(unsigned from_depth) {
    GridLine cache{grid_[from_depth]};
    grid_[from_depth].parent_depth = 0xFF;  // Mark slot as phantom

    unsigned result_depth = 0;
    bool first = true;
    unsigned prev_depth = 0;
    unsigned prev_slot = 0;

    while (true) {
        unsigned next_depth = 0;
        unsigned child_slot = 0;
        if (cache.kind != kLeaf) {
            for (unsigned i = 0; i < 16; i++) {
                if (cache.child_depth[i] != 0) {
                    next_depth = cache.child_depth[i];
                    child_slot = i;
                    break;
                }
            }
        }

        if (next_depth != 0) {
            std::swap(grid_[next_depth], cache);

            if (first) {
                result_depth = next_depth;
                first = false;
            } else {
                grid_[prev_depth].child_depth[prev_slot] = next_depth;
            }

            // Update other children's parent_depth to the new position
            auto& placed = grid_[next_depth];
            for (unsigned i = 0; i < 16; i++) {
                if (placed.child_depth[i] != 0 && placed.child_depth[i] != next_depth) {
                    grid_[placed.child_depth[i]].parent_depth = next_depth;
                }
            }

            cache.parent_depth = next_depth;
            prev_depth = next_depth;
            prev_slot = child_slot;
        } else {
            grid_.push_back(cache);
            auto pushed = static_cast<unsigned>(grid_.size() - 1);

            if (first) {
                result_depth = pushed;
            } else {
                grid_[prev_depth].child_depth[prev_slot] = pushed;
            }
            break;
        }
    }
    return result_depth;
}

template <bool DeletionEnabled>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled>::insert_line(unsigned parent_slot, unsigned parent_depth, NodeType&& node) {
    Kind kind;
    unsigned consumed;
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        kind = kLeaf;
        consumed = 0u;
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;  // read before the move below
    } else {  // BranchNode
        kind = kBranch;
        consumed = 1u;
    }
    GridLine* l = emplace_line(kind, parent_slot, parent_depth, consumed);
    if (!l) return false;  // parent_slot out of range
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        l->leaf = std::forward<NodeType>(node);
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        l->ext = std::forward<NodeType>(node);
    } else {  // BranchNode
        l->branch = std::forward<NodeType>(node);
    }
    return true;
}

template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::link_to_parent(GridLine& line, unsigned depth, unsigned parent_slot, unsigned parent_depth) {
    if (depth > 0) {
        auto& parent = grid_[parent_depth];
        line.consumed += parent.consumed;
        parent.child_depth[parent_slot] = static_cast<uint8_t>(depth);
        if (parent.kind == kBranch && parent.branch.child_len[parent_slot] == 0) {
            parent.branch.mask |= 1 << parent_slot;
            parent.branch.child_len[parent_slot] = 1;  // Placeholder, update during fold_line
        }
        if (parent.kind == kExt && parent.ext.child_len == 0) {
            parent.ext.child_len = 1;  // Placeholder, update during fold_line
        }
    }
}

template <bool DeletionEnabled>
inline GridLine* GridMPT<DeletionEnabled>::emplace_line(Kind kind, unsigned parent_slot, unsigned parent_depth, unsigned consumed_init) {
    if (parent_slot >= 16) return nullptr;
    grid_.emplace_back(kind, parent_slot, parent_depth, consumed_init);
    depth_ = grid_.size() - 1;
    if (depth_ > 0) link_to_parent(grid_.back(), depth_, parent_slot, parent_depth);
    return &grid_.back();
}

/// Create and insert a new line at the given target_depth
template <bool DeletionEnabled>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled>::insert_line_at(unsigned target_depth, unsigned parent_slot, unsigned parent_depth, NodeType&& node) {
    if (parent_slot >= 16) return false;

    if (target_depth == grid_.size()) {
        // Same as insert_line — append to back
        return insert_line(parent_slot, parent_depth, std::forward<NodeType>(node));
    }

    // Overwrite an existing (phantom) slot
    auto& line = grid_[target_depth];
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        line = GridLine(kLeaf, parent_slot, parent_depth, 0u);
        line.leaf = std::forward<NodeType>(node);
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        line = GridLine(kExt, parent_slot, parent_depth, node.path.len);
        line.ext = std::forward<NodeType>(node);
    } else {  // BranchNode
        line = GridLine(kBranch, parent_slot, parent_depth, 1u);
        line.branch = std::forward<NodeType>(node);
    }
    depth_ = target_depth;
    link_to_parent(line, target_depth, parent_slot, parent_depth);
    return true;
}

template <bool DeletionEnabled>
template <typename NodeType>
// Cast a given GridLine to a node of NodeType
inline bool GridMPT<DeletionEnabled>::transform_line(GridLine& line, NodeType&& node) {
    // extract parent_consumed info from existing line's consumed var
    unsigned parent_consumed = line.consumed;  // cumulative
    if (line.kind == kExt) {
        parent_consumed = parent_consumed - line.ext.path.len;
    } else if (line.kind == kBranch) {
        parent_consumed = parent_consumed - 1;
    }

    Kind kind;
    unsigned consumed;
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        kind = kLeaf;
        consumed = 0;
        line.leaf = std::move(node);
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;
        line.ext = std::move(node);
        if (consumed + parent_consumed > 255) {
            sys_println("{\"err\":\"cast_overflow\"}");
        }
    } else {
        kind = kBranch;
        consumed = 1;
        line.branch = std::move(node);
        if (consumed + parent_consumed > 255) {
            sys_println("{\"err\":\"cast_overflow\"}");
        }
    }
    line.consumed = static_cast<uint8_t>(consumed + parent_consumed);
    line.kind = kind;
    return true;
}

// Unfolds the node at the given slot of the branch at depth_
// Returns kEmpty when the slot is empty - 0x80 (caller should insert here),
// kMissing when a 32-byte hash ref has no entry in the node store
// (witness incomplete — caller should hard-fail), kSuccess otherwise.
template <bool DeletionEnabled>
inline UnfoldResult GridMPT<DeletionEnabled>::unfold_slot(unsigned slot) {
    if (slot > 15) [[unlikely]] {
        sys_println("{\"err\":\"slot > 15\"}");
        return UnfoldResult::kUndefined;
    }
    if (depth_ >= grid_.size()) [[unlikely]] {
        sys_println("{\"err\":\"depth >= grid_size\"}");
        return UnfoldResult::kUndefined;
    }
    if (grid_[depth_].kind != kBranch)  [[unlikely]] {
        sys_println("{\"err\":\"unfold_not_branch\"}");
        return UnfoldResult::kUndefined;
    }

    auto& grid_line = grid_[depth_];
    if (auto s = grid_line.child_depth[slot]; s) {  // Unfolded child exists
        if (s > grid_.size()) [[unlikely]] {
            sys_println("{\"err\":\"child_depth > size\"}");
            return UnfoldResult::kUndefined;
        }
        depth_ = s;
        return UnfoldResult::kSuccess;
    }

    auto child_len = grid_line.branch.child_len[slot];
    auto& child = grid_line.branch.child[slot];

    if (child_len == 0 || 
        (child_len == 1 && child.bytes[0] == 0x80)) {  // empty, nothing to "unfold"
        return UnfoldResult::kEmpty;
    }

    ByteView rlp;
    if (child_len == 32) {
        // Hash ref
        bytes32 ck;
        const uint8_t* hs = grid_line.branch.child_ptr[slot] ? grid_line.branch.child_ptr[slot] : child.bytes;
        std::memcpy(ck.bytes, hs, 32);
        auto rlp_opt = state_->find_node_rlp(ck);
        if (!rlp_opt) [[unlikely]] {
            ++missing_count_;
            sys_println("{\"err\":\"node_store_get_rlp_failed\"}");
            return UnfoldResult::kMissing;
        }
        rlp = *rlp_opt;
    } else {
        // Must move this outside of this object
        embedded_rlp_copies_.emplace_back(child);
        rlp = ByteView{embedded_rlp_copies_.back().bytes, child_len};
    }
    if (rlp.size() == 0) [[unlikely]] {
        sys_println("{\"err\":\"rlp_size_0\"}");
        return UnfoldResult::kMissing;
    }
    bool success = unfold_node_from_rlp(rlp, slot, depth_);
    if (success)
        grid_line.child_depth[slot] = depth_;
    return success ? UnfoldResult::kSuccess : UnfoldResult::kMissing;
}

}  // namespace zilkworm
