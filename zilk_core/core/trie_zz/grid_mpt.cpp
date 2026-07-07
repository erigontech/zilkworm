// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <format>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/print.hpp>

#include <zilk_core/core/state_zz/direct_state.hpp>
#include "fold_unfold.hpp"

//------------------------- GRID_MPT -----------------------------
// Here lies an optimized code for stateless Merkle Patricia Trie
// The core idea is processing nodes in a stack/grid where
// a node is inserted, processed and moved on to the next slot/node
// Now if updates are sorted by keys, you never have to visit the
// left sub-tree at any height of any branch once you are done processing that.
//
// ---------------------------------------------------------------
namespace zilkworm {

// LCP byte length; assumes little-endian host for ctzll byte index.
[[gnu::always_inline]] inline size_t lcp_nibbles(const uint8_t* a, const uint8_t* b, size_t max) noexcept {
    size_t i = 0;
    while (i + 8 <= max) {
        uint64_t wa, wb;
        std::memcpy(&wa, a + i, sizeof(wa));
        std::memcpy(&wb, b + i, sizeof(wb));
        const uint64_t diff = wa ^ wb;
        if (diff != 0) {
            return i + static_cast<size_t>(__builtin_ctzll(diff)) / 8u;
        }
        i += 8;
    }
    while (i < max && a[i] == b[i]) ++i;
    return i;
}
// Find the least common path of current key from the top, with the last key as reference
template <bool DeletionEnabled>
inline void GridMPT<DeletionEnabled>::seek_with_last_insert(nibbles64& new_nibbles) {
    //================================================
    // The last leaf must have been inserted to a branch, or deleted from it
    //  --> lcp: lowest common point (between the last inserted and new_nibbles) <--
    //  --> (note: lcp starts at 0 index, parent_consumed is a counter starting at 1) <--
    // 3 cases arise:
    // 1. If parent_consumed - 1 < lcp, the new leaf shares path, have to split
    // 2. if lcp == parent_consumed - 1, we are at common parent branch
    // 3. if lcp < parent_consumed - 1, fold the children and possibly more
    //
    // Tip: When we are searching for the next nibble, we don't need more than
    // the first level of children from the common branch, ever again
    //================================================
    if (grid_.size() == 1) {
        if (is_empty(grid_[0])) {
            delete_line(0);
        }
        return;
    }

    unsigned cur_parent_depth;
    if constexpr (DeletionEnabled) {
        if (last_was_delete_) {
            cur_parent_depth = depth_;
        } else {
            cur_parent_depth = grid_[depth_].parent_depth;
        }
    } else {
        cur_parent_depth = grid_[depth_].parent_depth;
    }
    auto& parent = grid_[cur_parent_depth];
    if (parent.kind != kBranch) {
        sys_println("{\"err\":\"seek: parent not branch\"}");
        depth_ = 0;
        return;
    }
    unsigned parent_consumed = parent.consumed;
    size_t lcp = lcp_nibbles(new_nibbles.nib.data(), search_nibbles_.nib.data(), parent_consumed);

    if (lcp >= parent_consumed) {
        if constexpr (DeletionEnabled) {
            if (last_was_delete_) {
                search_nib_cursor_ = parent_consumed - 1;
                return;
            }
        }
        // If last was not delete, the logic of splitting a leaf is there in the main loop for updates
    } else if (cur_parent_depth > 0) {
        unsigned next_parent_depth = grid_[cur_parent_depth].parent_depth;
        parent_consumed = grid_[next_parent_depth].consumed;  // For the next parent
        while (parent_consumed > lcp && cur_parent_depth > 0) {
            for (auto i = grid_.size() - 1; i > cur_parent_depth; --i) {
                if (grid_[i].parent_depth >= cur_parent_depth) {
                    fold_line(i);
                }
            }
            cur_parent_depth = next_parent_depth;
            next_parent_depth = grid_[cur_parent_depth].parent_depth;
            parent_consumed = grid_[next_parent_depth].consumed;
        }
        depth_ = cur_parent_depth;
        // For the case when a delete of a branch caused by delete of a leaf
        // This only matters if there are more entries to be added, so this
        // condition isn't required in the final loop
        // We avoid immediate deletes of branch following deletes of leaves
        // as more entries could be added.
        // Note that even for the top-level node fold isn't harmful
        if constexpr (DeletionEnabled) {
            if (auto& line = grid_.back();
                (line.kind == kBranch && (line.branch.mask == 0)) || (line.kind == kExt && line.ext.child_len == 0)) {
                depth_ = line.parent_depth;
                fold_line(grid_.size() - 1);
            }
        }
    } else {
        depth_ = cur_parent_depth;
    }

    if (depth_ == 0) {
        search_nib_cursor_ = 0;
    } else {
        search_nib_cursor_ = parent_consumed;
    }
    if (search_nib_cursor_ > 63) {
        sys_println("{\"err\":\"nib_cursor > 63\"}");
    }
}

template <bool DeletionEnabled>
bytes32 GridMPT<DeletionEnabled>::calc_root_from_updates(std::span<const TrieNodeFlat> updates_sorted) {
    for (auto updates_it = updates_sorted.begin(); updates_it != updates_sorted.end(); ++updates_it) {
        const auto& trie_upd = *updates_it;

        auto new_nibbles = nibbles64::from_bytes32(trie_upd.key);
        search_nib_cursor_ = 0;

        if (!grid_.empty() && search_nibbles_.len > 0) {
            // At this point a previous leaf exists on the grid,
            // and it's in a branch, or just a leaf, or nothing (can't be ext -> leaf)
            seek_with_last_insert(new_nibbles);
        }

        if (grid_.empty()) {
            // Either the very first update, or the preceding deletes emptied
            // the whole trie (seek pops the last line then). Descending the
            // main loop would read grid_[0] out of bounds; this key simply
            // (re)seeds the trie as a single full-path leaf.
            search_nibbles_ = new_nibbles;
            last_was_delete_ = false;
            LeafNode l{search_nibbles_, 0, trie_upd.current_value()};
            insert_line(0, 0, std::move(l));
            continue;
        }

        search_nibbles_ = new_nibbles;
        last_was_delete_ = false;

        // MAIN LOOP
        while (depth_ < 128) {  // Searching down
            auto& grid_line = grid_[depth_];
            if (grid_line.kind == kBranch) {
                unsigned nib = search_nibbles_[search_nib_cursor_];
                auto unfold_res = unfold_slot(nib);
                if (unfold_res == UnfoldResult::kEmpty) {
                    // Child is empty - insert here
                    auto l = make_cur_leaf(trie_upd.current_value());
                    insert_line(l.parent_slot, depth_, std::move(l));
                    grid_[depth_].modified = true;
                    break;
                }
                if (unfold_res == UnfoldResult::kMissing) {
                    sys_println("ERROR: missing hash ref in node store (witness incomplete)");
                    return {};
                }

                search_nib_cursor_++;
                continue;
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                unsigned m = 0;
                while (m < grid_line.ext.path.len && (search_nib_cursor_ + m) < 64 && grid_line.ext.path[m] == search_nibbles_[search_nib_cursor_ + m]) ++m;
                search_nib_cursor_ += m;
                unsigned last_nib = grid_line.ext.path[grid_line.ext.path.len - 1];
                unsigned old_child_depth{grid_line.child_depth[last_nib]};

                if (m == grid_line.ext.path.len) {
                    // Full match -> unfold child
                    if (old_child_depth == 0) {
                        ByteView rlp;
                        if (grid_line.ext.child_len < 32) {
                            embedded_rlp_copies_.emplace_back(grid_line.ext.child);
                            rlp = ByteView{embedded_rlp_copies_.back().bytes, grid_line.ext.child_len};
                        } else {
                            auto rlp_opt = state_->find_node_rlp(grid_line.ext.child);
                            if (!rlp_opt) [[unlikely]] {
                                ++missing_count_;
                                sys_println("ERROR: missing ext child rlp in node store (witness incomplete)");
                                return {};
                            }
                            rlp = *rlp_opt;
                        }
                        unfold_node_from_rlp(rlp, grid_line.ext.path[m - 1], depth_);
                    }
                    continue;
                }

                auto old_ext_line{grid_line};  // cache the value;
                auto new_ext_len = old_ext_line.ext.path.len - m - 1;
                unsigned d1{}, d2{};
                if (m > 0 || new_ext_len > 0) {
                    d1 = depth_ + 1;
                    while (d1 < grid_.size() && grid_[d1].parent_depth != 0xFF) ++d1;
                }
                if (new_ext_len > 0 && m > 0) {
                    d2 = d1 + 1;
                    while (d2 < grid_.size() && grid_[d2].parent_depth != 0xFF) ++d2;
                }

                if (old_child_depth != 0) {
                    if (d1 > old_child_depth) {
                        d1 = old_child_depth;
                        old_child_depth = move_line(old_child_depth);
                    }
                    if (d2 > old_child_depth) {
                        d2 = old_child_depth;
                        old_child_depth = move_line(old_child_depth);
                    }
                }

                if (m > 0) {  // orig_ext -> new_br -> (new_ext) -> old_child
                    grid_line.consumed = grid_line.consumed - 1 - new_ext_len;
                    grid_line.ext.child_len = 1;
                    grid_line.ext.path.len = m;
                    insert_line_at(d1, grid_line.ext.path[m - 1], depth_, BranchNode{});
                    grid_[d1].modified = true;
                    d1 = 0;  // Used up
                } else {     // new_br -> (new_ext) -> old_child
                    transform_line(grid_line, BranchNode{});
                    grid_line.modified = true;
                }
                grid_line.child_depth[last_nib] = 0;  // Reset unfolded child

                auto br_depth = depth_;
                if (new_ext_len > 0) {  // (orig_ext) -> new_br -> new_ext -> old_child
                    ExtensionNode ext_mplus1{};
                    ext_mplus1.path.len = new_ext_len;
                    std::memcpy(ext_mplus1.path.nib.data(),
                                old_ext_line.ext.path.nib.data() + m + 1,
                                new_ext_len);
                    ext_mplus1.set_child(ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                    if (d1 == 0) {  // To check if we need d2 slot
                        d1 = d2;
                    }
                    insert_line_at(d1, old_ext_line.ext.path[m], depth_, std::move(ext_mplus1));
                    grid_[d1].modified = true;
                } else {  // () -> new_br -> old_child
                    grid_[depth_].branch.set_child(last_nib, ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                }

                if (old_child_depth != 0) {
                    grid_[old_child_depth].parent_depth = depth_;
                    grid_[depth_].child_depth[grid_[old_child_depth].parent_slot] = old_child_depth;
                }
                auto l = make_cur_leaf(trie_upd.current_value());
                insert_line(l.parent_slot, br_depth, std::move(l));
                grid_[depth_].modified = true;
                break;  // insertion complete
            } else {
                // It's a leaf:
                // Find common path and create extension and push

                size_t cp = lcp_nibbles(grid_line.leaf.path.nib.data(),
                                        search_nibbles_.nib.data() + search_nib_cursor_,
                                        grid_line.leaf.path.len);
                if (search_nib_cursor_ + cp == 64) {  // All 64 matched - this is the insertion leaf
                    // check pre-value matches
                    if (grid_line.leaf.value != trie_upd.initial_value()) {
                        sys_println("Pre value mismatch in existing leaf");
                        return {};
                    }
                    if (trie_upd.current_value().size() == 0) {
                        break;  // read-only check
                    }
                    if constexpr (DeletionEnabled) {
                        if (trie_upd.current_value() == ByteView{{0x80}}) {
                            auto parent_depth = grid_line.parent_depth;
                            delete_leaf(depth_);
                            last_was_delete_ = true;
                            depth_ = parent_depth;
                            if (!grid_.empty()) {  // deleting a root leaf empties the grid
                                grid_[depth_].modified = true;
                            }
                            break;  // delete complete
                        }
                    }
                    if (grid_line.leaf.value != trie_upd.current_value()){
                        grid_line.leaf.value = trie_upd.current_value();
                        grid_line.modified = true;
                    }
                    break;  // update complete
                }

                LeafNode old_leaf{grid_[depth_].leaf};
                BranchNode bn;

                if (cp > 0) {  // Need to put an extension before the branch
                    ExtensionNode ext_common{};
                    std::memcpy(ext_common.path.nib.data(), grid_[depth_].leaf.path.nib.data(), cp);
                    ext_common.path.len = cp;

                    // Make the line an extension and insert a branch with this extension as the parent
                    unsigned ext_last_nib = ext_common.path[cp - 1];
                    transform_line(grid_[depth_], std::move(ext_common));
                    search_nib_cursor_ += cp;
                    insert_line(ext_last_nib, depth_, std::move(bn));  // sets the depth_ at the branch after
                } else {
                    // Make the line a branch
                    transform_line(grid_[depth_], std::move(bn));
                }
                old_leaf.path.len = old_leaf.path.len - cp - 1;  // cp: extension, 1: branch
                old_leaf.parent_slot = old_leaf.path[cp];

                // Shift the nibble array left by cp + 1
                if (old_leaf.path.len > 0) {
                    std::memmove(old_leaf.path.nib.data(),
                                 old_leaf.path.nib.data() + cp + 1,
                                 static_cast<size_t>(old_leaf.path.len));
                }
                // Insert the leaves to the branch (which is at depth_ now) as parent
                auto parent_depth = depth_;
                auto l = make_cur_leaf(trie_upd.current_value());  // sets parent_slot too at l, with first nib
                insert_line(old_leaf.parent_slot, parent_depth, std::move(old_leaf));
                grid_[depth_].modified = true;
                insert_line(l.parent_slot, parent_depth, std::move(l));
                grid_[depth_].modified = true;
                break;  // insertion complete
            }
        }
    }

    while (grid_.size() > 1) {
        fold_line(grid_.size() - 1);
    }

    if (grid_.size() == 0) {
        return kEmptyRoot;
    }
    fold_line(0);
    if (grid_.empty()) {
        return kEmptyRoot;
    }
    auto encoded = encode_line(grid_[0]);
    return keccak_bytes(encoded);
}

template <bool DeletionEnabled>
void GridMPT<DeletionEnabled>::init_from_root(bytes32 previous_root_hash) {
    if (previous_root_hash != kEmptyRoot) {
        auto rlp = state_->find_node_rlp(previous_root_hash);
        if (!rlp) [[unlikely]] {
            sys_println("{\"err\":\"no_rlp\"}");
            return;
        }
        unfold_node_from_rlp(*rlp, 0, 0);
    }
}

// Explicit template instantiations
template class GridMPT<false>;
template class GridMPT<true>;

}  // namespace zilkworm
