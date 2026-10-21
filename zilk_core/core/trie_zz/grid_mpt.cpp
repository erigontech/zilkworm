// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
// The HashState fold (GridMPT<*, HashState>) is emitted when that backend is selected (Z6M_HASH_STATE)
// or on a host build (!__riscv), where its unit test links; the DirectState guests pull in neither
// hash_state.hpp nor the instantiation.
#if defined(Z6M_HASH_STATE) || !defined(__riscv)
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/print.hpp>

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

// Find the least common path of current key from the top, with the last key as reference
// (search_nibbles_ still holds the expansion of prev's key, or of whatever key came last when prev is null).
template <bool DeletionEnabled, class StateT>
inline void GridMPT<DeletionEnabled, StateT>::seek_with_last_insert(const TrieNodeFlat& cur, const TrieNodeFlat* prev) {
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
    if (grid_n_ <= 1 || depth_ == 0) {
        if (grid_n_ > 0 && is_empty(grid_[0])) {
            grid_.clear();
            grid_n_ = 0;  // with every deleted line above the root, as cascade_delete() does
        }
        return;
    }

    unsigned cur_parent_depth;
    if constexpr (DeletionEnabled) {
        if (last_was_delete_) {
            cur_parent_depth = cascade_delete(depth_);
        } else {
            cur_parent_depth = grid_[depth_].parent_depth;
        }
    } else {
        cur_parent_depth = grid_[depth_].parent_depth;
    }
    if (cur_parent_depth == 0) {
        depth_ = 0;
        return;
    }
    auto& parent = grid_[cur_parent_depth];
    if (parent.kind != kBranch) {
        failed_ = true;
        sys_println("{\"err\":\"seek: parent not branch\"}");
        depth_ = 0;
        return;
    }
    unsigned parent_consumed = parent.consumed;
    size_t lcp;
    if (prev != nullptr && parent_consumed <= 64) [[likely]] {
        lcp = std::min<size_t>(key_lcp_nibbles(cur, *prev), parent_consumed);
    } else {
        // The first update of a call never gets here (depth_ is 0 after reset() or construction), nor does a
        // well-formed trie have a branch past nibble 64: compare the expanded keys as before.
        const nibbles64 new_nibbles = nibbles64::from_bytes32(cur.key);
        lcp = lcp_packed(new_nibbles.w.data(), search_nibbles_.w.data(), 0, parent_consumed);
    }

    if (lcp >= parent_consumed) {
        if constexpr (DeletionEnabled) {
            if (last_was_delete_) {
                depth_ = cur_parent_depth;
                search_nib_cursor_ = parent_consumed - 1;
                return;
            }
        }
        // If last was not delete, the logic of splitting a leaf is there in the main loop for updates
    } else if (cur_parent_depth > 0) {
        unsigned next_parent_depth = grid_[cur_parent_depth].parent_depth;
        parent_consumed = grid_[next_parent_depth].consumed;  // For the next parent
        GridLine* const lines = grid_.data();  // reserved at construction; appends never reallocate
        while (parent_consumed > lcp && cur_parent_depth > 0) {
            for (auto i = grid_n_ - 1; i > cur_parent_depth; --i) {
                if (lines[i].parent_depth >= cur_parent_depth) {
                    // Deletes line i alone: only an empty line takes more lines with it (cascade_delete deletes
                    // the ancestors it leaves empty), which would leave i and the lines this loop climbs to
                    // stale, and none gets here. A deletion's empty lines go in the cascade above, before any
                    // fold; a read of an absent key inserts no leaf; decode_node() rejects a leaf without a value.
                    fold_line(i);
                }
            }
            cur_parent_depth = next_parent_depth;
            next_parent_depth = grid_[cur_parent_depth].parent_depth;
            parent_consumed = grid_[next_parent_depth].consumed;
        }
        depth_ = cur_parent_depth;
    } else {
        depth_ = cur_parent_depth;
    }

    if (depth_ == 0) {
        search_nib_cursor_ = 0;  // No parent of 0'th element
    } else {
        search_nib_cursor_ = parent_consumed;
    }
    if (search_nib_cursor_ > 63) {
        failed_ = true;
        sys_println("{\"err\":\"nib_cursor > 63\"}");
    }
}

// A key the walk inserts is absent from the pre-state trie, so its claimed pre-value must say so: none for a
// created account or slot, 0x80 (zero) for a slot read as absent. Anything else is a value the block executed
// with that no leaf binds. A read-only update inserts nothing, so at each insertion point this check comes
// before its exit: the check is all that binds the claim of a read.
// Out of line: insertions are rare (about 51K over the 200-block corpus), and inlined at the four insertion
// sites the check cost the descent loop 3.4M cycles in register allocation and code layout.
template <bool DeletionEnabled, class StateT>
[[gnu::noinline]] bool GridMPT<DeletionEnabled, StateT>::claims_absent(const TrieNodeFlat& u) {
    const ByteView v = u.initial_value();
    if (v.empty() || (v.size() == 1 && v[0] == 0x80)) [[likely]] {
        return true;
    }
    failed_ = true;
    sys_println("Pre value claimed for a key absent from the trie");
    return false;
}

namespace {
[[gnu::always_inline]] inline const TrieNodeFlat& deref_update(const TrieNodeFlat& u) noexcept { return u; }
[[gnu::always_inline]] inline const TrieNodeFlat& deref_update(const TrieNodeFlat* u) noexcept { return *u; }
}  // namespace

template <bool DeletionEnabled, class StateT>
template <typename It>
bytes32 GridMPT<DeletionEnabled, StateT>::calc_root_impl(It updates_it, const It updates_end) {
    if (root_pending_) {
        root_pending_ = false;
        // Updates come in key order and a read changes nothing: the first slot of the root they change is the first
        // nibble of the first key written. The scan stops there; a trie that is only read is scanned to its end.
        unsigned first_slot = kprefix::kNoSlot;
        for (It it = updates_it; it != updates_end; ++it) {
            const TrieNodeFlat& u = deref_update(*it);
            if (u.current_value().size() != 0) {
                first_slot = u.key.bytes[0] >> 4;
                break;
            }
        }
        snap_ = first_slot != kprefix::kNoSlot;
        init_from_root(prev_root_, first_slot);
    }
    if (failed_) [[unlikely]] {
        return {};  // the root node could not be read: there is no trie to walk
    }
    // The update search_nibbles_ was last expanded from: the seek compares the keys themselves, and expanding
    // the new key straight into search_nibbles_ skips a zeroed temporary and its copy.
    const TrieNodeFlat* prev = nullptr;
    for (; updates_it != updates_end; ++updates_it) {
        const TrieNodeFlat& trie_upd = deref_update(*updates_it);

        search_nib_cursor_ = 0;

        if (grid_n_ != 0 && search_nibbles_.len > 0) {
            // At this point a previous leaf exists on the grid,
            // and it's in a branch, or just a leaf, or nothing (can't be ext -> leaf)
            seek_with_last_insert(trie_upd, prev);
        }
        search_nibbles_.assign_bytes32(trie_upd.key);
        prev = &trie_upd;

        if (grid_n_ == 0) {
            // Either the very first update, or the preceding deletes emptied
            // the whole trie (seek pops the last line then). Descending the
            // main loop would read grid_[0] out of bounds; this key simply
            // (re)seeds the trie as a single full-path leaf.
            if (!claims_absent(trie_upd)) [[unlikely]] {
                return {};
            }
            if (trie_upd.current_value().empty()) {
                continue;  // a read of a key the empty trie does not have: nothing to insert, see below
            }
            last_was_delete_ = false;
            root_unfolded_ = false;
            LeafNode l{search_nibbles_, 0, trie_upd.current_value()};
            insert_line(0, 0, std::move(l));
            continue;
        }

        last_was_delete_ = false;

        // MAIN LOOP
        // Every step goes down at least one nibble of the key, and only a leaf is reached with all 64 of them
        // consumed (a branch reads the nibble at the cursor). The bound is the key's, not the grid's: depth_ is
        // a line index, and the grid holds up to kMaxLines lines. Leaving the walk here would drop the update
        // unseen, so a node past nibble 63 that is not a leaf fails it.
        while (true) {  // Searching down
            if (!(search_nib_cursor_ < 64 || grid_[depth_].kind == kLeaf)) [[unlikely]] {
                failed_ = true;
                sys_println("{\"err\":\"descent past nibble 63\"}");
                return {};
            }
            auto& grid_line = grid_[depth_];
            if (grid_line.kind == kBranch) {
                unsigned nib = search_nibbles_.at(search_nib_cursor_);
                auto unfold_res = unfold_slot(nib);
                if (unfold_res == UnfoldResult::kEmpty) {
                    // Child is empty - insert here
                    if (!claims_absent(trie_upd)) [[unlikely]] {
                        return {};
                    }
                    if (trie_upd.current_value().empty()) {
                        // A read of a key absent from the trie, which reaching this empty slot shows: nothing to
                        // insert. An empty leaf would fold away again, but the cascade that deletes it can take
                        // lines the seek still climbs through, and leave a branch with a single child the walk
                        // folded already, whose new hash the witness cannot unfold. The next seek starts from
                        // this branch, as after a deletion from it.
                        last_was_delete_ = true;
                        break;
                    }
                    auto l = make_cur_leaf(trie_upd.current_value());
                    if (!has_room(1)) {
                        return {};
                    }
                    insert_line(l.parent_slot, depth_, std::move(l));
                    grid_[depth_].modified = true;
                    break;
                } else if (unfold_res == UnfoldResult::kMissing || unfold_res == UnfoldResult::kUndefined) {
                    failed_ = true;
                    sys_println("ERROR: missing hash ref in node store (witness incomplete)");
                    return {};
                }
                search_nib_cursor_++;
                continue;
            } else if (grid_line.kind == kExt) {
                // go down till the first divergence point
                const unsigned len{grid_line.ext.path.len};
                const size_t lim = std::min<unsigned>(len, 64 - search_nib_cursor_);
                unsigned m = static_cast<unsigned>(lcp_packed(grid_line.ext.path.w.data(), search_nibbles_.w.data(),
                                                               search_nib_cursor_, lim));
                search_nib_cursor_ += m;
                unsigned last_nib = grid_line.ext.path.at(len - 1);
                unsigned old_child_depth{grid_line.child_depth[last_nib]};

                if (m == len) {
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
                                failed_ = true;
                                sys_println("ERROR: missing ext child rlp in node store (witness incomplete)");
                                return {};
                            }
                            rlp = *rlp_opt;
                        }
                        if (!unfold_node_from_rlp(rlp, grid_line.ext.path.at(m - 1), depth_)) [[unlikely]] {
                            ++missing_count_;
                            failed_ = true;
                            sys_println("ERROR: malformed ext child rlp in node store");
                            return {};
                        }
                    }
                    continue;
                }

                if (!claims_absent(trie_upd)) [[unlikely]] {
                    return {};
                }
                if (trie_upd.current_value().empty()) {
                    // A read of a key absent from the trie: it leaves the extension inside its path. Nothing to
                    // insert, as for an empty slot; the next seek starts from the parent branch.
                    depth_ = grid_line.parent_depth;
                    last_was_delete_ = true;
                    break;
                }
                auto old_ext_line{grid_line};  // cache the value;
                auto new_ext_len = old_ext_line.ext.path.len - m - 1;
                unsigned d1{}, d2{};
                // The split appends up to five lines: the old child moved twice, a branch, an extension, the leaf.
                if (!has_room(5)) {
                    return {};
                }
                if (m > 0 || new_ext_len > 0) {
                    d1 = depth_ + 1;
                    while (d1 < grid_n_ && grid_[d1].parent_depth != 0xFF) ++d1;
                }
                if (new_ext_len > 0 && m > 0) {
                    d2 = d1 + 1;
                    while (d2 < grid_n_ && grid_[d2].parent_depth != 0xFF) ++d2;
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
                    grid_line.ext.path = grid_line.ext.path.slice(0, m);
                    grid_[depth_].modified = true;
                    const unsigned new_slot = grid_line.ext.path.at(m - 1);
                    insert_line_at(d1, new_slot, depth_, BranchNode{});
                    grid_[d1].modified = true;
                    d1 = 0;  // Used up
                    // insert_line_at wrote child_depth[new_slot]; clearing last_nib when they alias would orphan the new branch.
                    if (last_nib != new_slot) {
                        grid_line.child_depth[last_nib] = 0;
                    }
                } else {     // new_br -> (new_ext) -> old_child
                    transform_line(grid_line, BranchNode{});
                    grid_line.modified = true;
                    grid_line.child_depth[last_nib] = 0;  // Reset unfolded child
                }

                auto br_depth = depth_;
                if (new_ext_len > 0) {  // (orig_ext) -> new_br -> new_ext -> old_child
                    ExtensionNode ext_mplus1{};
                    ext_mplus1.path = old_ext_line.ext.path.slice(m + 1, new_ext_len);
                    ext_mplus1.set_child(ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                    if (d1 == 0) {  // To check if we need d2 slot
                        d1 = d2;
                    }
                    insert_line_at(d1, old_ext_line.ext.path.at(m), depth_, std::move(ext_mplus1));
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

                const size_t cp = lcp_packed(grid_line.leaf.path.w.data(), search_nibbles_.w.data(),
                                             search_nib_cursor_, grid_line.leaf.path.len);
                if (search_nib_cursor_ + cp == 64) {  // All 64 matched - this is the insertion leaf
                    // Pre-value bind + read-only short-circuit: DirectState only. HashState's update set
                    // carries no initial_value and no read-only entries; its reads are bound to prev_root
                    // at build time (state_keeps_prevalue_check<HashState> == false, hash_state.hpp).
                    if constexpr (state_keeps_prevalue_check<StateT>) {
                        // check pre-value matches
#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
                        const ByteView initial = trie_upd.initial_value();
                        const bool pre_value_ok = grid_line.leaf.value.size() == initial.size() &&
                                                  bytes_equal_any(grid_line.leaf.value.data(), initial.data(),
                                                                  initial.size());
#else
                        const bool pre_value_ok = grid_line.leaf.value == trie_upd.initial_value();
#endif
                        if (!pre_value_ok) {
                            failed_ = true;
                            sys_println("Pre value mismatch in existing leaf");
                            return {};
                        }
                        if (trie_upd.current_value().size() == 0) {
                            break;  // read-only check
                        }
                    }
                    if constexpr (DeletionEnabled) {
                        if (trie_upd.current_value() == ByteView{{0x80}}) {
                            auto parent_depth = grid_line.parent_depth;
                            delete_leaf(depth_);
                            last_was_delete_ = true;
                            depth_ = parent_depth;
                            if (grid_n_ != 0) {  // deleting a root leaf empties the grid
                                grid_[depth_].modified = true;
                            }
                            break;  // delete complete
                        }
                    }
                    if (grid_line.leaf.value != trie_upd.current_value()) {
                        grid_line.leaf.value = trie_upd.current_value();
                        grid_line.modified = true;
                    }
                    break;  // update complete
                }

                if (!claims_absent(trie_upd)) [[unlikely]] {
                    return {};
                }
                if (trie_upd.current_value().empty()) {
                    break;  // a read of a key absent from the trie, which leaves this leaf's path: nothing to insert
                }
                LeafNode old_leaf{grid_[depth_].leaf};
                BranchNode bn;

                if (!has_room(3)) {  // the branch and both leaves
                    return {};
                }
                if (cp > 0) {  // Need to put an extension before the branch
                    ExtensionNode ext_common{};
                    ext_common.path = grid_[depth_].leaf.path.slice(0, cp);

                    // Make the line an extension and insert a branch with this extension as the parent
                    unsigned ext_last_nib = ext_common.path.at(cp - 1);
                    transform_line(grid_[depth_], std::move(ext_common));
                    search_nib_cursor_ += cp;
                    insert_line(ext_last_nib, depth_, std::move(bn));  // sets the depth_ at the branch after
                } else {
                    // Make the line a branch
                    transform_line(grid_[depth_], std::move(bn));
                }
                old_leaf.parent_slot = old_leaf.path.at(cp);  // cp: extension, 1: branch
                old_leaf.path = old_leaf.path.slice(cp + 1, old_leaf.path.len - cp - 1);
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

    while (grid_n_ > 1) {
        fold_line(grid_n_ - 1);
    }

    if (grid_n_ == 0) {
        return kEmptyRoot;
    }
    fold_line(0);
    if (grid_n_ == 0) {
        return kEmptyRoot;
    }
    // An unmodified root is the node verified to hash to prev_root_.
    if (root_unfolded_ && !grid_[0].modified) {
        return prev_root_;
    }
    // As fold_line() hashes such a branch, resumed from the state init_from_root() saved in row 0, the root's line,
    // or a walk saved in DirectState's table.
    if (grid_[0].kind == kBranch && hashes_from_witness(grid_[0].branch)) {
        const kprefix::Resume r = take_resume_full(grid_[0].branch, 0);
        return std::bit_cast<bytes32>(grid_[0].branch.full_branch_hash(r.state, r.blocks));
    }
    const kprefix::Resume r =
        grid_[0].kind == kBranch ? take_resume_encoded(grid_[0].branch, 0) : kprefix::Resume{nullptr, 0};
    auto encoded = encode_line(grid_[0]);
    if (r.blocks != 0) {
        return std::bit_cast<bytes32>(ethash_keccak256_resume(r.state, r.blocks, encoded.data(), encoded.size()));
    }
    return keccak_bytes(encoded);
}

template <bool DeletionEnabled, class StateT>
void GridMPT<DeletionEnabled, StateT>::init_from_root(bytes32 previous_root_hash, unsigned first_slot) {
    root_unfolded_ = false;
    if (previous_root_hash != kEmptyRoot) {
        // Row 0: the grid is empty, and the root's line is grid_[0].
        auto rlp = state_->find_node_rlp(previous_root_hash,
                                         [first_slot]() noexcept { return kprefix::SnapRequest{first_slot, 0}; });
        if (!rlp) [[unlikely]] {
            failed_ = true;
            sys_println("{\"err\":\"no_rlp\"}");
            return;
        }
        root_unfolded_ = unfold_node_from_rlp(*rlp, 0, 0);
        if (!root_unfolded_) [[unlikely]] {
            failed_ = true;
            sys_println("{\"err\":\"init_from_root: malformed root rlp\"}");
        }
    }
}

template <bool DeletionEnabled, class StateT>
bytes32 GridMPT<DeletionEnabled, StateT>::calc_root_from_updates(std::span<const TrieNodeFlat> updates_sorted) {
    return calc_root_impl(updates_sorted.begin(), updates_sorted.end());
}

template <bool DeletionEnabled, class StateT>
bytes32 GridMPT<DeletionEnabled, StateT>::calc_root_from_updates(std::span<const TrieNodeFlat* const> updates_sorted) {
    return calc_root_impl(updates_sorted.begin(), updates_sorted.end());
}

// Explicit template instantiations. DirectState is named rather than left to the StateT default, so
// these emit GridMPT<*, DirectState> whichever backend Z6M_HASH_STATE selects; a defaulted trailing
// template argument is omitted from the Itanium mangling, so the symbols are those of GridMPT<*>.
template class GridMPT<false, DirectState>;
template class GridMPT<true, DirectState>;

#if defined(Z6M_HASH_STATE) || !defined(__riscv)
template class GridMPT<false, HashState>;
template class GridMPT<true, HashState>;
#endif

}  // namespace zilkworm
