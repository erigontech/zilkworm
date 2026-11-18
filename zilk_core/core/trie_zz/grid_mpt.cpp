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
// The HashState fold is emitted only with Z6M_HASH_STATE or on a host build.
#if defined(Z6M_HASH_STATE) || !defined(__riscv)
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/print.hpp>

#include "fold_unfold.hpp"

// Stateless MPT: updates arrive in key order, so a branch's left subtree is never revisited once left.
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
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
// lcp_nibbles(a, b + off, max) for 4-aligned a, b with off + max <= 64, via word loads shifted by off % 4.
[[gnu::always_inline]] inline size_t lcp_nibbles_aligned(const uint8_t* a, const uint8_t* b, size_t off,
                                                          size_t max) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    const w32* const wa = reinterpret_cast<const w32*>(std::assume_aligned<4>(a));
    const w32* const ea = wa + max / 4;
    const w32* pa = wa;
    const w32* pb = reinterpret_cast<const w32*>(std::assume_aligned<4>(b)) + off / 4;
    const unsigned sh = 8 * static_cast<unsigned>(off % 4);
    if (sh == 0) {
#pragma GCC unroll 4
        for (; pa != ea && *pa == *pb; ++pa, ++pb) {}
    } else {
        uint32_t lo = *pb++;
#pragma GCC unroll 4
        for (; pa != ea; ++pa, ++pb) {
            const uint32_t hi = *pb;
            if (*pa != ((lo >> sh) | (hi << (32 - sh)))) break;
            lo = hi;
        }
    }
    size_t k = 4 * static_cast<size_t>(pa - wa);
#pragma GCC unroll 1
    for (; k < max && a[k] == b[off + k]; ++k) {}
    return k;
}
#endif
// Least common path of the current key from the top, against the last key held in search_nibbles_.
template <bool DeletionEnabled, class StateT>
inline void GridMPT<DeletionEnabled, StateT>::seek_with_last_insert(const TrieNodeFlat& cur, const TrieNodeFlat* prev) {
    // lcp is 0-based, parent_consumed 1-based: parent_consumed - 1 < lcp splits, == is the common branch, > folds.
    if (grid_.size() <= 1 || depth_ == 0) {
        if (grid_.size() > 0 && is_empty(grid_[0])) {
            grid_.clear();
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
        // Not reached by a call's first update; a well-formed trie has no branch past nibble 64.
        const nibbles64 new_nibbles = nibbles64::from_bytes32(cur.key);
        lcp = lcp_nibbles(new_nibbles.nib.data(), search_nibbles_.nib.data(), parent_consumed);
    }

    if (lcp >= parent_consumed) {
        if constexpr (DeletionEnabled) {
            if (last_was_delete_) {
                depth_ = cur_parent_depth;
                search_nib_cursor_ = parent_consumed - 1;
                return;
            }
        }
    } else if (cur_parent_depth > 0) {
        unsigned next_parent_depth = grid_[cur_parent_depth].parent_depth;
        parent_consumed = grid_[next_parent_depth].consumed;
        while (parent_consumed > lcp && cur_parent_depth > 0) {
            for (auto i = grid_.size() - 1; i > cur_parent_depth; --i) {
                if (grid_[i].parent_depth >= cur_parent_depth) {
                    // Deletes line i alone: lines a deletion empties were cascaded above, so no other line goes stale.
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
        search_nib_cursor_ = 0;
    } else {
        search_nib_cursor_ = parent_consumed;
    }
    if (search_nib_cursor_ > 63) {
        failed_ = true;
        sys_println("{\"err\":\"nib_cursor > 63\"}");
    }
}

// A key the walk inserts is absent from the pre-state trie: its claimed pre-value is none or 0x80; checked first.
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
        // The first changed root slot is the first nibble of the first key written; read-only tries scan to the end.
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
        return {};
    }
    // The update search_nibbles_ was last expanded from.
    const TrieNodeFlat* prev = nullptr;
    for (; updates_it != updates_end; ++updates_it) {
        const TrieNodeFlat& trie_upd = deref_update(*updates_it);

        search_nib_cursor_ = 0;

        if (!grid_.empty() && search_nibbles_.len > 0) {
            // A previous leaf exists on the grid, in a branch or alone (never ext -> leaf).
            seek_with_last_insert(trie_upd, prev);
        }
        search_nibbles_.assign_bytes32(trie_upd.key);
        prev = &trie_upd;

        if (grid_.empty()) {
            // First update, or deletes emptied the trie (seek pops the last line): reseed as a single full-path leaf.
            if (!claims_absent(trie_upd)) [[unlikely]] {
                return {};
            }
            if (trie_upd.current_value().empty()) {
                continue;
            }
            last_was_delete_ = false;
            root_unfolded_ = false;
            LeafNode l{search_nibbles_, 0, trie_upd.current_value()};
            insert_line(0, 0, std::move(l));
            continue;
        }

        last_was_delete_ = false;

        // Every step consumes a nibble; only a leaf has all 64 consumed, so a non-leaf past nibble 63 fails.
        while (true) {
            if (!(search_nib_cursor_ < 64 || grid_[depth_].kind == kLeaf)) [[unlikely]] {
                failed_ = true;
                sys_println("{\"err\":\"descent past nibble 63\"}");
                return {};
            }
            auto& grid_line = grid_[depth_];
            if (grid_line.kind == kBranch) {
                unsigned nib = search_nibbles_[search_nib_cursor_];
                auto unfold_res = unfold_slot(nib);
                if (unfold_res == UnfoldResult::kEmpty) {
                    if (!claims_absent(trie_upd)) [[unlikely]] {
                        return {};
                    }
                    if (trie_upd.current_value().empty()) {
                        // A read of an absent key inserts nothing; the next seek starts from this branch.
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
                unsigned m = 0;
                while (m < grid_line.ext.path.len && (search_nib_cursor_ + m) < 64 && grid_line.ext.path[m] == search_nibbles_[search_nib_cursor_ + m]) ++m;
                search_nib_cursor_ += m;
                unsigned last_nib = grid_line.ext.path[grid_line.ext.path.len - 1];
                unsigned old_child_depth{grid_line.child_depth[last_nib]};

                if (m == grid_line.ext.path.len) {
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
                        if (!unfold_node_from_rlp(rlp, grid_line.ext.path[m - 1], depth_)) [[unlikely]] {
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
                    // A read of an absent key leaving the extension's path inserts nothing; the next seek starts at the parent.
                    depth_ = grid_line.parent_depth;
                    last_was_delete_ = true;
                    break;
                }
                auto old_ext_line{grid_line};
                auto new_ext_len = old_ext_line.ext.path.len - m - 1;
                unsigned d1{}, d2{};
                // The split appends up to five lines: old child moved twice, a branch, an extension, the leaf.
                if (!has_room(5)) {
                    return {};
                }
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

                if (m > 0) {
                    grid_line.consumed = grid_line.consumed - 1 - new_ext_len;
                    grid_line.ext.child_len = 1;
                    grid_line.ext.path.len = m;
                    grid_[depth_].modified = true;
                    const unsigned new_slot = grid_line.ext.path[m - 1];
                    insert_line_at(d1, new_slot, depth_, BranchNode{});
                    grid_[d1].modified = true;
                    d1 = 0;
                    // insert_line_at wrote child_depth[new_slot]; clearing last_nib on alias would orphan the new branch.
                    if (last_nib != new_slot) {
                        grid_line.child_depth[last_nib] = 0;
                    }
                } else {
                    transform_line(grid_line, BranchNode{});
                    grid_line.modified = true;
                    grid_line.child_depth[last_nib] = 0;
                }

                auto br_depth = depth_;
                if (new_ext_len > 0) {
                    ExtensionNode ext_mplus1{};
                    ext_mplus1.path.len = new_ext_len;
                    std::memcpy(ext_mplus1.path.nib.data(),
                                old_ext_line.ext.path.nib.data() + m + 1,
                                new_ext_len);
                    ext_mplus1.set_child(ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                    if (d1 == 0) {
                        d1 = d2;
                    }
                    insert_line_at(d1, old_ext_line.ext.path[m], depth_, std::move(ext_mplus1));
                    grid_[d1].modified = true;
                } else {
                    grid_[depth_].branch.set_child(last_nib, ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                }

                if (old_child_depth != 0) {
                    grid_[old_child_depth].parent_depth = depth_;
                    grid_[depth_].child_depth[grid_[old_child_depth].parent_slot] = old_child_depth;
                }
                auto l = make_cur_leaf(trie_upd.current_value());
                insert_line(l.parent_slot, br_depth, std::move(l));
                grid_[depth_].modified = true;
                break;
            } else {

                size_t cp;
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
                if (search_nib_cursor_ + grid_line.leaf.path.len <= 64) {
                    cp = lcp_nibbles_aligned(grid_line.leaf.path.nib.data(), search_nibbles_.nib.data(),
                                             search_nib_cursor_, grid_line.leaf.path.len);
                } else
#endif
                {
                    cp = lcp_nibbles(grid_line.leaf.path.nib.data(),
                                     search_nibbles_.nib.data() + search_nib_cursor_,
                                     grid_line.leaf.path.len);
                }
                if (search_nib_cursor_ + cp == 64) {
                    // DirectState only: HashState's updates carry no initial_value or read-only entries.
                    if constexpr (state_keeps_prevalue_check<StateT>) {
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
                            break;
                        }
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
                            break;
                        }
                    }
                    if (grid_line.leaf.value != trie_upd.current_value()) {
                        grid_line.leaf.value = trie_upd.current_value();
                        grid_line.modified = true;
                    }
                    break;
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
                    std::memcpy(ext_common.path.nib.data(), grid_[depth_].leaf.path.nib.data(), cp);
                    ext_common.path.len = cp;

                    unsigned ext_last_nib = ext_common.path[cp - 1];
                    transform_line(grid_[depth_], std::move(ext_common));
                    search_nib_cursor_ += cp;
                    insert_line(ext_last_nib, depth_, std::move(bn));
                } else {
                    transform_line(grid_[depth_], std::move(bn));
                }
                old_leaf.path.len = old_leaf.path.len - cp - 1;  // cp: extension, 1: branch
                old_leaf.parent_slot = old_leaf.path[cp];

                if (old_leaf.path.len > 0) {
                    std::memmove(old_leaf.path.nib.data(),
                                 old_leaf.path.nib.data() + cp + 1,
                                 static_cast<size_t>(old_leaf.path.len));
                }
                auto parent_depth = depth_;
                auto l = make_cur_leaf(trie_upd.current_value());
                insert_line(old_leaf.parent_slot, parent_depth, std::move(old_leaf));
                grid_[depth_].modified = true;
                insert_line(l.parent_slot, parent_depth, std::move(l));
                grid_[depth_].modified = true;
                break;
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
    // An unmodified root is the node verified to hash to prev_root_.
    if (root_unfolded_ && !grid_[0].modified) {
        return prev_root_;
    }
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

// DirectState is named explicitly: a defaulted template argument is omitted from the symbol mangling.
template class GridMPT<false, DirectState>;
template class GridMPT<true, DirectState>;

#if defined(Z6M_HASH_STATE) || !defined(__riscv)
template class GridMPT<false, HashState>;
template class GridMPT<true, HashState>;
#endif

}  // namespace zilkworm
