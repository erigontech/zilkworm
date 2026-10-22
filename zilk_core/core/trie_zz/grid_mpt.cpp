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
            cur_parent_depth = cascade_delete(static_cast<unsigned>(depth_));
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
        GridLine* const lines = grid_.data();  // reserved at construction; appends never reallocate
        GridLine* par = &lines[cur_parent_depth];
        unsigned next_parent_depth = par->parent_depth;
        parent_consumed = par->parent->consumed;  // For the next parent
        while (parent_consumed > lcp && cur_parent_depth > 0) {
            for (GridLine* p = lines + (grid_n_ - 1); p > lines + cur_parent_depth; --p) {
                if (p->parent_depth >= cur_parent_depth) {
                    // Deletes line i alone: only an empty line takes more lines with it (cascade_delete deletes
                    // the ancestors it leaves empty), which would leave i and the lines this loop climbs to
                    // stale, and none gets here. A deletion's empty lines go in the cascade above, before any
                    // fold; a read of an absent key inserts no leaf; decode_node() rejects a leaf without a value.
                    fold_line(static_cast<unsigned>(p - lines));
                }
            }
            cur_parent_depth = next_parent_depth;
            par = par->parent;
            next_parent_depth = par->parent_depth;
            parent_consumed = par->parent->consumed;
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

// fold's shape check for a lone child
bool ro_node_well_formed(ByteView node, unsigned at) {
    const auto hh = fast_decode_header(node);
    if (!hh.list) [[unlikely]] {
        return false;
    }
    const ByteView list = node.substr(0, hh.payload_length);

    if (list.size() == 16 * 33 + 1 && list[16 * 33] == rlp::kEmptyStringCode) [[likely]] {
        const uint8_t* const p = list.data();
        bool hashes = true;
        for (size_t i = 0; i < 16; ++i) {
            if (p[33 * i] != 0xa0) {
                hashes = false;
                break;
            }
        }
        if (hashes) {
            return true;
        }
    }

    ByteView rem = list;
    const uint8_t e0_start = rem.empty() ? 0 : *rem.data();
    const auto h0 = rlp::decode_header(rem);
    ByteView e0_payload;
    bool e0_list = false;
    if (h0) {
        e0_payload = rem.substr(0, h0->payload_length);
        e0_list = h0->list;
        rem.remove_prefix(h0->payload_length);
    }
    const uint8_t* const e1_start_ptr = rem.data();
    const uint8_t e1_start = rem.empty() ? 0 : *rem.data();
    const auto h1 = rlp::decode_header(rem);
    ByteView e1_payload;
    bool e1_list = false;
    if (h1) {
        e1_payload = rem.substr(0, h1->payload_length);
        e1_list = h1->list;
        rem.remove_prefix(h1->payload_length);
    }
    if (!h0 || !h1) [[unlikely]] {
        return false;
    }

    if (rem.empty()) {
        if (e0_list || e1_list) [[unlikely]] {
            return false;
        }
        nibbles64 path;
        bool is_leaf = false;
        uint8_t plen = 0;
        if (!hp_decode(e0_payload, is_leaf, path, plen)) [[unlikely]] {
            return false;
        }
        if (is_leaf ? at + plen != 64 : (plen == 0 || at + plen > 63)) [[unlikely]] {
            return false;
        }
        if (is_leaf) [[likely]] {
            return h1->payload_length != 0 && h1->payload_length <= kMaxLeafValueSize;
        }
        const ByteView child = h1->payload_length == 32
                                   ? e1_payload
                                   : ByteView{e1_start_ptr,
                                              static_cast<size_t>(e1_payload.data() - e1_start_ptr) +
                                                  h1->payload_length};
        return child.size() <= 32;  
    }

    const auto slot_ok = [](uint8_t start, ByteView payload) {
        return payload.empty() || start == 0xa0 || payload.size() <= 31;
    };
    if (!slot_ok(e0_start, e0_payload) || !slot_ok(e1_start, e1_payload)) [[unlikely]] {
        return false;
    }
    const uint8_t* p = rem.data();
    const uint8_t* const end = p + rem.size();
    for (unsigned i = 2; i < 16; ++i) {
        if (p == end) [[unlikely]] {
            return false;
        }
        const uint8_t b0 = *p;
        if (b0 == 0xa0) {
            if (end - p < 33) [[unlikely]] {
                return false;
            }
            p += 33;
        } else if (b0 == rlp::kEmptyStringCode) {
            ++p;
        } else if (b0 >= 0xc0 && b0 <= 0xf7) {
            const size_t pl = static_cast<size_t>(b0 - 0xc0);
            if (pl > 31) [[unlikely]] {
                return false;
            }
            if (static_cast<size_t>(end - p) < 1 + pl) [[unlikely]] {
                return false;
            }
            p += 1 + pl;
        } else [[unlikely]] {
            return false;
        }
    }
    return static_cast<size_t>(end - p) == 1 && *p == rlp::kEmptyStringCode;
}

// list header only; 0xf8 needs its byte
bool ro_child_shape(ByteView cell) {
    if (cell.empty()) [[unlikely]] {
        return false;
    }
    const uint8_t b0 = cell[0];
    return (b0 >= 0xc0 && b0 <= 0xf7) || (b0 == 0xf8 && cell.size() >= 2);
}
}  // namespace

// u == nullptr probes shape only
template <bool DeletionEnabled, class StateT>
[[gnu::noinline]] bool GridMPT<DeletionEnabled, StateT>::ro_descend(const TrieNodeFlat* u, ByteView node,
                                                                    unsigned consumed,
                                                                    std::vector<RoFoldEntry>* pend, bool from_ext) {
    nibbles64 key;
    key.assign_bytes32(u != nullptr ? u->key : bytes32{});
    const bool probe = u == nullptr;

// ping-pong buffers: parent overlaps child
    alignas(8) uint8_t embed[2][32];
    unsigned phase = 0;

    for (;;) {
        auto hh = fast_decode_header(node);
        if (!hh.list) [[unlikely]] {
            failed_ = true;
            if (from_ext) {
                ++missing_count_;
            }
            sys_println("{\"err\":\"ro_bind malformed node header\"}");
            return false;
        }
        const ByteView list = node.substr(0, hh.payload_length);

        if (list.size() == 16 * 33 + 1 && list[16 * 33] == rlp::kEmptyStringCode) {
            const uint8_t* const p = list.data();
            bool hashes = true;
#pragma GCC unroll 16
            for (size_t i = 0; i < 16; ++i) {
                if (p[33 * i] != 0xa0) {
                    hashes = false;
                    break;
                }
            }
            if (hashes) [[likely]] {
                if (probe) [[unlikely]] {
                    return true;
                }
                if (consumed >= 64) [[unlikely]] {
                    failed_ = true;
                    sys_println("{\"err\":\"descent past nibble 63\"}");
                    return false;
                }
                bytes32 h;
                std::memcpy(h.bytes, p + 33 * key.at(consumed) + 1, 32);
                const auto next = state_->find_node_rlp(h);
                if (!next) [[unlikely]] {
                    ++missing_count_;
                    failed_ = true;
                    sys_println("ERROR: missing hash ref in node store (witness incomplete)");
                    return false;
                }
                node = *next;
                ++consumed;
                from_ext = false;
                continue;
            }
        }

        auto malformed = [this, from_ext]() {
            failed_ = true;
            if (from_ext) {
                ++missing_count_;
            }
            sys_println("{\"err\":\"ro_bind malformed node\"}");
            return false;
        };

        ByteView rem = list;
        const uint8_t e0_start = rem.empty() ? 0 : *rem.data();
        auto h0 = rlp::decode_header(rem);
        ByteView e0_payload;
        bool e0_list = false;
        if (h0) {
            e0_payload = rem.substr(0, h0->payload_length);
            e0_list = h0->list;
            rem.remove_prefix(h0->payload_length);
        }
        const uint8_t* const e1_start_ptr = rem.data();
        const uint8_t e1_start = rem.empty() ? 0 : *rem.data();
        auto h1 = rlp::decode_header(rem);
        ByteView e1_payload;
        bool e1_list = false;
        if (h1) {
            e1_payload = rem.substr(0, h1->payload_length);
            e1_list = h1->list;
            rem.remove_prefix(h1->payload_length);
        }
        if (!h0 || !h1) [[unlikely]] {
            return malformed();
        }

        if (rem.empty()) {
            if (e0_list || e1_list) [[unlikely]] {
                return malformed();
            }
            nibbles64 path;
            bool is_leaf = false;
            uint8_t plen = 0;
            if (!hp_decode(e0_payload, is_leaf, path, plen)) [[unlikely]] {
                return malformed();
            }
            if (is_leaf ? consumed + plen != 64 : (plen == 0 || consumed + plen > 63)) [[unlikely]] {
                return malformed();
            }
            if (is_leaf) {
                if (h1->payload_length == 0 || h1->payload_length > kMaxLeafValueSize) [[unlikely]] {
                    return malformed();
                }
                if (probe) [[unlikely]] {
                    return true;
                }
                if (consumed + lcp_packed(path.w.data(), key.w.data(), consumed, plen) == 64) {
                    if (e1_payload != u->initial_value()) {
                        failed_ = true;
                        sys_println("Pre value mismatch in existing leaf");
                        return false;
                    }
                    return true;
                }
                return claims_absent(*u);
            }
            const ByteView child = h1->payload_length == 32
                                       ? e1_payload
                                       : ByteView{e1_start_ptr,
                                                  static_cast<size_t>(e1_payload.data() - e1_start_ptr) +
                                                      h1->payload_length};
            if (child.size() > 32) [[unlikely]] {  
                return malformed();
            }
            if (probe) [[unlikely]] {
                return true;
            }
            const unsigned m = static_cast<unsigned>(
                lcp_packed(path.w.data(), key.w.data(), consumed, std::min<unsigned>(plen, 64 - consumed)));
            if (m != plen) {
                return claims_absent(*u);  
            }
            consumed += plen;
            if (child.size() == 32) {
                bytes32 h;
                std::memcpy(h.bytes, child.data(), 32);
                const auto r = state_->find_node_rlp(h);
                if (!r) [[unlikely]] {
                    ++missing_count_;
                    failed_ = true;
                    sys_println("ERROR: missing ext child rlp in node store (witness incomplete)");
                    return false;
                }
                node = *r;
            } else {
                if (!ro_child_shape(child)) [[unlikely]] {
                    failed_ = true;
                    ++missing_count_;
                    sys_println("ERROR: malformed ext child rlp in node store");
                    return false;
                }
                uint8_t* const d = embed[phase];
                std::memcpy(d, child.data(), child.size());
                node = ByteView{d, child.size()};
                phase ^= 1;
            }
            from_ext = true;
            continue;
        }

        if (consumed >= 64) [[unlikely]] {
            failed_ = true;
            sys_println("{\"err\":\"descent past nibble 63\"}");
            return false;
        }
        const unsigned nib = key.at(consumed);
        uint8_t* const dst = embed[phase];
        const uint8_t* child_at = nullptr;
        uint8_t clen = 0;
// grid folds only single-child branches
        unsigned n_children = 0;
        const uint8_t* fc_p = nullptr;
        uint8_t fc_start = 0, fc_len = 0;
        const auto note = [&](uint8_t start, const uint8_t* q, uint8_t len) {
            if (n_children++ == 0) {
                fc_start = start;
                fc_p = q;
                fc_len = len;
            }
        };

        const auto fill = [&](unsigned i, uint8_t start, ByteView payload) -> bool {
            if (payload.empty()) {
                return true;  
            }
            if (start == 0xa0) {
                note(0xa0, payload.data(), 32);
                if (i == nib) {
                    child_at = payload.data();
                    clen = 32;
                }
                return true;
            }
            if (payload.size() > 31) {
                return false;  
            }
            note(start, payload.data(), static_cast<uint8_t>(payload.size() + 1));
            if (i == nib) {
                dst[0] = start;  
                std::memcpy(dst + 1, payload.data(), payload.size());
                child_at = dst;
                clen = static_cast<uint8_t>(payload.size() + 1);
            }
            return true;
        };
        if (!fill(0, e0_start, e0_payload) || !fill(1, e1_start, e1_payload)) [[unlikely]] {
            return malformed();
        }

        const uint8_t* p = rem.data();
        const uint8_t* const end = p + rem.size();
        for (unsigned i = 2; i < 16; ++i) {
            if (p == end) [[unlikely]] {
                return malformed();
            }
            const uint8_t b0 = *p;
            if (b0 == 0xa0) {
                if (end - p < 33) [[unlikely]] {
                    return malformed();
                }
                note(0xa0, p + 1, 32);
                if (i == nib) {
                    child_at = p + 1;
                    clen = 32;
                }
                p += 33;
            } else if (b0 == rlp::kEmptyStringCode) {
                ++p;  
            } else if (b0 >= 0xc0 && b0 <= 0xf7) {
                const size_t pl = static_cast<size_t>(b0 - 0xc0);
                if (pl > 31) [[unlikely]] {
                    return malformed();
                }
                if (static_cast<size_t>(end - p) < 1 + pl) [[unlikely]] {
                    return malformed();
                }
                note(b0, p + 1, static_cast<uint8_t>(pl + 1));
                if (i == nib) {
                    dst[0] = b0;
                    std::copy_n(p + 1, pl, dst + 1);
                    child_at = dst;
                    clen = static_cast<uint8_t>(pl + 1);
                }
                p += 1 + pl;
            } else {
                return malformed();  
            }
        }
// fixed-key tries end at leaves
        if (static_cast<size_t>(end - p) != 1 || *p != rlp::kEmptyStringCode) [[unlikely]] {
            return malformed();
        }
        if (pend != nullptr && n_children == 1) [[unlikely]] {
            Bytes cell(fc_len, 0);
            if (fc_start == 0xa0) {
                std::memcpy(cell.data(), fc_p, 32);
            } else {
                cell[0] = fc_start;
                std::memcpy(cell.data() + 1, fc_p, fc_len - 1);
            }
            pend->push_back(RoFoldEntry{consumed, std::move(cell)});
        }

        if (probe) [[unlikely]] {
            return true;
        }

        ++consumed;
        if (clen == 0 || (clen == 1 && child_at[0] == rlp::kEmptyStringCode)) {
            return claims_absent(*u);  
        }
        if (clen == 32) {
            bytes32 h;
            std::memcpy(h.bytes, child_at, 32);
            const auto next = state_->find_node_rlp(h);
            if (!next) [[unlikely]] {
                ++missing_count_;
                failed_ = true;
                sys_println("ERROR: missing hash ref in node store (witness incomplete)");
                return false;
            }
            node = *next;
        } else {
            if (!ro_child_shape(ByteView{child_at, clen})) [[unlikely]] {
                failed_ = true;
                sys_println("ERROR: malformed branch child rlp in node store");
                return false;
            }
            node = ByteView{child_at, clen};  // inside embed[phase]
            phase ^= 1;
        }
        from_ext = false;
    }
}

template <bool DeletionEnabled, class StateT>
template <typename It>
[[gnu::noinline]] bytes32 GridMPT<DeletionEnabled, StateT>::calc_root_read_only_impl(It updates_it,
                                                                                      const It updates_end) {
    if (prev_root_ == kEmptyRoot) {
        for (; updates_it != updates_end; ++updates_it) {
            if (!claims_absent(deref_update(*updates_it))) {
                return {};
            }
        }
        return kEmptyRoot;
    }
    const auto root = state_->find_node_rlp(prev_root_);
    if (!root) [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"no_rlp\"}");
        return {};
    }
    std::vector<RoFoldEntry> pend;
    const auto drain = [&](int lcp) {
        std::erase_if(pend, [&](const RoFoldEntry& e) {
            if (lcp >= 0 && static_cast<int>(e.depth) <= lcp) {
                return false;
            }
            if (e.cell.size() == 32) {
                bytes32 h;
                std::memcpy(h.bytes, e.cell.data(), 32);
                const auto r = state_->find_node_rlp(h);
                if (!r) [[unlikely]] {
                    ++missing_count_;
                    failed_ = true;
                    sys_println("Error: fold_line unexpected error unfolding non_emtpy_nib");
                } else if (!ro_node_well_formed(*r, e.depth + 1)) [[unlikely]] {
                    failed_ = true;
                    sys_println("Error: fold_line unexpected error unfolding non_emtpy_nib");
                }
            } else if (!ro_node_well_formed(ByteView{e.cell.data(), e.cell.size()}, e.depth + 1)) [[unlikely]] {
                failed_ = true;
                sys_println("Error: fold_line unexpected error unfolding non_emtpy_nib");
            }
            return true;
        });
    };
    if (updates_it == updates_end) {
        if (!ro_descend(nullptr, *root, 0, &pend, false)) {
            return {};
        }
        drain(-1);  // probe pops the root line too
        return prev_root_;
    }
    bytes32 prev_key{};
    bool have_prev = false;
    for (; updates_it != updates_end; ++updates_it) {
        const TrieNodeFlat& u = deref_update(*updates_it);
        if (have_prev) {
            nibbles64 a, b;
            a.assign_bytes32(prev_key);
            b.assign_bytes32(u.key);
            drain(static_cast<int>(lcp_packed(a.w.data(), b.w.data(), 0, 64)));
        }
        if (!ro_descend(&u, *root, 0, &pend, false)) {
            return {};
        }
        prev_key = u.key;
        have_prev = true;
    }
    drain(-1);  // end fold reaches root line too
    return prev_root_;
}

template <bool DeletionEnabled, class StateT>
template <typename It>
bytes32 GridMPT<DeletionEnabled, StateT>::calc_root_impl(It updates_it, const It updates_end) {
    bool ro_reads = false;
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
        if constexpr (state_keeps_prevalue_check<StateT>) {
            if (!snap_ && light_ro_) {
                return calc_root_read_only_impl(updates_it, updates_end);
            }
            if constexpr (DeletionEnabled) {
                if (snap_ && light_ro_) {
                    light_writes_.clear();
                    for (It it = updates_it; it != updates_end; ++it) {
                        const TrieNodeFlat& u = deref_update(*it);
                        if (!u.current_value().empty()) {
                            light_writes_.push_back(&u);
                        }
                    }
                    ro_reads = true;  
                }
            }
        }
        init_from_root(prev_root_, first_slot);
    }
    if (failed_) [[unlikely]] {
        return {};  // the root node could not be read: there is no trie to walk
    }
    // The update search_nibbles_ was last expanded from: the seek compares the keys themselves, and expanding
    // the new key straight into search_nibbles_ skips a zeroed temporary and its copy.
    const TrieNodeFlat* prev = nullptr;
    size_t ro_wi = 0;  
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
            insert_line(0, 0, std::move(l), nullptr);
            continue;
        }

        last_was_delete_ = false;

// clean subtree: no write diverges below
        unsigned ro_limit = 0;
        const bool ro_active = ro_reads && trie_upd.current_value().empty();
        if (ro_active) {
            while (ro_wi < light_writes_.size() && lt_bytes32(light_writes_[ro_wi]->key.bytes, trie_upd.key.bytes)) {
                ++ro_wi;
            }
            if (ro_wi > 0) {
                ro_limit = key_lcp_nibbles(trie_upd, *light_writes_[ro_wi - 1]);
            }
            if (ro_wi < light_writes_.size()) {
                const unsigned l2 = key_lcp_nibbles(trie_upd, *light_writes_[ro_wi]);
                if (l2 > ro_limit) {
                    ro_limit = l2;
                }
            }
        }

        // MAIN LOOP
        // Every step goes down at least one nibble of the key, and only a leaf is reached with all 64 of them
        // consumed (a branch reads the nibble at the cursor). The bound is the key's, not the grid's: depth_ is
        // a line index, and the grid holds up to kMaxLines lines. Leaving the walk here would drop the update
        // unseen, so a node past nibble 63 that is not a leaf fails it.
        while (true) {  // Searching down
            auto& grid_line = grid_[depth_];
            if (!(search_nib_cursor_ < 64 || grid_line.kind == kLeaf)) [[unlikely]] {
                failed_ = true;
                sys_println("{\"err\":\"descent past nibble 63\"}");
                return {};
            }
            if (grid_line.kind == kBranch) {
                unsigned nib = search_nibbles_.at(search_nib_cursor_);
                if (ro_active && ro_limit <= search_nib_cursor_ && grid_line.child_depth[nib] == 0) {
                    const BranchNode& bn = grid_line.branch;
                    const uint8_t clen = bn.child_len[nib];
                    const uint8_t* const cb = bn.child[nib].bytes;
                    if (clen == 0 || (clen == 1 && cb[0] == rlp::kEmptyStringCode)) {
                        if (!claims_absent(trie_upd)) [[unlikely]] {
                            return {};
                        }
                        last_was_delete_ = true;
                        break;
                    }
                    ByteView cell;
                    if (clen == 32) {
                        bytes32 h;
                        std::memcpy(h.bytes, branch_hash_src(bn, nib), 32);
                        const auto r = state_->find_node_rlp(h);
                        if (!r) [[unlikely]] {
                            ++missing_count_;
                            failed_ = true;
                            sys_println("ERROR: missing hash ref in node store (witness incomplete)");
                            return {};
                        }
                        cell = *r;
                    } else {
                        cell = ByteView{cb, clen};
                        if (!ro_child_shape(cell)) [[unlikely]] {
                            failed_ = true;
                            sys_println("ERROR: malformed branch child rlp in node store");
                            return {};
                        }
                    }
                    if (!ro_descend(&trie_upd, cell, static_cast<unsigned>(search_nib_cursor_ + 1), nullptr, false)) [[unlikely]] {
                        return {};
                    }
                    last_was_delete_ = true;
                    break;
                }
                auto unfold_res = unfold_slot(nib, grid_line);
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
                    insert_line(l.parent_slot, static_cast<unsigned>(depth_), std::move(l), &grid_line);
                    grid_.back().modified = true;  // the new leaf, depth_ now names it
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
                const size_t lim = std::min<unsigned>(len, static_cast<unsigned>(64 - search_nib_cursor_));
                unsigned m = static_cast<unsigned>(lcp_packed(grid_line.ext.path.w.data(), search_nibbles_.w.data(),
                                                               search_nib_cursor_, lim));
                search_nib_cursor_ += m;
                unsigned last_nib = grid_line.ext.path.at(len - 1);
                unsigned old_child_depth{grid_line.child_depth[last_nib]};

                if (m == len) {
                    if (ro_active && ro_limit <= search_nib_cursor_ && old_child_depth == 0) {
// malformed ext child must bump (from_ext)
                        ByteView cell;
                        const uint8_t clen = grid_line.ext.child_len;
                        if (clen == 32) {
                            auto rlp_opt = state_->find_node_rlp(grid_line.ext.child);
                            if (!rlp_opt) [[unlikely]] {
                                ++missing_count_;
                                failed_ = true;
                                sys_println("ERROR: missing ext child rlp in node store (witness incomplete)");
                                return {};
                            }
                            cell = *rlp_opt;
                        } else {
                            cell = ByteView{grid_line.ext.child.bytes, clen};
                            if (!ro_child_shape(cell)) [[unlikely]] {
                                ++missing_count_;
                                failed_ = true;
                                sys_println("ERROR: malformed ext child rlp in node store");
                                return {};
                            }
                        }
                        if (!ro_descend(&trie_upd, cell, static_cast<unsigned>(search_nib_cursor_), nullptr, true)) [[unlikely]] {
                            return {};
                        }
                        depth_ = grid_line.parent_depth;
                        last_was_delete_ = true;
                        break;
                    }
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
                        if (!unfold_node_from_rlp(rlp, grid_line.ext.path.at(m - 1), static_cast<unsigned>(depth_), &grid_line)) [[unlikely]] {
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
                GridLine* const lines = grid_.data();  // reserved at construction; appends never reallocate
                if (m > 0 || new_ext_len > 0) {
                    d1 = static_cast<unsigned>(depth_ + 1);
                    GridLine* q = lines + d1;
                    while (d1 < grid_n_ && q->parent_depth != 0xFF) {
                        ++d1;
                        ++q;
                    }
                }
                if (new_ext_len > 0 && m > 0) {
                    d2 = d1 + 1;
                    GridLine* q = lines + d2;
                    while (d2 < grid_n_ && q->parent_depth != 0xFF) {
                        ++d2;
                        ++q;
                    }
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
                    grid_line.consumed = static_cast<uint8_t>(grid_line.consumed - 1 - new_ext_len);
                    grid_line.ext.child_len = 1;
                    grid_line.ext.path = grid_line.ext.path.slice(0, m);
                    grid_line.modified = true;
                    const unsigned new_slot = grid_line.ext.path.at(m - 1);
                    insert_line_at(d1, new_slot, static_cast<unsigned>(depth_), BranchNode{}, &grid_line);
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
                auto* br = &grid_[br_depth];  // d1 when m > 0, else grid_line
                if (new_ext_len > 0) {  // (orig_ext) -> new_br -> new_ext -> old_child
                    ExtensionNode ext_mplus1{};
                    ext_mplus1.path = old_ext_line.ext.path.slice(m + 1, new_ext_len);
                    ext_mplus1.set_child(ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                    if (d1 == 0) {  // To check if we need d2 slot
                        d1 = d2;
                    }
                    insert_line_at(d1, old_ext_line.ext.path.at(m), static_cast<unsigned>(depth_), std::move(ext_mplus1), br);
                    grid_[d1].modified = true;
                } else {  // () -> new_br -> old_child
                    br->branch.set_child(last_nib, ByteView{old_ext_line.ext.child.bytes, old_ext_line.ext.child_len});
                }

                if (old_child_depth != 0) {
                    auto& par = grid_[depth_];
                    auto* och = &grid_[old_child_depth];
                    och->parent_depth = static_cast<uint8_t>(depth_);
                    och->parent = &par;
                    par.child_depth[och->parent_slot] = static_cast<uint8_t>(old_child_depth);
                }
                auto l = make_cur_leaf(trie_upd.current_value());
                insert_line(l.parent_slot, static_cast<unsigned>(br_depth), std::move(l), br);
                grid_.back().modified = true;  // the new leaf, depth_ now names it
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
                            delete_leaf(static_cast<unsigned>(depth_));
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
                LeafNode old_leaf{grid_line.leaf};
                BranchNode bn;

                if (!has_room(3)) {  // the branch and both leaves
                    return {};
                }
                if (cp > 0) {  // Need to put an extension before the branch
                    ExtensionNode ext_common{};
                    ext_common.path = grid_line.leaf.path.slice(0, cp);

                    // Make the line an extension and insert a branch with this extension as the parent
                    unsigned ext_last_nib = ext_common.path.at(cp - 1);
                    transform_line(grid_line, std::move(ext_common));
                    search_nib_cursor_ += cp;
                    insert_line(ext_last_nib, static_cast<unsigned>(depth_), std::move(bn), &grid_line);  // sets the depth_ at the branch after
                } else {
                    // Make the line a branch
                    transform_line(grid_line, std::move(bn));
                }
                old_leaf.parent_slot = old_leaf.path.at(cp);  // cp: extension, 1: branch
                old_leaf.path = old_leaf.path.slice(cp + 1, old_leaf.path.len - cp - 1);
                // Insert the leaves to the branch (which is at depth_ now) as parent
                auto parent_depth = depth_;
                auto* br = &grid_[parent_depth];  // grid_line itself when cp == 0
                auto l = make_cur_leaf(trie_upd.current_value());  // sets parent_slot too at l, with first nib
                insert_line(old_leaf.parent_slot, static_cast<unsigned>(parent_depth), std::move(old_leaf), br);
                grid_.back().modified = true;  // the new leaf, depth_ now names it
                insert_line(l.parent_slot, static_cast<unsigned>(parent_depth), std::move(l), br);
                grid_.back().modified = true;
                break;  // insertion complete
            }
        }
    }

    while (grid_n_ > 1) {
        fold_line(static_cast<unsigned>(grid_n_ - 1));
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
        root_unfolded_ = unfold_node_from_rlp(*rlp, 0, 0, nullptr);
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
