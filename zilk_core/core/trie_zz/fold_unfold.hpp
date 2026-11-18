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
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/print.hpp>

#include "mpt.hpp"
#include "rlp_sw.hpp"

namespace zilkworm {

#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
// Copies 32 bytes from any-alignment src to word-aligned dst with aligned loads only; kept out of line.
[[gnu::noinline]] inline void copy32_to_aligned(unsigned char* dst, const uint8_t* src) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    w32* const dw = reinterpret_cast<w32*>(dst);
    const auto a = reinterpret_cast<uintptr_t>(src);
    const w32* const sw = reinterpret_cast<const w32*>(a & ~uintptr_t{3});
    if ((a & 3) == 0) {
#pragma GCC unroll 8
        for (int k = 0; k < 8; ++k) dw[k] = sw[k];
        return;
    }
    const unsigned sh = static_cast<unsigned>(a & 3) * 8;
    uint32_t prev = sw[0];
#pragma GCC unroll 8
    for (int k = 0; k < 8; ++k) {
        const uint32_t nx = sw[k + 1];
        dw[k] = (prev >> sh) | (nx << (32 - sh));
        prev = nx;
    }
}
#endif

namespace rlp = ::silkworm::rlp;

[[gnu::always_inline]] inline rlp::Header fast_decode_header(ByteView& from) noexcept {
    if (from.size() < 8) [[unlikely]] {
        return {false, from.size()};
    }
#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
    // Only bytes 0..3 are read.
    typedef uint32_t __attribute__((may_alias)) w32;
    uint32_t word;
    if ((reinterpret_cast<uintptr_t>(from.data()) & 3) == 0) [[likely]] {
        word = *reinterpret_cast<const w32*>(from.data());
    } else {
        std::memcpy(&word, from.data(), 4);
    }
#else
    uint64_t word;
    std::memcpy(&word, from.data(), 8);
#endif
    uint8_t first = word & 0xFF;

    if (first < 0x80) return {false, 1};

    bool is_list = first >= 0xC0;
    uint8_t offset = first & 0x3Fu;
    // 4..8 length bytes mean a payload of 16 MiB or more; no trie node is that large, so the node is rejected.
    if (offset > 58) [[unlikely]] return {false, 0};

    from.remove_prefix(1);
    if (offset <= 55) return {is_list, offset};

    size_t len_bytes = offset - 55;
    size_t length = ((word >> 8) & 0xFF) << 16 | ((word >> 16) & 0xFF) << 8 | ((word >> 24) & 0xFF);
    length >>= (8 * (3 - len_bytes));
    from.remove_prefix(len_bytes);
    return {is_list, length};
}

// Stateless MPT: updates arrive in key order, so a branch's left subtree is never revisited once left.

template <bool DeletionEnabled, class StateT>
bool GridMPT<DeletionEnabled, StateT>::unfold_node_from_rlp(ByteView payload, unsigned parent_slot_index, unsigned parent_depth) {
    const uint8_t* const node_begin = payload.data();
    auto hh{fast_decode_header(payload)};
    if (!hh.list) [[unlikely]] {
        failed_ = true;
        sys_println(("ERROR: unfold_node_from_rlp Invalid Payload Header, parent_slot_index: "
            + std::to_string(parent_slot_index) 
            + " parent_depth: " + std::to_string(parent_depth)).c_str());
        return false;
    }
    auto list{payload.substr(0, hh.payload_length)};

    bool is_leaf = false;
    uint8_t plen = 0;
    ByteView second{};

    GridLine* line_ptr = emplace_line(kBranch, parent_slot_index, parent_depth, 1u);
    if (!line_ptr) [[unlikely]] return false;
    GridLine& line = *line_ptr;

    // A leaf or extension path is decoded straight into the line; decode_node writes no branch field for those.
    Kind kind = decode_node(list, line.branch, is_leaf, line.leaf.path.nib, plen, second);
    if (kind == kBranch) {
        // Union members are uninitialized: reset the origin fields explicitly.
        line.branch.orig = nullptr;
        line.branch.dirty = 0;
        const auto node_size = static_cast<size_t>(list.data() + list.size() - node_begin);
        if (node_size >= 32 && node_size <= UINT16_MAX) {
            line.branch.orig = node_begin;
            line.branch.orig_size = static_cast<uint16_t>(node_size);
            line.branch.orig_child_len = line.branch.child_len;
        }
        return true;
    }
    if (kind == kInvalid) [[unlikely]] {
        failed_ = true;
        pop_back();
        return false;
    }
    const unsigned parent_consumed = line.consumed - 1u;
    // Keys are 64 nibbles: a leaf path must end the key, an extension must leave one nibble (else a length wraps).
    if (is_leaf ? parent_consumed + plen != 64 : (plen == 0 || parent_consumed + plen > 63)) [[unlikely]] {
        failed_ = true;
        pop_back();
        return false;
    }
    line.leaf.path.len = plen;
    if (is_leaf) {
        line.leaf.parent_slot = static_cast<uint8_t>(parent_slot_index);
        line.leaf.value = second;
        line.consumed = static_cast<uint8_t>(parent_consumed);
        line.kind = kLeaf;
    } else {
        // Reject an oversized child that would overflow child (a 32-byte bytes32).
        if (second.size() > sizeof(line.ext.child.bytes)) {
            failed_ = true;
            pop_back();
            return false;
        }
        std::copy(second.cbegin(), second.cend(), line.ext.child.bytes);
        line.ext.child_len = static_cast<uint8_t>(second.size());
        line.consumed = static_cast<uint8_t>(plen + parent_consumed);
        line.kind = kExt;
    }
    return true;
}

// Use only if grid_.back() has the current parent.
template <bool DeletionEnabled, class StateT>
void GridMPT<DeletionEnabled, StateT>::delete_leaf(unsigned depth) {
    if (depth > 0) {
        GridLine& grid_line = grid_[depth];
        GridLine& parent = grid_[grid_line.parent_depth];
        unsigned parent_slot = grid_line.parent_slot;
        parent.branch.delete_child(parent_slot);
        parent.child_depth[parent_slot] = 0;

        if (depth != grid_.size() - 1 && grid_.back().parent_depth == grid_line.parent_depth) {
            grid_line = grid_.back();  // TODO: Use smaller copy for leaf
            parent.child_depth[grid_line.parent_slot] = depth;
            depth = grid_.size() - 1;
        }
    }
    delete_line(depth);
}

template <bool DeletionEnabled, class StateT>
void GridMPT<DeletionEnabled, StateT>::pop_back() {
    grid_.pop_back();
    depth_ = grid_.size() - 1;
}

// Soft delete a line in the middle, hard-delete from the end
template <bool DeletionEnabled, class StateT>
inline void GridMPT<DeletionEnabled, StateT>::delete_line(unsigned depth) {
    if (depth == grid_.size() - 1) {
        grid_.pop_back();
    } else {
        grid_[depth].parent_depth = 0xff;
    }
}
template <bool DeletionEnabled, class StateT>
inline unsigned GridMPT<DeletionEnabled, StateT>::cascade_delete(unsigned depth) {
    while (is_empty(grid_[depth])) {
        auto& grid_line = grid_[depth];
        if (grid_.size() > 1 && depth > 0) {
            auto parent_depth = grid_line.parent_depth;
            auto& parent = grid_[parent_depth];
            switch (parent.kind) {
                case kBranch:
                    parent.branch.delete_child(grid_line.parent_slot);
                    parent.child_depth[grid_line.parent_slot] = 0;
                    parent.modified = true;
                    break;
                case kExt:
                    parent.ext.delete_child();
                    parent.child_depth[grid_line.parent_slot] = 0;
                    parent.modified = true;
                    break;
                default:
                    std::unreachable();
            }
            delete_line(depth);
            depth = parent_depth;
        } else {
            // An empty root has no line below it: drop the deleted lines above it too.
            grid_.clear();
            return 0;
        }
    }
    return depth;
}

template <bool DeletionEnabled, class StateT>
inline void GridMPT<DeletionEnabled, StateT>::fold_line(unsigned depth) {
    auto& grid_line = grid_[depth];
    if (grid_line.parent_depth == 0xFF) {
        // A middle line stays until it is last: popping would take a live line from the end.
        if (depth == grid_.size() - 1) {
            grid_.pop_back();
        }
        return;
    }
    if constexpr (DeletionEnabled) {
        if (is_empty(grid_line)) {
            cascade_delete(depth);
            return;
        }
        if (grid_line.kind == kBranch && grid_line.branch.has_single_child()) {
            unsigned non_empty_nib = grid_line.branch.first_set_bit();
            depth_ = depth;
            ExtensionNode ext{nibbles64{1, {static_cast<uint8_t>(non_empty_nib)}}};
            // TODO optimize by checking it's a branch or not
            if (unfold_slot(non_empty_nib) != UnfoldResult::kSuccess) {  // Needed because if it's a leaf this will get extended.
                failed_ = true;
                sys_println("Error: fold_line unexpected error unfolding non_emtpy_nib");
            } else if (grid_.back().kind == kBranch) {
                if (grid_.back().branch.child_count() < 2) [[unlikely]] {  // no read walked this sibling
                    failed_ = true;
                    sys_println("Error: fold_line collapse onto a branch with fewer than two children");
                }
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
                // The extension folds into the parent now; merging later would use the parent's stale reference.
            } else {
                transform_line(grid_line, std::move(ext));

                fold_line(grid_line.child_depth[non_empty_nib]);
                // An empty child (witness leaf without a value) takes every line it leaves empty with it.
                if (depth >= grid_.size() || grid_line.parent_depth == 0xFF) {
                    return;
                }
            }
        }

        if (grid_.size() > 1) {
            GridLine& parent = grid_[grid_line.parent_depth];

            // Applies the parent's single-child branch -> ext transformation here, avoiding a second unfold.
            if (parent.kind == kBranch && parent.branch.has_single_child()) {
                unsigned kept_nib = parent.branch.first_set_bit();
                ExtensionNode ext{nibbles64{1, {static_cast<uint8_t>(kept_nib)}}};
                auto clen = parent.branch.child_len[kept_nib];
                const uint8_t* src = (clen == 32 && parent.branch.child_ptr[kept_nib])
                                         ? parent.branch.child_ptr[kept_nib]
                                         : parent.branch.child[kept_nib].bytes;
                ext.set_child(ByteView{src, clen});
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
    // The root has no parent to take its reference: calc_root_from_updates() encodes and hashes it.
    if (grid_.size() <= 1) {
        return;
    }

    const unsigned slot = grid_line.parent_slot;
    auto& parent = grid_[grid_line.parent_depth];
    parent.modified = true;
    parent.child_depth[slot] = 0;
    // A full branch differing from its witness node only in hash refs is hashed from the node, resuming saved state.
    if (grid_line.kind == kBranch && hashes_from_witness(grid_line.branch)) {
        const kprefix::Resume r = take_resume_full(grid_line.branch, depth & (kprefix::kRows - 1));
        switch (parent.kind) {
            case kBranch:
                parent.branch.set_child_hash_of(slot, grid_line.branch, r.state, r.blocks);
                break;
            case kExt:
                parent.ext.set_child_hash_of(grid_line.branch, r.state, r.blocks);
                break;
            default:
                std::unreachable();
        }
        delete_line(depth);
        return;
    }
    // A patched copy of its witness node resumes from a state of the blocks before its first dirty slot.
    const kprefix::Resume r = grid_line.kind == kBranch ? take_resume_encoded(grid_line.branch, depth & (kprefix::kRows - 1))
                                                        : kprefix::Resume{nullptr, 0};
    const ByteView encoded = encode_line(grid_line);
    // The line goes before its reference is written to the parent: its encoding stays in static_buffer.
    delete_line(depth);
    switch (parent.kind) {
        case kBranch:
            if (encoded.size() >= 32) {
                parent.branch.set_child_hash(slot, encoded, r);
            } else {
                parent.branch.set_child(slot, encoded);
            }
            break;
        case kExt:
            if (encoded.size() >= 32) {
                parent.ext.set_child_hash(encoded, r);
            } else {
                parent.ext.set_child(encoded);
            }
            break;
        default:
            std::unreachable();
    }
}

// Saved keccak state for full branch b in pool row `row` covering no dirty slot; {.., 0} if none.
template <bool DeletionEnabled, class StateT>
[[gnu::always_inline]] inline kprefix::Resume GridMPT<DeletionEnabled, StateT>::take_resume_full(const BranchNode& b, size_t row) {
    if (const unsigned blocks = take_resumable_blocks(b, row); blocks != 0) return {kprefix::pool[row], blocks};
#if USE_HASH_KEY
    return state_->take_walk_state(b.orig, full_branch_clean_blocks(b));
#else
    return {nullptr, 0};
#endif
}

// Saved state for a patched-copy branch b covering no byte of a dirty slot; {nullptr, 0} if none.
template <bool DeletionEnabled, class StateT>
inline kprefix::Resume GridMPT<DeletionEnabled, StateT>::take_resume_encoded(const BranchNode& b, size_t row) {
    if (b.mask == 0 || b.orig == nullptr || (reinterpret_cast<uintptr_t>(b.orig) & 7) != 0 ||
        b.orig_size < kprefix::kBlock || !b.same_layout_as_orig()) {
        return {nullptr, 0};
    }
    const unsigned allowed = same_layout_clean_blocks(b);
    if (allowed == 0) return {nullptr, 0};
    if (kprefix::tag_orig[row] == b.orig) {
        const unsigned blocks = kprefix::tag_sb[row];
        if (blocks == 0 || blocks > allowed) return {nullptr, 0};
        kprefix::tag_orig[row] = nullptr;
        return {kprefix::pool[row], blocks};
    }
#if USE_HASH_KEY
    return state_->take_walk_state(b.orig, allowed);
#else
    return {nullptr, 0};
#endif
}

template <bool DeletionEnabled, class StateT>
inline LeafNode GridMPT<DeletionEnabled, StateT>::make_cur_leaf(ByteView value_rlp) {
    LeafNode l{};
    l.parent_slot = search_nibbles_[search_nib_cursor_];
    l.path.len = 64 - (search_nib_cursor_ + 1);
    std::memcpy(l.path.nib.data(),
                search_nibbles_.nib.data() + search_nib_cursor_ + 1,
                l.path.len);
    l.value = value_rlp;
    return l;
}

// Displaces the subtree chain at from_depth by cascading swaps; frees from_depth, returns the node's new depth.
template <bool DeletionEnabled, class StateT>
unsigned GridMPT<DeletionEnabled, StateT>::move_line(unsigned from_depth) {
    GridLine cache{grid_[from_depth]};
    grid_[from_depth].parent_depth = 0xFF;

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

template <bool DeletionEnabled, class StateT>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled, StateT>::insert_line(unsigned parent_slot, unsigned parent_depth, NodeType&& node) {
    Kind kind;
    unsigned consumed;
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        kind = kLeaf;
        consumed = 0u;
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        kind = kExt;
        consumed = node.path.len;  // read before the move below
    } else {
        kind = kBranch;
        consumed = 1u;
    }
    GridLine* l = emplace_line(kind, parent_slot, parent_depth, consumed);
    if (!l) return false;  // parent_slot out of range
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        l->leaf = std::forward<NodeType>(node);
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        l->ext = std::forward<NodeType>(node);
    } else {
        l->branch = std::forward<NodeType>(node);
    }
    return true;
}

template <bool DeletionEnabled, class StateT>
inline void GridMPT<DeletionEnabled, StateT>::link_to_parent(GridLine& line, unsigned depth, unsigned parent_slot, unsigned parent_depth) {
    if (depth > 0) {
        auto& parent = grid_[parent_depth];
        line.consumed += parent.consumed;
        parent.child_depth[parent_slot] = static_cast<uint8_t>(depth);
        if (parent.kind == kBranch && parent.branch.child_len[parent_slot] == 0) {
            parent.branch.mask |= 1 << parent_slot;
            parent.branch.child_len[parent_slot] = 1;  // Placeholder, update during fold_line
            parent.branch.dirty |= static_cast<uint16_t>(1u << parent_slot);
        }
        if (parent.kind == kExt && parent.ext.child_len == 0) {
            parent.ext.child_len = 1;  // Placeholder, update during fold_line
        }
    }
}

template <bool DeletionEnabled, class StateT>
inline GridLine* GridMPT<DeletionEnabled, StateT>::emplace_line(Kind kind, unsigned parent_slot, unsigned parent_depth, unsigned consumed_init) {
    if (parent_slot >= 16) {
        failed_ = true;
        return nullptr;
    }
    // The grid never outgrows its allocation (kMaxLines).
    if (grid_.size() >= kMaxLines) [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"grid full\"}");
        return nullptr;
    }
    grid_.emplace_back(kind, parent_slot, parent_depth, consumed_init);
    depth_ = grid_.size() - 1;
    if (depth_ > 0) link_to_parent(grid_.back(), depth_, parent_slot, parent_depth);
    return &grid_.back();
}

template <bool DeletionEnabled, class StateT>
inline bool GridMPT<DeletionEnabled, StateT>::has_room(unsigned lines) {
    if (grid_.size() + lines <= kMaxLines) [[likely]] {
        return true;
    }
    failed_ = true;
    sys_println("{\"err\":\"grid full\"}");
    return false;
}

template <bool DeletionEnabled, class StateT>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled, StateT>::insert_line_at(unsigned target_depth, unsigned parent_slot, unsigned parent_depth, NodeType&& node) {
    if (parent_slot >= 16) {
        failed_ = true;
        return false;
    }

    if (target_depth == grid_.size()) {
        return insert_line(parent_slot, parent_depth, std::forward<NodeType>(node));
    }

    auto& line = grid_[target_depth];
    if constexpr (std::is_same_v<std::decay_t<NodeType>, LeafNode>) {
        line = GridLine(kLeaf, parent_slot, parent_depth, 0u);
        line.leaf = std::forward<NodeType>(node);
    } else if constexpr (std::is_same_v<std::decay_t<NodeType>, ExtensionNode>) {
        line = GridLine(kExt, parent_slot, parent_depth, node.path.len);
        line.ext = std::forward<NodeType>(node);
    } else {
        line = GridLine(kBranch, parent_slot, parent_depth, 1u);
        line.branch = std::forward<NodeType>(node);
    }
    depth_ = target_depth;
    link_to_parent(line, target_depth, parent_slot, parent_depth);
    return true;
}

template <bool DeletionEnabled, class StateT>
template <typename NodeType>
inline bool GridMPT<DeletionEnabled, StateT>::transform_line(GridLine& line, NodeType&& node) {
    unsigned parent_consumed = line.consumed;
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
            failed_ = true;
            sys_println("{\"err\":\"cast_overflow\"}");
        }
    } else {
        kind = kBranch;
        consumed = 1;
        line.branch = std::move(node);
        if (consumed + parent_consumed > 255) {
            failed_ = true;
            sys_println("{\"err\":\"cast_overflow\"}");
        }
    }
    line.consumed = static_cast<uint8_t>(consumed + parent_consumed);
    line.kind = kind;
    return true;
}

// kEmpty: empty slot; kMissing: hash ref absent from the node store (incomplete witness, caller hard-fails).
template <bool DeletionEnabled, class StateT>
inline UnfoldResult GridMPT<DeletionEnabled, StateT>::unfold_slot(unsigned slot) {
    if (slot > 15) [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"slot > 15\"}");
        return UnfoldResult::kUndefined;
    }
    if (depth_ >= grid_.size()) [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"depth >= grid_size\"}");
        return UnfoldResult::kUndefined;
    }
    if (grid_[depth_].kind != kBranch)  [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"unfold_not_branch\"}");
        return UnfoldResult::kUndefined;
    }

    auto& grid_line = grid_[depth_];
    if (auto s = grid_line.child_depth[slot]; s) {
        if (s >= grid_.size()) [[unlikely]] {
            failed_ = true;
            sys_println("{\"err\":\"child_depth past the grid\"}");
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
        alignas(8) uint8_t ck[32];
        const uint8_t* hs = grid_line.branch.child_ptr[slot] ? grid_line.branch.child_ptr[slot] : child.bytes;
#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
        copy32_to_aligned(ck, hs);
#else
        std::memcpy(ck, hs, 32);
#endif
        auto rlp_opt = state_->find_node_rlp(ck, [this]() noexcept {
            return kprefix::SnapRequest{snap_ && search_nib_cursor_ < 63 ? search_nibbles_[search_nib_cursor_ + 1]
                                                                         : kprefix::kNoSlot,
                                        grid_.size() & (kprefix::kRows - 1)};
        });
        if (!rlp_opt) [[unlikely]] {
            ++missing_count_;
            failed_ = true;
            sys_println("{\"err\":\"node_store_get_rlp_failed\"}");
            return UnfoldResult::kMissing;
        }
        if (rlp_opt->size() < 32) [[unlikely]] {  // a node under 32 bytes is embedded, never hashed
            failed_ = true;
            sys_println("{\"err\":\"hash ref to a node short enough to embed\"}");
            return UnfoldResult::kUndefined;
        }
        rlp = *rlp_opt;
    } else {
        // Must move this outside of this object
        embedded_rlp_copies_.emplace_back(child);
        rlp = ByteView{embedded_rlp_copies_.back().bytes, child_len};
    }
    if (rlp.size() == 0) [[unlikely]] {
        failed_ = true;
        sys_println("{\"err\":\"rlp_size_0\"}");
        return UnfoldResult::kMissing;
    }
    bool success = unfold_node_from_rlp(rlp, slot, depth_);
    if (success)
        grid_line.child_depth[slot] = depth_;
    else
        failed_ = true;
    return success ? UnfoldResult::kSuccess : UnfoldResult::kMissing;
}

}  // namespace zilkworm
