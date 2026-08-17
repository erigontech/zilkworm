// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash_state.hpp"

#include <array>
#include <bit>
#include <cstring>
#include <utility>
#include <vector>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>  // silkworm::kEmptyRoot
#include <zilk_core/core/common/util.hpp>           // silkworm::keccak256(ByteView)
#include <zilk_core/core/rlp/decode.hpp>            // rlp::decode_header (free helper)
#include <zilk_core/core/types_zz/account.hpp>      // Account, decode_trie_account

// The standalone DFS mirrors the DECODE logic of GridMPT::unfold_node_from_rlp
// (fold_unfold.hpp:64) but calls no GridMPT method. It reuses the shared node types
// (BranchNode / LeafNode / nibbles64 / Kind) and the FREE single-pass node decoder
// decode_node (rlp_sw.hpp:315), which itself drives hp_decode (rlp_sw.hpp:62) and the
// branch-child iteration (fill_branch_child* rlp_sw.hpp:189,215).
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm {

HashState::HashState(std::uint32_t expected_nodes, std::uint32_t expected_codes,
                     std::uint32_t expected_accounts, std::uint32_t expected_storage_slots)
    : node_index_{expected_nodes},
      code_index_{expected_codes},
      account_index_{expected_accounts},
      storage_index_{expected_storage_slots} {
    // Front-pad all arenas so the first real entry offset is >= 8 and can never
    // equal HashIndex's empty-bucket sentinel (offset 0). std::vector<uint8_t> data is
    // max_align_t-aligned, and every account entry is a whole Account (256 B, a multiple
    // of 8) starting at offset 8, so each stays 8-aligned for the reinterpret_cast. The
    // storage arena stores bare 32-byte words (32 is a multiple of 8) from offset 8, so
    // those stay 8-aligned too.
    node_arena_.resize(8, 0);
    code_arena_.resize(8, 0);
    accounts_arena_.resize(8, 0);
    storage_arena_.resize(8, 0);
}

namespace {

// Inverse of nibbles64::from_bytes32 (mpt.hpp:50): pack a full 64-nibble path back into
// its 32-byte key. A well-formed account/storage leaf always accumulates exactly 64
// nibbles (fixed-length keys), so p.len == 64 here.
[[gnu::always_inline]] inline evmc::bytes32 path_to_bytes32(const nibbles64& p) noexcept {
    evmc::bytes32 out{};
    for (unsigned i = 0; i < 32; ++i) {
        out.bytes[i] = static_cast<std::uint8_t>((p.nib[2 * i] << 4) | (p.nib[2 * i + 1] & 0x0F));
    }
    return out;
}

}  // namespace

const Account* HashState::emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value) {
    ++leaf_count_;  // a leaf was reached, whether or not its value decodes as an account

    Account acc{};  // value-init: addr/deleted/slot_count/code_store_*/rlp cache all zero
    if (!decode_trie_account(leaf_value, acc)) {
        // Not an account-shaped leaf (e.g. a small embedded non-account leaf in a test
        // fixture, or a malformed witness). Do not cache; leave it observable via the
        // leaf_count_/account_count() gap. The account sweep never crashes on a leaf.
        return nullptr;
    }

    // Append the decoded Account POD to the arena (offset stays 8-aligned) and index it
    // by addr_hash. A duplicate addr_hash overwrites the offset (last write wins) but the
    // arena is append-only, matching add_node's dedupe-by-content spirit loosely enough
    // for a witness-derived, collision-free key set.
    const std::uint32_t off = static_cast<std::uint32_t>(accounts_arena_.size());
    accounts_arena_.resize(accounts_arena_.size() + sizeof(Account));
    std::memcpy(accounts_arena_.data() + off, &acc, sizeof(Account));
    account_index_.insert(addr_hash.bytes, off);
    return reinterpret_cast<const Account*>(accounts_arena_.data() + off);
}

void HashState::emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                           ByteView leaf_value) {
    ++storage_slot_count_;  // a storage leaf was reached

    // The trie leaf value is rlp::encode(zeroless_view(word)) — an RLP string whose payload
    // is the big-endian word with leading zeros trimmed (0..32 bytes). Peel that one string
    // header; decode_header advances `v` to the payload, exactly as decode_trie_account peels
    // the account list header. A single small byte (< 0x80) is its own payload (no header),
    // which decode_header reports as payload_length 1 without advancing — handled uniformly.
    ByteView v = leaf_value;
    auto h = rlp::decode_header(v);
    if (!h || h->list || h->payload_length > 32) return;  // not a <=32-byte string: skip
    evmc::bytes32 word{};
    if (h->payload_length) {
        std::memcpy(word.bytes + (32u - h->payload_length), v.data(), h->payload_length);
    }

    // Append the 32-byte word (offset stays 8-aligned) and index it by addr_hash||slot_hash.
    const std::uint32_t off = static_cast<std::uint32_t>(storage_arena_.size());
    storage_arena_.resize(storage_arena_.size() + sizeof(word));
    std::memcpy(storage_arena_.data() + off, word.bytes, sizeof(word));

    std::uint8_t key[64];
    std::memcpy(key, account_key.bytes, 32);
    std::memcpy(key + 32, slot_hash.bytes, 32);
    storage_index_.insert(key, off);
}

// One frame of the explicit DFS stack. A frame is only ever a BRANCH — the sole node
// kind that must be revisited (it fans out to <=16 children). Extensions and leaves are
// consumed inline in descend_() as the sweep walks down, so they never occupy a frame.
namespace {
struct DeriveFrame {
    BranchNode branch;    // the decoded branch at this position
    nibbles64 path;       // nibble path from the root down to (not including) this branch's children
    std::uint8_t next_slot;  // next child slot (0..15) to visit, left to right
};
}  // namespace

template <class EmitLeaf>
bool HashState::sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf) {
    // Look up the seeding root by hash. Absence is REPORTED to the caller (return false),
    // never counted here: derive_state applies the fail-closed policy per trie kind (an
    // absent account root is fail-closed; an absent storage root is a legitimate omission).
    auto root_rlp = find_node_rlp(root);
    if (!root_rlp) return false;

    // Explicit stack, sized past the 64-nibble max trie depth so it never reallocates
    // during a well-formed sweep. That keeps every DeriveFrame (and the ByteViews into a
    // frame's embedded child bytes) stable across a push in descend().
    std::vector<DeriveFrame> stack;
    stack.reserve(128);

    // Chase down from a node's RLP at `path`: strip the outer list header, decode it,
    // then either push a branch frame, fold an extension's path in and descend into its
    // one child, or reach a leaf and hand it to emit_leaf. Written as a loop (not
    // recursion) so an extension chain never grows the C++ call stack. Mirrors
    // unfold_node_from_rlp: outer-header strip + decode_node, then the branch / ext / leaf
    // split. The leaf's meaning (account vs storage slot) is entirely the caller's emit —
    // the traversal is identical for both.
    const auto descend = [&](ByteView node_rlp, nibbles64 path) {
        while (true) {
            // Strip the outer list header. rlp::decode_header (the size-safe free helper
            // decode_node itself uses) is used rather than fold_unfold's fast_decode_header
            // because the sweep must also decode <8-byte embedded nodes, which the >=8-byte
            // fast path mis-reads.
            auto oh = rlp::decode_header(node_rlp);
            if (!oh || !oh->list) return;  // malformed node — not a list
            const ByteView list = node_rlp.substr(0, oh->payload_length);

            BranchNode branch;
            bool is_leaf = false;
            std::array<std::uint8_t, 64> np{};
            std::uint8_t plen = 0;
            ByteView second{};
            const Kind kind = decode_node(list, branch, is_leaf, np, plen, second);
            if (kind == kInvalid) return;
            if (kind == kBranch) {
                // A branch consumes one nibble per child, so a well-formed branch sits at
                // path.len <= 63 (its children land at <= 64). Reject a malformed deeper
                // branch: it has no room for a child nibble (would overflow nibbles64).
                if (path.len >= 64) return;
                stack.push_back(DeriveFrame{std::move(branch), path, 0});
                return;
            }

            // kExtOrLeaf: append this node's own path nibbles, guarding the 64 bound so a
            // malformed over-long path can never overflow nibbles64 (its append assumes it).
            if (static_cast<unsigned>(path.len) + plen > 64) return;
            path.append(nibbles64{plen, np});

            if (is_leaf) {
                emit_leaf(path_to_bytes32(path), second);
                return;
            }

            // Extension: descend into its single child. decode_node returns `second` as
            // the raw 32-byte hash for a hash ref, or the full inline RLP for an embedded
            // (<32-byte) child — the exact distinction unfold_node_from_rlp draws.
            if (second.size() == 32) {
                evmc::bytes32 h;
                std::memcpy(h.bytes, second.data(), 32);
                auto child = find_node_rlp(h);
                if (!child) {  // dangling ext-child ref — record, do not silently skip
                    ++missing_count_;
                    return;
                }
                node_rlp = *child;
                continue;  // decode the fetched child in place
            }
            node_rlp = second;  // embedded inline child: decode directly, no store lookup
        }
    };

    descend(*root_rlp, nibbles64{});  // seed: push the root (or emit it if the root is a leaf)

    while (!stack.empty()) {
        const std::size_t top = stack.size() - 1;

        // Advance to the next present child slot, left to right. child_len == 0 is an
        // empty slot (decode_node leaves it so; mpt.hpp branch slots 0..15).
        unsigned s = stack[top].next_slot;
        while (s < 16 && stack[top].branch.child_len[s] == 0) ++s;
        if (s >= 16) {
            // No child left (slot 16, the branch value, is never populated for a
            // fixed-32-byte-key account/storage trie — every key ends at a leaf). Subtree
            // done: fold back to the parent.
            stack.pop_back();
            continue;
        }
        stack[top].next_slot = static_cast<std::uint8_t>(s + 1);

        // Path to this child = the branch's path + the child's nibble s.
        nibbles64 child_path = stack[top].path;
        child_path.nib[child_path.len++] = static_cast<std::uint8_t>(s);

        const std::uint8_t clen = stack[top].branch.child_len[s];
        if (clen == 32) {
            // 32-byte hash ref: read the hash (child_ptr into the node RLP, or the inline
            // child.bytes — exactly unfold_slot's source pick, fold_unfold.hpp:524) and
            // resolve it through the store.
            evmc::bytes32 h;
            const std::uint8_t* hsrc = stack[top].branch.child_ptr[s]
                                           ? stack[top].branch.child_ptr[s]
                                           : stack[top].branch.child[s].bytes;
            std::memcpy(h.bytes, hsrc, 32);
            auto child = find_node_rlp(h);
            if (!child) {  // dangling child ref — witness incomplete, surface it
                ++missing_count_;
                continue;
            }
            descend(*child, child_path);
        } else {
            // Embedded (<32-byte) inline child: its RLP lives in the parent's child bytes
            // (copied there by decode_node); decode it directly, no store lookup.
            descend(ByteView{stack[top].branch.child[s].bytes, clen}, child_path);
        }
    }

    return true;
}

HashState::DeriveStatus HashState::derive_state(const evmc::bytes32& prev_root) {
    missing_count_ = 0;
    leaf_count_ = 0;
    storage_slot_count_ = 0;

    // (addr_hash, storage_root) for every derived account carrying a non-empty storage
    // trie, captured during the account pass so the storage passes can run once it ends.
    // storage_root is copied out immediately: the Account* emit_account_ returns is only
    // valid until the next emit grows the accounts arena.
    std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage_roots;

    // --- account pass ---
    // Empty account trie derives nothing, cleanly (design §2.6): no root to fetch.
    if (prev_root != silkworm::kEmptyRoot) {
        const bool root_present =
            sweep(prev_root, [&](const evmc::bytes32& addr_hash, ByteView leaf_value) {
                if (const Account* acc = emit_account_(addr_hash, leaf_value)) {
                    evmc::bytes32 sroot;
                    std::memcpy(sroot.bytes, acc->storage_root, 32);
                    if (sroot != silkworm::kEmptyRoot)
                        storage_roots.emplace_back(addr_hash, sroot);
                }
            });
        // A missing ACCOUNT root is the B2 fail-closed case — the anchor of everything.
        if (!root_present) ++missing_count_;
    }

    // --- storage passes ---
    // One sibling sweep per derived account, rooted at its storage_root. An absent storage
    // root is NOT fail-closed: a witness legitimately omits the storage trie of an account
    // the block never touches, so sweep() == false is skipped, not counted. A dangling ref
    // reached WHILE walking an included storage trie still bumps missing_count_ (inside
    // sweep), accumulating with the account pass.
    for (const auto& pr : storage_roots) {
        const evmc::bytes32 account_key = pr.first;
        const evmc::bytes32 sroot = pr.second;
        sweep(sroot, [this, account_key](const evmc::bytes32& slot_hash, ByteView leaf_value) {
            emit_slot_(account_key, slot_hash, leaf_value);
        });
    }

    return missing_count_ > 0 ? DeriveStatus::kMissingNode : DeriveStatus::kOk;
}

evmc::bytes32 HashState::add_node(ByteView rlp) {
    // Identity binding: the index key IS the real keccak256 of the bytes (matches the
    // direct_state.cpp:417-418 idiom exactly).
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(rlp));
    if (node_index_.find(h.bytes)) return h;  // dedupe: already stored, no re-append

    const std::uint32_t off = static_cast<std::uint32_t>(node_arena_.size());
    const std::uint32_t len = static_cast<std::uint32_t>(rlp.size());
    node_arena_.resize(node_arena_.size() + sizeof(len) + rlp.size());
    std::memcpy(node_arena_.data() + off, &len, sizeof(len));
    std::memcpy(node_arena_.data() + off + sizeof(len), rlp.data(), rlp.size());
    node_index_.insert(h.bytes, off);
    return h;
}

evmc::bytes32 HashState::add_code(ByteView code) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    if (code_index_.find(h.bytes)) return h;  // dedupe

    const std::uint32_t off = static_cast<std::uint32_t>(code_arena_.size());
    const std::uint32_t len = static_cast<std::uint32_t>(code.size());
    code_arena_.resize(code_arena_.size() + sizeof(len) + code.size());
    std::memcpy(code_arena_.data() + off, &len, sizeof(len));
    std::memcpy(code_arena_.data() + off + sizeof(len), code.data(), code.size());
    code_index_.insert(h.bytes, off);
    return h;
}

}  // namespace zilkworm
