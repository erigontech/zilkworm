// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash_state.hpp"

#include <algorithm>  // std::lower_bound (insert_header / get_block_hash)
#include <array>
#include <bit>
#include <cstring>
#include <utility>
#include <vector>

#include <intx/intx.hpp>

#include <evmone/test/state/state_diff.hpp>         // evmone::state::StateDiff (apply_state_diff)
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>  // silkworm::kEmptyHash / kEmptyRoot
#include <zilk_core/core/common/util.hpp>           // silkworm::keccak256(ByteView)
#include <zilk_core/core/rlp/decode.hpp>            // rlp::decode_header (free helper)
#include <zilk_core/core/types/transaction.hpp>     // silkworm::eip7702::is_code_delegated
#include <zilk_core/core/types_zz/account.hpp>      // Account, decode_trie_account

// The standalone DFS mirrors the DECODE logic of GridMPT::unfold_node_from_rlp
// (fold_unfold.hpp:64) but calls no GridMPT method. The sweep classifies a node by its
// item extents (exactly two items: extension or leaf; more: branch, the rule decode_node
// applies), decodes an extension's or leaf's two items with the size-safe rlp::decode_header
// and an inline HP decode (the grammar of hp_decode, rlp_sw.hpp), and reads a branch's
// children one at a time with the three-case grammar of fill_branch_child_rlp. The
// confirmation walk reads the same grammar the same way, but only along one path: at a
// branch it skips to the target's child slot with that child grammar and reads nothing
// past it, and at an extension or leaf it compares the HP-encoded path nibbles in place
// against the target key. Neither decodes a whole node (no BranchNode, no decode_node).
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm {

HashState::HashState(std::uint32_t expected_nodes, std::uint32_t expected_codes,
                     std::uint32_t expected_accounts, std::uint32_t expected_storage_slots)
    : node_index_{expected_nodes},
      code_index_{expected_codes},
      account_index_{expected_accounts},
      storage_index_{expected_storage_slots} {
    // Front-pad both arenas so the first real entry offset is >= 8 and can never
    // equal HashIndex's empty-bucket sentinel (offset 0). std::vector<uint8_t> data is
    // max_align_t-aligned, and every account entry is a whole Account (256 B, a multiple
    // of 8) starting at offset 8, so each stays 8-aligned for the reinterpret_cast. The
    // storage arena stores bare 32-byte words (32 is a multiple of 8) from offset 8, so
    // those stay 8-aligned too.
    accounts_arena_.resize(8, 0);
    storage_arena_.resize(8, 0);
    // One frame per branch on the deepest well-formed path (64 nibbles), with headroom.
    sweep_stack_.reserve(80);
}

void HashState::reserve_stores(std::uint32_t nodes, std::uint32_t codes,
                               std::uint32_t accounts, std::uint32_t storage_slots) {
    node_index_.reserve(nodes);
    code_index_.reserve(codes);
    account_index_.reserve(accounts);
    storage_index_.reserve(storage_slots);
    // The arenas hold the 8-byte front pad plus one fixed-size entry per cached account
    // (a whole Account) / slot (a 32-byte word); see emit_account_ / emit_slot_. Like the
    // index reserves, these are no-ops once a build has filled the stores: a reallocation
    // would move the records the overlay and the read path point into.
    if (account_index_.size() == 0)
        accounts_arena_.reserve(8u + static_cast<std::size_t>(accounts) * sizeof(Account));
    if (storage_index_.size() == 0)
        storage_arena_.reserve(8u + static_cast<std::size_t>(storage_slots) * 32u);
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

// Size of the RLP item at `p` (header plus payload), bounds-checked against `end`: 0 when
// the item is truncated. Used only to find where a node's first two items end, which
// classifies the node the way decode_node does (the cursor at the payload's end after item
// 1 is an extension or leaf, anything left is a branch). The items themselves are then read
// by rlp::decode_header (an extension's or leaf's two items, with its canonical-form checks)
// or by next_branch_child (a branch's children, with the strict child grammar).
[[gnu::always_inline]] inline std::size_t rlp_item_size(const std::uint8_t* p,
                                                        const std::uint8_t* end) noexcept {
    if (p >= end) return 0;
    const std::size_t avail = static_cast<std::size_t>(end - p);
    const std::uint8_t b0 = *p;
    if (b0 < 0x80) return 1;  // a single byte is its own payload
    std::size_t len_of_len = 0;
    std::size_t n = 0;
    if (b0 < 0xb8) {
        n = b0 - 0x80u;  // short string
    } else if (b0 < 0xc0) {
        len_of_len = b0 - 0xb7u;  // long string: 1..8 length bytes follow
    } else if (b0 < 0xf8) {
        n = b0 - 0xc0u;  // short list
    } else {
        len_of_len = b0 - 0xf7u;  // long list: 1..8 length bytes follow
    }
    const std::size_t head = 1 + len_of_len;
    if (avail < head) return 0;
    for (std::size_t i = 1; i < head; ++i) n = (n << 8) | p[i];
    if (avail - head < n) return 0;
    return head + n;
}

// How next_branch_child read a branch child item.
enum class ChildKind : std::uint8_t { kEmpty, kHash, kEmbedded, kBad };

// Read the branch child item at `cur` and advance past it, with exactly the three-case
// grammar and bounds checks of fill_branch_child_rlp (rlp_sw.hpp): 0x80 is an empty slot;
// 0xa0 followed by 32 bytes is a hash ref, returned as `ptr` to those 32 bytes; 0xc0..0xf7
// is an embedded node whose list payload is at most 31 bytes, returned as `ptr`/`len` over
// its whole RLP (header included) where it lies in the parent's bytes. Anything else, or an
// item running past `end`, is kBad. Nothing is read at or past `end`.
[[gnu::always_inline]] inline ChildKind next_branch_child(const std::uint8_t*& cur,
                                                          const std::uint8_t* end,
                                                          const std::uint8_t*& ptr,
                                                          std::uint8_t& len) noexcept {
    if (cur >= end) return ChildKind::kBad;
    const std::uint8_t b0 = *cur;
    if (b0 == rlp::kEmptyStringCode) {  // 0x80: empty slot
        ++cur;
        return ChildKind::kEmpty;
    }
    if (b0 == 0xa0) {  // 32-byte hash ref
        if (end - cur < 33) return ChildKind::kBad;
        ptr = cur + 1;
        cur += 33;
        return ChildKind::kHash;
    }
    if (b0 >= 0xc0 && b0 <= 0xf7) {  // embedded short list
        const std::ptrdiff_t payload = b0 - 0xc0;
        if (payload > 31 || end - cur < 1 + payload) return ChildKind::kBad;
        ptr = cur;
        len = static_cast<std::uint8_t>(1 + payload);
        cur += 1 + payload;
        return ChildKind::kEmbedded;
    }
    return ChildKind::kBad;  // not a valid branch child
}

// Nibble `c` (0..63) of a 32-byte trie key, read in place: the high half of byte c/2 for
// an even c, the low half for an odd one, the order nibbles64::from_bytes32 (mpt.hpp)
// unpacks a key in. The confirmation walk indexes the target key with this instead of
// unpacking all 64 nibbles up front, since a walk usually looks at only a few of them.
[[gnu::always_inline]] inline unsigned target_nibble(const evmc::bytes32& key,
                                                     unsigned c) noexcept {
    return (key.bytes[c >> 1] >> ((c & 1u) ? 0 : 4)) & 0xFu;
}

}  // namespace

const Account* HashState::emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value) {
    ++leaf_count_;  // a leaf was reached, whether or not its value decodes as an account

    // Decode straight into the arena slot. resize value-initialises the new 256 bytes, so
    // addr/deleted/modified/slot_count/code_store_*/absent_reads and the RLP cache fields
    // are zero (find_or_create_account, rlp_into and read_code rely on that), and
    // decode_trie_account fills nonce/balance/storage_root/code_hash in place. The offset
    // stays 8-aligned (the front pad is 8 bytes and every entry is a whole Account).
    const std::uint32_t off = static_cast<std::uint32_t>(accounts_arena_.size());
    accounts_arena_.resize(accounts_arena_.size() + sizeof(Account));
    Account* const acc = reinterpret_cast<Account*>(accounts_arena_.data() + off);
    if (!decode_trie_account(leaf_value, *acc)) {
        // Not an account-shaped leaf (e.g. a small embedded non-account leaf in a test
        // fixture, or a malformed witness). Give the slot back (a later resize zero-fills it
        // again) and do not cache; leave it observable via the leaf_count_/account_count()
        // gap. The account sweep never crashes on a leaf.
        accounts_arena_.resize(off);
        return nullptr;
    }

    // Index the entry by addr_hash. A duplicate addr_hash overwrites the offset (last write
    // wins) but the arena is append-only, matching add_node's dedupe-by-content spirit
    // loosely enough for a witness-derived, collision-free key set.
    account_index_.insert(addr_hash.bytes, off);
    return acc;
}

void HashState::emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                           ByteView leaf_value) {
    ++storage_slot_count_;  // a storage leaf was reached

    // The trie leaf value is rlp::encode(zeroless_view(word)) — an RLP string whose payload
    // is the big-endian word with leading zeros trimmed (0..32 bytes). Peel that one string
    // header; decode_header advances `v` to the payload, exactly as decode_trie_account peels
    // the account list header. A single small byte (< 0x80) is its own payload (no header),
    // which decode_header reports as payload_length 1 without advancing — handled uniformly.
    // A payload wider than 32 bytes or running past the value is not a word: skip.
    ByteView v = leaf_value;
    auto h = rlp::decode_header(v);
    if (!h || h->list || h->payload_length > 32 || h->payload_length > v.size()) return;

    // Append the word straight into the arena (resize zero-fills the 32 bytes, so the
    // right-aligned payload lands on a zero prefix; the offset stays 8-aligned) and index it
    // by addr_hash||slot_hash.
    const std::uint32_t off = static_cast<std::uint32_t>(storage_arena_.size());
    storage_arena_.resize(storage_arena_.size() + 32);
    if (h->payload_length) {
        std::memcpy(storage_arena_.data() + off + (32u - h->payload_length), v.data(),
                    h->payload_length);
    }

    alignas(8) std::uint8_t key[64];
    std::memcpy(key, account_key.bytes, 32);
    std::memcpy(key + 32, slot_hash.bytes, 32);
    storage_index_.insert(key, off);
}

template <class EmitLeaf>
bool HashState::sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf) {
    // The frame stack is empty whenever a sweep ends (the loop below drains it); clear it
    // before the root probe regardless, so nothing from an earlier sweep can carry over.
    sweep_stack_.clear();

    // Look up the seeding root by hash. Absence is REPORTED to the caller (return false),
    // never counted here: build_state_from_trie applies the fail-closed policy per trie kind
    // (an absent account root is fail-closed; an absent storage root is a legitimate omission).
    auto root_rlp = find_node_rlp(root);
    if (!root_rlp) return false;

    // ONE path buffer for the whole sweep. path.len is the live prefix: a frame records the
    // length at its branch, each child visit resets to that length and appends the child's
    // nibble, and an extension or leaf appends its own nibbles in place. A write only ever
    // lands at or past the top frame's path_len, so the prefix of every frame below stays
    // intact. Nibbles past path.len are stale; they are zeroed before a short (malformed)
    // leaf path is packed.
    nibbles64 path{};

    // Chase down from a node's RLP: strip the outer list header, classify the node, then
    // either push a branch frame, fold an extension's path in and descend into its one
    // child, or reach a leaf and hand it to emit_leaf. Written as a loop (not recursion) so
    // an extension chain never grows the C++ call stack. Mirrors unfold_node_from_rlp's
    // branch / ext / leaf split. The leaf's meaning (account vs storage slot) is entirely
    // the caller's emit — the traversal is identical for both. Every node here is genuine:
    // it was fetched by its keccak from node_index_ (add_view_ keys a view by the real
    // keccak and find compares all 32 bytes) or sits embedded inside such a node, so a
    // malformed shape is unreachable from a keccak-bound root; where one is met anyway
    // (hand-built fixtures) the descent stops and nothing is emitted below it.
    const auto descend = [&](ByteView node_rlp) {
        while (true) {
            // Strip the outer list header. rlp::decode_header (the size-safe free helper
            // decode_node itself uses) is used rather than fold_unfold's fast_decode_header
            // because the sweep must also decode <8-byte embedded nodes, which the >=8-byte
            // fast path mis-reads. The payload is clamped to the view, as substr did.
            auto oh = rlp::decode_header(node_rlp);
            if (!oh || !oh->list) return;  // malformed node — not a list
            const std::uint8_t* const p = node_rlp.data();
            const std::uint8_t* const end = p + std::min(oh->payload_length, node_rlp.size());

            // Classify by the extents of items 0 and 1, the rule decode_node applies: exactly
            // two items is an extension or leaf, anything longer a branch. Both skips are
            // bounds-checked against the payload's end; a truncated item stops the descent.
            const std::size_t s0 = rlp_item_size(p, end);
            if (s0 == 0) return;
            const std::size_t s1 = rlp_item_size(p + s0, end);
            if (s1 == 0) return;

            if (p + s0 + s1 != end) {
                // Branch. A branch consumes one nibble per child, so a well-formed branch sits
                // at path.len <= 63 (its children land at <= 64). Reject a malformed deeper
                // branch: it has no room for a child nibble (would overflow nibbles64). The
                // frame's cursor starts at the payload's first byte: the main loop reads every
                // child item, items 0 and 1 included, with the strict child grammar, and no
                // child is decoded before it is visited.
                if (path.len >= 64) return;
                sweep_stack_.push_back(SweepFrame{p, end, 0, path.len});
                return;
            }

            // Extension or leaf: decode the two items as decode_node does, with
            // rlp::decode_header. Item 0 is the HP-encoded path string, never empty (hp_decode
            // rejects an empty one); a one-nibble path is a single byte < 0x80, which
            // decode_header reports as payload_length 1 without advancing, so the payload is
            // always taken from the view it returns. Item 1 must be a string (decode_node
            // rejects a list there).
            ByteView items{p, static_cast<std::size_t>(end - p)};
            auto h0 = rlp::decode_header(items);
            if (!h0 || h0->list || h0->payload_length == 0 || h0->payload_length > items.size())
                return;
            const std::uint8_t* const hp = items.data();
            const std::size_t hp_len = h0->payload_length;
            items.remove_prefix(hp_len);
            auto h1 = rlp::decode_header(items);
            if (!h1 || h1->list || h1->payload_length > items.size()) return;
            const std::uint8_t* const second = items.data();
            const std::size_t second_len = h1->payload_length;

            // Inline HP decode, the grammar of hp_decode (rlp_sw.hpp): the first byte's high
            // nibble holds the flags (bit 1 leaf, bit 0 odd length), its low nibble the first
            // path nibble when odd, and every following byte two nibbles. The bound is
            // hp_decode's own (more than 64 nibbles is malformed) plus the sweep's guard on
            // the appended path; both stop the descent, and together they keep every write
            // inside the 64-nibble buffer.
            const std::uint8_t flag = hp[0] >> 4;
            const bool is_leaf = (flag & 0x2) != 0;
            const bool odd = (flag & 0x1) != 0;
            const std::size_t n = (odd ? 1u : 0u) + 2u * (hp_len - 1);
            if (n > 64 || path.len + n > 64) return;
            std::uint8_t* out = path.nib.data() + path.len;
            if (odd) *out++ = hp[0] & 0x0F;
            for (std::size_t i = 1; i < hp_len; ++i) {
                *out++ = hp[i] >> 4;
                *out++ = hp[i] & 0x0F;
            }
            path.len = static_cast<std::uint8_t>(path.len + n);

            if (is_leaf) {
                // No trie has a leaf without a value (decode_node rejects it). A well-formed
                // account or storage leaf completes a 64-nibble path; a shorter one only
                // comes from a malformed fixture, so zero the stale nibbles past path.len
                // there (cold) and pack the zero-padded key a fresh buffer would have given.
                if (second_len == 0) return;
                if (path.len < 64) [[unlikely]]
                    std::memset(path.nib.data() + path.len, 0, 64u - path.len);
                emit_leaf(path_to_bytes32(path), ByteView{second, second_len});
                return;
            }

            // Extension: descend into its single child, which must be a 32-byte hash ref
            // (decode_node rejects an inline list as an extension child, and any other string
            // fails the next node's outer header check: nothing is emitted either way). The
            // store is probed straight from the hash's bytes in the node RLP (the size check
            // is the pointer overload's 32-byte guarantee).
            if (second_len != 32) return;
            auto child = find_node_rlp(second);
            if (!child) {
                // PRUNED BOUNDARY: this extension points into a pruned subtree (same rule as
                // the branch-child case below). Stop descending; do NOT bump missing_count_ —
                // a pruned child is not a missing node.
                return;
            }
            node_rlp = *child;  // decode the fetched child in place
        }
    };

    descend(*root_rlp);  // seed: push the root (or emit it if the root is a leaf)

    while (!sweep_stack_.empty()) {
        // The frame reference is taken fresh each iteration and is not used after descend(),
        // which pushes.
        SweepFrame& f = sweep_stack_.back();
        unsigned s = f.next_slot;
        if (s >= 16) {
            // Every child slot visited (slot 16, the branch value, is never populated for a
            // fixed-32-byte-key account/storage trie — every key ends at a leaf — so the
            // sweep never reads it). Subtree done: fold back to the parent.
            sweep_stack_.pop_back();
            continue;
        }

        // Advance to the next present child slot, left to right, reading each item with the
        // strict child grammar as it is passed. Validation is lazy: a malformed item at slot
        // k stops this branch there, after the children of slots < k were swept, where
        // decode_node rejected the whole branch before any child was visited. Nothing is
        // counted for it: as with every malformed shape, it is unreachable from a
        // keccak-bound root (see descend), and a fixture that has one emits the leaves under
        // the slots before it and none under the slots from it on.
        const std::uint8_t* ptr = nullptr;
        std::uint8_t len = 0;
        ChildKind k;
        do {
            k = next_branch_child(f.cur, f.end, ptr, len);
            ++s;
        } while (k == ChildKind::kEmpty && s < 16);
        if (k == ChildKind::kEmpty || k == ChildKind::kBad) {
            // No present child left (the remaining slots were all empty), or a malformed item.
            sweep_stack_.pop_back();
            continue;
        }
        f.next_slot = static_cast<std::uint8_t>(s);

        // Path to this child = the branch's path + the child's nibble (s - 1). path_len is
        // at most 63 (the push guard), so the nibble lands inside the buffer.
        path.len = f.path_len;
        path.nib[path.len++] = static_cast<std::uint8_t>(s - 1);

        if (k == ChildKind::kHash) {
            // 32-byte hash ref: resolve it through the store straight from where the hash
            // lies in the node RLP (kHash is the pointer overload's 32-byte guarantee), no
            // copy into a bytes32.
            auto child = find_node_rlp(ptr);
            if (!child) {
                // Pruned boundary (partial witness): do not descend, do not count as missing.
                // See docs/hashstate.md, "Fail-closed policy".
                continue;
            }
            descend(*child);
        } else {
            // Embedded (<32-byte) inline child: its RLP lies in the parent's bytes, which
            // live in the input blob or owned_bytes_, so it is decoded in place, no copy.
            descend(ByteView{ptr, len});
        }
    }

    return true;
}

HashState::BuildStatus HashState::build_state_from_trie(const evmc::bytes32& prev_root) {
    missing_count_ = 0;
    leaf_count_ = 0;
    storage_slot_count_ = 0;
    // Reset the read-miss counter and memo and remember the account-trie root so a later
    // read miss can seed confirm_absent. The reads that a caller runs after this build
    // accumulate into unconfirmed_read_count_ (and the proven-absent slots into
    // absent_slots_) until the next build clears them again.
    unconfirmed_read_count_ = 0;
    absent_slots_.clear();
    prev_root_ = prev_root;

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

    // --- storage passes --- one sweep per derived account; an absent storage root is skipped.
    // See docs/hashstate.md, "Fail-closed policy".
    for (const auto& pr : storage_roots) {
        const evmc::bytes32 account_key = pr.first;
        const evmc::bytes32 sroot = pr.second;
        sweep(sroot, [this, account_key](const evmc::bytes32& slot_hash, ByteView leaf_value) {
            emit_slot_(account_key, slot_hash, leaf_value);
        });
    }

    return missing_count_ > 0 ? BuildStatus::kMissingNode : BuildStatus::kOk;
}

// Single-path confirmation walk — see the header for the full contract. It mirrors
// sweep()'s descend() one node at a time, but keeps only ONE position (no stack, no emit)
// and decodes nothing it does not need: the target's own nibbles pick the single child to
// follow at every branch, and that child is the only slot read; an extension's or leaf's
// path is compared in place against the target's nibbles, not unpacked. Every node the
// walk follows lives in the input blob or owned_bytes_ (a hash child through the store, an
// embedded child inside its parent's bytes), so the position is a view into immutable
// bytes and no node is copied out. Should node storage ever move to a transient buffer,
// an embedded child would need the stable copy back.
bool HashState::confirm_absent(const evmc::bytes32& root,
                               const evmc::bytes32& target_hash) const noexcept {
    // The empty trie holds nothing, so every key is provably absent below it. (kEmptyRoot's
    // node is never in the store, so without this the fetch below would read as a missing
    // node and wrongly fail to confirm.)
    if (eq_hash32(root.bytes, silkworm::kEmptyRoot.bytes)) return true;

    auto cur = find_node_rlp(root);
    if (!cur) return false;  // seeding root missing -> cannot confirm absence
    const std::uint8_t* p = cur->data();  // the current node's RLP ...
    std::size_t n = cur->size();          // ... and its size
    unsigned consumed = 0;                // target nibbles matched on the way down so far

    while (true) {
        // Strip the outer list header exactly as descend() does (rlp::decode_header, the
        // size-safe helper that also handles <8-byte embedded nodes); the payload is clamped
        // to the view, as substr did.
        ByteView node_rlp{p, n};
        auto oh = rlp::decode_header(node_rlp);
        if (!oh || !oh->list) return false;  // malformed node -> cannot confirm
        const std::uint8_t* const q = node_rlp.data();
        const std::uint8_t* const end = q + std::min(oh->payload_length, node_rlp.size());

        // Classify by the extents of items 0 and 1, the rule decode_node applies (exactly two
        // items is an extension or leaf, anything longer a branch). Both skips are bounds-
        // checked against the payload's end; a truncated item cannot confirm anything.
        const std::size_t s0 = rlp_item_size(q, end);
        if (s0 == 0) return false;
        const std::size_t s1 = rlp_item_size(q + s0, end);
        if (s1 == 0) return false;

        if (q + s0 + s1 != end) {
            // Branch. A well-formed branch sits at consumed <= 63 (its children land at <= 64);
            // one deeper has no nibble left to index it (malformed). Read the child items from
            // the payload's first byte up to the target's slot, one at a time with the strict
            // child grammar (items 0 and 1 included, re-read in that grammar), and stop there:
            // the siblings past the slot and the value item are never read. Validation is
            // lazy, as in the sweep: a malformed item at or before the slot stops the walk
            // unconfirmed, one past it is not seen. Both are confined to shapes unreachable
            // from a keccak-bound root (see descend); a genuine branch's slot is read exactly.
            if (consumed >= 64) return false;
            const unsigned s = target_nibble(target_hash, consumed);
            const std::uint8_t* c = q;
            const std::uint8_t* ptr = nullptr;
            std::uint8_t len = 0;
            ChildKind k = ChildKind::kBad;
            for (unsigned i = 0; i <= s; ++i) {
                k = next_branch_child(c, end, ptr, len);
                if (k == ChildKind::kBad) return false;  // malformed child -> cannot confirm
            }
            // Empty child slot (the RLP 0x80 marker): the target's next nibble leads nowhere
            // -> proven absent.
            if (k == ChildKind::kEmpty) return true;
            ++consumed;
            if (k == ChildKind::kHash) {
                // 32-byte hash ref: resolve it through the store straight from where the hash
                // lies in the node RLP (kHash is the pointer overload's 32-byte guarantee).
                auto child = find_node_rlp(ptr);
                if (!child) return false;  // needed node missing -> cannot confirm
                p = child->data();
                n = child->size();
                continue;
            }
            // Embedded (<32-byte) inline child: its RLP lies in the parent's bytes, which are
            // immutable for the life of the store, so it is followed in place.
            p = ptr;
            n = len;
            continue;
        }

        // Extension or leaf: decode the two items as decode_node does, with rlp::decode_header
        // (its canonical-form checks). Item 0 is the HP-encoded path string, never empty; a
        // one-nibble path is a single byte < 0x80, which decode_header reports as
        // payload_length 1 without advancing, so the payload is always taken from the view it
        // returns. Item 1 is a string, never a list: a leaf's value (never empty: no trie has a
        // leaf without a value) or an extension's child ref.
        ByteView items{q, static_cast<std::size_t>(end - q)};
        auto h0 = rlp::decode_header(items);
        if (!h0 || h0->list || h0->payload_length == 0 || h0->payload_length > items.size())
            return false;
        const std::uint8_t* const hp = items.data();
        const std::size_t hp_len = h0->payload_length;
        items.remove_prefix(hp_len);
        auto h1 = rlp::decode_header(items);
        if (!h1 || h1->list || h1->payload_length > items.size()) return false;
        const std::uint8_t* const second = items.data();
        const std::size_t second_len = h1->payload_length;

        // The HP path, read with hp_decode's grammar (rlp_sw.hpp): the first byte's high
        // nibble holds the flags (bit 1 leaf, bit 0 odd length), its low nibble the first path
        // nibble when odd, and every following byte two nibbles, high half first. The bound is
        // hp_decode's own: more than 64 nibbles is malformed and cannot confirm. A leaf without
        // a value is rejected before its path is looked at, as decode_node rejects the node.
        const std::uint8_t flag = hp[0] >> 4;
        const bool is_leaf = (flag & 0x2) != 0;
        const bool odd = (flag & 0x1) != 0;
        const unsigned plen = (odd ? 1u : 0u) + 2u * static_cast<unsigned>(hp_len - 1);
        if (plen > 64) return false;
        if (is_leaf && second_len == 0) return false;

        // Match the path nibbles against the target's remainder in place, with a running byte
        // pointer and a high/low toggle: an odd path starts in the low half of hp[0], an even
        // one in the high half of hp[1]. The pointer only ever reads bytes of the path string
        // (overlap <= plen nibbles, which the string holds); it may step one past its last
        // byte after the last nibble, and that byte is never read.
        const unsigned remaining = 64u - consumed;
        const unsigned overlap = plen < remaining ? plen : remaining;
        const std::uint8_t* b = odd ? hp : hp + 1;
        bool high = !odd;
        for (unsigned i = 0; i < overlap; ++i) {
            const unsigned nib = high ? (*b >> 4) : (*b & 0x0Fu);
            if (nib != target_nibble(target_hash, consumed + i)) return true;  // diverges -> absent
            if (high) {
                high = false;
            } else {
                high = true;
                ++b;
            }
        }
        if (plen > remaining) return true;  // node path outlasts the key -> divergence -> absent
        consumed += plen;

        if (is_leaf) {
            // Whole leaf path matched. Exactly consuming the key (consumed == 64) means the key
            // is PRESENT (not proven absent); a shorter leaf leaves the key hanging past a
            // terminal node (absent). A present key here is a cache-miss anomaly, so fail-closed.
            return consumed == 64 ? false : true;
        }

        // Extension: descend into its single child, which must be a 32-byte hash ref (an
        // inline list was rejected above, as decode_node rejects it; a string of any other
        // size is no node, and stops the walk unconfirmed where it failed the next outer
        // header check before). The store is probed straight from the hash's bytes in the
        // node RLP (the size check is the pointer overload's 32-byte guarantee).
        if (second_len != 32) return false;
        auto child = find_node_rlp(second);
        if (!child) return false;  // needed node missing -> cannot confirm
        p = child->data();
        n = child->size();
    }
}

void HashState::note_account_miss_(const evmc::bytes32& addr_hash) const noexcept {
    // Cache miss on an account. If confirm_absent can prove the key empty in the account trie
    // the blank read is correct and nothing is recorded; otherwise a node the walk needed was
    // missing (or the key is unexpectedly present), so the read is unconfirmed — record it.
    if (!confirm_absent(prev_root_, addr_hash)) ++unconfirmed_read_count_;
}

void HashState::note_storage_miss_(const std::uint8_t (&key)[64]) const noexcept {
    // A storage slot is zero unless its account exists AND carries a non-empty storage trie.
    // The account is probed in place from the key's first half (the addr_hash).
    auto aoff = account_index_.find_ptr(key);
    if (!aoff) return;  // account not cached -> slot is zero, no storage trie to confirm against
    const Account* const acc = reinterpret_cast<const Account*>(accounts_arena_.data() + *aoff);
    if (eq_hash32(acc->storage_root, silkworm::kEmptyRoot.bytes))
        return;  // empty storage trie -> slot is zero, no walk

    // A slot an earlier walk since the build proved absent: the same answer, no walk.
    if (absent_slots_.find(key)) return;

    // Confirm against the account's own storage_root, read in place from the arena record
    // (32 bytes at offset 96 of an 8-aligned 256-byte Account, so the cast is aligned, as
    // read_code's cast of code_hash is), toward the slot_hash in the key's second half. This
    // is where a storage root the build skipped (its node never added) is caught:
    // find_node_rlp misses inside confirm_absent, so it returns false and the read is
    // recorded rather than passed off as a silent zero. Only a proven miss is memoized.
    const auto& sroot = *reinterpret_cast<const evmc::bytes32*>(acc->storage_root);
    const auto& slot_hash = *reinterpret_cast<const evmc::bytes32*>(key + 32);  // key is alignas(8)
    if (!confirm_absent(sroot, slot_hash)) {
        ++unconfirmed_read_count_;
        return;
    }
    absent_slots_.insert(key, 1);
}

evmc::bytes32 HashState::add_view_(HashIndex<32, &hash_key8, StoredBytes>& index,
                                   ByteView bytes) {
    // Identity binding: the index key IS the real keccak256 of the bytes (matches the
    // direct_state.cpp:417-418 idiom exactly). One probe inserts or finds the key present:
    // a repeat is the same content under the same hash, so the first view stays (first
    // wins, which is what a find followed by an insert-if-absent would do, at one probe).
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(bytes));
    index.try_insert(h.bytes, stored_view_(bytes));
    return h;
}

evmc::bytes32 HashState::add_node_borrowed(ByteView rlp) { return add_view_(node_index_, rlp); }

evmc::bytes32 HashState::add_code_borrowed(ByteView code) { return add_view_(code_index_, code); }

evmc::bytes32 HashState::add_node(ByteView rlp) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(rlp));
    if (node_index_.find(h.bytes)) return h;  // dedupe: already stored, no second copy
    const Bytes& copy = owned_bytes_.emplace_back(rlp);
    node_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

evmc::bytes32 HashState::add_code(ByteView code) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    if (code_index_.find(h.bytes)) return h;  // dedupe
    const Bytes& copy = owned_bytes_.emplace_back(code);
    code_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

// --- silkworm::BlockState interface + BLOCKHASH store ---------------------------------
// Near-verbatim copies of DirectState (direct_state.cpp:696-730, :818-840) so a later
// retype of the execution surface to ActiveState is a drop-in. See hash_state.hpp for the
// per-method contract and the one divergence (no witness block_hashes_ span in get_block_hash).

std::optional<BlockHeader> HashState::read_header(BlockNum,
                                                  const evmc::bytes32& block_hash) const noexcept {
    const auto it = headers_.find(block_hash);
    if (it == headers_.end()) return std::nullopt;
    return it->second;
}

void HashState::insert_header(const BlockHeader& header) {
    headers_[header.hash()] = header;

    // created_block_hashes_ kept sorted ascending for log-n BLOCKHASH lookup.
    const uint64_t block_num = header.number;
    const auto h = header.hash();
    auto it = std::lower_bound(created_block_hashes_.begin(),
                               created_block_hashes_.end(), block_num,
                               [](const BlockHashEntry& e, uint64_t n) {
                                   return e.block_number < n;
                               });
    if (it != created_block_hashes_.end() && it->block_number == block_num) {
        std::memcpy(it->block_hash, h.bytes, 32);
    } else {
        BlockHashEntry e{};
        e.block_number = block_num;
        std::memcpy(e.block_hash, h.bytes, 32);
        created_block_hashes_.insert(it, e);
    }
}

bool HashState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> HashState::total_difficulty(uint64_t,
                                                         const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

evmc::bytes32 HashState::get_block_hash(BlockNum n) const noexcept {
    // No witness block_hashes_ span here (see hash_state.hpp): created_block_hashes_ alone.
    if (!created_block_hashes_.empty()) {
        const auto it = std::lower_bound(created_block_hashes_.begin(),
                                         created_block_hashes_.end(), n,
                                         [](const BlockHashEntry& e, BlockNum k) {
                                             return e.block_number < k;
                                         });
        if (it != created_block_hashes_.end() && it->block_number == n) {
            return std::bit_cast<evmc::bytes32>(it->block_hash);
        }
    }

    // Fail-closed BLOCKHASH miss: record an unconfirmed read, still return zero.
    // See docs/hashstate.md, "Block headers and BLOCKHASH".
    ++unconfirmed_read_count_;
    return {};
}

// --- Write overlay + mutators + address-keyed readers (S2) ----------------------------
// Copy-on-write over the PRISTINE built caches: every write lands in the overlay
// (created_accounts_ / overflow_slots_ / created_code_) and a read sees overlay-then-built.
// Bodies mirror direct_state.cpp:337-694 line-for-line except the two divergences marked
// DIVERGENCE(a)/(b). See hash_state.hpp for the design rationale.

namespace {

namespace eip7702 = ::silkworm::eip7702;

// Balance is stored native-endian (Account::balance, account.hpp:28; see
// direct_state.cpp:203-212). memcpy in/out preserves the intx::uint256 byte layout.
inline void store_be_u256(uint8_t (&out)[32], const intx::uint256& v) noexcept {
    std::memcpy(out, &v, 32);
}
inline intx::uint256 load_be_u256(const uint8_t (&in)[32]) noexcept {
    intx::uint256 v;
    std::memcpy(&v, in, 32);
    return v;
}
inline void copy32(uint8_t (&dst)[32], const evmc::bytes32& src) noexcept {
    std::memcpy(dst, src.bytes, 32);
}
// keccak256(addr) — the 32-byte account-trie path that keys the built account cache.
inline evmc::bytes32 addr_hash_of(const evmc::address& addr) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{addr.bytes, 20}));
}
// keccak256(slot key) — the storage-trie path that keys the built storage cache.
inline evmc::bytes32 slot_hash_of(const evmc::bytes32& key) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{key.bytes, 32}));
}

}  // namespace

// Non-recording overlay-or-built probe (DirectState::lookup_account_ analog,
// direct_state.cpp:349-357): overlay first, then the built cache, no confirm side effect.
const Account* HashState::lookup_account_(const evmc::address& addr) const noexcept {
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    return find_built_account(addr_hash_of(addr));
}

// Read resolver: overlay hit (nullptr if deleted) else the RECORDING built-cache read path
// (get_account -> note_account_miss_), so an address-keyed read of a pruned account is
// recorded fail-closed rather than silently returning a wrong-empty.
const Account* HashState::resolve_for_read_(const evmc::address& addr) const noexcept {
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return it->second.deleted ? nullptr : &it->second;
    return get_account(addr_hash_of(addr));
}

const Account* HashState::read_account(const evmc::address& addr) const noexcept {
    return resolve_for_read_(addr);
}

evmc::bytes32 HashState::read_storage(const evmc::address& addr,
                                      const evmc::bytes32& key) const noexcept {
    // Overlay slot first: a written value — INCLUDING a retained zero (divergence a) —
    // shadows the built (pre-state) value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        if (auto kv = it->second.find(key); kv != it->second.end())
            return kv->second;
    }
    // A wiped account reads every pre-state slot as zero (divergence b).
    if (storage_wiped_.contains(addr)) [[unlikely]]
        return {};
    // Built storage cache: get_storage records an unprovable miss (note_storage_miss_).
    return get_storage(addr_hash_of(addr), slot_hash_of(key));
}

ByteView HashState::read_code(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return {};
    if (eq_hash32(pa->code_hash, kEmptyHash.bytes)) return {};  // empty code — not a fault

    const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa->code_hash);

    // In-block created code (set via set_code / apply_code_diff): the code_store_offset
    // sentinel, resolved through created_code_ (verbatim direct_state.cpp:332-344).
    if (pa->code_store_offset == kCreatedCodeOffset) [[unlikely]] {
        if (const ByteView cc = find_created_code_(h); !cc.empty()) [[likely]]
            return cc;
        // Created-code marker with no stored bytes (should not happen) -> fail-closed.
        ++unconfirmed_read_count_;
        return {};
    }

    // Witness code store (built accounts and set_code dedup hits): resolve by code_hash.
    if (const ByteView cv = find_code(h); !cv.empty())
        return cv;

    // Witness store miss. The bytes may still be legitimately DERIVABLE: a contract created
    // in-block with the SAME code_hash makes an omitted witness code available (EIP-8025
    // optional proofs — "create same hash then read"). This is exactly what DirectState gets
    // for free because it always holds the full pre-state; the partial slib witness prunes
    // such code, so fall back to the in-block created-code overlay before failing.
    if (const ByteView cc = find_created_code_(h); !cc.empty())
        return cc;

    // FAIL-CLOSED: a derived account carries a code_hash whose bytes the witness omitted AND
    // that no in-block creation reproduces. DirectState guarantees presence via sanitize
    // (direct_state.cpp:762-777); HashState has no such binding, so record the genuine gap for
    // the accept gate instead of silently executing empty code.
    ++unconfirmed_read_count_;
    return {};
}

// In-block created-code lookup by keccak code_hash (created_code_ + key8-collision spill).
// Verbatim shape of read_code's former created-code sentinel resolution, factored out so the
// witness-store-miss fallback can reuse it. Hit -> stored bytes; miss -> empty ByteView.
ByteView HashState::find_created_code_(const evmc::bytes32& h) const noexcept {
    const uint64_t k8 = hash_key8(h);
    if (auto it = created_code_.find(k8); it != created_code_.end() &&
            std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) [[likely]] {
        return ByteView{it->second.bytes.data(), it->second.bytes.size()};
    }
    if (auto cit = created_code_collisions_.find(h); cit != created_code_collisions_.end()) {
        return ByteView{cit->second.data(), cit->second.size()};
    }
    return {};
}

intx::uint256 HashState::get_balance(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);  // nullptr also covers deleted
    if (pa == nullptr) return 0;
    return load_be_u256(pa->balance);
}

uint64_t HashState::get_nonce(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr) return 0;
    return pa->nonce;
}

bool HashState::has_storage(const evmc::address& addr) const noexcept {
    const Account* pa = lookup_account_(addr);  // non-recording is enough here
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    // A live (non-zero) overlay slot means storage exists. Zero writes are RETAINED
    // (divergence a), so a bare non-empty test would misreport — scan for a live value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        for (const auto& [k, v] : it->second)
            if (!evmc::is_zero(v)) return true;
    }
    // Built pre-state storage, unless wiped (divergence b).
    if (storage_wiped_.contains(addr)) return false;
    return !eq_hash32(pa->storage_root, kEmptyRoot.bytes);
}

// "Not in state" is a materialized (deleted) overlay record, not a null pointer — verbatim
// DirectState::materialize_absent_account_ (direct_state.cpp:327-335) over the overlay.
Account* HashState::materialize_absent_account_(const evmc::address& addr) {
    Account fresh{};
    std::memcpy(fresh.addr, addr.bytes, 20);
    copy32(fresh.code_hash, kEmptyHash);
    copy32(fresh.storage_root, kEmptyRoot);
    fresh.deleted = true;
    auto [ins, _] = created_accounts_.emplace(addr, fresh);
    return &ins->second;
}

Account* HashState::find_or_create_account(const evmc::address& addr) {
    // Overlay hit (DirectState lookup finding a created record) — deleted or not.
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    const evmc::bytes32 h = addr_hash_of(addr);
    // Built hit -> copy-on-write into the overlay (the built cache stays pristine).
    if (const Account* built = find_built_account(h)) {  // side-effect-free: no confirm
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);          // the build leaves addr zero (hpp:152)
        auto [ins, _] = created_accounts_.emplace(addr, copy);
        return &ins->second;
    }
    // Total miss: materialize a fresh (deleted) record, never null. That the pre-state trie has
    // no leaf for the address is claimed by the record's account-trie update at accept time
    // (check_root_hashstate, HashStateAccountWrite::absent), which the fold checks where the
    // key leaves the trie: no confirm_absent walk here. A pruned boundary on the way, or a leaf
    // at the key, fails that walk, and the accept gate rejects.
    return materialize_absent_account_(addr);
}

// Caller guarantees pa.deleted; reset to a fresh account (DirectState:356-369).
bool HashState::revive_if_deleted_slow(const evmc::address& addr, Account& pa) {
    pa.deleted = false;
    copy32(pa.code_hash, kEmptyHash);
    copy32(pa.storage_root, kEmptyRoot);
    pa.slot_count = 0;
    pa.code_store_len = 0;
    pa.code_store_offset = 0;
    pa.nonce = 0;
    store_be_u256(pa.balance, intx::uint256{0});
    overflow_slots_.erase(addr);
    // DIVERGENCE (b): the built pre-state slots must now read zero (the DirectState in-place
    // slot_count=0 wipe has no analog on the immutable built cache).
    storage_wiped_.insert(addr);
    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
    return true;
}

void HashState::set_account_from_diff(Account& pa, uint64_t nonce,
                                      const intx::uint256& balance) noexcept {
    bool changed = false;
    if (pa.nonce != nonce) {
        pa.nonce = nonce;
        changed = true;
    }
    if (load_be_u256(pa.balance) != balance) {
        store_be_u256(pa.balance, balance);
        changed = true;
    }
    if (changed) {
        pa.modified = true;
        pa.acc_rlp_sroot_off = 0;  // invalidate the RLP cache — force re-encode
    }
}

void HashState::set_storage_slot(const evmc::address& addr, Account& pa,
                                 const evmc::bytes32& key, const evmc::bytes32& value) {
    pa.modified = true;
    // HashState has no inline blob slots; every write lands in the overlay. DIVERGENCE (a):
    // a zero write is RETAINED (DirectState erases it, direct_state.cpp:391-397) so the fold
    // emits it as a 0x80 delete — the incremental fold over prev_root needs the explicit
    // delete, whereas DirectState recomputes each storage root from its live slots.
    overflow_slots_[addr][key] = value;
}

void HashState::apply_code_diff(const evmc::address& addr, Account& pa,
                                const evmc::bytes& code) {
    const ByteView code_view{code.data(), code.size()};
    const bool is_delegated = eip7702::is_code_delegated(code_view);

    // Wipe storage on contract creation unless the new code is a delegation or the address
    // was already a delegation target (mirrors direct_state.cpp:406-415). DIVERGENCE (b):
    // set the storage_wiped_ flag + drop overlay slots instead of the in-place inline-slot
    // wipe (the built cache is immutable).
    if (!is_delegated && !delegated_designations_.contains(addr)) {
        overflow_slots_.erase(addr);
        storage_wiped_.insert(addr);
    }
    if (is_delegated) {
        delegated_designations_.insert(addr);
    }

    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code_view));
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the WITNESS code store via find_code — the HashState analog of
    // DirectState's code_store_map_.find (direct_state.cpp:424-427). Otherwise stash in
    // created_code_ keyed by key8(hash), spilling key8 collisions into
    // created_code_collisions_ (verbatim direct_state.cpp:428-440).
    if (!find_code(h).empty()) {
        pa.code_store_offset = 0;  // resolvable via find_code(code_hash) in read_code
    } else {
        pa.code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
            // Exact dedup hit (same hash, possibly different addr). Skip insert.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h); cins) {
                cit->second.assign(code.begin(), code.end());
            }
        }
    }

    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
}

void HashState::set_balance(const evmc::address& addr, const intx::uint256& value) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    bool changed = false;
    if (load_be_u256(pa->balance) != value) {
        store_be_u256(pa->balance, value);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::add_to_balance(const evmc::address& addr, const intx::uint256& addend) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    const auto cur = load_be_u256(pa->balance);
    bool changed = false;
    if (addend != 0) {
        store_be_u256(pa->balance, cur + addend);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    const auto cur = load_be_u256(pa->balance);
    bool changed = false;
    if (subtrahend != 0) {
        store_be_u256(pa->balance, cur - subtrahend);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::set_nonce(const evmc::address& addr, uint64_t nonce) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    bool changed = false;
    if (pa->nonce != nonce) {
        pa->nonce = nonce;
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::set_code(const evmc::address& addr, ByteView code) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);

    if (eip7702::is_code_delegated(code)) {
        delegated_designations_.insert(addr);
    }
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    bool changed = false;
    if (std::memcmp(pa->code_hash, h.bytes, 32) != 0) {
        std::memcpy(pa->code_hash, h.bytes, 32);
        changed = true;
    }
    pa->code_store_len = static_cast<uint32_t>(code.size());

    if (!find_code(h).empty()) {
        pa->code_store_offset = 0;  // resolvable via find_code(code_hash) in read_code
    } else {
        pa->code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
            // Exact dedup hit. Skip.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h); cins) {
                cit->second.assign(code.begin(), code.end());
            }
        }
    }

    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::destruct(const evmc::address& addr) {
    // The built cache is immutable, so mark the overlay record deleted (copy-on-write a
    // deleted marker if the account exists only in the built cache) so read_account sees it
    // gone. If it exists in neither store there is nothing to mask (mirrors
    // direct_state.cpp:566-570).
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end()) {
        it->second.deleted = true;
    } else if (const Account* built = find_built_account(addr_hash_of(addr))) {
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);
        copy.deleted = true;
        created_accounts_.emplace(addr, copy);
    }
    overflow_slots_.erase(addr);
    // DIVERGENCE (b): the built pre-state slots must now read zero (DirectState zeroes the
    // blob slot_count in place, direct_state.cpp:568; HashState cannot mutate the built cache).
    storage_wiped_.insert(addr);
    touched_.insert(addr);
    journal_address_changed(addr);
}

bool HashState::is_deleted(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    return pa == nullptr || pa->deleted;
}

bool HashState::is_empty_account(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    return pa->nonce == 0 && eq_hash32(pa->code_hash, kEmptyHash.bytes) &&
           load_be_u256(pa->balance) == 0;
}

bool HashState::is_dead(const evmc::address& addr) const noexcept {
    return is_deleted(addr) || is_empty_account(addr);
}

void HashState::destruct_dead_among(const FlatHashSet<evmc::address>& addrs) {
    for (const auto& addr : addrs) {
        if (is_dead(addr)) destruct(addr);
    }
}

void HashState::apply_state_diff(const evmone::state::StateDiff& diff) {
    for (const auto& m : diff.modified_accounts) {
        auto* pa = find_or_create_account(m.addr);
        revive_if_deleted(m.addr, *pa);
        journal_address_changed(m.addr);
        if (m.code) apply_code_diff(m.addr, *pa, *m.code);
        set_account_from_diff(*pa, m.nonce, m.balance);
        for (const auto& [k, v] : m.modified_storage) {
            journal_slot_changed(m.addr, k);
            set_storage_slot(m.addr, *pa, k, v);
        }
    }
    for (const auto& a : diff.deleted_accounts) {
        journal_address_changed(a);
        destruct(a);
    }
}

}  // namespace zilkworm
