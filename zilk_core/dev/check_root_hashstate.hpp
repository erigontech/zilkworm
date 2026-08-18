// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// check_root_hashstate — the HashState accept check, an additive sibling to
// StateTransition::check_root (state_transition.cpp:423-631). It folds ONLY a block's
// writes over a HashState whose account/storage caches were already built from the
// pre-state trie (build_state_from_trie), recomputes the post-state root with the SAME
// shared trie code check_root uses (GridMPT), and decides acceptance.
//
// It mirrors check_root's two-level fold structure exactly:
//   1. per touched account, fold its storage trie first (reset() from the account's
//      current storage_root) to obtain the account's NEW storage_root, then patch the
//      account leaf with that root (check_root: state_transition.cpp:538-587, 605-607);
//   2. fold the account trie from prev_root (check_root: state_transition.cpp:618-619).
//
// What differs from check_root — and why there is a separate function rather than a
// branch inside it — is the accept decision. check_root runs the pre-value / read-only
// check inside the fold; that check is COMPILED OUT for the HashState instantiation
// (state_keeps_prevalue_check<HashState> == false, hash_state.hpp:324, grid_mpt.cpp:303).
// In its place the accept gate here folds in two witness-completeness counters that the
// HashState build + reads accumulate:
//     accept  <=>  new_root == header_state_root
//                  && hash_state.missing_count()          == 0
//                  && hash_state.unconfirmed_read_count() == 0
// i.e. the recomputed root matches the header AND the seeding account root was present
// (missing_count() now flags ONLY a broken root — a real EIP-8025 partial witness prunes
// untouched subtrees to bare hash refs, which the build treats as legitimate boundaries)
// AND every read either hit the cache or was proven genuinely empty (fail-closed — see
// hash_state.hpp:200-208). A write whose fold must descend into a pruned boundary is still
// caught without a fourth condition: GridMPT cannot unfold the absent node, so it recomputes
// a non-matching (zero) root and new_root == header_state_root fails.
//
// The write set can be supplied two ways. The span-based overload takes it as an INPUT
// (HashStateAccountWrite below), shaped the way check_root shapes its internal update set
// (sorted mpt::TrieNodeFlat). The GATHER overload (no supplied span, at the bottom of this
// header) builds that same set from HashState's own write overlay — the analog of check_root's
// gather over DirectState (state_transition.cpp:452-609) — then delegates to the span-based
// overload unchanged, so the real execution path (S6) can accept a block right after running it.
//
// This header is compiled ONLY into HashState guest builds and host/native builds (the
// unit tests). The guard mirrors grid_mpt.cpp:26 / :411 so the rv64im DirectState guest
// pulls in NOTHING from here and its ELF stays byte-identical. Nothing in the guest
// includes this header, and the guard is a belt-and-braces second line of defence.

#pragma once

#if defined(Z6M_HASH_STATE) || !defined(__riscv)

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>          // silkworm::zeroless_view
#include <zilk_core/core/rlp/encode.hpp>           // silkworm::rlp::encode_into_small
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>          // GridMPT<bool, StateT>, TrieNodeFlat, is_zero_quick, kEmptyRoot, keccak_bytes[32]
#include <zilk_core/core/types_zz/account.hpp>     // Account::rlp_into

namespace zilkworm {

// One touched account's contribution to a block's write set, in the shape check_root
// builds internally (state_transition.cpp:452-608) but supplied as INPUT here. Only
// accounts that actually changed appear — HashState carries no read-only / pre-value
// entries (the pre-value check is compiled out), exactly as check_root skips readonly
// accounts from its update set.
struct HashStateAccountWrite {
    // Account-trie path == keccak256(addr); the key of the account-trie update
    // (check_root: node key is it_existing_hashes->addr_hash, state_transition.cpp:591).
    evmc::bytes32 addr_hash{};

    // The account's CURRENT (pre-write) storage root — the seed the per-account storage
    // fold reset()s from (check_root: storage_trie.reset(storage_root),
    // state_transition.cpp:584). When storage_updates is empty this root is used
    // unchanged as the account leaf's storage_root.
    evmc::bytes32 storage_root{};

    // Storage-slot writes for this account, sorted by slot_hash (== keccak256(slot key)),
    // the same storage_updates check_root sorts before folding (state_transition.cpp:564-580).
    // Empty => storage unchanged: the storage fold is skipped and storage_root is used as-is.
    // (Unqualified TrieNodeFlat: this header lives in namespace zilkworm, where the trie
    // types are direct members — the mpt:: alias check_root uses only exists under silkworm.)
    std::span<const TrieNodeFlat> storage_updates{};

    // The account whose leaf is (re)encoded with the folded storage_root via rlp_into
    // (check_root: pa->rlp_into(inserted.buf, storage_root), state_transition.cpp:607).
    // nullptr => the account is destructed this block, so its account-trie leaf is deleted
    // (current value 0x80, mirroring check_root's deletion path, state_transition.cpp:506-511).
    const Account* account{nullptr};
};

// Fold the writes over the (already-built) HashState, recompute the post-state root, and
// return whether to ACCEPT. `writes_sorted` MUST be sorted by addr_hash (memcmp order),
// exactly as check_root's acc_updates are (they arrive as a merge of two sorted hash
// sequences, state_transition.cpp:611). `prev_root` is the pre-state account-trie root the
// HashState was built from; `header_state_root` is the block header's claimed post-state root.
[[nodiscard]] inline bool check_root_hashstate(
    const HashState& hash_state,
    const evmc::bytes32& prev_root,
    std::span<const HashStateAccountWrite> writes_sorted,
    const evmc::bytes32& header_state_root) {
    std::vector<TrieNodeFlat> acc_updates;
    acc_updates.reserve(writes_sorted.size());

    // One storage GridMPT hoisted out of the per-account loop and reset() per account,
    // mirroring check_root's single storage_trie reused across accounts
    // (state_transition.cpp:480 + :584) to avoid per-account grid_ malloc/free.
    GridMPT<true, HashState> storage_trie{hash_state, kEmptyRoot};

    for (const auto& w : writes_sorted) {
        auto& node = acc_updates.emplace_back(w.addr_hash);

        if (w.account == nullptr) {
            // Destructed account: 0x80 current value signals leaf deletion
            // (check_root: state_transition.cpp:509).
            node.buf[0] = 0x80;
            node.current_off = 0;
            node.current_len = 1;
            continue;
        }

        // Per-account storage fold FIRST — seed from the account's current storage_root,
        // fold its sorted slot writes, take the new storage_root
        // (check_root: state_transition.cpp:581-587). No storage writes => root unchanged.
        evmc::bytes32 storage_root = w.storage_root;
        if (!w.storage_updates.empty()) {
            if (is_zero_quick(storage_root)) {  // new/empty account storage (check_root:581)
                storage_root = kEmptyRoot;
            }
            storage_trie.reset(storage_root);
            storage_root = storage_trie.calc_root_from_updates(w.storage_updates);
        }

        // Patch the account leaf with the (possibly new) storage_root
        // (check_root: state_transition.cpp:605-607).
        node.current_off = 0;
        node.current_len = w.account->rlp_into(node.buf + 0, storage_root);
    }

    // Account-trie fold from prev_root (check_root: state_transition.cpp:618-619).
    GridMPT<true, HashState> acc_trie(hash_state, prev_root);
    const evmc::bytes32 new_root =
        acc_trie.calc_root_from_updates({acc_updates.data(), acc_updates.size()});

    // Accept iff the recomputed root matches the header AND the witness was complete AND
    // every read was resolved. The pre-value / read-only check check_root runs inside the
    // fold is compiled out for HashState; these two counters replace it.
    return new_root == header_state_root
        && hash_state.missing_count() == 0
        && hash_state.unconfirmed_read_count() == 0;
}

// GATHER overload — build the write set from HashState's own write overlay, then delegate to
// the span-based check_root_hashstate above. This is the analog of StateTransition::check_root's
// gather over DirectState (state_transition.cpp:452-609), producing the SAME sorted update set
// from a different substrate so the real execution path can accept a block right after running
// it (no hand-supplied span). Mirror of check_root's gather, step for step:
//   * iterate the overlay `created_accounts()` — only WRITTEN accounts live there, exactly
//     check_root's `modified` split expressed structurally (read-only accounts never enter);
//   * per account keccak the 20-byte address to its addr_hash (mirroring st.cpp:457);
//   * a DESTRUCTED account (deleted) with a pre-trie leaf (find_built_account hits) emits an
//     `account == nullptr` 0x80 leaf delete (st.cpp:503-512); a created-then-destructed account
//     (find_built_account MISSES) is SKIPPED (st.cpp:513-516). The probe is the side-effect-free
//     find_built_account, NOT get_account, so a legitimate miss never bumps
//     unconfirmed_read_count_ and wrongly rejects;
//   * a LIVE account's overlay storage writes become a sorted-by-slot-hash TrieNodeFlat set,
//     each value encoded as check_root does — rlp::encode_into_small(buf+40, zeroless_view(v))
//     into current_off=40, so a ZERO value encodes as 0x80 and folds as a delete (st.cpp:585-586;
//     this is why HashState RETAINS zero writes, divergence a);
//   * the storage-fold seed is the account's pre-write storage_root, taken from the OVERLAY POD
//     (frozen at copy-on-write, exactly check_root's `pa->storage_root`, st.cpp:565,629) with a
//     `storage_wiped()` override to kEmptyRoot (contract-creation wipe leaves the POD's
//     storage_root stale — divergence b). The frozen-overlay-copy source is chosen over the
//     "built account else zero" variant because a created account with NO storage writes must
//     seed kEmptyRoot, not zero (the span overload only normalizes zero->kEmptyRoot when
//     storage_updates is non-empty), and the overlay POD already carries kEmptyRoot for created /
//     revived accounts;
//   * the account leaf is re-encoded by the span overload via `account->rlp_into` from the
//     overlay POD, which reads `code_hash` (never code_store_offset — account.cpp:46), so a
//     witness-code account (code_store_offset==0) still encodes its real code_hash;
//   * sort the writes by addr_hash (memcmp) — the span contract — and delegate.
[[nodiscard]] inline bool check_root_hashstate(
    const HashState& hash_state,
    const evmc::bytes32& prev_root,
    const evmc::bytes32& header_state_root) {
    const auto& overlay = hash_state.created_accounts();

    std::vector<HashStateAccountWrite> writes;
    writes.reserve(overlay.size());

    // Per-account storage TrieNodeFlat vectors must OUTLIVE the fold — the spans in
    // HashStateAccountWrite::storage_updates point into them. Reserved to overlay.size() so the
    // outer vector never reallocates (only LIVE accounts push, so at most overlay.size() pushes);
    // even a move would preserve each inner buffer, but reserving keeps the reference stable.
    std::vector<std::vector<TrieNodeFlat>> storage_pool;
    storage_pool.reserve(overlay.size());

    for (const auto& kv : overlay) {
        const evmc::address& addr = kv.first;
        const Account& acc = kv.second;
        const evmc::bytes32 addr_hash = keccak_bytes(ByteView{addr.bytes, 20});

        // Destructed account: 0x80 leaf delete if a pre-trie leaf exists, else created-then-
        // destructed -> no pre-trie leaf, skip (st.cpp:503-516). Side-effect-free probe.
        if (acc.deleted) {
            if (hash_state.find_built_account(addr_hash) != nullptr) {
                writes.push_back(HashStateAccountWrite{addr_hash, {}, {}, nullptr});
            }
            continue;
        }

        // Live account: gather its storage writes, sorted by slot_hash.
        auto& storage = storage_pool.emplace_back();
        if (const auto* slots = hash_state.overflow_slots_for(addr)) {
            storage.reserve(slots->size());
            for (const auto& [k, v] : *slots) {
                auto& node = storage.emplace_back(keccak_bytes32(k));
                node.current_off = 40;
                // Stage the word 8-byte aligned before zeroless_view (evmc::bytes32 is only
                // alignas(4), but zeroless_view asserts 8-byte alignment on the host and the
                // rv64im guest forbids unaligned loads — mirrors the test's encode_storage_value
                // and util.hpp:106). The encoded bytes are identical to check_root's
                // zeroless_view(ByteView{v.bytes,32}) (state_transition.cpp:585-586).
                alignas(8) uint8_t word[32];
                std::memcpy(word, v.bytes, 32);
                node.current_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
                    node.buf + 40, silkworm::zeroless_view(ByteView{word, 32})));
            }
            // Raw-key order != keccak(key) order; sort by slot_hash (st.cpp:589-606).
            std::sort(storage.begin(), storage.end());
        }

        // Pre-write storage-root seed: frozen overlay POD (== check_root's pa->storage_root),
        // overridden to the empty-trie root when the account's storage was wiped this block.
        evmc::bytes32 storage_root{};
        if (hash_state.storage_wiped(addr)) {
            storage_root = kEmptyRoot;
        } else {
            std::memcpy(storage_root.bytes, acc.storage_root, 32);
        }

        writes.push_back(HashStateAccountWrite{
            addr_hash, storage_root, std::span<const TrieNodeFlat>{storage}, &acc});
    }

    // The span overload requires addr_hash (memcmp) order; the overlay is a hash map, so sort.
    std::sort(writes.begin(), writes.end(),
              [](const HashStateAccountWrite& a, const HashStateAccountWrite& b) {
                  return std::memcmp(a.addr_hash.bytes, b.addr_hash.bytes, 32) < 0;
              });

    return check_root_hashstate(hash_state, prev_root,
                                std::span<const HashStateAccountWrite>{writes},
                                header_state_root);
}

}  // namespace zilkworm

#endif  // defined(Z6M_HASH_STATE) || !defined(__riscv)
