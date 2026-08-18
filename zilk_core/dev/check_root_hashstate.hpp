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
// i.e. the recomputed root matches the header AND the witness contained every node the
// build/fold needed AND every read either hit the cache or was proven genuinely empty
// (fail-closed — see hash_state.hpp:200-208).
//
// The write set is an INPUT here (HashStateAccountWrite below), shaped the way check_root
// shapes its internal update set (sorted mpt::TrieNodeFlat). Wiring the write set from
// execution — the analog of check_root's gather over DirectState's journals
// (state_transition.cpp:426-609) — is the follow-on step; for now the caller supplies it.
//
// This header is compiled ONLY into HashState guest builds and host/native builds (the
// unit tests). The guard mirrors grid_mpt.cpp:26 / :411 so the rv64im DirectState guest
// pulls in NOTHING from here and its ELF stays byte-identical. Nothing in the guest
// includes this header, and the guard is a belt-and-braces second line of defence.

#pragma once

#if defined(Z6M_HASH_STATE) || !defined(__riscv)

#include <cstdint>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>          // GridMPT<bool, StateT>, TrieNodeFlat, is_zero_quick, kEmptyRoot
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

}  // namespace zilkworm

#endif  // defined(Z6M_HASH_STATE) || !defined(__riscv)
