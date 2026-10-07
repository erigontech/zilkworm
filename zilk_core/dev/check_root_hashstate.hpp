// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// check_root_hashstate: the HashState accept check, a sibling of StateTransition::check_root.
// See docs/hashstate.md, "Accept check".

#pragma once

#if defined(Z6M_HASH_STATE) || !defined(__riscv)

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>          // silkworm::zeroless_view, silkworm::to_hex
#include <zilk_core/core/rlp/encode.hpp>           // silkworm::rlp::encode_into_small
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>          // GridMPT<bool, StateT>, TrieNodeFlat, is_zero_quick, kEmptyRoot, keccak_bytes[32]
#include <zilk_core/core/types_zz/account.hpp>     // Account::rlp_into
#include <zilk_core/print.hpp>                      // sys_println (recomputed-root diagnostic)

namespace zilkworm {

// The pre-value an update claims for a key the pre-state trie does not have: zero, RLP 0x80
// (what check_root claims for a slot read as zero). GridMPT::claims_absent accepts it where
// the key leaves the trie; the HashState leaf match refutes it.
inline constexpr std::uint8_t kAbsentClaim[1] = {0x80};

// One touched account's contribution to a block's write set, in the shape check_root
// builds internally (state_transition.cpp:452-608) but supplied as INPUT here. Accounts
// that changed appear, and accounts the block read as absent (see `absent`); HashState
// carries no other read-only entry and no pre-value (the pre-value check is compiled
// out), exactly as check_root skips readonly accounts from its update set.
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

    // The pre-state trie has no leaf for addr_hash: the block read the account as absent
    // (find_or_create_account's total miss), and created it when `account` is set. The
    // account-trie update then claims the key absent (the 0x80 pre-value), which the walk
    // checks where the key leaves the trie (GridMPT::claims_absent) and refutes at a leaf
    // (grid_mpt.cpp, the HashState arm of the leaf match). With `account == nullptr` the
    // update is a read: it inserts nothing, and the root stays as it was.
    bool absent{false};
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

        if (w.absent) {
            // The claim that the pre-state trie has no leaf for this key (see `absent`). Out of
            // line of buf, which the leaf RLP of a created account can take in full.
            node.ext_initial = ByteView{kAbsentClaim, 1};
            if (w.account == nullptr) {
                continue;  // a read: nothing to write (current_len == 0)
            }
        } else if (w.account == nullptr) {
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
            // A failed walk binds none of the slots (check_root: "storage trie walk failed").
            if (storage_trie.failed()) [[unlikely]] {
                sys_println("ERROR: storage trie walk failed (HashState)");
                return false;
            }
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

    // Recomputed-root diagnostic, symmetric with StateTransition::check_root's
    // sys_println("New Root: ...") (state_transition.cpp:646): surfaces the folded root for
    // the accept decision (the first true end-to-end signal in the slib runner arm). Purely
    // observational — the accept gate below is unchanged.
    sys_println(std::format("New Root (hashstate): {}",
                            silkworm::to_hex(ByteView{new_root.bytes, 32})));

    // Accept iff the account walk went through, the recomputed root matches the header, the
    // witness was complete AND every read was resolved. The pre-value / read-only check
    // check_root runs inside the fold is compiled out for HashState; the two counters and
    // the claims of absence (HashStateAccountWrite::absent) replace it. A failed walk (a
    // node missing or malformed, a claim refuted at a leaf) returns a zero root, which only
    // a header committing to one would match.
    return !acc_trie.failed()
        && new_root == header_state_root
        && hash_state.missing_count() == 0
        && hash_state.unconfirmed_read_count() == 0;
}

// Gather overload: build the write set from HashState's write overlay, then delegate above.
// See docs/hashstate.md, "Gather overload".
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

        // Whether the pre-state trie has a leaf for the address: a built account. The probe is
        // the side-effect-free find_built_account, not get_account, which would bump
        // unconfirmed_read_count_ on a legitimate miss. An address the probe misses is one
        // find_or_create_account materialized on a total miss: its write claims the key absent.
        const bool built = hash_state.find_built_account(addr_hash) != nullptr;

        // Destructed account: 0x80 leaf delete if a pre-trie leaf exists (st.cpp:503-516).
        // Otherwise an address the pre-state does not have, read as absent (or created and
        // destructed again): a read-only claim of absence, which inserts nothing.
        if (acc.deleted) {
            writes.push_back(HashStateAccountWrite{addr_hash, {}, {}, nullptr, /*absent=*/!built});
            continue;
        }

        // Live account: gather its storage writes, sorted by slot_hash.
        auto& storage = storage_pool.emplace_back();
        if (const auto* slots = hash_state.overflow_slots_for(addr)) {
            // A wiped account (contract creation / destruct / revive) has NO pre-state slots
            // any more, so every zero write over it is a no-op that must be OMITTED.
            const bool wiped = hash_state.storage_wiped(addr);
            storage.reserve(slots->size());
            for (const auto& [k, v] : *slots) {
                const evmc::bytes32 slot_hash = keccak_bytes32(k);
                // Omit a zero write unless it deletes a slot that exists in the pre-state trie.
                // See docs/hashstate.md, "Zero storage writes".
                if (evmc::is_zero(v) &&
                    (wiped || !hash_state.find_built_storage(addr_hash, slot_hash)))
                    continue;
                auto& node = storage.emplace_back(slot_hash);
                node.current_off = 40;
                // Stage the word 8-byte aligned before zeroless_view (evmc::bytes32 is only
                // alignas(4), but zeroless_view asserts 8-byte alignment on the host and the
                // rv64im guest forbids unaligned loads — mirrors the test's encode_storage_value
                // and util.hpp:106). The encoded bytes are identical to check_root's
                // zeroless_view(ByteView{v.bytes,32}) (state_transition.cpp:585-586); a genuine
                // zero DELETE that survives the filter encodes as 0x80.
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
            addr_hash, storage_root, std::span<const TrieNodeFlat>{storage}, &acc, /*absent=*/!built});
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
