// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// The HashState accept check, a sibling of StateTransition::check_root.

#pragma once

#if defined(Z6M_HASH_STATE) || !defined(__riscv)

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/print.hpp>

namespace zilkworm {

// One touched account's write-set entry; only changed accounts appear.
struct HashStateAccountWrite {
    evmc::bytes32 addr_hash{};

    // The account's pre-write storage root: the seed of the storage fold, kept as the leaf's root when storage_updates is empty.
    evmc::bytes32 storage_root{};

    // Sorted by slot_hash (keccak256 of the slot key); empty => storage unchanged.
    std::span<const TrieNodeFlat> storage_updates{};

    // nullptr => the account is destructed this block and its leaf is deleted.
    const Account* account{nullptr};
};

// Folds the writes over the built HashState and returns whether to ACCEPT; `writes_sorted` must be in addr_hash order.
[[nodiscard]] inline bool check_root_hashstate(
    const HashState& hash_state,
    const evmc::bytes32& prev_root,
    std::span<const HashStateAccountWrite> writes_sorted,
    const evmc::bytes32& header_state_root) {
    std::vector<TrieNodeFlat> acc_updates;
    acc_updates.reserve(writes_sorted.size());

    // One storage trie reused across accounts via reset().
    GridMPT<true, HashState> storage_trie{hash_state, kEmptyRoot};

    for (const auto& w : writes_sorted) {
        auto& node = acc_updates.emplace_back(w.addr_hash);

        if (w.account == nullptr) {
            // 0x80 current value signals leaf deletion.
            node.buf[0] = 0x80;
            node.current_off = 0;
            node.current_len = 1;
            continue;
        }

        // Storage fold first: seed from the account's current storage_root; no writes => root unchanged.
        evmc::bytes32 storage_root = w.storage_root;
        if (!w.storage_updates.empty()) {
            if (is_zero_quick(storage_root)) {
                storage_root = kEmptyRoot;
            }
            storage_trie.reset(storage_root);
            storage_root = storage_trie.calc_root_from_updates(w.storage_updates);
            // A failed walk returns a zero root: a leaf the witness lacks, or a malformed node.
            if (storage_trie.failed()) [[unlikely]] {
                sys_println("ERROR: storage walk failed in the HashState accept check");
                return false;
            }
        }

        // Patch the account leaf with the (possibly new) storage_root.
        node.current_off = 0;
        node.current_len = w.account->rlp_into(node.buf + 0, storage_root);
    }

    GridMPT<true, HashState> acc_trie(hash_state, prev_root);
    const evmc::bytes32 new_root =
        acc_trie.calc_root_from_updates({acc_updates.data(), acc_updates.size()});

    // Recomputed-root diagnostic; observational only.
    sys_println(std::format("New Root (hashstate): {}",
                            silkworm::to_hex(ByteView{new_root.bytes, 32})));

    // Accept iff the walk succeeded, the root matches the header, the witness was complete and every read was confirmed.
    return !acc_trie.failed()
        && new_root == header_state_root
        && hash_state.missing_count() == 0
        && hash_state.unconfirmed_read_count() == 0;
}

// Gather overload: build the write set from HashState's write overlay, then delegate above.
[[nodiscard]] inline bool check_root_hashstate(
    const HashState& hash_state,
    const evmc::bytes32& prev_root,
    const evmc::bytes32& header_state_root) {
    const auto& overlay = hash_state.created_accounts();

    std::vector<HashStateAccountWrite> writes;
    writes.reserve(overlay.size());

    // Must outlive the fold (storage_updates spans point into it); reserved so the outer vector never reallocates.
    std::vector<std::vector<TrieNodeFlat>> storage_pool;
    storage_pool.reserve(overlay.size());

    for (const auto& kv : overlay) {
        const evmc::address& addr = kv.first;
        const Account& acc = kv.second;
        const evmc::bytes32 addr_hash = keccak_bytes(ByteView{addr.bytes, 20});

        // Destructed: delete the leaf if a pre-trie leaf exists, else created-then-destructed: skip.
        if (acc.deleted) {
            if (hash_state.find_built_account(addr_hash) != nullptr) {
                writes.push_back(HashStateAccountWrite{addr_hash, {}, {}, nullptr});
            }
            continue;
        }

        // Unmodified built record: its leaf is unchanged.
        if (!acc.modified && hash_state.find_built_account(addr_hash) != nullptr) continue;

        // Live account: gather its storage writes, sorted by slot_hash.
        auto& storage = storage_pool.emplace_back();
        if (const auto* slots = hash_state.overflow_slots_for(addr)) {
            // A wiped account has no pre-state slots, so every zero write over it is a no-op to omit.
            const bool wiped = hash_state.storage_wiped(addr);
            storage.reserve(slots->size());
            for (const auto& [k, v] : *slots) {
                const evmc::bytes32 slot_hash = keccak_bytes32(k);
                // Omit a zero write unless it deletes a slot that exists in the pre-state trie.
                if (evmc::is_zero(v) &&
                    (wiped || !hash_state.find_built_storage(addr_hash, slot_hash)))
                    continue;
                auto& node = storage.emplace_back(slot_hash);
                node.current_off = 40;
                // Stage 8-byte aligned before zeroless_view (rv64im forbids unaligned loads); a surviving zero DELETE encodes as 0x80.
                alignas(8) uint8_t word[32];
                std::memcpy(word, v.bytes, 32);
                node.current_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
                    node.buf + 40, silkworm::zeroless_view(ByteView{word, 32})));
            }
            // Raw-key order != keccak(key) order.
            std::sort(storage.begin(), storage.end());
        }

        // Pre-write storage-root seed; the empty-trie root when the account's storage was wiped this block.
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
