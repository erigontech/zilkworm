// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Reusable host-side harness for end-to-end account-read tests driven through the
// PUBLIC guest entry point (`StateTransition::run` over a real MFBD envelope).
//
// Everything here is `inline` and header-only so several test translation units can
// share it. Nothing in this header is adversarial by itself: it builds *genuine*
// bundles, derives the header commitments an honest producer would publish, and
// exposes two byte-level forgery primitives (`forge_slot_transposition`,
// `forge_drop_highest_slot`) plus a faithful mirror of
// `StateTransition::check_root` (`mirror_check_root`) so a test can compute the
// state root the guest is going to compute.
//
// Typical use
// -----------
//   const auto tx = make_legacy_txn(D, /*gas_limit=*/1'000'000, /*value=*/0);
//   const evmc::address S = recover_sender(tx);            // sender comes from the sig
//   ... build leaves / node store / code store / prestate blob ...
//   const ChainSetup chain = make_chain(prev_root, tx, /*beneficiary=*/S);
//   ShadowRun sr = shadow_execute(blob, nodestore, prev_root, chain.base.header, tx);
//   std::vector<uint8_t> env = make_envelope(chain, sr, blob, nodestore);
//   StateTransition st{std::span<uint8_t>{env}};
//   const uint64_t gas = st.run().gas_used;  // run() returns StateTransition::Result
//
// Notes / gotchas encoded here
// ----------------------------
// * `Transaction::set_sender` does NOT survive RLP encode/decode, and `run()` decodes
//   the block, so the sender must be RECOVERED from a fixed valid signature and the
//   pre-state built around that address. See `make_legacy_txn` / `recover_sender`.
// * `shadow_execute` sanitizes the very bytes it is handed, exactly like the guest,
//   and uses `execute_transaction` (not `execute_block`, whose post-validation needs
//   the gas figure we are trying to learn). For a single-tx post-Merge block with an
//   empty withdrawals list the resulting state is the same.
// * `mirror_check_root` reproduces `check_root`'s merge over
//   (`addr_hashes()` x `created_accounts()`) update-for-update, minus the clash
//   rejection, so the root it returns is what `check_root` would compare against.
//   That includes the ANCHORED per-account storage walk (`mirror_storage_root`),
//   which is NOT interchangeable with `DirectState::account_storage_root` once a
//   bundle is incomplete — see the comment on `mirror_storage_root`.
// * The created/existing clash guard lives in `StateTransition::check_root`, which runs
//   only for the FIRST block of a bundle; `check_root_new_block` (subsequent blocks) has
//   no such guard. Every bundle these tests build therefore carries a single block.
//
// Running the suite
// -----------------
// The account-read files (`account_read_spoof_test.cpp`, `account_read_honest_test.cpp`)
// and `mphf_map_test.cpp` all feed the top-level `zilkworm.tests` target, and
// `catch_discover_tests` registers each TEST_CASE with ctest individually. The spoofing
// file holds two cases: the account-spoofing one (its eight reads are `DYNAMIC_SECTION`s,
// so it registers as a single test however many reads it covers) and the storage-slot
// omission one. Adding `-s` also prints the `CAPTURE`d gas figures and occupied-vs-empty
// splits. Useful filters (assertion / case counts as of this writing):
//
//   ninja -C build zilkworm.tests
//   ./build/zilkworm.tests                             # 1548 assertions, 22 cases (whole target)
//   ./build/zilkworm.tests "[clash]"                   #  530 assertions,  8 cases
//   ./build/zilkworm.tests "[clash]~[honest]"          #  308 assertions,  1 case  (the spoof case)
//   ./build/zilkworm.tests "[honest]"                  #  222 assertions,  7 cases
//   ./build/zilkworm.tests "[omission]"                #   50 assertions,  1 case
//   ./build/zilkworm.tests "[mphf]"                    # 1538 assertions, 17 cases
//   ./build/zilkworm.tests "[mphf]~[state_transition]" #  958 assertions,  8 cases (builder units)

#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/crypto/ecdsa.h>
#include <zilk_core/core/common_zz/data_byte_count.hpp>
#include <zilk_core/core/execution/processor.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie/vector_root.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/bloom.hpp>
#include <zilk_core/core/types/receipt.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>
#include <zilk_core/dev/state_transition.hpp>

namespace zilkworm::test_util {

using silkworm::ByteView;
using silkworm::Bytes;

// ---------------------------------------------------------------------------
// Addresses / hashing
// ---------------------------------------------------------------------------

/// Address with only bytes[0] and bytes[19] set. `addr_key8` folds bytes[0..6] plus
/// bytes[19], so varying either byte yields a distinct MPHF key.
inline evmc::address make_addr(uint8_t b0, uint8_t b19) {
    evmc::address a{};
    a.bytes[0] = b0;
    a.bytes[19] = b19;
    return a;
}

/// keccak256 of the 20 address bytes, i.e. the account trie key.
inline bytes32 keccak_addr32(const evmc::address& a) { return keccak_bytes(ByteView{a.bytes, 20}); }

// ---------------------------------------------------------------------------
// Pre-state accounts and their trie leaves
// ---------------------------------------------------------------------------

/// The account-trie leaf RLP for an account, produced through the very encoder the
/// guest uses (`Account::rlp_into_cache`), so it is byte-identical to the pre-state
/// value `check_root` will see in `acc_rlp_buf`.
inline Bytes account_rlp(const evmc::address& addr, uint64_t nonce, const intx::uint256& balance,
                         const bytes32& code_hash, const bytes32& storage_root) {
    Account acc{};
    std::memcpy(acc.addr, addr.bytes, 20);
    acc.nonce = nonce;
    std::memcpy(acc.balance, &balance, 32);
    std::memcpy(acc.code_hash, code_hash.bytes, 32);
    std::memcpy(acc.storage_root, storage_root.bytes, 32);
    const uint8_t len = acc.rlp_into_cache(storage_root);
    return Bytes{acc.acc_rlp_buf, acc.acc_rlp_buf + len};
}

/// Codeless account (empty code hash, empty storage root).
inline DirectState::AccountInfo make_eoa(const evmc::address& addr, uint64_t nonce,
                                         const intx::uint256& balance) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = nonce;
    std::memcpy(info.account.balance, &balance, 32);
    std::memcpy(info.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(info.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    return info;
}

/// Code account. `code_len` must be non-zero, otherwise `sanitize()` will not resolve
/// the code-store offset for this record.
inline DirectState::AccountInfo make_contract(const evmc::address& addr, uint64_t nonce,
                                             const intx::uint256& balance,
                                             const bytes32& code_hash, uint32_t code_len) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = nonce;
    std::memcpy(info.account.balance, &balance, 32);
    std::memcpy(info.account.code_hash, code_hash.bytes, 32);
    std::memcpy(info.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    info.account.code_store_len = code_len;
    return info;
}

// ---------------------------------------------------------------------------
// Witness side-stores
// ---------------------------------------------------------------------------

/// MPHF code store over `{code_hash -> code}` pairs, keyed by `hash_key8(code_hash)`.
inline std::vector<uint8_t> build_code_store(
    const std::vector<std::pair<bytes32, Bytes>>& codes) {
    MphfBuilder<32> cb{kMphfCodeStoreMagic, kMphfMapVersion};
    for (const auto& [code_hash, code] : codes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, code_hash, ByteView{code.data(), code.size()});
        cb.add(hash_key8(code_hash), ByteView{body.data(), body.size()});
    }
    return std::move(cb).finalize();
}

/// Runs a `HashBuilder` over `leaves` (`{trie key -> leaf value}`), APPENDS every node RLP it
/// emits to `captured`, and returns the resulting root. Trie-agnostic: used for the account
/// trie and for each account's storage trie, so one node store can serve both.
inline bytes32 collect_trie_nodes(std::vector<std::pair<bytes32, Bytes>> leaves,
                                  std::vector<std::pair<bytes32, Bytes>>& captured) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    std::sort(leaves.begin(), leaves.end(), [](const auto& x, const auto& y) {
        return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0;
    });
    silkworm::trie::HashBuilder hb;
    hb.rlp_collector = [&](ByteView node_rlp) {
        captured.emplace_back(keccak_bytes(node_rlp), Bytes{node_rlp.begin(), node_rlp.end()});
    };
    for (const auto& [k, v] : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), ByteView{v.data(), v.size()});
    }
    return hb.root_hash();
}

/// MPHF node store over `{keccak(node_rlp) -> node_rlp}`, deduplicated by hash. This is what
/// `GridMPT` unfolds from (`DirectState::find_node_rlp`), so a complete capture is what makes
/// `missing_count() == 0` achievable.
inline std::vector<uint8_t> build_node_store(
    const std::vector<std::pair<bytes32, Bytes>>& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    std::vector<bytes32> seen;
    seen.reserve(nodes.size());
    for (const auto& [h, rlp] : nodes) {
        const bool dup = std::any_of(seen.begin(), seen.end(), [&](const bytes32& s) {
            return std::memcmp(s.bytes, h.bytes, 32) == 0;
        });
        if (dup) continue;  // the same node can appear in two tries; one MPHF key each
        seen.push_back(h);
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, ByteView{rlp.data(), rlp.size()});
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

/// Builds the account trie over `leaves` (`{keccak(addr) -> leaf RLP}`), captures every node
/// RLP the `HashBuilder` emits into an MPHF node store, and returns the resulting root.
/// Account-trie nodes ONLY — an account whose storage trie `check_root` has to unfold needs
/// `build_prestate` (or `collect_trie_nodes` + `build_node_store`) instead.
inline bytes32 build_account_node_store(std::vector<std::pair<bytes32, Bytes>> leaves,
                                        std::vector<uint8_t>& node_store_out) {
    std::vector<std::pair<bytes32, Bytes>> captured;
    const bytes32 root = collect_trie_nodes(std::move(leaves), captured);
    node_store_out = build_node_store(captured);
    return root;
}

/// The storage-trie leaves of `storage`: `{keccak(key) -> RLP(zeroless(value))}` over the
/// NON-ZERO values, i.e. exactly the leaf set `DirectState::account_storage_root` hashes.
inline std::vector<std::pair<bytes32, Bytes>> storage_trie_leaves(
    const std::vector<std::pair<evmc::bytes32, evmc::bytes32>>& storage) {
    std::vector<std::pair<bytes32, Bytes>> leaves;
    for (const auto& [key, value] : storage) {
        if (evmc::is_zero(value)) continue;  // zero == absent, per Yellow-Paper trie semantics
        Bytes v;
        silkworm::rlp::encode(v, silkworm::zeroless_view(value.bytes));
        leaves.emplace_back(keccak_bytes(ByteView{key.bytes, 32}), std::move(v));
    }
    return leaves;
}

// ---------------------------------------------------------------------------
// One-shot pre-state: blob + node store + prev_root from a list of accounts
// ---------------------------------------------------------------------------

/// One pre-state account. Empty `code` means an EOA; `storage` may be empty.
struct AcctSpec {
    evmc::address addr{};
    uint64_t nonce{};
    intx::uint256 balance{};
    Bytes code{};
    std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage{};

    bytes32 code_hash() const {
        return code.empty() ? silkworm::kEmptyHash : keccak_bytes(ByteView{code.data(), code.size()});
    }
};

struct Prestate {
    std::vector<uint8_t> blob;
    std::vector<uint8_t> nodestore;
    bytes32 prev_root{};
};

/// Builds a complete, self-consistent witness for `specs`: code store, account MPHF blob,
/// node store and the resulting `prev_root`, with every account's `storage_root` and trie
/// leaf agreeing with its slots.
///
/// Storage roots are not hand-rolled: the blob is built twice, and the first (throwaway)
/// pass is read back through `DirectState::account_storage_root` — the very function
/// `check_root` uses — so the committed `storage_root` cannot drift from production code.
///
/// The node store holds the account trie's nodes AND every account's storage-trie nodes,
/// because `check_root` unfolds a second `GridMPT` per account anchored at that account's
/// `storage_root`; without those nodes the storage walk reports missing nodes (or silently
/// rebuilds a fresh trie) and no root derived from the bundle would mean anything.
inline Prestate build_prestate(const std::vector<AcctSpec>& specs) {
    std::vector<std::pair<bytes32, Bytes>> codes;
    for (const auto& s : specs) {
        if (!s.code.empty()) codes.emplace_back(s.code_hash(), s.code);
    }

    auto infos_with_roots = [&](const std::vector<bytes32>& sroots) {
        std::vector<DirectState::AccountInfo> infos;
        infos.reserve(specs.size());
        for (std::size_t i = 0; i < specs.size(); ++i) {
            const auto& s = specs[i];
            DirectState::AccountInfo info =
                s.code.empty()
                    ? make_eoa(s.addr, s.nonce, s.balance)
                    : make_contract(s.addr, s.nonce, s.balance, s.code_hash(),
                                    static_cast<uint32_t>(s.code.size()));
            std::memcpy(info.account.storage_root, sroots[i].bytes, 32);
            info.storage = s.storage;
            infos.push_back(std::move(info));
        }
        return infos;
    };

    std::vector<bytes32> sroots(specs.size(), silkworm::kEmptyRoot);
    bool any_storage = false;
    for (const auto& s : specs) any_storage = any_storage || !s.storage.empty();
    if (any_storage) {
        std::vector<uint8_t> probe_blob = DirectState::build_blob_from_accounts(
            infos_with_roots(sroots), {}, build_code_store(codes));
        DirectState probe{std::span<uint8_t>{probe_blob}};
        for (std::size_t i = 0; i < specs.size(); ++i) {
            if (!specs[i].storage.empty()) sroots[i] = probe.account_storage_root(specs[i].addr);
        }
    }

    // Storage-trie nodes first: `storage_trie_leaves` hashes the same leaf set
    // `account_storage_root` does, so the root it returns is `sroots[i]` again.
    std::vector<std::pair<bytes32, Bytes>> nodes;
    for (std::size_t i = 0; i < specs.size(); ++i) {
        if (specs[i].storage.empty()) continue;
        collect_trie_nodes(storage_trie_leaves(specs[i].storage), nodes);
    }

    std::vector<std::pair<bytes32, Bytes>> leaves;
    leaves.reserve(specs.size());
    for (std::size_t i = 0; i < specs.size(); ++i) {
        leaves.emplace_back(keccak_addr32(specs[i].addr),
                            account_rlp(specs[i].addr, specs[i].nonce, specs[i].balance,
                                        specs[i].code_hash(), sroots[i]));
    }

    Prestate ps{};
    ps.prev_root = collect_trie_nodes(leaves, nodes);
    ps.nodestore = build_node_store(nodes);
    ps.blob = DirectState::build_blob_from_accounts(infos_with_roots(sroots), {},
                                                    build_code_store(codes));
    return ps;
}

// ---------------------------------------------------------------------------
// Transaction with a recovered sender
// ---------------------------------------------------------------------------

/// A legacy, zero-gas-price transaction carrying a FIXED valid secp256k1 signature
/// (r is a real curve x-coordinate). The sender is whatever the signature recovers to
/// for this exact payload — see `recover_sender`. `set_sender` is deliberately not used:
/// `StateTransition::run` RLP-decodes the block, which drops it.
inline silkworm::Transaction make_legacy_txn(const evmc::address& to, uint64_t gas_limit,
                                            const intx::uint256& value = 0, uint64_t nonce = 0) {
    silkworm::Transaction tx{};
    tx.type = silkworm::TransactionType::kLegacy;
    tx.chain_id = 1;
    tx.nonce = nonce;
    tx.max_fee_per_gas = 0;
    tx.max_priority_fee_per_gas = 0;
    tx.gas_limit = gas_limit;
    tx.to = to;
    tx.value = value;
    tx.r = intx::from_string<intx::uint256>(
        "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276");
    tx.s = intx::from_string<intx::uint256>(
        "0x67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    tx.odd_y_parity = false;
    return tx;
}

/// The address `tx`'s signature recovers to (same computation as `Transaction::sender`).
/// Returns the zero address if recovery fails.
inline evmc::address recover_sender(const silkworm::Transaction& tx) {
    Bytes rlp;
    tx.encode_for_signing(rlp);
    const auto hash = silkworm::keccak256(rlp);
    uint8_t sig[64];
    intx::be::unsafe::store(sig, tx.r);
    intx::be::unsafe::store(sig + 32, tx.s);
    evmc::address out{};
    const bool ok = silkworm_recover_address(out.bytes, hash.bytes, sig, tx.odd_y_parity);
    return ok ? out : evmc::address{};
}

// ---------------------------------------------------------------------------
// Chain scaffolding: genesis (parent) + the block under test
// ---------------------------------------------------------------------------

/// Genesis anchors `prev_root`; `base` is block 1 carrying `tx` with every header field
/// filled except the four the producer can only know after execution
/// (gas_used, receipts_root, logs_bloom, state_root) — see `make_envelope`.
struct ChainSetup {
    silkworm::Block genesis;
    Bytes genesis_rlp;
    silkworm::Block base;
};

inline ChainSetup make_chain(const bytes32& prev_root,
                             std::span<const silkworm::Transaction> txs,
                             const evmc::address& beneficiary) {
    namespace protocol = silkworm::protocol;
    ChainSetup cs{};

    cs.genesis.header.number = 0;
    cs.genesis.header.state_root = prev_root;
    cs.genesis.header.gas_limit = 30'000'000;
    cs.genesis.header.gas_used = 0;
    cs.genesis.header.timestamp = 1000;
    cs.genesis.header.ommers_hash = silkworm::kEmptyListHash;
    cs.genesis.header.transactions_root = silkworm::kEmptyRoot;
    cs.genesis.header.receipts_root = silkworm::kEmptyRoot;
    cs.genesis.header.base_fee_per_gas = intx::uint256{0};
    cs.genesis.header.withdrawals_root = silkworm::kEmptyRoot;
    cs.genesis.withdrawals = std::vector<silkworm::Withdrawal>{};
    silkworm::rlp::encode(cs.genesis_rlp, cs.genesis);

    cs.base.header.parent_hash = cs.genesis.header.hash();
    cs.base.header.number = 1;
    cs.base.header.beneficiary = beneficiary;
    cs.base.header.gas_limit = 30'000'000;
    cs.base.header.timestamp = 1001;
    cs.base.header.ommers_hash = silkworm::kEmptyListHash;
    cs.base.header.difficulty = 0;
    cs.base.header.base_fee_per_gas = protocol::expected_base_fee_per_gas(cs.genesis.header);
    cs.base.transactions.assign(txs.begin(), txs.end());
    cs.base.withdrawals = std::vector<silkworm::Withdrawal>{};
    cs.base.header.withdrawals_root = protocol::compute_withdrawals_root(cs.base);
    cs.base.header.transactions_root = protocol::compute_transaction_root(cs.base);
    return cs;
}

/// Single-transaction block: the common case.
inline ChainSetup make_chain(const bytes32& prev_root, const silkworm::Transaction& tx,
                             const evmc::address& beneficiary) {
    const std::array<silkworm::Transaction, 1> one{tx};
    return make_chain(prev_root, std::span<const silkworm::Transaction>{one}, beneficiary);
}

// ---------------------------------------------------------------------------
// Mirror of StateTransition::check_root
// ---------------------------------------------------------------------------

struct MirrorRoot {
    bytes32 root{};
    unsigned missing{~0u};
    /// True iff some address is present both in `addr_hashes()` and in
    /// `created_accounts()` — the condition `check_root` rejects with
    /// "Created and existing hashes clash".
    bool clashed{false};
    /// True iff `check_root` rejects whatever the header's state root: a storage or the account
    /// trie walk failed (`GridMPT::failed()`), or the storage walk of an unmodified account, or
    /// of the wiped storage of a deleted or recreated one, did not come back to its storage root;
    /// `root` then means nothing.
    bool rejected{false};
};

/// The distinct keys of the reads of slots the witness does not carry in the list from `head`
/// (`DirectState::absent_reads`), less those `written` holds, as `check_root` takes them.
inline std::vector<bytes32> mirror_absent_read_keys(const DirectState& ds, uint32_t head,
                                                    const silkworm::FlatHashMap<bytes32, bytes32>* written) {
    std::vector<bytes32> keys;
    for (uint32_t i = head; i != 0; i = ds.absent_reads()[i - 1].prev) {
        const bytes32& key = ds.absent_reads()[i - 1].key;
        if (written == nullptr || !written->contains(key)) keys.push_back(key);
    }
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
    return keys;
}

/// The read-only update `check_root` makes of a slot read as zero: the claim that its key is absent.
inline void mirror_absent_read(std::vector<TrieNodeFlat>& ups, const bytes32& key) {
    auto& node = ups.emplace_back(keccak_bytes32(key));
    node.buf[0] = 0x80;
    node.self_initial_len = 1;
}

/// Reproduces `check_root`'s per-account STORAGE root: a `GridMPT` ANCHORED at the record's
/// committed `storage_root`, fed one update per inline slot (its `initial`, plus its `current`
/// when the account was modified and the value actually changed), one per overflow slot and
/// one read-only claim per slot read as zero that the witness does not carry, sorted by
/// keccak(key) — same construction, same `kEmptyRoot` substitution for a fresh account, same
/// `reset()`-per-account `GridMPT`.
///
/// This is deliberately NOT `DirectState::account_storage_root`, which rebuilds the storage
/// trie FROM SCRATCH out of the slots the bundle happens to carry. The two agree only when the
/// bundle carries every slot of the account: anything the bundle omits survives inside the
/// folded node hashes the anchored walk never unfolds. Mirroring the ANCHORED version is what
/// lets a test derive the root the guest will actually compute.
///
/// `missing_out` accumulates `missing_count()` across accounts, so a storage node absent from
/// the node store surfaces in `MirrorRoot::missing` instead of hiding behind a matching root;
/// `rejected_out` is set when `check_root` rejects the walk: it failed, or it did not come back to
/// the root of an account that was not modified.
inline bytes32 mirror_storage_root(DirectState& ds, const evmc::address& addr, Account& pa,
                                   bool has_existing, bool acc_modified,
                                   GridMPT<true>& storage_trie, unsigned& missing_out,
                                   bool& rejected_out) {
    std::span<const Slot> existing_slots;
    if (has_existing && pa.slot_count > 0) {
        existing_slots = ds.slots_for(pa).first(pa.slot_count);
    }
    const auto* created_slots = ds.overflow_slots_for(addr);
    const bool has_pre_slots = !existing_slots.empty();
    const bool has_created = created_slots != nullptr && !created_slots->empty();
    const bool has_absent_reads = pa.absent_reads != 0;
    if (!has_pre_slots && !has_created && !has_absent_reads) return std::bit_cast<bytes32>(pa.storage_root);
    const std::vector<bytes32> absent_keys = mirror_absent_read_keys(ds, pa.absent_reads, created_slots);

    std::vector<TrieNodeFlat> ups;
    ups.reserve(existing_slots.size() + absent_keys.size() +
                (created_slots != nullptr ? created_slots->size() : 0));
    for (const auto& slot : existing_slots) {
        const auto& key = *reinterpret_cast<const bytes32*>(slot.key);
        auto& node = ups.emplace_back(keccak_bytes32(key));
        node.self_initial_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
            node.buf + 0, silkworm::zeroless_view(ByteView{slot.initial, 32})));
        if (acc_modified && !eq_hash32(slot.initial, slot.current)) {
            node.current_off = 40;
            node.current_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
                node.buf + 40, silkworm::zeroless_view(ByteView{slot.current, 32})));
        }
    }
    if (created_slots != nullptr) {
        for (const auto& [k, v] : *created_slots) {
            auto& node = ups.emplace_back(keccak_bytes32(k));
            node.current_off = 40;
            node.current_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
                node.buf + 40, silkworm::zeroless_view(ByteView{v.bytes, 32})));
        }
    }
    for (const auto& key : absent_keys) mirror_absent_read(ups, key);
    std::sort(ups.begin(), ups.end());  // raw-key order != keccak(key) order

    bytes32 storage_root = std::bit_cast<bytes32>(pa.storage_root);
    if (is_zero_quick(storage_root)) storage_root = silkworm::kEmptyRoot;  // new account
    storage_trie.reset(storage_root);
    const bytes32 out = storage_trie.calc_root_from_updates({ups.data(), ups.size()});
    missing_out += storage_trie.missing_count();
    rejected_out = rejected_out || storage_trie.failed() || (!acc_modified && out != storage_root);
    return out;
}

/// Reproduces `check_root`'s read-only walks of the witness slots of the accounts whose storage the
/// block wiped (`DirectState::wiped_storage`), and of their reads of slots the witness does not
/// carry, each anchored at the storage root it was read under; `rejected_out` is set when one fails
/// or does not come back to that root.
inline void mirror_wiped_storage(const DirectState& ds, GridMPT<true>& storage_trie, unsigned& missing_out,
                                 bool& rejected_out) {
    for (const WipedStorage& wiped : ds.wiped_storage()) {
        const std::vector<bytes32> absent_keys = mirror_absent_read_keys(ds, wiped.absent_reads, nullptr);
        std::vector<TrieNodeFlat> ups;
        ups.reserve(wiped.slots.size() + absent_keys.size());
        for (const auto& slot : wiped.slots) {
            const auto& key = *reinterpret_cast<const bytes32*>(slot.key);
            auto& node = ups.emplace_back(keccak_bytes32(key));
            node.self_initial_len = static_cast<uint8_t>(silkworm::rlp::encode_into_small(
                node.buf + 0, silkworm::zeroless_view(ByteView{slot.initial, 32})));
        }
        for (const auto& key : absent_keys) mirror_absent_read(ups, key);
        std::sort(ups.begin(), ups.end());
        storage_trie.reset(wiped.storage_root);
        const bytes32 out = storage_trie.calc_root_from_updates({ups.data(), ups.size()});
        missing_out += storage_trie.missing_count();
        rejected_out = rejected_out || storage_trie.failed() || out != wiped.storage_root;
    }
}

/// Recomputes the account root exactly the way `StateTransition::check_root` does,
/// with the single difference that a created/existing hash clash, or a trie walk `check_root`
/// rejects (`rejected`), is recorded instead of aborting. Update-for-update faithful: same
/// merge order over the two sorted sequences, same `ext_initial` (the record's own
/// `acc_rlp_buf`), same read-only elision (`current_len == 0` when `!pa->modified`), same
/// `0x80` deletion marker, same read-only claim of absence for the deleted record of an address
/// the witness does not carry, anchored at the same `prev_root`. `missing` is
/// `GridMPT::missing_count()` summed over the account trie and every per-account storage trie,
/// and must be 0 for the derived root to mean anything.
///
/// Storage roots come from `mirror_storage_root`, i.e. the anchored per-account storage
/// `GridMPT` — computed for every non-deleted account with slots even when the account is
/// read-only, exactly as `check_root` does, so the node lookups counted in `missing` are the
/// ones the guest performs. The read-only walks of wiped storage (`mirror_wiped_storage`) come
/// first, as in `check_root`.
inline MirrorRoot mirror_check_root(DirectState& ds, const bytes32& prev_root) {
    struct Created {
        bytes32 addr_hash;
        evmc::address addr;
    };
    std::vector<Created> created;
    created.reserve(ds.created_accounts().size());
    for (const auto& [addr, _] : ds.created_accounts()) {
        created.push_back(Created{keccak_addr32(addr), addr});
    }
    std::sort(created.begin(), created.end(), [](const Created& x, const Created& y) {
        return std::memcmp(x.addr_hash.bytes, y.addr_hash.bytes, 32) < 0;
    });

    MirrorRoot out{};
    out.missing = 0;
    std::vector<TrieNodeFlat> ups;
    ups.reserve(ds.addr_hashes().size() + created.size());

    // One instance hoisted out of the walk and `reset()` per account, as check_root does.
    GridMPT<true> storage_trie{ds, silkworm::kEmptyRoot};

    // Before the merge, exactly as in check_root.
    mirror_wiped_storage(ds, storage_trie, out.missing, out.rejected);

    auto it_ex = ds.addr_hashes().begin();
    const auto end_ex = ds.addr_hashes().end();
    std::size_t it_cr = 0;

    while (it_ex != end_ex || it_cr < created.size()) {
        int cur_cmp = 0;
        if (it_ex != end_ex && it_cr < created.size()) {
            cur_cmp = std::memcmp(it_ex->addr_hash, created[it_cr].addr_hash.bytes, 32);
            if (cur_cmp == 0) out.clashed = true;  // check_root returns false right here
        }
        const bool has_existing = it_cr >= created.size() ? true
                                  : it_ex == end_ex      ? false
                                                         : cur_cmp < 0;
        const evmc::address addr = has_existing
                                       ? *reinterpret_cast<const evmc::address*>(it_ex->addr)
                                       : created[it_cr].addr;

        const Account* rec = has_existing ? ds.account_at_offset(it_ex->entry_offset)
                                          : ds.find_created_account(addr);
        if (rec->deleted) {
            if (has_existing) {
                auto& node = ups.emplace_back(std::bit_cast<bytes32>(it_ex->addr_hash));
                node.ext_initial = ByteView{rec->acc_rlp_buf, rec->acc_rlp_len};
                node.buf[0] = 0x80;  // leaf deletion marker
                node.current_off = 0;
                node.current_len = 1;
                ++it_ex;
            } else {
                ups.emplace_back(created[it_cr].addr_hash);  // read-only: the claim that the key is absent
                ++it_cr;
            }
            continue;
        }

        Account* pa = has_existing ? ds.account_at_offset(it_ex->entry_offset)
                                   : ds.find_created_account(addr);
        const bool acc_modified = has_existing ? pa->modified : true;

        // Before the account update is emplaced, exactly as in check_root.
        const bytes32 storage_root = mirror_storage_root(ds, addr, *pa, has_existing, acc_modified,
                                                        storage_trie, out.missing, out.rejected);

        bool readonly = false;
        if (has_existing) {
            auto& node = ups.emplace_back(std::bit_cast<bytes32>(it_ex->addr_hash));
            node.ext_initial = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
            readonly = !acc_modified;
            ++it_ex;
        } else {
            ups.emplace_back(created[it_cr].addr_hash);
            ++it_cr;
        }
        if (!readonly) {
            auto& inserted = ups.back();
            inserted.current_off = 0;
            inserted.current_len = pa->rlp_into(inserted.buf + 0, storage_root);
        }
    }

    GridMPT<true> acc_trie{ds, prev_root};
    out.root = acc_trie.calc_root_from_updates({ups.data(), ups.size()});
    out.missing += acc_trie.missing_count();
    out.rejected = out.rejected || acc_trie.failed();
    return out;
}

// ---------------------------------------------------------------------------
// Shadow execution (block production)
// ---------------------------------------------------------------------------

/// A completed shadow run: owns its own copies of the witness bytes so the bundle handed
/// to the guest stays byte-identical to what the test authored, and keeps the resulting
/// `DirectState` alive for post-mortem reads (`read_storage`, `created_accounts`, ...).
struct ShadowRun {
    std::vector<uint8_t> blob;
    std::vector<uint8_t> nodestore;
    std::unique_ptr<DirectState> ds;

    bool sanitize_ok{false};
    uint64_t gas_used{};
    evmc::bytes32 receipts_root{};
    silkworm::Bloom logs_bloom{};
    /// One receipt per transaction, in block order.
    std::vector<silkworm::Receipt> receipts{};
    /// The last receipt, i.e. the one carrying the block's cumulative gas.
    silkworm::Receipt receipt{};
    MirrorRoot post{};

    /// True iff every transaction in the block succeeded.
    bool all_succeeded() const {
        for (const auto& rc : receipts) {
            if (!rc.success) return false;
        }
        return !receipts.empty();
    }

    evmc::bytes32 storage(const evmc::address& a, uint64_t slot) const {
        evmc::bytes32 key{};
        intx::be::store(key.bytes, intx::uint256{slot});
        return ds->read_storage(a, key);
    }
};

/// Runs `tx` against a private copy of the witness exactly as the guest would: sanitize
/// the bytes as handed over, execute, then derive the header commitments a producer
/// would publish (gas used, receipts root, logs bloom) and the post-state root
/// (`mirror_check_root`).
///
/// `provisional` supplies the block context (number, timestamp, base fee, beneficiary,
/// gas limit); its gas_used/roots are irrelevant here.
inline ShadowRun shadow_execute(const std::vector<uint8_t>& blob_in,
                                const std::vector<uint8_t>& nodestore_in,
                                const bytes32& prev_root,
                                const silkworm::BlockHeader& provisional,
                                std::span<const silkworm::Transaction> txs,
                                const silkworm::ChainConfig& cfg = silkworm::test::kShanghaiConfig) {
    ShadowRun r{};
    r.blob = blob_in;
    r.nodestore = nodestore_in;
    r.ds = std::make_unique<DirectState>(std::span<uint8_t>{r.blob}, std::span<uint8_t>{r.nodestore});
    r.sanitize_ok = r.ds->sanitize();
    if (!r.sanitize_ok) return r;

    silkworm::Block block{};
    block.header = provisional;
    block.transactions.assign(txs.begin(), txs.end());
    block.withdrawals = std::vector<silkworm::Withdrawal>{};

    auto rule_set = silkworm::protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rule_set, *r.ds, cfg};
    // One receipt per transaction, executed in block order against the same state:
    // `cumulative_gas_used` accumulates inside the processor, so the last receipt
    // carries the block's gas figure.
    r.receipts.resize(block.transactions.size());
    for (std::size_t i = 0; i < block.transactions.size(); ++i) {
        // Bypasses pre-validation, so publish what it would have computed.
        const auto& t = block.transactions[i];
        t.set_data_non_zero_bytes(zilkworm::count_nonzero_bytes(t.data));
        proc.execute_transaction(t, r.receipts[i]);
    }
    r.receipt = r.receipts.back();

    r.gas_used = r.receipt.cumulative_gas_used;
    static constexpr auto kEncoder = [](Bytes& to, const silkworm::Receipt& rc) {
        silkworm::rlp::encode(to, rc);
    };
    r.receipts_root = silkworm::trie::root_hash(r.receipts, kEncoder);
    r.logs_bloom = silkworm::Bloom{};
    for (const auto& rc : r.receipts) {
        silkworm::join(r.logs_bloom, rc.bloom);
    }
    r.post = mirror_check_root(*r.ds, prev_root);
    return r;
}

/// Single-transaction block: the common case.
inline ShadowRun shadow_execute(const std::vector<uint8_t>& blob_in,
                                const std::vector<uint8_t>& nodestore_in,
                                const bytes32& prev_root,
                                const silkworm::BlockHeader& provisional,
                                const silkworm::Transaction& tx,
                                const silkworm::ChainConfig& cfg = silkworm::test::kShanghaiConfig) {
    const std::array<silkworm::Transaction, 1> one{tx};
    return shadow_execute(blob_in, nodestore_in, prev_root, provisional,
                          std::span<const silkworm::Transaction>{one}, cfg);
}

// ---------------------------------------------------------------------------
// MFBD envelope
// ---------------------------------------------------------------------------

/// 16-byte MFBD envelope header (magic, version, n=1) followed by one flat bundle.
inline std::vector<uint8_t> wrap_mfbd(const std::vector<uint8_t>& flat_bundle) {
    std::vector<uint8_t> env(kInputHeaderSizeMFBD, 0);
    const uint32_t magic = kInputMagicMFBD;
    const uint32_t version = kInputVersionMFBD;
    const uint64_t n = 1;
    std::memcpy(env.data() + 0, &magic, 4);
    std::memcpy(env.data() + 4, &version, 4);
    std::memcpy(env.data() + 8, &n, 8);
    env.insert(env.end(), flat_bundle.begin(), flat_bundle.end());
    return env;
}

/// Seals `chain` + `witness` into a single-block MFBD envelope, committing the four
/// post-execution header fields learned from `sr`. This is the block a producer would
/// publish for the execution `sr` observed — honest or spoofed.
inline std::vector<uint8_t> make_envelope(const ChainSetup& chain, const ShadowRun& sr,
                                          const std::vector<uint8_t>& blob,
                                          const std::vector<uint8_t>& nodestore,
                                          const char* network = "Shanghai") {
    silkworm::Block b = chain.base;
    b.header.gas_used = sr.gas_used;
    b.header.receipts_root = sr.receipts_root;
    b.header.logs_bloom = sr.logs_bloom;
    b.header.state_root = sr.post.root;
    Bytes brlp;
    silkworm::rlp::encode(brlp, b);
    const std::array<ByteView, 1> brlps{ByteView{brlp.data(), brlp.size()}};
    std::vector<uint8_t> flat = build_flat_bundle(
        ByteView{chain.genesis_rlp.data(), chain.genesis_rlp.size()},
        std::span<const ByteView>{brlps},
        /*ancestors_rlp=*/ByteView{}, blob, nodestore, network);
    if (flat.empty()) return {};
    return wrap_mfbd(flat);
}

// ---------------------------------------------------------------------------
// Forgery primitives
// ---------------------------------------------------------------------------

/// Transposes the MPHF `slot_offsets` entries of `a` and `b` in the serialized
/// pre-state, at rest — a producer-controllable layout field. Afterwards `find(a)`
/// lands on `b`'s body (20-byte key mismatch -> miss) and vice versa, while BOTH bodies
/// remain reachable from `for_each`, so `sanitize()` still resolves code offsets, refills
/// both RLP caches with genuine values and its modified-flag parity still balances.
/// Requires `addr_key8(a) != addr_key8(b)` (each must own a slot).
inline void forge_slot_transposition(std::vector<uint8_t>& blob, const evmc::address& a,
                                     const evmc::address& b) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    auto* slots = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mh) + mh->slot_offsets_offset);
    std::swap(slots[mh->index_lookup(addr_key8(a))], slots[mh->index_lookup(addr_key8(b))]);
}

// ---------------------------------------------------------------------------
// stdout capture (sys_println writes to std::cout on the host)
// ---------------------------------------------------------------------------

/// Redirects `std::cout` for its lifetime so a test can assert WHICH guest-side check
/// fired. Keep the scope tight: Catch2 also writes to std::cout.
class StdoutCapture {
  public:
    StdoutCapture() : prev_{std::cout.rdbuf(buf_.rdbuf())} {}
    ~StdoutCapture() { std::cout.rdbuf(prev_); }
    StdoutCapture(const StdoutCapture&) = delete;
    StdoutCapture& operator=(const StdoutCapture&) = delete;

    std::string str() const { return buf_.str(); }

  private:
    std::ostringstream buf_;
    std::streambuf* prev_;
};

// ---------------------------------------------------------------------------
// Small EVM bytecode helpers
// ---------------------------------------------------------------------------

/// PUSH1 <v>
inline void push1(Bytes& code, uint8_t v) {
    code.push_back(0x60);
    code.push_back(v);
}

/// PUSH20 <addr>
inline void push20(Bytes& code, const evmc::address& a) {
    code.push_back(0x73);
    code.insert(code.end(), a.bytes, a.bytes + 20);
}

/// `PUSH1 1; PUSH1 1; SSTORE; STOP` — writes the sentinel `storage[1] = 1` that proves
/// the probe body actually ran, then halts. Append after storing the observation, so a
/// zero-valued observation in `storage[0]` is still distinguishable from "nothing ran".
inline void append_sentinel_and_stop(Bytes& code) {
    push1(code, 0x01);  // value
    push1(code, 0x01);  // key
    code.push_back(0x55);  // SSTORE
    code.push_back(0x00);  // STOP
}

/// `PUSH1 0; SSTORE` — stores the value on top of the stack into `storage[0]`.
inline void store_observation(Bytes& code) {
    push1(code, 0x00);     // key
    code.push_back(0x55);  // SSTORE
}

}  // namespace zilkworm::test_util
