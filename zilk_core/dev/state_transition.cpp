// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <cassert>
#include <cstring>
#include <format>
#include <fstream>
#include <memory>
#include <new>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <magic_enum/magic_enum.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/inline_vec.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/print.hpp>

namespace silkworm::cmd::state_transition {

using silkworm::protocol::Blockchain;
using silkworm::protocol::kMaxRlpBlockSize;

StateTransition::StateTransition(std::span<uint8_t> envelope) noexcept
    : envelope_{envelope} {
}

std::pair<uint64_t, bool> StateTransition::run_one_bundle(::zilkworm::FlatBundle& bundle) {
#ifdef Z6M_HASH_STATE
    // The MFBD flat-bundle path is DirectState-only: FlatBundle::direct is a DirectState and
    // Blockchain binds ActiveState==HashState under the flag, so this arm cannot execute. It
    // is disabled under Z6M_HASH_STATE (the slib path runs through blockchain_test's slib arm,
    // S6); reject fail-closed.
    (void)bundle;
    sys_println("ERROR: flat-bundle (MFBD) path disabled under Z6M_HASH_STATE");
    failed_ = true;
    return {0, false};
#else
    if (!bundle.direct.sanitize()) {
        sys_println("ERROR: Witness sanitize failed (identity↔hash mismatch)");
        failed_ = true;
        return {0, false};
    }
    for (const auto& h : bundle.ancestors) {
        bundle.direct.insert_header(h);
    }

    const auto cfg_it = test::kNetworkConfig.find(std::string{bundle.network});
    if (cfg_it == test::kNetworkConfig.end()) [[unlikely]] {
        sys_println("ERROR: unknown network in flat bundle");
        failed_ = true;
        return {0, false};
    }
    chain_id_ = cfg_it->second.chain_id;
    bundle.direct.set_multi_block(bundle.block_rlps.size() > 1);
    Blockchain blockchain{bundle.direct, cfg_it->second, bundle.genesis};
    uint64_t cumulative_gas = 0;
    bool first_root_check = true;
    for (size_t i = 0; i < bundle.block_rlps.size(); ++i) {
        const bool expect_invalid =
            i < bundle.block_flags.size() &&
            (bundle.block_flags[i] & ::zilkworm::kBlockFlagExpectInvalid);
        Block block;
        ByteView view{bundle.block_rlps[i]};
        if (!rlp::decode(view, block).has_value()) {
            if (expect_invalid) {
                sys_println(std::format("block {} rejected as expected: decode", i));
                continue;
            }
            sys_println(std::format("ERROR: block {} RLP decode failed", i));
            failed_ = true;
            return {0, false};
        }
        // Only after decode: the fork gate needs the block's number/timestamp.
        if (bundle.block_rlps[i].size() > kMaxRlpBlockSize && cfg_it->second.revision(block.header.number, block.header.timestamp) >= EVMC_OSAKA) {
            if (expect_invalid) {
                sys_println(std::format("block {} rejected as expected: size", i));
                continue;
            } else {
                sys_println(std::format("ERROR: block {} RLP size exceeds kMaxRlpBlockSize", i));
                failed_ = true;
                return {0, false};
            }
        }

        if (ValidationResult err{blockchain.insert_block(block, false)}; err != ValidationResult::kOk) {
            if (expect_invalid) {
                sys_println(std::format("block {} rejected as expected: {}",
                                        i, magic_enum::enum_name(err)));
                continue;
            }
            sys_println(std::format("ERROR: validation error at block {}: {} ({})",
                                    i, magic_enum::enum_name(err), magic_enum::enum_integer(err)));
            failed_ = true;
            return {0, false};
        }
        if (expect_invalid) {
            sys_println(std::format("ERROR: expected-invalid block {} was accepted", i));
            failed_ = true;
            return {0, false};
        }
        const evmc_revision rev = cfg_it->second.revision(block.header.number, block.header.timestamp);
        const bool root_ok = first_root_check
                                 ? check_root(bundle.direct, block.header, rev)
                                 : check_root_new_block(bundle.direct, block.header, rev);
        first_root_check = false;
        if (!root_ok) {
            sys_println(std::format("ERROR: State Root Mismatch at block {}: expected {}",
                                    i, to_hex(block.header.state_root)));
            failed_ = true;
            return {0, false};
        }
        // Last validated block in the run is the committed post-state root / block hash.
        post_state_root_ = block.header.state_root;
        block_hash_ = block.header.hash();
        bundle.direct.insert_header(block.header);
        cumulative_gas += block.header.gas_used;
    }
    return {cumulative_gas, true};
#endif  // Z6M_HASH_STATE
}

bool StateTransition::check_root(DirectState& direct_state, BlockHeader& header,
                                 evmc_revision rev) {
    const bool clear_empty = rev >= EVMC_SPURIOUS_DRAGON;
    std::vector<zilkworm::AddrHashEntry> created_acc_hashes_spill;  // to be used with InlineVec additional cache area
    zilkworm::InlineVec<zilkworm::AddrHashEntry, 32> created_acc_hashes(
        direct_state.created_accounts().size(), created_acc_hashes_spill);
    for (auto& [addr, _] : direct_state.created_accounts()) {
        auto& e = created_acc_hashes.emplace_back();
        std::memcpy(e.addr_hash, keccak_bytes(addr.bytes).bytes, 32);
        std::memcpy(e.addr, addr.bytes, 20);
    }
    if (created_acc_hashes.size() > 1) [[likely]] {
        auto* const data = created_acc_hashes.data();
        const std::size_t n = created_acc_hashes.size();
        if (n <= 16) [[likely]] {
            for (std::size_t i = 1; i < n; ++i) {
                zilkworm::AddrHashEntry key = std::move(data[i]);
                std::size_t j = i;
                while (j > 0 && key < data[j - 1]) {
                    data[j] = std::move(data[j - 1]);
                    --j;
                }
                data[j] = std::move(key);
            }
        } else {
            std::sort(data, data + n);
        }
    }

    std::vector<mpt::TrieNodeFlat> acc_updates;
    acc_updates.reserve(direct_state.addr_hashes().size() + created_acc_hashes.size());

    auto it_existing_hashes = direct_state.addr_hashes().begin();
    auto end_it_existing = direct_state.addr_hashes().end();
    auto it_created_hashes = created_acc_hashes.begin();
    auto end_created_hashes = created_acc_hashes.end();

    std::vector<mpt::TrieNodeFlat> storage_spill;

    zilkworm::GridMPT<true, DirectState> storage_trie{direct_state, kEmptyRoot};

    while (it_existing_hashes != end_it_existing || it_created_hashes != end_created_hashes) {
        // Blob and created addr sets should be disjoint.
        int cur_cmp = 0;
        if (it_existing_hashes != end_it_existing && it_created_hashes != end_created_hashes) {
            cur_cmp = std::memcmp(it_existing_hashes->addr_hash, it_created_hashes->addr_hash, 32);
            if (cur_cmp == 0) [[unlikely]] {
                sys_println("Created and existing hashes clash");
                return false;
            }
        }
        const bool has_existing =
            it_created_hashes == end_created_hashes ? true
            : it_existing_hashes == end_it_existing ? false
                                                    : cur_cmp < 0;
        const auto& addr = *reinterpret_cast<const evmc::address*>(
            has_existing ? it_existing_hashes->addr : it_created_hashes->addr);

        {
            const Account* rec = has_existing
                                     ? direct_state.account_at_offset(it_existing_hashes->entry_offset)
                                     : direct_state.find_created_account(addr);
            if (rec->deleted) [[unlikely]] {
                if (has_existing) {
                    // 0x80 current value signals leaf deletion.
                    auto& node = acc_updates.emplace_back(
                        std::bit_cast<bytes32>(it_existing_hashes->addr_hash));
                    node.ext_initial = ByteView{rec->acc_rlp_buf, rec->acc_rlp_len};
                    node.buf[0] = 0x80;
                    node.current_off = 0;
                    node.current_len = 1;
                    ++it_existing_hashes;
                } else {
                    // Created-then-destructed: no pre-trie leaf.
                    ++it_created_hashes;
                }
                continue;
            }
        }

        Account* pa = has_existing
                          ? direct_state.account_at_offset(it_existing_hashes->entry_offset)
                          : direct_state.find_created_account(addr);

        // Readonly accounts: pa.modified=false guarantees initial==current.
        const bool acc_modified = has_existing ? pa->modified : true;

        std::span<const zilkworm::Slot> existing_slots;
        if (has_existing && pa->slot_count > 0) {
            existing_slots = direct_state.slots_for(*pa).first(pa->slot_count);
        }
        const auto* created_slots = direct_state.overflow_slots_for(addr);
#if USE_HASH_KEY
        const auto* rec_slots = direct_state.recovered_slots_for(addr);
        std::size_t rec_count = 0;  // found entries only; negatives are skipped
        if (rec_slots != nullptr) {
            for (const auto& kv : *rec_slots) rec_count += kv.second.found ? 1u : 0u;
        }
#endif

        // Walk pre-state slots even with no SSTORE: binds slot.initial to keccak(key) under pa->storage_root.
        const bool has_pre_slots = !existing_slots.empty();
        const bool has_created = (created_slots != nullptr && !created_slots->empty());
        bytes32 storage_root;
#if USE_HASH_KEY
        if (has_pre_slots || has_created || rec_count > 0) {
#else
        if (has_pre_slots || has_created) {
#endif
            storage_root = std::bit_cast<bytes32>(pa->storage_root);
#if USE_HASH_KEY
            const std::size_t need = existing_slots.size() + rec_count +
                                     (created_slots != nullptr ? created_slots->size() : 0);
#else
            const std::size_t need = existing_slots.size() + (created_slots != nullptr
                                                                  ? created_slots->size()
                                                                  : 0);
#endif
            zilkworm::InlineVec<mpt::TrieNodeFlat, 32> storage_updates(need, storage_spill);
            for (const auto& slot : existing_slots) {
                const auto& key = *reinterpret_cast<const bytes32*>(slot.key);
                auto& node = storage_updates.emplace_back(keccak_bytes32(key));
                node.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
                    node.buf + 0, zeroless_view(ByteView{slot.initial, 32})));
                if (acc_modified && !zilkworm::eq_hash32(slot.initial, slot.current)) [[unlikely]] {
                    node.current_off = 40;
                    node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 40, zeroless_view(ByteView{slot.current, 32})));
                }
            }
            if (created_slots != nullptr) {
                for (const auto& [k, v] : *created_slots) {
                    auto& node = storage_updates.emplace_back(keccak_bytes32(k));
                    node.current_off = 40;
                    node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 40, zeroless_view(ByteView{v.bytes, 32})));
                }
            }
#if USE_HASH_KEY
            if (rec_slots != nullptr) {
                for (const auto& [k, rs] : *rec_slots) {
                    if (!rs.found) continue;
                    auto& node = storage_updates.emplace_back(keccak_bytes32(k));
                    node.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 0, zeroless_view(ByteView{rs.initial.bytes, 32})));
                    if (acc_modified && !::zilkworm::eq_hash32(rs.initial.bytes, rs.current.bytes)) [[unlikely]] {
                        node.current_off = 40;
                        node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                            node.buf + 40, zeroless_view(ByteView{rs.current.bytes, 32})));
                    }
                }
            }
#endif
            // Raw-key order != keccak(key) order; sort required.
            if (storage_updates.size() > 1) [[likely]] {
                auto* const data = storage_updates.data();
                const std::size_t n = storage_updates.size();
                if (n <= 16) [[likely]] {
                    for (std::size_t i = 1; i < n; ++i) {
                        mpt::TrieNodeFlat key = std::move(data[i]);
                        std::size_t j = i;
                        while (j > 0 && key < data[j - 1]) {
                            data[j] = std::move(data[j - 1]);
                            --j;
                        }
                        data[j] = std::move(key);
                    }
                } else {
                    std::sort(data, data + n);
                }
            }
            if (mpt::is_zero_quick(storage_root)) {  // new account
                storage_root = kEmptyRoot;
            }
            storage_trie.reset(storage_root);
            storage_root = storage_trie.calc_root_from_updates(
                {storage_updates.data(), storage_updates.size()});
            assert(!storage_trie.failed());  // debug-only: in release caught by root compare below
        }

        bool readonly = false;
        if (has_existing) {
            auto& node = acc_updates.emplace_back(
                std::bit_cast<bytes32>(it_existing_hashes->addr_hash));
            node.ext_initial = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
            readonly = !acc_modified;
            ++it_existing_hashes;
        } else {
            acc_updates.emplace_back(std::bit_cast<bytes32>(it_created_hashes->addr_hash));
            ++it_created_hashes;
        }

        if (!readonly) {
#if USE_HASH_KEY
            if (!has_pre_slots && !has_created && rec_count == 0) {
#else
            if (!has_pre_slots && !has_created) {
#endif
                storage_root = std::bit_cast<bytes32>(pa->storage_root);
            }
            auto& inserted = acc_updates.back();
            inserted.current_off = 0;
            inserted.current_len = pa->rlp_into(inserted.buf + 0, storage_root);
        }
    }

#if USE_HASH_KEY
    // Witness-bug fallback: emit recovered accounts (absent from addr_hashes) as updates — pre-state snapshot as initial, post-state as current when modified.
    if (!direct_state.recovered_accounts().empty()) {
        for (const auto& up : direct_state.recovered_accounts()) {
            const Account* pa = up.get();
            const evmc::address addr = *reinterpret_cast<const evmc::address*>(pa->addr);
            auto& node = acc_updates.emplace_back(keccak_bytes(addr.bytes));
            node.ext_initial = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
            // Emptiness from the copy: is_empty_account(addr) could recover more accounts while we iterate.
            uint8_t bal_or = 0;
            for (size_t bi = 0; bi < sizeof(pa->balance); ++bi) bal_or |= pa->balance[bi];
            const bool is_empty = pa->nonce == 0 && bal_or == 0 &&
                                  ::zilkworm::eq_hash32(pa->code_hash, silkworm::kEmptyHash.bytes);
            if (pa->deleted || (clear_empty && pa->modified && is_empty)) {
                // 0x80 current value signals leaf deletion.
                node.buf[0] = 0x80;
                node.current_off = 0;
                node.current_len = 1;
            } else if (pa->modified) {
                bytes32 storage_root = std::bit_cast<bytes32>(pa->storage_root);
                if (mpt::is_zero_quick(storage_root)) {
                    storage_root = kEmptyRoot;
                }
                const auto* created_slots = direct_state.overflow_slots_for(addr);
                const auto* rec_slots = direct_state.recovered_slots_for(addr);
                const std::size_t created_count =
                    created_slots != nullptr ? created_slots->size() : 0;
                std::size_t rec_count = 0;
                if (rec_slots != nullptr) {
                    for (const auto& kv : *rec_slots) rec_count += kv.second.found ? 1u : 0u;
                }
                if (created_count + rec_count > 0) {
                    zilkworm::InlineVec<mpt::TrieNodeFlat, 32> storage_updates(
                        created_count + rec_count, storage_spill);
                    if (created_slots != nullptr) {
                        for (const auto& [k, v] : *created_slots) {
                            auto& sn = storage_updates.emplace_back(keccak_bytes32(k));
                            sn.current_off = 40;
                            sn.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                                sn.buf + 40, zeroless_view(ByteView{v.bytes, 32})));
                        }
                    }
                    if (rec_slots != nullptr) {
                        for (const auto& [k, rs] : *rec_slots) {
                            if (!rs.found) continue;
                            auto& sn = storage_updates.emplace_back(keccak_bytes32(k));
                            sn.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
                                sn.buf + 0, zeroless_view(ByteView{rs.initial.bytes, 32})));
                            if (!::zilkworm::eq_hash32(rs.initial.bytes, rs.current.bytes)) {
                                sn.current_off = 40;
                                sn.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                                    sn.buf + 40, zeroless_view(ByteView{rs.current.bytes, 32})));
                            }
                        }
                    }
                    std::sort(storage_updates.data(),
                              storage_updates.data() + storage_updates.size());
                    storage_trie.reset(storage_root);
                    storage_root = storage_trie.calc_root_from_updates(
                        {storage_updates.data(), storage_updates.size()});
                }
                node.current_off = 0;
                node.current_len = pa->rlp_into(node.buf + 0, storage_root);
            }
            // else: unmodified — read-only anchor (initial only).
        }
        std::sort(acc_updates.begin(), acc_updates.end());
    }
#endif

    // acc_updates already sorted: merge of two sorted hash sequences.
    auto prev_root = direct_state.read_header(header.number - 1, header.parent_hash)->state_root;
    // First check_root in the run anchors the whole transition: commit it as the pre-state root in the guest public values.
    if (!pre_root_set_) {
        pre_state_root_ = prev_root;
        pre_root_set_ = true;
    }
    zilkworm::GridMPT<true, DirectState> acc_trie(direct_state, prev_root);
    auto new_root = acc_trie.calc_root_from_updates({acc_updates.data(), acc_updates.size()});
    assert(!acc_trie.failed());  // debug-only: in release caught by root compare below
    sys_println(std::format("New Root: {}", to_hex(new_root)));
    const bool ok = (new_root == header.state_root);
    for (const auto& addr : direct_state.changed_addresses_journal()) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        Account* pa = direct_state.read_account(addr);
        if (pa == nullptr) continue;
        const auto storage_root = direct_state.account_storage_root(addr);
        pa->rlp_into_cache(storage_root);
    }
    direct_state.clear_change_journal();
    return ok;
}

bool StateTransition::check_root_new_block(DirectState& direct_state,
                                           BlockHeader& header,
                                           evmc_revision rev) {
    const bool clear_empty = rev >= EVMC_SPURIOUS_DRAGON;
    const auto& changed = direct_state.changed_addresses_journal();
    for (const auto& addr : changed) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        Account* pa = direct_state.read_account(addr);
        if (pa == nullptr) [[unlikely]] {
            sys_println("ERROR: check_root_new_block journaled addr resolves to nullptr");
            direct_state.clear_change_journal();
            return false;
        }
        const auto storage_root = direct_state.account_storage_root(addr);
        pa->rlp_into_cache(storage_root);
    }

    struct LeafRef {
        bytes32 addr_hash;
        ByteView rlp;
    };
    std::vector<LeafRef> leaves;
    leaves.reserve(direct_state.addr_hashes().size() + direct_state.created_accounts().size());

    for (const auto& e : direct_state.addr_hashes()) {
        const auto& addr = *reinterpret_cast<const evmc::address*>(e.addr);
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        const Account* pa = direct_state.account_at_offset(e.entry_offset);
        LeafRef r;
        std::memcpy(r.addr_hash.bytes, e.addr_hash, 32);
        r.rlp = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
        leaves.push_back(r);
    }
    for (const auto& [addr, pa] : direct_state.created_accounts()) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        LeafRef r;
        const auto h = silkworm::keccak256(ByteView{addr.bytes, 20});
        std::memcpy(r.addr_hash.bytes, h.bytes, 32);
        r.rlp = ByteView{pa.acc_rlp_buf, pa.acc_rlp_len};
        leaves.push_back(r);
    }
    std::sort(leaves.begin(), leaves.end(),
              [](const LeafRef& a, const LeafRef& b) {
                  return std::memcmp(a.addr_hash.bytes, b.addr_hash.bytes, 32) < 0;
              });

    silkworm::trie::HashBuilder hb;
    for (const auto& r : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{r.addr_hash.bytes, 32}),
                    r.rlp);
    }
    const auto new_root = leaves.empty() ? kEmptyRoot : hb.root_hash();
    sys_println(std::format("New Root (incremental): {}", to_hex(new_root)));
    const bool ok = (new_root == header.state_root);
    direct_state.clear_change_journal();
    return ok;
}

StateTransition::Result StateTransition::run() {
    uint64_t gas = kRunFailure;
    if (envelope_.size() < 4) [[unlikely]] {
        sys_println("ERROR: input envelope too small for magic");
        failed_ = true;
    } else {
        uint32_t magic = 0;
        std::memcpy(&magic, envelope_.data(), sizeof(uint32_t));
        switch (magic) {
            case ::zilkworm::kInputMagicEJSN:
                gas = run_ejsn();
                break;
            case ::zilkworm::kInputMagicMFBD:
                gas = run_mfbd();
                break;
            default:
                // TODO: detect and dispatch a raw StatelessInput blob (schema_id 0x1501) here.
                // See docs/hashstate.md, "Raw StatelessInput dispatch".
                sys_println("ERROR: unsupported input magic");
                failed_ = true;
                break;
        }
    }
    return Result{
        .gas_used = gas,
        .pre_state_root = pre_state_root_,
        .post_state_root = post_state_root_,
        .block_hash = block_hash_,
        .chain_id = chain_id_,
    };
}

uint64_t StateTransition::run_mfbd() {
#ifdef Z6M_HASH_STATE
    // MFBD is the DirectState flat-bundle path (see run_one_bundle); disabled under the
    // HashState build. Reject early rather than parse bundles that cannot execute.
    sys_println("ERROR: MFBD path disabled under Z6M_HASH_STATE");
    failed_ = true;
    return kRunFailure;
#else
    auto align8 = [](size_t v) noexcept { return (v + 7u) & ~size_t{7u}; };

    if (envelope_.size() < ::zilkworm::kInputHeaderSizeMFBD) [[unlikely]] {
        sys_println("ERROR: MFBD envelope too small");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t version = 0;
    std::memcpy(&version, envelope_.data() + 4, sizeof(uint32_t));
    if (version != ::zilkworm::kInputVersionMFBD) [[unlikely]] {
        sys_println("ERROR: MFBD envelope bad version");
        failed_ = true;
        return kRunFailure;
    }
    uint64_t n_bundles = 0;
    std::memcpy(&n_bundles, envelope_.data() + 8, sizeof(uint64_t));

    const std::size_t end = envelope_.size();
    std::size_t cursor = ::zilkworm::kInputHeaderSizeMFBD;
    uint64_t cumulative_gas = 0;

    for (uint64_t i = 0; i < n_bundles; ++i) {
        std::span<uint8_t> tail{envelope_.data() + cursor, end - cursor};
        auto fb = ::zilkworm::load_flat_bundle(tail);
        if (!fb) [[unlikely]] {
            sys_println("ERROR: MFBD bundle parse failed");
            failed_ = true;
            return kRunFailure;
        }
        auto [gas, ok] = run_one_bundle(*fb);
        if (!ok) [[unlikely]] {
            failed_ = true;
            return kRunFailure;
        }
        cumulative_gas += gas;
        cursor = align8(cursor + fb->blob.size());
    }
    if (n_bundles == 0)
        return kRunSkipped;
    return cumulative_gas;
#endif  // Z6M_HASH_STATE
}

}  // namespace silkworm::cmd::state_transition
