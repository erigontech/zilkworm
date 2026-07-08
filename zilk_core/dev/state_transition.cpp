// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <cstring>
#include <format>
#include <fstream>
#include <memory>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>
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

StateTransition::StateTransition(std::span<uint8_t> envelope) noexcept
    : envelope_{envelope} {
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        out = hex_to_address(address);
    }

    return out;
}

std::unique_ptr<evmc::address> StateTransition::sender_to_address(const std::string& sender) {
    return std::make_unique<evmc::address>(hex_to_address(sender));
}

namespace {
    using namespace silkworm::protocol;
    enum class Status {
        kPassed,
        kFailed,
        kSkipped
    };

    Status run_json_block(const nlohmann::json& json_block, Blockchain& blockchain, DirectState& direct) {
        bool invalid{json_block.contains("expectException")};
        std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
        if (!rlp) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println("Failure to read hex");
            return Status::kFailed;
        }

        Block block;
        ByteView view{*rlp};
        if (!rlp::decode(view, block)) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println("Failure to decode RLP");
            return Status::kFailed;
        }
        // Only after decode: the fork gate needs the block's number/timestamp.
        if (rlp->size() > kMaxRlpBlockSize && blockchain.config().revision(block.header.number, block.header.timestamp) >= EVMC_OSAKA) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println("Block exceeded kMaxRlpBlockSize");
            return Status::kFailed;
        }

        const bool check_state_root{true};
        if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
            if (invalid) {
                return Status::kPassed;
            }
            (void)err;
            sys_println("ERROR: validation error");
            return Status::kFailed;
        }

        if (invalid) {
            sys_println("Invalid block executed successfully");
            sys_println("ERROR: expected exception");
            return Status::kFailed;
        }

        direct.insert_header(block.header);
        return Status::kPassed;
    }

    struct [[nodiscard]] RunResults {
        size_t passed{0};
        size_t failed{0};
        size_t skipped{0};

        constexpr RunResults() = default;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        constexpr RunResults(Status status) {
            switch (status) {
                case Status::kPassed:
                    passed = 1;
                    return;
                case Status::kFailed:
                    failed = 1;
                    return;
                case Status::kSkipped:
                    skipped = 1;
                    return;
            }
        }

        RunResults& operator+=(const RunResults& rhs) {
            passed += rhs.passed;
            failed += rhs.failed;
            skipped += rhs.skipped;
            return *this;
        }
    };

    // https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html
    RunResults blockchain_test(const nlohmann::json& json_test) {
        const auto network{json_test["network"].get<std::string>()};
        const auto config_it{test::kNetworkConfig.find(network)};
        if (config_it == test::kNetworkConfig.end()) {
            sys_println("ERROR: unknown network");
            return Status::kSkipped;
        }
        auto genesisRLPStr = json_test["genesisRLP"].get<std::string>();
        Bytes genesis_rlp{from_hex(genesisRLPStr).value()};
        ByteView genesis_view{genesis_rlp};
        Block genesis_block;
        if (!rlp::decode(genesis_view, genesis_block)) {
            sys_println("Failure to decode genesisRLP");
            return Status::kFailed;
        }

        // blob must outlive direct.
        auto blob = read_genesis_allocation(json_test["pre"]);
        DirectState direct{std::span<uint8_t>{blob.data(), blob.size()}};
        if (!direct.sanitize()) {
            sys_println("ERROR: blockchain_test sanitize failed (identity↔hash mismatch)");
            return Status::kFailed;
        }
        Blockchain blockchain{direct, config_it->second, genesis_block};

        for (const auto& json_block : json_test["blocks"]) {
            Status status{run_json_block(json_block, blockchain, direct)};
            if (status != Status::kPassed) {
                return status;
            }
        }

        if (json_test.contains("postStateHash")) {
            const auto state_root = direct.state_root_hash();
            if (!state_root) {
                sys_println("ERROR: state_root_hash failed (witness incomplete)");
                return Status::kFailed;
            }
            std::string expected_hex{json_test["postStateHash"].get<std::string>()};
            if (*state_root != to_bytes32(from_hex(expected_hex).value())) {
                sys_println("ERROR: postStateHash mismatch");
                return Status::kFailed;
            }
            return Status::kPassed;
        }
        return Status::kPassed;
    }
}  // namespace

std::pair<uint64_t, bool> StateTransition::run_one_bundle(::zilkworm::FlatBundle& bundle) {
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
        bundle.direct.insert_header(block.header);
        cumulative_gas += block.header.gas_used;
    }
    return {cumulative_gas, true};
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

    // keccak(slot_key) depends only on key bytes (account- and block-independent),
    // so entries never go stale. Soft cap bounds memory.
    static thread_local FlatHashMap<bytes32, bytes32> keccak_cache_map = [] {
        FlatHashMap<bytes32, bytes32> m;
        m.reserve(4096);
        return m;
    }();
    if (keccak_cache_map.size() > 16384) [[unlikely]] {
        keccak_cache_map.clear();
    }
    auto keccak_cache = [&](const bytes32& key) [[gnu::always_inline]] -> const bytes32& {
        auto [it, inserted] = keccak_cache_map.try_emplace(key);
        if (inserted) [[unlikely]] {
            it->second = keccak_bytes32(key);
        }
        return it->second;
    };

    mpt::GridMPT<true> storage_trie{direct_state, kEmptyRoot};

    while (it_existing_hashes != end_it_existing || it_created_hashes != end_created_hashes) {
        // Blob and created addr sets are disjoint.
        const bool has_existing =
            it_created_hashes == end_created_hashes ? true
            : it_existing_hashes == end_it_existing ? false
                                                    : std::memcmp(it_existing_hashes->addr_hash, it_created_hashes->addr_hash, 32) < 0;
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

        // Walk pre-state slots even with no SSTORE: binds slot.initial to keccak(key) under pa->storage_root.
        const bool has_pre_slots = !existing_slots.empty();
        const bool has_created = (created_slots != nullptr && !created_slots->empty());
        bytes32 storage_root;
        if (has_pre_slots || has_created) {
            storage_root = std::bit_cast<bytes32>(pa->storage_root);
            const std::size_t need = existing_slots.size() + (created_slots != nullptr
                                                                  ? created_slots->size()
                                                                  : 0);
            zilkworm::InlineVec<mpt::TrieNodeFlat, 32> storage_updates(need, storage_spill);
            for (const auto& slot : existing_slots) {
                const auto& key = *reinterpret_cast<const bytes32*>(slot.key);
                auto& node = storage_updates.emplace_back(keccak_cache(key));
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
                    auto& node = storage_updates.emplace_back(keccak_cache(k));
                    node.current_off = 40;
                    node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 40, zeroless_view(ByteView{v.bytes, 32})));
                }
            }
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
            if (!has_pre_slots && !has_created) {
                storage_root = std::bit_cast<bytes32>(pa->storage_root);
            }
            auto& inserted = acc_updates.back();
            inserted.current_off = 0;
            inserted.current_len = pa->rlp_into(inserted.buf + 0, storage_root);
        }
    }

    // acc_updates already sorted: merge of two sorted hash sequences.
    auto prev_root = direct_state.read_header(header.number - 1, header.parent_hash)->state_root;
    mpt::GridMPT<true> acc_trie(direct_state, prev_root);
    auto new_root = acc_trie.calc_root_from_updates({acc_updates.data(), acc_updates.size()});
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

uint64_t StateTransition::run() {
    if (envelope_.size() < 4) [[unlikely]] {
        sys_println("ERROR: input envelope too small for magic");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t magic = 0;
    std::memcpy(&magic, envelope_.data(), sizeof(uint32_t));
    switch (magic) {
        case ::zilkworm::kInputMagicEJSN:
            return run_ejsn();
        case ::zilkworm::kInputMagicMFBD:
            return run_mfbd();
        default:
            sys_println("ERROR: unsupported input magic");
            failed_ = true;
            return kRunFailure;
    }
}

uint64_t StateTransition::run_ejsn() {
    if (envelope_.size() < ::zilkworm::kInputHeaderSizeEJSN) [[unlikely]] {
        sys_println("ERROR: EJSN envelope too small");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t version = 0;
    std::memcpy(&version, envelope_.data() + 4, sizeof(uint32_t));
    if (version != ::zilkworm::kInputVersionEJSN) [[unlikely]] {
        sys_println("ERROR: EJSN envelope bad version");
        failed_ = true;
        return kRunFailure;
    }
    const std::string_view json_str{
        reinterpret_cast<const char*>(envelope_.data() + ::zilkworm::kInputHeaderSizeEJSN),
        envelope_.size() - ::zilkworm::kInputHeaderSizeEJSN};

    bool any_failed = false;
    bool any_skipped = false;
    const auto base_json = nlohmann::json::parse(json_str);
    for (const auto& [name, test] : base_json.items()) {
        const auto result = blockchain_test(test);
        if (result.failed != 0) {
            any_failed = true;
            sys_println("    FAILED");
        } else if (result.skipped != 0) {
            sys_println("    SKIPPED");
            any_skipped = true;
        } else {
            sys_println("    passed");
        }
    }
    if (any_failed) {
        failed_ = true;
        return kRunFailure;
    }
    if (any_skipped)
        return kRunSkipped;
    return 0;
}

uint64_t StateTransition::run_mfbd() {
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
}

}  // namespace silkworm::cmd::state_transition
