// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <format>
#include <fstream>

#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/state/in_memory_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/print.hpp>

namespace silkworm::cmd::state_transition {

using namespace silkworm::protocol;

StateTransition::StateTransition(std::string_view json_str, const bool terminate_on_error, const bool show_diagnostics) noexcept
    : json_str_{json_str},
      terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
}

StateTransition::StateTransition(ByteView& unified_rlp) noexcept
    : unified_rlp_{unified_rlp} {
}

StateTransition::StateTransition(const std::string& unified_rlp_str) noexcept {
    // Copy the data to own it
    unified_rlp_data_ = unified_rlp_str;
    unified_rlp_ = ByteView{reinterpret_cast<const uint8_t*>(unified_rlp_data_.data()), unified_rlp_data_.size()};
}

StateTransition::StateTransition(std::string&& unified_rlp_str) noexcept
    : unified_rlp_data_{std::move(unified_rlp_str)} {
    // Create view into the moved data
    unified_rlp_ = ByteView{reinterpret_cast<const uint8_t*>(unified_rlp_data_.data()), unified_rlp_data_.size()};
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
    enum class Status {
        kPassed,
        kFailed,
        kSkipped
    };

    Status run_json_block(const nlohmann::json& json_block, Blockchain& blockchain) {
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

        /// The CL gossip protocol constraint of the maximum block size (EIP-7934).
        constexpr size_t MAX_BLOCK_SIZE = 10 * 1024 * 1024;
        /// The safety margin for beacon block content (EIP-7934).
        constexpr size_t SAFETY_MARGIN = 2 * 1024 * 1024;
        /// The maximum EL block size when RLP encoded (EIP-7934).
        constexpr size_t MAX_RLP_BLOCK_SIZE = MAX_BLOCK_SIZE - SAFETY_MARGIN;

        if (view.size() > MAX_RLP_BLOCK_SIZE) {
            if (invalid)
                return Status::kPassed;

            // TODO: Ignore big blocks before Osaka because we don't have fork config here.
            return Status::kSkipped;
        }

        if (!rlp::decode(view, block)) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println("Failure to decode RLP");
            return Status::kFailed;
        }

        const bool check_state_root{true};
        if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println(std::format("Validation error {}", magic_enum::enum_name<ValidationResult>(err)).c_str());
            return Status::kFailed;
        }

        if (invalid) {
            sys_println("Invalid block executed successfully");
            sys_println(std::format("Expected: {}", json_block["expectException"].dump()).c_str());
            return Status::kFailed;
        }

        return Status::kPassed;
    }

    bool post_check(const InMemoryState& state, const nlohmann::json& expected) {
        if (state.accounts().size() != expected.size()) {
            sys_println(std::format("Account number mismatch: {} != {}", state.accounts().size(), expected.size()).c_str());

            // Find and report accounts missing from the expected set.
            for (const auto& [addr, _] : state.accounts()) {
                if (const auto addr_hex = "0x" + hex(addr); !expected.contains(addr_hex)) {
                    sys_println(std::format("Unexpected account: {}", addr_hex).c_str());
                }
            }

            return false;
        }

        for (const auto& entry : expected.items()) {
            const evmc::address address{hex_to_address(entry.key())};
            const nlohmann::json& j{entry.value()};

            std::optional<Account> account{state.read_account(address)};
            if (!account) {
                sys_println(std::format("Missing account {}", entry.key()).c_str());
                return false;
            }

            const auto expected_balance{intx::from_string<intx::uint256>(j["balance"].get<std::string>())};
            if (account->balance != expected_balance) {
                sys_println(std::format("Balance mismatch for {}:\n{} != {}", entry.key(), to_string(account->balance, 16), j["balance"].get<std::string>()).c_str());
                return false;
            }

            const auto expected_nonce{intx::from_string<intx::uint256>(j["nonce"].get<std::string>())};
            if (account->nonce != expected_nonce) {
                sys_println(std::format("Nonce mismatch for {}:\n{} != {}", entry.key(), account->nonce, j["nonce"].get<std::string>()).c_str());
                return false;
            }

            auto expected_code{j["code"].get<std::string>()};
            Bytes actual_code{state.read_code(address, account->code_hash)};
            if (actual_code != from_hex(expected_code)) {
                sys_println(std::format("Code mismatch for {}:\n{} != {}", entry.key(), to_hex(actual_code), expected_code).c_str());
                return false;
            }

            size_t storage_size{state.storage_size(address)};
            if (storage_size != j["storage"].size()) {
                sys_println(std::format("Storage size mismatch for {}:\n{} != {}", entry.key(), storage_size, j["storage"].size()).c_str());
                return false;
            }

            for (const auto& storage : j["storage"].items()) {
                Bytes key{from_hex(storage.key()).value()};
                Bytes expected_value{from_hex(storage.value().get<std::string>()).value()};
                evmc::bytes32 actual_value{state.read_storage(address, to_bytes32(key))};
                if (actual_value != to_bytes32(expected_value)) {
                    sys_println(std::format("Storage mismatch for {} at {}:\n{} != {}", entry.key(), storage.key(), to_hex(actual_value), to_hex(expected_value)).c_str());
                    return false;
                }
            }
        }

        return true;
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
            sys_println(std::format("unknown network {}", network).c_str());
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

        InMemoryState state{read_genesis_allocation(json_test["pre"])};
        Blockchain blockchain{state, config_it->second, genesis_block};

        for (const auto& json_block : json_test["blocks"]) {
            Status status{run_json_block(json_block, blockchain)};
            if (status != Status::kPassed) {
                return status;
            }
        }

        if (json_test.contains("postStateHash")) {
            evmc::bytes32 state_root{state.state_root_hash()};
            std::string expected_hex{json_test["postStateHash"].get<std::string>()};
            if (state_root != to_bytes32(from_hex(expected_hex).value())) {
                sys_println(std::format("postStateHash mismatch:\n{} != {}", to_hex(state_root), expected_hex).c_str());
                return Status::kFailed;
            }
            return Status::kPassed;
        }

        if (post_check(state, json_test["postState"])) {
            return Status::kPassed;
        }
        return Status::kFailed;
    }
}  // namespace

uint64_t StateTransition::run_rlp() {
    sys_println(std::format("run_rlp: Unified RLP length: {}", unified_rlp_.size()).c_str());

    Block genesis_block;

    const auto rlp_head{rlp::decode_header(unified_rlp_)};
    if (!rlp_head || !rlp_head->list) {
        sys_println("ERROR: outer RLP decode failed");
        return kRunFailure;
    }
    ByteView payload_view = unified_rlp_.substr(0, rlp_head->payload_length);
    if (payload_view.empty()) {
        sys_println("ERROR: empty unified_rlp payload");
        return kRunFailure;
    }

    // Auto-detect v0 vs v1 by the first byte of the outer-list payload (see `docs/architecture.md` "Per-subtest unified RLP").
    std::string fork_name;
    bool legacy_v0 = false;
    if (payload_view[0] >= 0xb8 && payload_view[0] <= 0xbf) {
        legacy_v0 = true;
        fork_name = "Mainnet";
    } else if (payload_view[0] == 0x01) {
        payload_view.remove_prefix(1);
        Bytes fork_name_bytes;
        if (!rlp::decode(payload_view, fork_name_bytes, rlp::Leftover::kAllow)) {
            sys_println("ERROR: Failed to Decode fork_name");
            return kRunFailure;
        }
        fork_name.assign(reinterpret_cast<const char*>(fork_name_bytes.data()), fork_name_bytes.size());
    } else {
        sys_println(std::format("ERROR: unsupported unified_rlp version byte {:#x}", payload_view[0]).c_str());
        return kRunFailure;
    }

    const ChainConfig* chain_config_ptr = nullptr;
    if (fork_name == "Mainnet") {
        chain_config_ptr = &kMainnetConfig;
    } else {
        const auto it = test::kNetworkConfig.find(fork_name);
        if (it == test::kNetworkConfig.end()) {
            sys_println(std::format("ERROR: run_rlp: unknown fork '{}'", fork_name).c_str());
            return kRunFailure;
        }
        chain_config_ptr = &it->second;
    }
    const ChainConfig& chain_config = *chain_config_ptr;

    auto genesis_header = rlp::decode_header(payload_view);
    if (!genesis_header) {
        sys_println("ERROR: Failed to Decode Genesis Block RLP header");
        return kRunFailure;
    }
    ByteView genesis_payload = payload_view.substr(0, genesis_header->payload_length);
    if (!rlp::decode(genesis_payload, genesis_block)) {
        sys_println("ERROR: Failed to Decode Genesis Block RLP body");
        return kRunFailure;
    }
    payload_view.remove_prefix(genesis_header->payload_length);

    constexpr size_t kMaxBlockSize = 10 * 1024 * 1024;
    constexpr size_t kBlockSafetyMargin = 2 * 1024 * 1024;
    constexpr size_t kMaxRlpBlockSize = kMaxBlockSize - kBlockSafetyMargin;

    // Decode blocks: v0 has just one block_rlp, v1 has a list of [block_rlp, expect_invalid_byte] tuples.
    enum class EntryStatus { Ok, Oversized, DecodeFailed };
    struct BlockEntry { Block block; EntryStatus status; bool expect_invalid; };
    std::vector<BlockEntry> entries;

    if (legacy_v0) {
        BlockEntry e{};
        auto bh = rlp::decode_header(payload_view);
        if (!bh) {
            sys_println("ERROR: Failed to Decode Block RLP header");
            return kRunFailure;
        }
        ByteView bp = payload_view.substr(0, bh->payload_length);
        payload_view.remove_prefix(bh->payload_length);
        if (bh->payload_length > kMaxRlpBlockSize) {
            e.status = EntryStatus::Oversized;
        } else if (!rlp::decode(bp, e.block)) {
            e.status = EntryStatus::DecodeFailed;
        }
        entries.push_back(std::move(e));
    } else {
        // v1: blocks_list slot is RLP string-wrapped. Unwrap, then decode the inner list of `[block, ei]` tuples.
        auto bl_outer = rlp::decode_header(payload_view);
        if (!bl_outer) {
            sys_println("ERROR: blocks_list outer header decode failed");
            return kRunFailure;
        }
        ByteView bl_payload = payload_view.substr(0, bl_outer->payload_length);
        payload_view.remove_prefix(bl_outer->payload_length);

        auto bl_inner = rlp::decode_header(bl_payload);
        if (!bl_inner || !bl_inner->list) {
            sys_println("ERROR: blocks_list inner is not a list");
            return kRunFailure;
        }
        ByteView entries_view = bl_payload.substr(0, bl_inner->payload_length);

        while (!entries_view.empty()) {
            auto entry_hdr = rlp::decode_header(entries_view);
            if (!entry_hdr || !entry_hdr->list) {
                sys_println("ERROR: blocks_list entry is not a list");
                return kRunFailure;
            }
            ByteView ev = entries_view.substr(0, entry_hdr->payload_length);
            entries_view.remove_prefix(entry_hdr->payload_length);

            // Split entry into [block_view, ei_view] up front so a malformed
            // block doesn't desync the cursor used to read the ei byte.
            ByteView ev_after_header = ev;
            auto bh = rlp::decode_header(ev_after_header);
            if (!bh) {
                sys_println("ERROR: blocks_list entry: failed to decode block header");
                return kRunFailure;
            }
            const size_t header_bytes = ev.size() - ev_after_header.size();
            const size_t block_total = header_bytes + bh->payload_length;
            ByteView block_view = ev.substr(0, block_total);
            ev.remove_prefix(block_total);

            BlockEntry e{};
            // EIP-7934 limit applies to the total block RLP (header + payload).
            if (block_total > kMaxRlpBlockSize) {
                e.status = EntryStatus::Oversized;
            } else if (!rlp::decode(block_view, e.block, rlp::Leftover::kAllow)) {
                e.status = EntryStatus::DecodeFailed;
            }

            Bytes ei_bytes;
            if (rlp::decode(ev, ei_bytes, rlp::Leftover::kAllow)) {
                e.expect_invalid = !ei_bytes.empty() && ei_bytes[0] != 0;
            }
            entries.push_back(std::move(e));
        }
    }

    auto pre_rlp_head = rlp::decode_header(payload_view);
    if (!pre_rlp_head) {
        sys_println("ERROR: Failed to Decode Pre-State RLP");
        return kRunFailure;
    }
    ByteView pre_rlp_payload = payload_view.substr(0, pre_rlp_head->payload_length);
    InMemoryState state{read_pre_state_from_rlp(pre_rlp_payload)};
    payload_view.remove_prefix(pre_rlp_head->payload_length);

    auto headers_overall_rlp_header = rlp::decode_header(payload_view);
    ByteView headers_overall_view = payload_view.substr(0, headers_overall_rlp_header->payload_length);
    if (headers_overall_rlp_header) {
        auto headers_list_header = rlp::decode_header(headers_overall_view);
        if (!headers_list_header || !headers_list_header->list) {
            sys_println("Invalid headers list entry");
        } else {
            ByteView headers_list_view = headers_overall_view.substr(0, headers_list_header->payload_length);
            while (!headers_list_view.empty()) {
                auto entry_header{rlp::decode_header(headers_list_view)};
                ByteView hh_view = headers_list_view.substr(0, entry_header->payload_length);
                Block bb;
                rlp::decode(hh_view, bb.header);
                state.insert_block(bb, bb.header.hash());
                headers_list_view.remove_prefix(entry_header->payload_length);
            }
        }
    }
    payload_view.remove_prefix(headers_overall_rlp_header->payload_length);

    Blockchain blockchain{state, chain_config, genesis_block};

    // Use in-memory state-root verification for non-Mainnet forks: EEST
    // payloads ship the full pre-state and `insert_block(true)` checks the
    // post-state root per block. Mainnet uses witness-based check_root below.
    const bool use_in_memory_state_root = (fork_name != "Mainnet");

    uint64_t cumulative_gas = 0;
    Block* last_applied_block = nullptr;

    for (auto& entry : entries) {
        switch (entry.status) {
            case EntryStatus::Oversized:
                if (entry.expect_invalid) continue;
                return kRunSkipped;
            case EntryStatus::DecodeFailed:
                if (entry.expect_invalid) continue;
                sys_println("ERROR: Failed to Decode Block RLP body");
                return kRunFailure;
            case EntryStatus::Ok:
                break;
        }
        const ValidationResult err = blockchain.insert_block(entry.block, use_in_memory_state_root);
        if (entry.expect_invalid) {
            if (err == ValidationResult::kOk) {
                sys_println("ERROR: block expected to be invalid but executed successfully");
                return kRunFailure;
            }
            continue;
        }
        if (err != ValidationResult::kOk) {
            sys_println(std::format("Validation error {}", magic_enum::enum_name<ValidationResult>(err)).c_str());
            return kRunFailure;
        }
        cumulative_gas += entry.block.header.gas_used;
        last_applied_block = &entry.block;
    }

    auto pre_trie_head = rlp::decode_header(payload_view);
    if (!pre_trie_head) {
        sys_println("ERROR: Failed to Decode Pre-Trie List RLP");
        return kRunFailure;
    }
    ByteView pre_trie_payload = payload_view.substr(0, pre_trie_head->payload_length);
    payload_view.remove_prefix(pre_trie_head->payload_length);
    if (!use_in_memory_state_root && last_applied_block != nullptr &&
        !check_root(pre_trie_payload, state, last_applied_block->header)) {
        sys_println("ERROR: State Root Mismatch");
        return kRunFailure;
    }

    // Check the post-state root from the in-memory state against the expected root hash in the payload.
    // If the payload doesn't have post-state info, skip the check (legacy v0 format or empty payload in v1 or zero hash).
    if (!legacy_v0 && !payload_view.empty()) {
        Bytes post_state_hash_bytes;
        if (!rlp::decode(payload_view, post_state_hash_bytes, rlp::Leftover::kAllow)) {
            sys_println("ERROR: Failed to Decode post_state_hash");
            return kRunFailure;
        }
        if (post_state_hash_bytes.size() == 32) {
            evmc::bytes32 expected = to_bytes32(post_state_hash_bytes);
            if (expected != evmc::bytes32{}) {
                evmc::bytes32 actual = state.state_root_hash();
                if (actual != expected) {
                    sys_println(std::format("ERROR: postStateHash mismatch: expected {} got {}",
                                            to_hex(expected), to_hex(actual)).c_str());
                    return kRunFailure;
                }
            }
        }
    }

    return cumulative_gas;
}

bool StateTransition::check_root(ByteView pre_trie_payload, InMemoryState& state, BlockHeader& header) {
    // Create and populate the node store
    node_store_.populate_from_rlp(pre_trie_payload);

    auto& acc_changes = state.account_changes().at(header.number);
    const InMemoryState::StorageChanges& storage_changes = state.storage_changes().at(header.number);
    std::vector<mpt::TrieNodeFlat> acc_updates;

    Bytes val_rlp;
    val_rlp.reserve(33);
    for (auto& [addr, acc_opt] : acc_changes) {
        const Account& acc = acc_opt.has_value() ? acc_opt.value() : Account{};

        auto it = storage_changes.find(addr);
        bytes32 storage_root{acc.storage_root_};
        if (it != storage_changes.end()) {
            std::vector<mpt::TrieNodeFlat> storage_updates{};
            for (auto& [key, val] : it->second) {
                auto cur_val = state.read_storage(addr, key);
                if (cur_val == val) {
                    continue;
                }
                auto zerolessVal = zeroless_view(cur_val.bytes);
                val_rlp.clear();
                rlp::encode(val_rlp, zerolessVal);
                auto hashed_key = keccak_bytes32(key);
                storage_updates.emplace_back(mpt::TrieNodeFlat{hashed_key, val_rlp});
            }

            if (storage_updates.size() > 0) {

                if (mpt::is_zero_quick(acc.storage_root_)) {    // In case of a new account
                    storage_root = kEmptyRoot;
                }
                mpt::GridMPT<true> storage_trie{node_store_, storage_root};

                std::sort(storage_updates.begin(), storage_updates.end());
                storage_root = storage_trie.calc_root_from_updates(storage_updates);
            }
        }
        auto cur_acc_opt = state.read_account(addr);
        if (!cur_acc_opt.has_value()) {
            sys_println(("ERROR: Account in acc_changes but not in storage" + to_hex(addr.bytes)).c_str());
            continue;
        }
        auto& curr_acc = cur_acc_opt.value();

        if (acc == *cur_acc_opt && storage_root == acc.storage_root_) {
            continue;
        }
        auto acc_rlp = curr_acc.rlp(storage_root);
        auto addr_hash = keccak_bytes(addr.bytes);
        acc_updates.emplace_back(addr_hash, acc_rlp);
    }

    std::sort(acc_updates.begin(), acc_updates.end());
    auto prev_root = state.read_header(header.number - 1, header.parent_hash)->state_root;
    mpt::GridMPT<false> acc_trie(node_store_, prev_root);
    auto new_root = acc_trie.calc_root_from_updates(acc_updates);
    return (new_root == header.state_root);
}

uint64_t StateTransition::run() {
    bool any_failed = false;
    bool any_skipped = false;
    const auto base_json = nlohmann::json::parse(json_str_);
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
    if (any_failed)
        return kRunFailure;
    if (any_skipped)
        return kRunSkipped;
    return 0;
}

}  // namespace silkworm::cmd::state_transition
