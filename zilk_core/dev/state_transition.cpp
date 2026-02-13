// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <fstream>

#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/execution/execution.hpp>
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

StateTransition::StateTransition(std::string_view json_str, const bool terminate_on_error, const bool show_diagnostics)
    : json_str_{json_str},
      terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
}

StateTransition::StateTransition(ByteView& unified_rlp)
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

/*
//  * This function is used to clean up the state after a failed block execution.
//  * Certain post-processing would be a part of the execute_transaction() function,
//  * but since the validation failed, we need to do it manually.
//  */
void cleanup_error_block(Block& block, ExecutionProcessor& processor, const evmc_revision rev) {
    if (rev >= EVMC_SHANGHAI) {
        processor.evm().state().access_account(block.header.beneficiary);
    }
    processor.evm().state().add_to_balance(block.header.beneficiary, 0);
    processor.evm().state().finalize_transaction(rev);
    processor.evm().state().write_to_db(block.header.number);
}

// From silkworm/cmd/test/ethereum.
namespace {
    using namespace silkworm::protocol;
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
            sys_println("Validation error");
            sys_println(std::string(magic_enum::enum_name<ValidationResult>(err)).c_str());
            return Status::kFailed;
        }

        if (invalid) {
            sys_println("Invalid block executed successfully");
            sys_println("Expected:");
            sys_println(json_block["expectException"].dump().c_str());
            return Status::kFailed;
        }

        return Status::kPassed;
    }

    bool post_check(const InMemoryState& state, const nlohmann::json& expected) {
        if (state.accounts().size() != expected.size()) {
            sys_println("Account number mismatch:");
            sys_println(std::to_string(state.accounts().size()).c_str());
            sys_println("!=");
            sys_println(std::to_string(expected.size()).c_str());

            // Find and report accounts missing from the expected set.
            for (const auto& [addr, _] : state.accounts()) {
                if (const auto addr_hex = "0x" + hex(addr); !expected.contains(addr_hex)) {
                    sys_println("Unexpected account:");
                    sys_println(addr_hex.c_str());
                }
            }

            return false;
        }

        for (const auto& entry : expected.items()) {
            const evmc::address address{hex_to_address(entry.key())};
            const nlohmann::json& j{entry.value()};

            std::optional<Account> account{state.read_account(address)};
            if (!account) {
                sys_println("Missing account");
                sys_println(entry.key().c_str());
                return false;
            }

            const auto expected_balance{intx::from_string<intx::uint256>(j["balance"].get<std::string>())};
            if (account->balance != expected_balance) {
                sys_println("Balance mismatch for");
                sys_println(entry.key().c_str());
                sys_println(to_string(account->balance, 16).c_str());
                sys_println("!=");
                sys_println(j["balance"].get<std::string>().c_str());
                return false;
            }

            const auto expected_nonce{intx::from_string<intx::uint256>(j["nonce"].get<std::string>())};
            if (account->nonce != expected_nonce) {
                sys_println("Nonce mismatch for");
                sys_println(entry.key().c_str());
                sys_println(std::to_string(account->nonce).c_str());
                sys_println("!=");
                sys_println(j["nonce"].get<std::string>().c_str());
                return false;
            }

            auto expected_code{j["code"].get<std::string>()};
            Bytes actual_code{state.read_code(address, account->code_hash)};
            if (actual_code != from_hex(expected_code)) {
                sys_println("Code mismatch for");
                sys_println(entry.key().c_str());
                sys_println(to_hex(actual_code).c_str());
                sys_println("!=");
                sys_println(expected_code.c_str());
                return false;
            }

            size_t storage_size{state.storage_size(address)};
            if (storage_size != j["storage"].size()) {
                sys_println("Storage size mismatch for");
                sys_println(entry.key().c_str());
                sys_println(std::to_string(storage_size).c_str());
                sys_println("!=");
                sys_println(std::to_string(j["storage"].size()).c_str());
                return false;
            }

            for (const auto& storage : j["storage"].items()) {
                Bytes key{from_hex(storage.key()).value()};
                Bytes expected_value{from_hex(storage.value().get<std::string>()).value()};
                evmc::bytes32 actual_value{state.read_storage(address, to_bytes32(key))};
                if (actual_value != to_bytes32(expected_value)) {
                    sys_println("Storage mismatch for");
                    sys_println(entry.key().c_str());
                    sys_println("at");
                    sys_println(storage.key().c_str());
                    sys_println(to_hex(actual_value).c_str());
                    sys_println("!=");
                    sys_println(to_hex(expected_value).c_str());
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
            sys_println("unknown network");
            sys_println(network.c_str());
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
        // blockchain.exo_evm = exo_evm;

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
                sys_println("postStateHash mismatch:");
                sys_println(to_hex(state_root).c_str());
                sys_println("!=");
                sys_println(expected_hex.c_str());
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
    sys_println("run_rlp: Unified RLP length:");
    sys_println(std::to_string(unified_rlp_.size()).c_str());

    Block genesisBlock, block;

    const auto rlp_head{rlp::decode_header(unified_rlp_)};
    if (!rlp_head) {
        sys_println("ERROR: Failed to Decode unified_rlp overall header");
        return 0;
    }
    if (!rlp_head->list) {
        sys_println("ERROR: Failed to Decode unified_rlp: Not list. Payload length:");
        sys_println(std::to_string(rlp_head->payload_length).c_str());
        return 0;
    }

    // Decode Genesis Block
    ByteView payload_view = unified_rlp_.substr(0, rlp_head->payload_length);
    if (payload_view.empty()) {
        sys_println("ERROR: Failed to Decode unified_rlp payload view");
        return 0;
    }
    auto genesis_header = rlp::decode_header(payload_view);
    if (!genesis_header) {
        sys_println("ERROR: Failed to Decode Genesis Block RLP");
        return 0;
    }
    ByteView genesis_payload = payload_view.substr(0, genesis_header->payload_length);
    if (!rlp::decode(genesis_payload, genesisBlock)) {
        sys_println("ERROR: Failed to Decode Genesis Block RLP");
        return 0;
    }
    payload_view.remove_prefix(genesis_header->payload_length);

    if (payload_view.empty()) {
        sys_println("ERROR: Failed to Decode Block RLP");
        return 0;
    }
    auto block_header = rlp::decode_header(payload_view);
    if (!block_header) {
        sys_println("ERROR: Failed to Decode Block RLP");
        return 0;
    }
    ByteView block_payload = payload_view.substr(0, block_header->payload_length);
    if (!rlp::decode(block_payload, block)) {
        sys_println("ERROR: Failed to Decode Genesis Block RLP");
        return 0;
    }
    payload_view.remove_prefix(block_header->payload_length);

    auto pre_rlp_head = rlp::decode_header(payload_view);
    if (!pre_rlp_head) {
        sys_println("ERROR: Failed to Decode Pre-State RLP");
        return 0;
    }
    ByteView pre_rlp_payload = payload_view.substr(0, pre_rlp_head->payload_length);
    InMemoryState state{read_pre_state_from_rlp(pre_rlp_payload)};
    payload_view.remove_prefix(pre_rlp_head->payload_length);

    auto headers_overall_rlp_header = rlp::decode_header(payload_view);
    ByteView headers_overall_view = payload_view.substr(0, headers_overall_rlp_header->payload_length);
    if (headers_overall_rlp_header) {  // Skip invalid headers list rlp
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

    // Use Mainnet config.
    // This can be latter extended to public testnets by providing chain id
    // and selecting the appropriate config from kKnownChainConfigs.
    Blockchain blockchain{state, kMainnetConfig, genesisBlock};

    if (ValidationResult err{blockchain.insert_block(block, false)}; err != ValidationResult::kOk) {
        sys_println(std::format("Validation error {}", magic_enum::enum_name<ValidationResult>(err)).c_str());
        return 0;
    }
    auto pre_trie_head = rlp::decode_header(payload_view);
    if (!pre_trie_head) {
        sys_println("ERROR: Failed to Decode Pre-Trie List RLP");
        return 0;
    }
    ByteView pre_trie_payload = payload_view.substr(0, pre_trie_head->payload_length);
    payload_view.remove_prefix(pre_trie_head->payload_length);
    if (!check_root(pre_trie_payload, state, block.header)) {
        sys_println("ERROR: State Root Mismatch");
    }

    return block.header.gas_used;
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
        sys_println(name.c_str());
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
        return 1;
    if (any_skipped)
        return 2;
    return 0;
}

}  // namespace silkworm::cmd::state_transition
