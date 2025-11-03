// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/blockchain.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/dev/common/ecc_key_pair.hpp>

#include "../print.hpp"
#include "expected_state.hpp"

namespace silkworm::cmd::state_transition {

StateTransition::StateTransition(const std::string& json_str, const bool terminate_on_error, const bool show_diagnostics) noexcept
    : terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
    sys_println("StateTransition::StateTransition");

    // Redirect std::cout and std::cerr to out_stream_ for capturing output.
    std::cout.rdbuf(out_stream_.rdbuf());
    std::cerr.rdbuf(out_stream_.rdbuf());

    std::cout << "Test std::cout\n";
    sys_println("std::cout tested");
    std::cerr << "Test std::cerr\n";
    sys_println("std::cerr tested");

    // Test the captured output dump.
    sys_println("OUT dump:");
    sys_println(out_stream_.str().c_str());

    base_json_ = nlohmann::json::parse(json_str);
    auto test_object = base_json_.begin();
    test_name_ = test_object.key();
    blockchain_test_ = test_object->contains("_info") && test_object->contains("blocks");
    if (blockchain_test_) {
        sys_println("Blockchain test detected");
    }
    test_data_ = test_object.value();
}

StateTransition::StateTransition(const bool terminate_on_error, const bool show_diagnostics) noexcept
    : terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
    nlohmann::json base_json;
    const std::string json_str = R"json(
    )json";
    base_json = nlohmann::json::parse(json_str);
    auto test_object = base_json.begin();
    test_name_ = test_object.key();
    test_data_ = test_object.value();
}

std::vector<ExpectedState> StateTransition::get_expected_states() {
    std::vector<ExpectedState> expected_states;
    auto post_items = test_data_.at("transactions").items();
    // std::cout << "get_expected_states:test_data" << post_items;
    for (const auto& post_state : post_items) {
        // std::cout << "get_expected_states: test_data_.at(\"post\").items(i)" << post_state << "\n";
        auto data = post_state.value();
        // std::cout << "get_expected_states:items(i).value().array:" << data;
        const std::string& key = post_state.key();
        expected_states.emplace_back(data[0], key);
    }

    return expected_states;
}

ExpectedState StateTransition::get_expected_state() {
    auto post_items = test_data_.at("transactions").items();
    // std::cout << "get_expected_states:test_data====post_items\n"
    //           << post_items << "\n";
    // ExpectedState expected_state{"", ""};
    return ExpectedState{post_items.begin().value(), post_items.begin().key()};
    // for (const auto& post_state : post_items) {
    //     // std::cout << "get_expected_states: test_data_.at(\"post\").items(i)" << post_state << "\n";
    //     const auto& data = post_state.value();
    //     // std::cout << "get_expected_states:items(i).value().array:" << data;
    //     const std::string& key = post_state.key();
    //     expected_state = ExpectedState{data, key};
    //     break; // should only have one item for testing, for now
    // }
    // return nullptr;
}

std::string StateTransition::get_env(const std::string& key) {
    return test_data_.at("env").at(key);
}

bool StateTransition::contains_env(const std::string& key) {
    return test_data_.at("env").contains(key);
}

std::vector<Withdrawal> StateTransition::get_withdrawals() {
    auto wrs = std::vector<Withdrawal>{};
    for (auto& wr : test_data_.at("env").at("withdrawals")) {
        wrs.emplace_back(Withdrawal{
            .index = wr.at("index").get<uint64_t>(),
            .validator_index = wr.at("validatorIndex").get<uint64_t>(),
            .address = to_evmc_address(wr.at("address").get<std::string>()),
            .amount = wr.at("amount").get<uint64_t>()});
    }
    return wrs;
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        out = hex_to_address(address);
    }

    return out;
}

Block StateTransition::get_block(InMemoryState& state, ChainConfig& chain_config) {
    auto block = Block();

    block.header.beneficiary = to_evmc_address(get_env("miner"));

    block.header.gas_limit = std::stoull(get_env("gasLimit"), nullptr, /*base=*/16);
    block.header.number = std::stoull(get_env("number"), nullptr, /*base=*/16);
    block.header.timestamp = std::stoull(get_env("timestamp"), nullptr, /*base=*/16);
    block.header.parent_hash = to_bytes32(from_hex(get_env("parentHash")).value_or(Bytes{}));

    if (contains_env("currentRandom")) {
        block.header.prev_randao = to_bytes32(from_hex(get_env("currentRandom")).value_or(Bytes{}));
    }

    const evmc_revision rev{chain_config.revision(block.header.number, block.header.timestamp)};

    // set difficulty only for revisions before The Merge
    // current block difficulty cannot fall below minimum: https://eips.ethereum.org/EIPS/eip-2
    static constexpr uint64_t kMinDifficulty{0x20000};
    if (!chain_config.terminal_total_difficulty.has_value()) {
        block.header.difficulty = intx::from_string<intx::uint256>(get_env("difficulty"));
        if (block.header.difficulty < kMinDifficulty && rev <= EVMC_LONDON) {
            block.header.difficulty = kMinDifficulty;
        }
    }

    if (contains_env("baseFeePerGas") && rev >= EVMC_LONDON) {
        block.header.base_fee_per_gas = intx::from_string<intx::uint256>(get_env("baseFeePerGas"));
    }

    if (rev >= EVMC_SHANGHAI) {
        if (contains_env("withdrawalsRoot")) {
            block.header.withdrawals_root = to_bytes32(from_hex(get_env("withdrawalsRoot")).value_or(Bytes{}));
        } else {
            block.header.withdrawals_root = kEmptyRoot;
        }
        if (contains_env("withdrawals")) {
            block.withdrawals = get_withdrawals();
        } else {
            block.withdrawals = std::vector<Withdrawal>{};
        }
    }

    if (rev >= EVMC_CANCUN) {
        if (contains_env("parentBeaconBlockRoot")) {
            block.header.parent_beacon_block_root = to_bytes32(from_hex(get_env("parentBeaconBlockRoot")).value_or(Bytes{}));
        }
        if (contains_env("excessBlobGas")) {
            block.header.excess_blob_gas = test_data_.at("env").at("excessBlobGas").get<uint64_t>();
        }
        if (contains_env("blobGasUsed")) {
            block.header.blob_gas_used = test_data_.at("env").at("blobGasUsed").get<uint64_t>();
        }
    }

    if (rev >= EVMC_PRAGUE) {
        if (contains_env("requestsHash")) {
            block.header.requests_hash = to_bytes32(from_hex(get_env("requestsHash")).value_or(Bytes{}));
        }
    }

    block.header.transactions_root = protocol::compute_transaction_root(block);
    block.header.ommers_hash = kEmptyListHash;

    auto parent_block = Block();
    parent_block.header.gas_limit = block.header.gas_limit;
    parent_block.header.gas_used = parent_block.header.gas_limit / protocol::kElasticityMultiplier;
    parent_block.header.number = block.header.number - 1;
    parent_block.header.base_fee_per_gas = block.header.base_fee_per_gas;
    parent_block.header.ommers_hash = kEmptyListHash;
    parent_block.header.difficulty = intx::from_string<intx::uint256>(get_env("difficulty"));
    state.insert_block(parent_block, block.header.parent_hash);

    return block;
}

std::unique_ptr<evmc::address> StateTransition::private_key_to_address(const std::string& private_key) {
    /// Example
    // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
    // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
    // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B

    auto private_key_bytes = from_hex(private_key).value();

    if (private_key_bytes.length() == 32) {
        auto pair = sentry::EccKeyPair(private_key_bytes);
        uint8_t out[kAddressLength];
        auto public_key_hash = keccak256(pair.public_key().serialized());
        std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));
        return std::make_unique<evmc::address>(bytes_to_address(out));
    }

    uint8_t out[kAddressLength];
    // auto public_key_hash = keccak256(pair.public_key().serialized());
    // std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));

    return std::make_unique<evmc::address>(bytes_to_address(out));
}

std::unique_ptr<evmc::address> StateTransition::sender_to_address(const std::string& sender) {
    return std::make_unique<evmc::address>(hex_to_address(sender));
}

Transaction StateTransition::get_txn_from_sub_state(const ExpectedSubState& expected_state) {
    Transaction txn;
    auto& j_transaction = expected_state.get_sub_state_data();
    txn.nonce = std::stoull(j_transaction.at("nonce").get<std::string>(), nullptr, 16);
    auto senderPtr = sender_to_address(j_transaction["sender"]);
    txn.set_sender(*senderPtr);

    const auto to_address = j_transaction.at("to").get<std::string>();
    if (!to_address.empty()) {
        txn.to = to_evmc_address(to_address);
    }

    if (j_transaction.contains("gasPrice")) {
        txn.type = TransactionType::kLegacy;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    } else {
        txn.type = TransactionType::kDynamicFee;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxFeePerGas").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxPriorityFeePerGas").get<std::string>());
    }

    txn.data = from_hex(j_transaction.at("data").get<std::string>()).value();

    txn.gas_limit = std::stoull(j_transaction.at("gasLimit").get<std::string>(), nullptr, 16);

    auto value_str = j_transaction.at("value").get<std::string>();
    // // in case of bigint, set max value; compatible with all test cases so far
    txn.value = (value_str.starts_with("0x:bigint ")) ? std::numeric_limits<intx::uint256>::max() : intx::from_string<intx::uint256>(value_str);

    if (j_transaction.contains("accessLists")) {
        auto j_access_list = j_transaction.at("accessLists");

        for (const auto& j_access_entry : j_access_list.items()) {
            AccessListEntry entry;
            entry.account = to_evmc_address(j_access_entry.value().at("address"));

            for (const auto& j_storage_key : j_access_entry.value().at("storageKeys").items()) {
                if (j_storage_key.value().is_string()) {
                    auto hex_storage = from_hex(j_storage_key.value().get<std::string>());
                    entry.storage_keys.emplace_back(to_bytes32(hex_storage.value()));
                }
            }
            txn.access_list.emplace_back(entry);
        }

        if (txn.type == TransactionType::kLegacy) {
            txn.type = TransactionType::kAccessList;
        }
    }

    return txn;
}

void StateTransition::validate_transition(const Receipt& receipt, const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const InMemoryState& state) {
    // if (expected_sub_state.exceptionExpected) {
    //     if (receipt.success) {
    //         ++failed_count_;
    //     }
    // }

    if (expected_state.fork_name().length() == 0) {
    }

    if (state.state_root_hash() != expected_sub_state.stateHash) {
        // print_error_message(expected_state, expected_sub_state, "Failed: State root hash does not match");
        ++failed_count_;
    } else {
        Bytes encoded;
        rlp::encode(encoded, receipt.logs);
        if (std::bit_cast<evmc_bytes32>(keccak256(encoded)) != expected_sub_state.logsHash) {
            // print_error_message(expected_state, expected_sub_state, "Failed: Logs hash does not match");
            ++failed_count_;
        } else {
            // print_diagnostic_message(expected_state, expected_sub_state, "OK");
        }
    }
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

    Status run_block(const nlohmann::json& json_block, Blockchain& blockchain) {
        bool invalid{json_block.contains("expectException")};

        std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
        if (!rlp) {
            if (invalid) {
                return Status::kPassed;
            }
            std::cout << "Failure to read hex" << std::endl;
            return Status::kFailed;
        }

        Block block;
        ByteView view{*rlp};
        if (!rlp::decode(view, block)) {
            if (invalid) {
                return Status::kPassed;
            }
            std::cout << "Failure to decode RLP" << std::endl;
            return Status::kFailed;
        }

        const bool check_state_root{true};
        if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
            if (invalid) {
                return Status::kPassed;
            }
            std::cout << "Validation error " << static_cast<int>(err) << std::endl;
            return Status::kFailed;
        }

        if (invalid) {
            std::cout << "Invalid block executed successfully\n";
            std::cout << "Expected: " << json_block["expectException"] << std::endl;
            return Status::kFailed;
        }

        return Status::kPassed;
    }

    bool post_check(const InMemoryState& state, const nlohmann::json& expected) {
        if (state.accounts().size() != expected.size()) {
            std::cout << "Account number mismatch: " << state.accounts().size() << " != " << expected.size()
                      << std::endl;

            // Find and report accounts missing from the expected set.
            for (const auto& [addr, _] : state.accounts()) {
                if (const auto addr_hex = "0x" + hex(addr); !expected.contains(addr_hex)) {
                    std::cout << "Unexpected account: " << addr_hex << std::endl;
                }
            }

            return false;
        }

        for (const auto& entry : expected.items()) {
            const evmc::address address{hex_to_address(entry.key())};
            const nlohmann::json& j{entry.value()};

            std::optional<Account> account{state.read_account(address)};
            if (!account) {
                std::cout << "Missing account " << entry.key() << std::endl;
                return false;
            }

            const auto expected_balance{intx::from_string<intx::uint256>(j["balance"].get<std::string>())};
            if (account->balance != expected_balance) {
                std::cout << "Balance mismatch for " << entry.key() << ":\n"
                          << to_string(account->balance, 16) << " != " << j["balance"] << std::endl;
                return false;
            }

            const auto expected_nonce{intx::from_string<intx::uint256>(j["nonce"].get<std::string>())};
            if (account->nonce != expected_nonce) {
                std::cout << "Nonce mismatch for " << entry.key() << ":\n"
                          << account->nonce << " != " << j["nonce"] << std::endl;
                return false;
            }

            auto expected_code{j["code"].get<std::string>()};
            Bytes actual_code{state.read_code(address, account->code_hash)};
            if (actual_code != from_hex(expected_code)) {
                std::cout << "Code mismatch for " << entry.key() << ":\n"
                          << to_hex(actual_code) << " != " << expected_code << std::endl;
                return false;
            }

            size_t storage_size{state.storage_size(address, account->incarnation)};
            if (storage_size != j["storage"].size()) {
                std::cout << "Storage size mismatch for " << entry.key() << ":\n"
                          << storage_size << " != " << j["storage"].size() << std::endl;
                return false;
            }

            for (const auto& storage : j["storage"].items()) {
                Bytes key{from_hex(storage.key()).value()};
                Bytes expected_value{from_hex(storage.value().get<std::string>()).value()};
                evmc::bytes32 actual_value{state.read_storage(address, account->incarnation, to_bytes32(key))};
                if (actual_value != to_bytes32(expected_value)) {
                    std::cout << "Storage mismatch for " << entry.key() << " at " << storage.key() << ":\n"
                              << to_hex(actual_value) << " != " << to_hex(expected_value) << std::endl;
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
            std::cout << "unknown network " << network << std::endl;
            return Status::kSkipped;
        }

        Bytes genesis_rlp{from_hex(json_test["genesisRLP"].get<std::string>()).value()};
        ByteView genesis_view{genesis_rlp};
        Block genesis_block;
        if (!rlp::decode(genesis_view, genesis_block)) {
            std::cout << "Failure to decode genesisRLP" << std::endl;
            return Status::kFailed;
        }

        InMemoryState state{read_genesis_allocation(json_test["pre"])};
        Blockchain blockchain{state, config_it->second, genesis_block};
        // blockchain.exo_evm = exo_evm;

        for (const auto& json_block : json_test["blocks"]) {
            Status status{run_block(json_block, blockchain)};
            if (status != Status::kPassed) {
                return status;
            }
        }

        if (json_test.contains("postStateHash")) {
            evmc::bytes32 state_root{state.state_root_hash()};
            std::string expected_hex{json_test["postStateHash"].get<std::string>()};
            if (state_root != to_bytes32(from_hex(expected_hex).value())) {
                std::cout << "postStateHash mismatch:\n"
                          << to_hex(state_root) << " != " << expected_hex << std::endl;
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

uint64_t StateTransition::run(uint32_t num_runs) {
    if (blockchain_test_) {
        sys_println("Running blockchain test");

        for (const auto& [name, test] : base_json_.items()) {
            sys_print(name.c_str());
            const auto result = blockchain_test(test);
            if (result.failed != 0) {
                sys_println(" FAILED");
                // TODO: Use panic, because syscall_halt() doesn't link.
                __builtin_trap();
            } else if (result.skipped != 0) {
                sys_println(" SKIPPED");
            } else {
                sys_println(" passed");
            }
        }
        return 0;
    }

    sys_println("Running State transition");
    failed_count_ = 0;
    total_count_ = 0;
    uint64_t total_gas = 0;
    auto expected_state = get_expected_state();
    auto sub_states = expected_state.get_sub_states();
    auto config = expected_state.get_config();
    auto rule_set = protocol::rule_set_factory(config);
    auto state = read_genesis_allocation(test_data_["pre"]);
    auto block = get_block(state, config);
    ExecutionProcessor processor{block, *rule_set, state, config, true};
    auto pre_block_validation = rule_set->pre_validate_block_body(block, state);
    auto block_validation = rule_set->validate_block_header(block.header, state, true);

    // std::cout << "\n\n =========== run() ===\nsub_states:\n" << sub_states;
    for (const auto& expected_sub_state : sub_states) {
        ++total_count_;
        auto txn = get_txn_from_sub_state(expected_sub_state);

        if (processor.evm().vm().get_raw_pointer() == nullptr) {
            return 0;
        }

        Receipt receipt;
        const evmc_revision rev{config.revision(block.header.number, block.header.timestamp)};
        auto pre_txn_validation = protocol::pre_validate_transaction(txn, rev, config.chain_id, block.header.base_fee_per_gas, block.header.blob_gas_price());
        auto txn_validation = protocol::validate_transaction(txn, processor.evm().state(), processor.available_gas());

        if (pre_block_validation == ValidationResult::kOk &&
            block_validation == ValidationResult::kOk &&
            pre_txn_validation == ValidationResult::kOk &&
            txn_validation == ValidationResult::kOk) {
            //============== [TESTING ONLY] SIMULATING MULTIPLE RUNS=====
            for (uint32_t i = 0; i < num_runs; i++) {
                sys_println("Inside multiple runs loop");

                auto state_cp = read_genesis_allocation(test_data_["pre"]);
                ExecutionProcessor ccprocessor{block, *rule_set, state_cp, config, true};
                ccprocessor.execute_transaction(txn, receipt);
                // processor.execute_transaction(txn, receipt);
                total_gas += receipt.cumulative_gas_used;
            }
            //=====================================================

            // processor.execute_transaction(txn, receipt);
            // total_gas += receipt.cumulative_gas_used;
            // std::cout << "\n Total Gas: " << total_gas;
            // processor.evm().state().write_to_db(block.header.number);
        } else {
            // INCORRECT PATH =============
            // processor.execute_transaction(txn, receipt);
            // processor.evm().state().write_to_db(block.header.number);
            // receipt.success = true;
            // ============================
            cleanup_error_block(block, processor, rev);
            receipt.success = false;
            std::cerr << "Something Went Wrong!";
        }

        // validate_transition(receipt, expected_state, expected_sub_state, state);
    }

    if (show_diagnostics_) {
        // std::cout doesn't play well with risv
        // std::cout << "Total Gas: " << total_gas;
    }
    return total_gas;
}

}  // namespace silkworm::cmd::state_transition

// COUT can't be executed on rv32im ::: ====>

// void StateTransition::print_error_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     if (terminate_on_error_) {
//         throw std::runtime_error(message);
//     }
//     // print_message(expected_state, expected_sub_state, message);
// }

// void StateTransition::print_diagnostic_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     if (show_diagnostics_) {
//         print_message(expected_state, expected_sub_state, message);
//     }
// }

// void StateTransition::print_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
//     // std::cout << "[" << test_name_ << ":" << expected_state.fork_name() << ":" << expected_sub_state.index << "] " << message << std::endl;
// }
