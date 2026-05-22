// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "processor.hpp"
#include <evmone/test/state/state.hpp>
#include <evmone/test/state/system_contracts.hpp>
#include <zilk_core/core/protocol/intrinsic_gas.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/trie/vector_root.hpp>
#include <zilk_core/core/types/eip_7685_requests.hpp>

namespace silkworm {
class StateView final : public evmone::state::StateView {
    IntraBlockState& state_;

  public:
    explicit StateView(IntraBlockState& state) noexcept : state_{state} {}

    std::optional<Account> get_account(const evmc::address& addr) const noexcept override {
        const auto* obj = state_.get_object(addr);
        if (obj == nullptr || !obj->current.has_value())
        return std::nullopt;
        
        const auto& cur = *obj->current;
        bool has_storage = state_.db().storage_size(addr) > 0;
        return Account{
            .nonce = cur.nonce,
            .balance = cur.balance,
            .code_hash = cur.code_hash,

            // The change to include the storage size 
            // as an indication of storage presence works with EESTs, but haven't investigated ALL
            // edge cases (TODO)
            .has_storage = has_storage
        };
    }

    evmone::bytes get_account_code(const evmc::address& addr) const noexcept override {
        return evmone::bytes{state_.get_code(addr)};
    }

    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
        return state_.get_original_storage(addr, key);
    }
};

namespace {
    class BlockHashes final : public evmone::state::BlockHashes {
        EVM& evm_;

      public:
        explicit BlockHashes(EVM& evm) noexcept : evm_{evm} {}
        evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override {
            return evm_.get_block_hash(block_number);
        }
    };

    /// Checks the result of the transaction execution in evmone (APIv2)
    /// against the result produced by Silkworm.
    void check_evm1_execution_result(const evmone::state::StateDiff& state_diff, const IntraBlockState& state) {
        for (const auto& entry : state_diff.modified_accounts) {
            if (std::ranges::find(state_diff.deleted_accounts, entry.addr) != state_diff.deleted_accounts.end()) {
                continue;
            }

            for (const auto& [k, v] : entry.modified_storage) {
                auto expected = state.get_current_storage(entry.addr, k);
                if (v != expected) {
                    // std::cerr << "k: " << hex(k) << "e1: " << hex(v) << ", silkworm: " << hex(expected) << "\n";
                }
            }
        }
        // for (const auto& a : state_diff.deleted_accounts) {
        // SILKWORM_ASSERT(!state.exists(a));
        // }
        for (const auto& m : state_diff.modified_accounts) {
            if (std::ranges::find(state_diff.deleted_accounts, m.addr) != state_diff.deleted_accounts.end()) {
                continue;
            }

            // SILKWORM_ASSERT(state.get_nonce(m.addr) == m.nonce);
            if (m.balance != state.get_balance(m.addr)) {
                // std::cerr << "b: " << hex(m.addr) << " " << to_string(m.balance) << ", silkworm: " << to_string(state.get_balance(m.addr)) << "\n";
                // SILKWORM_ASSERT(state.get_balance(m.addr) == m.balance);
            }
            if (m.code) {
                // SILKWORM_ASSERT(state.get_code(m.addr) == m.code);
            }
        }
    }
}  // namespace

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set, State& state,
                                       const ChainConfig& config, bool evm1_v2)
    : state_{state}, rule_set_{rule_set}, evm_{block, state_, config}, evm1_v2_{evm1_v2} {
    evm_.beneficiary = rule_set.get_beneficiary(block.header);
    evm_.transfer = rule_set.transfer_func();
    // if(evm_.vm().get_raw_pointer() == nullptr) {
    //     return;
    // }
    evm1_block_ = {
        .number = static_cast<int64_t>(block.header.number),
        .timestamp = static_cast<int64_t>(block.header.timestamp),
        .gas_limit = static_cast<int64_t>(block.header.gas_limit),
        .coinbase = block.header.beneficiary,
        .difficulty = static_cast<int64_t>(block.header.difficulty),
        .prev_randao = block.header.difficulty == 0 ? block.header.prev_randao : intx::be::store<evmone::state::bytes32>(intx::uint256{block.header.difficulty}),
        .parent_beacon_block_root = block.header.parent_beacon_block_root.value_or(evmc::bytes32{}),
        .base_fee = static_cast<uint64_t>(block.header.base_fee_per_gas.value_or(0)),
        .excess_blob_gas = block.header.excess_blob_gas.value_or(0),
        .blob_base_fee = block.header.blob_gas_price(config).value_or(0),
    };
    for (const auto& o : block.ommers)
        evm1_block_.ommers.emplace_back(evmone::state::Ommer{o.beneficiary, static_cast<uint32_t>(block.header.number - o.number)});
    if (block.withdrawals) {
        for (const auto& w : *block.withdrawals)
            evm1_block_.withdrawals.emplace_back(evmone::state::Withdrawal{w.index, w.validator_index, w.address, w.amount});
    }
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    // Plain debug assertion instead of SILKWORM_ASSERT not to validate txn twice (see execute_block_no_post_validation)
    // assert(protocol::validate_transaction(txn, state_, available_gas()) == ValidationResult::kOk);

    StateView evm1_state_view{state_};
    BlockHashes evm1_block_hashes{evm_};

    evmone::state::Transaction evm1_txn{
        .type = static_cast<evmone::state::Transaction::Type>(txn.type),
        .data = txn.data,
        .gas_limit = static_cast<int64_t>(txn.gas_limit),
        .max_gas_price = txn.max_fee_per_gas,
        .max_priority_gas_price = txn.max_priority_fee_per_gas,
        .max_blob_gas_price = txn.max_fee_per_blob_gas,
        .sender = *txn.sender(),
        .to = txn.to,
        .value = txn.value,
        // access_list
        // blob_hashes
        // TODO: This should be corrected in the evmone APIv2,
        //   because it uses transaction's chain id for CHAINID instruction.
        .chain_id = evm().config().chain_id,
        .nonce = txn.nonce};
    for (const auto& [account, storage_keys] : txn.access_list)
        evm1_txn.access_list.emplace_back(account, storage_keys);
    for (const evmc::bytes32& h : txn.blob_versioned_hashes)
        evm1_txn.blob_hashes.emplace_back(h);
    for (const auto& authorization : txn.authorizations) {
        evm1_txn.authorization_list.push_back({.chain_id = authorization.chain_id,
                                               .addr = authorization.address,
                                               .nonce = authorization.nonce,
                                               .signer = authorization.recover_authority(txn),
                                               .r = authorization.r,
                                               .s = authorization.s,
                                               .v = authorization.y_parity});
    }

    const auto rev = evm_.revision();
    const auto g0 = protocol::intrinsic_gas(txn, rev);
    if (g0 > 1000) {
    }
    // // SILKWORM_ASSERT(g0 <= INT64_MAX);  // true due to the precondition (transaction must be valid)
    const auto execution_gas_limit = txn.gas_limit - static_cast<uint64_t>(g0);

    // // Execute transaction with evmone APIv2.
    // // This must be done before the Silkworm execution so that the state is unmodified.
    // // evmone will not modify the state itself: state is read-only and the state modifications
    // // are provided as the state diff in the returned receipt.

    // // EIP-7623: Increase calldata cost
    const int64_t floor_cost = rev >= EVMC_PRAGUE ? static_cast<int64_t>(protocol::floor_cost(txn)) : 0;

    if (execution_gas_limit > 10000 || floor_cost > 120302) {
    }
    auto evm1_receipt = evmone::state::transition(
        evm1_state_view, evm1_block_, evm1_block_hashes, evm1_txn, rev, evm_.vm(), {.execution_gas_limit = static_cast<int64_t>(execution_gas_limit), .min_gas_cost = floor_cost});

    auto gas_used = static_cast<uint64_t>(evm1_receipt.gas_used);
    cumulative_gas_used_ += gas_used;

    // Prepare the receipt using the result from evmone.
    receipt.type = txn.type;
    receipt.success = evm1_receipt.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.logs.clear();  // can be dirty
    receipt.logs.reserve(evm1_receipt.logs.size());
    for (auto& [addr, data, topics] : evm1_receipt.logs)
        receipt.logs.emplace_back(Log{addr, std::move(topics), std::move(data)});
    receipt.bloom = logs_bloom(receipt.logs);

    if (evm1_v2_) {
        apply_state_diff(evm1_receipt.state_diff);
        return;
    }

    state_.clear_journal_and_substate();

    const std::optional<evmc::address> sender{txn.sender()};
    // // SILKWORM_ASSERT(sender);

    update_access_lists(*sender, txn, rev);

    if (txn.to) {
        // EVM itself increments the nonce for contract creation
        state_.set_nonce(*sender, txn.nonce + 1);
    }

    const BlockHeader& header{evm_.block().header};

    const intx::uint256 sender_initial_balance{state_.get_balance(*sender)};
    const intx::uint256 recipient_initial_balance{state_.get_balance(evm_.beneficiary)};

    // EIP-1559 normal gas cost
    const intx::uint256 base_fee_per_gas{header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    state_.subtract_from_balance(*sender, txn.gas_limit * effective_gas_price);

    // EIP-4844 blob gas cost (calc_data_fee)
    const intx::uint256 blob_gas_price{header.blob_gas_price(evm_.config()).value_or(0)};
    state_.subtract_from_balance(*sender, txn.total_blob_gas() * blob_gas_price);

    const CallResult vm_res = evm_.execute(txn, execution_gas_limit);
    // SILKWORM_ASSERT((vm_res.status == EVMC_SUCCESS) == receipt.success);
    // SILKWORM_ASSERT(state_.logs().size() == receipt.logs.size());

    auto gas_left = calculate_refund_gas(txn, vm_res.gas_left, vm_res.gas_refund);

    gas_used = txn.gas_limit - gas_left;

    //  EIP-7623: Increase calldata cost
    if (evm().revision() >= EVMC_PRAGUE) {
        gas_used = std::max(gas_used, protocol::floor_cost(txn));
        // SILKWORM_ASSERT(gas_used <= txn.gas_limit);
    }

    gas_left = txn.gas_limit - gas_used;
    state_.add_to_balance(*txn.sender(), gas_left * effective_gas_price);

    // award the fee recipient
    const intx::uint256 amount{txn.priority_fee_per_gas(base_fee_per_gas) * gas_used};
    state_.add_to_balance(evm_.beneficiary, amount);

    if (rev >= EVMC_LONDON) {
        const evmc::address* burnt_contract{protocol::bor::config_value_lookup(evm_.config().burnt_contract,
                                                                               header.number)};
        if (burnt_contract) {
            const intx::uint256 would_be_burnt{gas_used * base_fee_per_gas};
            state_.add_to_balance(*burnt_contract, would_be_burnt);
        }
    }

    rule_set_.add_fee_transfer_log(state_, amount, *sender, sender_initial_balance,
                                   evm_.beneficiary, recipient_initial_balance);

    state_.finalize_transaction(rev);

    check_evm1_execution_result(evm1_receipt.state_diff, state_);
}

CallResult ExecutionProcessor::call(const Transaction& txn) noexcept {
    const std::optional<evmc::address> sender{txn.sender()};
    // SILKWORM_ASSERT(sender);

    ValidationResult validation_result = protocol::validate_call_precheck(txn, evm_);
    if (validation_result != ValidationResult::kOk) {
        return {validation_result, EVMC_SUCCESS, 0, {}, {}};
    }

    const BlockHeader& header{evm_.block().header};
    const intx::uint256 base_fee_per_gas{header.base_fee_per_gas.value_or(0)};

    const intx::uint256 effective_gas_price{txn.max_fee_per_gas >= base_fee_per_gas ? txn.effective_gas_price(base_fee_per_gas)
                                                                                    : txn.max_priority_fee_per_gas};

    const evmc_revision rev{evm_.revision()};
    update_access_lists(*sender, txn, rev);

    if (txn.to) {
        state_.set_nonce(*sender, state_.get_nonce(*txn.sender()) + 1);
    }

    intx::uint256 required_funds = protocol::compute_call_cost(txn, effective_gas_price, evm_);
    validation_result = protocol::validate_call_funds(txn, evm_, state_.get_balance(*txn.sender()));
    if (validation_result != ValidationResult::kOk) {
        return {validation_result, EVMC_SUCCESS, 0, {}, {}};
    }
    state_.subtract_from_balance(*txn.sender(), required_funds);
    const intx::uint128 g0{protocol::intrinsic_gas(txn, evm_.revision())};
    const auto result = evm_.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0));

    uint64_t gas_used{txn.gas_limit - result.gas_left};

    const uint64_t gas_left_plus_refund = calculate_refund_gas(txn, result.gas_left, result.gas_refund);
    uint64_t gas_refund = gas_left_plus_refund - result.gas_left;
    gas_used = txn.gas_limit - gas_left_plus_refund;
    //  EIP-7623: Increase calldata cost
    if (evm().revision() >= EVMC_PRAGUE) {
        gas_used = std::max(gas_used, protocol::floor_cost(txn));
        // SILKWORM_ASSERT(gas_used <= txn.gas_limit);
    }
    uint64_t gas_left = txn.gas_limit - gas_used;
    state_.add_to_balance(*txn.sender(), gas_left * effective_gas_price);

    // Reward the fee recipient
    const intx::uint256 priority_fee_per_gas{txn.max_fee_per_gas >= base_fee_per_gas ? txn.priority_fee_per_gas(base_fee_per_gas)
                                                                                     : txn.max_priority_fee_per_gas};

    state_.add_to_balance(evm_.beneficiary, priority_fee_per_gas * gas_used);

    // for (auto& tracer : evm_.tracers()) {
    //     tracer.get().on_reward_granted(result, state_);
    // }
    state_.finalize_transaction(evm_.revision());

    // evm_.remove_tracers();

    return {ValidationResult::kOk, result.status, gas_left, gas_refund, gas_used, result.data, result.error_message};
}

void ExecutionProcessor::reset() {
    state_.clear_journal_and_substate();
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    return evm_.block().header.gas_limit - cumulative_gas_used_;
}

void ExecutionProcessor::update_access_lists(const evmc::address& sender, const Transaction& txn, evmc_revision rev) noexcept {
    state_.access_account(sender);

    if (txn.to) {
        state_.access_account(*txn.to);
    }

    for (const AccessListEntry& ae : txn.access_list) {
        state_.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            state_.access_storage(ae.account, key);
        }
    }

    if (rev >= EVMC_SHANGHAI) {
        // EIP-3651: Warm COINBASE
        state_.access_account(evm_.beneficiary);
    }
}

uint64_t ExecutionProcessor::calculate_refund_gas(const Transaction& txn, uint64_t gas_left, uint64_t gas_refund) const noexcept {
    const evmc_revision rev{evm_.revision()};

    const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? protocol::kMaxRefundQuotientLondon
                                                          : protocol::kMaxRefundQuotientFrontier};
    const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
    uint64_t refund = std::min(gas_refund, max_refund);
    gas_left += refund;

    return gas_left;
}

void ExecutionProcessor::apply_state_diff(const evmone::state::StateDiff& diff) {
    for (const auto& m : diff.modified_accounts) {
        // Ensure the object exists with a current account, bypassing the journal.
        auto* obj = state_.get_object(m.addr);
        if (obj == nullptr) {
            obj = &state_.objects_[m.addr];
            obj->current = Account{};
        } else if (!obj->current) {
            obj->current = Account{};
        }

        if (m.code) {
            const bool is_delegated = eip7702::is_code_delegated(*m.code);
            // Wipe storage for contract creation (non-journaled).
            if (!is_delegated && !state_.delegated_designations_.contains(m.addr)) {
                state_.storage_.erase(m.addr);
            }
            obj->current->code_hash = std::bit_cast<evmc_bytes32>(keccak256(*m.code));
            if (is_delegated) {
                state_.delegated_designations_.insert(m.addr);
            }
            state_.new_code_.try_emplace(obj->current->code_hash, m.code->begin(), m.code->end());
        }

        obj->current->nonce = m.nonce;
        obj->current->balance = m.balance;
        auto& storage = state_.storage_[m.addr];
        for (const auto& [k, v] : m.modified_storage) {
            storage.committed[k].original = v;
        }
    }
    for (const auto& a : diff.deleted_accounts) {
        state_.destruct(a);
    }
}

ValidationResult ExecutionProcessor::execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept {
    const evmc_revision rev{evm_.revision()};
    rule_set_.initialize(evm_);

    // Block-start system calls (EIP-4788 beacon roots, EIP-2935 history storage)
    {
        StateView state_view{state_};
        BlockHashes block_hashes{evm_};
        auto diff = evmone::state::system_call_block_start(
            state_view, evm1_block_, block_hashes, rev, evm_.vm());
        apply_state_diff(diff);
    }

    state_.finalize_transaction(rev);

    cumulative_gas_used_ = 0;

    const Block& block{evm_.block()};

    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};

    for (const auto& txn : block.transactions) {
        const ValidationResult err{protocol::validate_transaction(txn, state_, available_gas())};
        if (err != ValidationResult::kOk) {
            return err;
        }
        execute_transaction(txn, *receipt_it);
        ++receipt_it;
    }

    std::vector<Log> logs;
    logs.reserve(receipts.size());
    for (const auto& receipt : receipts) {
        std::ranges::copy(receipt.logs, std::back_inserter(logs));
    }
    state_.clear_journal_and_substate();

    // Block-end system calls (EIP-7002 withdrawals, EIP-7251 consolidations)
    // + requests hash validation
    if (rev >= EVMC_PRAGUE && evm_.block().header.requests_hash) {
        // Collect deposit requests from logs (EIP-6110)
        FlatRequests flat_requests;
        if (!flat_requests.extract_deposits_from_logs(logs))
            return ValidationResult::kRequestsProcessingFailure;

        StateView state_view{state_};
        BlockHashes block_hashes{evm_};
        auto requests_result = evmone::state::system_call_block_end(
            state_view, evm1_block_, block_hashes, rev, evm_.vm());
        if (!requests_result.has_value())
            return ValidationResult::kRequestsProcessingFailure;
        apply_state_diff(requests_result->state_diff);

        // Add withdrawal + consolidation request data from system calls
        using evmone::state::Requests;
        static_assert(static_cast<uint8_t>(Requests::Type::deposit) == static_cast<uint8_t>(FlatRequestType::kDepositRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::withdrawal) == static_cast<uint8_t>(FlatRequestType::kWithdrawalRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::consolidation) == static_cast<uint8_t>(FlatRequestType::kConsolidationRequest));
        for (const auto& req : requests_result->requests) {
            const auto type = static_cast<FlatRequestType>(static_cast<uint8_t>(req.type()));
            flat_requests.add_request(type, Bytes{req.data()});
        }

        // Validate requests hash
        if (flat_requests.calculate_sha256() != evm_.block().header.requests_hash)
            return ValidationResult::kRequestsRootMismatch;
    }

    const auto finalization_result = rule_set_.finalize(state_, block, evm_, logs);
    state_.finalize_transaction(rev);

    return finalization_result;
}

ValidationResult ExecutionProcessor::execute_block(std::vector<Receipt>& receipts) noexcept {
    if (const ValidationResult res{execute_block_no_post_validation(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    const auto& header{evm_.block().header};

    if (cumulative_gas_used_ != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    if (evm_.revision() >= EVMC_BYZANTIUM) {
        // Prior to Byzantium (EIP-658), receipts contained the root of the state after each individual transaction.
        // We don't calculate such intermediate state roots and thus can't verify the receipt root before Byzantium.
        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
        if (receipt_root != header.receipts_root) {
            return ValidationResult::kWrongReceiptsRoot;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (bloom != header.logs_bloom) {
        return ValidationResult::kWrongLogsBloom;
    }

    return ValidationResult::kOk;
}

void ExecutionProcessor::flush_state() {
    state_.write_to_db(evm_.block().header.number);
}

// //! \brief Notify the registered tracers at the start of block execution.
// void ExecutionProcessor::notify_block_execution_start(const Block& block) {
//     for (auto& tracer : evm_.tracers()) {
//         tracer.get().on_block_start(block);
//     }
// }

// //! \brief Notify the registered tracers at the end of block execution.
// void ExecutionProcessor::notify_block_execution_end(const Block& block) {
//     for (auto& tracer : evm_.tracers()) {
//         tracer.get().on_block_end(block);
//     }
// }

}  // namespace silkworm
