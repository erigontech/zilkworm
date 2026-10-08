// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "processor.hpp"

#include <algorithm>
#include <variant>

#include <evmone/evmone.h>
#include <evmone/vm.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/test/state/system_contracts.hpp>
#include <zilk_core/core/protocol/intrinsic_gas.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/vector_root.hpp>
#include <zilk_core/core/types/eip_7685_requests.hpp>

namespace silkworm {

namespace {
    class BlockHashes final : public evmone::state::BlockHashes {
        ExecutionProcessor& execution_processor_;

      public:
        explicit BlockHashes(ExecutionProcessor& ep) noexcept : execution_processor_{ep} {}
        evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override {
            return execution_processor_.get_block_hash_for_evm(block_number);
        }
    };
}  // namespace

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set,
                                       DirectState& direct, const ChainConfig& config)
    : direct_{direct},
      rule_set_{rule_set},
      block_{block},
      config_{config},
      beneficiary_{rule_set.get_beneficiary(block.header)},
      vm_{new evmone::VM{}} {
    evm1_block_ = {
        .number = static_cast<int64_t>(block.header.number),
        .timestamp = static_cast<int64_t>(block.header.timestamp),
        .gas_limit = static_cast<int64_t>(block.header.gas_limit),
        .coinbase = block.header.beneficiary,
        .difficulty = static_cast<int64_t>(block.header.difficulty),
        .prev_randao = block.header.difficulty == 0 ? block.header.prev_randao : intx::be::store<evmone::state::bytes32>(intx::uint256{block.header.difficulty}),
        .parent_beacon_block_root = block.header.parent_beacon_block_root.value_or(evmc::bytes32{}),
        .base_fee = static_cast<uint64_t>(block.header.base_fee_per_gas.value_or(0)),
        .chain_id = config.chain_id,
        .excess_blob_gas = block.header.excess_blob_gas.value_or(0),
        .blob_base_fee = block.header.blob_gas_price(config).value_or(0),
        .slot_number = block.header.slot_number.value_or(0),  // EIP-7843
    };
    for (const auto& o : block.ommers)
        evm1_block_.ommers.emplace_back(evmone::state::Ommer{o.beneficiary, static_cast<uint32_t>(block.header.number - o.number)});
    if (block.withdrawals) {
        evm1_block_.withdrawals.reserve(block.withdrawals->size());
        for (const auto& w : *block.withdrawals)
            evm1_block_.withdrawals.emplace_back(
                evmone::state::Withdrawal{w.index, w.validator_index, w.address, w.amount});
    }
}

ExecutionProcessor::~ExecutionProcessor() = default;

evmc_revision ExecutionProcessor::revision() const noexcept {
    return config_.revision(block_.header.number, block_.header.timestamp);
}

evmc::bytes32 ExecutionProcessor::get_block_hash_for_evm(int64_t block_num) const noexcept {
    return direct_.get_block_hash(static_cast<uint64_t>(block_num));
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    DirectStateView evm1_state_view{direct_};
    BlockHashes evm1_block_hashes{*this};

    evmone::state::Transaction evm1_txn{
        .type = static_cast<evmone::state::Transaction::Type>(txn.type),
        .data = Bytes{txn.data},
        .gas_limit = static_cast<int64_t>(txn.gas_limit),
        .max_gas_price = txn.max_fee_per_gas,
        .max_priority_gas_price = txn.max_priority_fee_per_gas,
        .max_blob_gas_price = txn.max_fee_per_blob_gas,
        .sender = *txn.sender(),
        .to = txn.to,
        .value = txn.value,
        // The chain's id: evmone validates the EIP-7702 authorizations' chain id against it.
        .chain_id = config_.chain_id,
        .nonce = txn.nonce};
    for (const auto& [account, storage_keys] : txn.access_list)
        evm1_txn.access_list.emplace_back(account, storage_keys);
    for (const evmc::bytes32& h : txn.blob_versioned_hashes)
        evm1_txn.blob_hashes.emplace_back(h);
    // evmone recovers the authority from the signature itself (EIP-7702).
    for (const auto& authorization : txn.authorizations) {
        evm1_txn.authorization_list.push_back({.chain_id = authorization.chain_id,
                                               .addr = authorization.address,
                                               .nonce = authorization.nonce,
                                               .y_parity = authorization.y_parity,
                                               .r = authorization.r,
                                               .s = authorization.s});
    }

    const auto rev = revision();
    const auto non_zero_bytes = txn.data_non_zero_bytes();

    // Amsterdam (EIP-2780/8037): g0 is regular gas only - every state-dependent
    // charge moved to the top frame (EELS #3126). The EIP-7623 floor follows the
    // EIP-7976/7981 token rules. evmone splits execution_gas_limit into the regular
    // budget and the state-gas reservoir itself, from intrinsic_regular_gas.
    evmone::state::TransactionProperties tx_props;
    if (rev >= EVMC_AMSTERDAM) {
        const auto cost = protocol::amsterdam_tx_gas_cost(txn, non_zero_bytes);
        tx_props = {.execution_gas_limit = static_cast<int64_t>(txn.gas_limit) - cost.regular,
                    .intrinsic_regular_gas = cost.regular,
                    .min_gas_cost = cost.floor};
    } else {
        const auto g0 = protocol::intrinsic_gas(txn, rev, non_zero_bytes);
        // EIP-7623: Increase calldata cost
        const int64_t floor_cost =
            rev >= EVMC_PRAGUE ? static_cast<int64_t>(protocol::floor_cost(txn, non_zero_bytes)) : 0;
        tx_props = {.execution_gas_limit =
                        static_cast<int64_t>(txn.gas_limit - static_cast<uint64_t>(g0)),
                    .min_gas_cost = floor_cost};
    }

    // EIP-7928: record cold account/slot accesses in the block access list.
    const evmone::state::BalStateView bal_view{evm1_state_view, bal_builder_};
    const auto& exec_view = rev >= EVMC_AMSTERDAM
                                ? static_cast<const evmone::state::StateView&>(bal_view)
                                : evm1_state_view;
    auto evm1_receipt =
        evmone::state::transition(exec_view, evm1_block_, evm1_block_hashes, evm1_txn, rev, vm_, tx_props);

    const auto gas_used = static_cast<uint64_t>(evm1_receipt.gas_used);
    cumulative_gas_used_ += gas_used;
    if (rev >= EVMC_AMSTERDAM) {
        sum_regular_block_gas_ += evm1_receipt.regular_block_gas;
        sum_state_block_gas_ += evm1_receipt.state_block_gas;
        // record_diff needs the pre-state (unwrapped) view, before apply_state_diff below.
        bal_builder_.record_diff(evmone::state::bal_tx_index::tx(tx_index_),
                                 evm1_receipt.state_diff, evm1_state_view);
    }
    ++tx_index_;

    // Prepare the receipt using the result from evmone.
    receipt.type = txn.type;
    receipt.success = evm1_receipt.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.logs.clear();  // can be dirty
    receipt.logs.reserve(evm1_receipt.logs.size());
    for (auto& [addr, data, topics] : evm1_receipt.logs)
        receipt.logs.emplace_back(Log{addr, std::move(topics), std::move(data)});
    receipt.bloom = logs_bloom(receipt.logs);

    apply_state_diff(evm1_receipt.state_diff);
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    // EIP-7778/8037 (Amsterdam): the block gas consumed so far is the maximum
    // of the two accounting dimensions.
    if (sum_regular_block_gas_ != 0 || sum_state_block_gas_ != 0) {
        const auto used = std::max(sum_regular_block_gas_, sum_state_block_gas_);
        return block_.header.gas_limit - static_cast<uint64_t>(used);
    }
    return block_.header.gas_limit - cumulative_gas_used_;
}

void ExecutionProcessor::apply_state_diff(const evmone::state::StateDiff& diff) {
    direct_.apply_state_diff(diff);
}

ValidationResult ExecutionProcessor::execute_block(std::vector<Receipt>& receipts) noexcept {
    const evmc_revision rev{revision()};
    rule_set_.initialize(block_, direct_);

    // Block-start system calls (EIP-4788 beacon roots, EIP-2935 history storage)
    {
        DirectStateView state_view{direct_};
        BlockHashes block_hashes{*this};
        const evmone::state::BalStateView bal_view{state_view, bal_builder_};
        const auto& sys_view = rev >= EVMC_AMSTERDAM
                                   ? static_cast<const evmone::state::StateView&>(bal_view)
                                   : state_view;
        auto diff = evmone::state::system_call_block_start(
            sys_view, evm1_block_, block_hashes, rev, vm_);
        if (rev >= EVMC_AMSTERDAM)
            bal_builder_.record_diff(evmone::state::bal_tx_index::PRE_BLOCK, diff, state_view);
        apply_state_diff(diff);
    }

    if (rev >= EVMC_SPURIOUS_DRAGON) {
        direct_.destruct_dead_among(direct_.touched());
    }

    cumulative_gas_used_ = 0;

    recover_senders(block_.transactions);

    receipts.resize(block_.transactions.size());
    auto receipt_it{receipts.begin()};

    for (const auto& txn : block_.transactions) {
        if (rev >= EVMC_AMSTERDAM) {
            // EIP-8037 "Transaction validation" rule 2: per-dimension worst-case
            // inclusion check with bare tx.gas_limit (execution-specs#2892).
            constexpr int64_t kTxMaxGasLimit = 0x1000000;  // 2**24, EIP-7825
            const auto block_gas_limit = static_cast<int64_t>(block_.header.gas_limit);
            const auto gas_limit = static_cast<int64_t>(txn.gas_limit);
            if (std::min(kTxMaxGasLimit, gas_limit) > block_gas_limit - sum_regular_block_gas_ ||
                gas_limit > block_gas_limit - sum_state_block_gas_) {
                return ValidationResult::kBlockGasLimitExceeded;
            }
        }
        // Amsterdam replaces the cumulative available-gas inclusion rule with the
        // per-dimension check above, so the per-tx budget is the whole block.
        const uint64_t gas_available =
            rev >= EVMC_AMSTERDAM ? block_.header.gas_limit : available_gas();
        const ValidationResult err{protocol::validate_transaction(txn, direct_, gas_available)};
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
    direct_.clear_touched();

    // Block-end system calls (EIP-7002 withdrawals, EIP-7251 consolidations) + requests hash validation
    if (rev >= EVMC_PRAGUE && block_.header.requests_hash) {
        // Collect deposit requests from logs (EIP-6110)
        FlatRequests flat_requests;
        if (!flat_requests.extract_deposits_from_logs(logs))
            return ValidationResult::kRequestsProcessingFailure;

        DirectStateView state_view{direct_};
        BlockHashes block_hashes{*this};
        const evmone::state::BalStateView bal_view{state_view, bal_builder_};
        const auto& sys_view = rev >= EVMC_AMSTERDAM
                                   ? static_cast<const evmone::state::StateView&>(bal_view)
                                   : state_view;
        auto block_end_result = evmone::state::system_call_block_end(
            sys_view, evm1_block_, block_hashes, rev, vm_);
        const auto* requests_result = std::get_if<evmone::state::RequestsResult>(&block_end_result);
        if (requests_result == nullptr)
            return ValidationResult::kRequestsProcessingFailure;
        if (rev >= EVMC_AMSTERDAM) {
            bal_builder_.record_diff(
                evmone::state::bal_tx_index::post_block(block_.transactions.size()),
                requests_result->state_diff, state_view);
        }
        apply_state_diff(requests_result->state_diff);

        using evmone::state::Requests;
        static_assert(static_cast<uint8_t>(Requests::Type::deposit) == static_cast<uint8_t>(FlatRequestType::kDepositRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::withdrawal) == static_cast<uint8_t>(FlatRequestType::kWithdrawalRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::consolidation) == static_cast<uint8_t>(FlatRequestType::kConsolidationRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::builder_deposit) == static_cast<uint8_t>(FlatRequestType::kBuilderDepositRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::builder_exit) == static_cast<uint8_t>(FlatRequestType::kBuilderExitRequest));
        for (const auto& req : requests_result->requests) {
            const auto type = static_cast<FlatRequestType>(static_cast<uint8_t>(req.type()));
            flat_requests.add_request(type, Bytes{req.data()});
        }
        // Validate requests hash
        if (flat_requests.calculate_sha256() != block_.header.requests_hash)
            return ValidationResult::kRequestsRootMismatch;
    }

    if (rev >= EVMC_AMSTERDAM) {
        // Finalize via evmone so withdrawals and the EIP-161 sweep produce a
        // StateDiff the BAL can record; rule_set_.finalize mutates DirectState
        // in place and leaves nothing to record. Amsterdam is always
        // post-merge, so the block reward is absent.
        DirectStateView state_view{direct_};
        const evmone::state::BalStateView bal_view{state_view, bal_builder_};
        const auto fin_diff =
            evmone::state::finalize(bal_view, rev, block_.header.beneficiary,
                                    /*block_reward=*/std::nullopt, evm1_block_.ommers,
                                    evm1_block_.withdrawals);
        bal_builder_.record_diff(
            evmone::state::bal_tx_index::post_block(block_.transactions.size()), fin_diff,
            state_view);
        apply_state_diff(fin_diff);
    } else {
        const auto finalization_result = rule_set_.finalize(direct_, block_, logs);
        if (finalization_result != ValidationResult::kOk) {
            if (rev >= EVMC_SPURIOUS_DRAGON) {
                direct_.destruct_dead_among(direct_.touched());
            }
            return finalization_result;
        }
    }
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        direct_.destruct_dead_among(direct_.touched());
    }

    const auto& header{block_.header};

    // EIP-7778 (Amsterdam): header.gas_used commits to max(regular, state).
    const uint64_t expected_gas_used =
        rev >= EVMC_AMSTERDAM
            ? static_cast<uint64_t>(std::max(sum_regular_block_gas_, sum_state_block_gas_))
            : cumulative_gas_used_;
    if (expected_gas_used != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    if (rev >= EVMC_BYZANTIUM) {
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

    // EIP-7928: validate the block-level access list commitment.
    if (rev >= EVMC_AMSTERDAM) {
        const auto bal = bal_builder_.build();
        if (bal.exceeds_gas_limit(header.gas_limit)) {
            return ValidationResult::kBlockAccessListGasExceeded;
        }
        if (bal.hash() != header.block_access_list_hash.value_or(evmc::bytes32{})) {
            return ValidationResult::kBlockAccessListHashMismatch;
        }
    }

    return ValidationResult::kOk;
}

}  // namespace silkworm
