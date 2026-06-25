// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "processor.hpp"

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
        .excess_blob_gas = block.header.excess_blob_gas.value_or(0),
        .blob_base_fee = block.header.blob_gas_price(config).value_or(0),
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
        .data = txn.data,
        .gas_limit = static_cast<int64_t>(txn.gas_limit),
        .max_gas_price = txn.max_fee_per_gas,
        .max_priority_gas_price = txn.max_priority_fee_per_gas,
        .max_blob_gas_price = txn.max_fee_per_blob_gas,
        .sender = *txn.sender(),
        .to = txn.to,
        .value = txn.value,
        // TODO: evmone APIv2 uses transaction's chain id for CHAINID instruction; should be config chain_id.
        .chain_id = config_.chain_id,
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

    const auto rev = revision();
    const auto g0 = protocol::intrinsic_gas(txn, rev);
    const auto execution_gas_limit = txn.gas_limit - static_cast<uint64_t>(g0);

    // EIP-7623: Increase calldata cost
    const int64_t floor_cost = rev >= EVMC_PRAGUE ? static_cast<int64_t>(protocol::floor_cost(txn)) : 0;
    auto evm1_receipt = evmone::state::transition(
        evm1_state_view, evm1_block_, evm1_block_hashes, evm1_txn, rev, vm_,
        {.execution_gas_limit = static_cast<int64_t>(execution_gas_limit), .min_gas_cost = floor_cost});

    const auto gas_used = static_cast<uint64_t>(evm1_receipt.gas_used);
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

    apply_state_diff(evm1_receipt.state_diff);
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
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
        auto diff = evmone::state::system_call_block_start(
            state_view, evm1_block_, block_hashes, rev, vm_);
        apply_state_diff(diff);
    }

    if (rev >= EVMC_SPURIOUS_DRAGON) {
        direct_.destruct_dead_among(direct_.touched());
    }

    cumulative_gas_used_ = 0;

    receipts.resize(block_.transactions.size());
    auto receipt_it{receipts.begin()};

    for (const auto& txn : block_.transactions) {
        const ValidationResult err{protocol::validate_transaction(txn, direct_, available_gas())};
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
        auto requests_result = evmone::state::system_call_block_end(
            state_view, evm1_block_, block_hashes, rev, vm_);
        if (!requests_result.has_value())
            return ValidationResult::kRequestsProcessingFailure;
        apply_state_diff(requests_result->state_diff);

        using evmone::state::Requests;
        static_assert(static_cast<uint8_t>(Requests::Type::deposit) == static_cast<uint8_t>(FlatRequestType::kDepositRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::withdrawal) == static_cast<uint8_t>(FlatRequestType::kWithdrawalRequest));
        static_assert(static_cast<uint8_t>(Requests::Type::consolidation) == static_cast<uint8_t>(FlatRequestType::kConsolidationRequest));
        for (const auto& req : requests_result->requests) {
            const auto type = static_cast<FlatRequestType>(static_cast<uint8_t>(req.type()));
            flat_requests.add_request(type, Bytes{req.data()});
        }
        // Validate requests hash
        if (flat_requests.calculate_sha256() != block_.header.requests_hash)
            return ValidationResult::kRequestsRootMismatch;
    }

    const auto finalization_result = rule_set_.finalize(direct_, block_, logs);
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        direct_.destruct_dead_among(direct_.touched());
    }

    if (finalization_result != ValidationResult::kOk) {
        return finalization_result;
    }

    const auto& header{block_.header};

    if (cumulative_gas_used_ != header.gas_used) {
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

    return ValidationResult::kOk;
}

}  // namespace silkworm
