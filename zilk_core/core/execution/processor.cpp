// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "processor.hpp"

#include <algorithm>
#include <limits>
#include <variant>

#include <evmone/evmone.h>
#include <evmone/vm.hpp>
#include <evmone/test/state/errors.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/test/state/system_contracts.hpp>
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

    //! The ValidationResult of an evmone transaction validation error.
    ValidationResult to_validation_result(std::error_code ec) noexcept {
        using namespace evmone::state;
        switch (ec.value()) {
            case INTRINSIC_GAS_TOO_LOW:
                return ValidationResult::kIntrinsicGas;
            case TYPE_NOT_SUPPORTED:
                return ValidationResult::kUnsupportedTransactionType;
            case INSUFFICIENT_ACCOUNT_FUNDS:
                return ValidationResult::kInsufficientFunds;
            case NONCE_IS_MAX:
                return ValidationResult::kNonceTooHigh;
            case NONCE_TOO_HIGH:
            case NONCE_TOO_LOW:
                return ValidationResult::kWrongNonce;
            case PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS:
                return ValidationResult::kMaxPriorityFeeGreaterThanMax;
            case INSUFFICIENT_MAX_FEE_PER_GAS:
                return ValidationResult::kMaxFeeLessThanBase;
            case INSUFFICIENT_MAX_FEE_PER_BLOB_GAS:
                return ValidationResult::kMaxFeePerBlobGasTooLow;
            case GAS_ALLOWANCE_EXCEEDED:
                return ValidationResult::kBlockGasLimitExceeded;
            case SENDER_NOT_EOA:
                return ValidationResult::kSenderNoEOA;
            case INITCODE_SIZE_EXCEEDED:
                return ValidationResult::kMaxInitCodeSizeExceeded;
            case CREATE_BLOB_TX:
            case CREATE_SET_CODE_TX:
                return ValidationResult::kProhibitedContractCreation;
            case EMPTY_BLOB_HASHES_LIST:
                return ValidationResult::kNoBlobs;
            case INVALID_BLOB_HASH_VERSION:
                return ValidationResult::kWrongBlobCommitmentVersion;
            case BLOB_GAS_LIMIT_EXCEEDED:
                return ValidationResult::kTooManyBlobs;
            case EMPTY_AUTHORIZATION_LIST:
                return ValidationResult::kEmptyAuthorizations;
            case GAS_LIMIT_EXCEEDS_MAXIMUM:
                return ValidationResult::kMaxTransactionGasLimitExceeded;
            case INVALID_CHAIN_ID:
                return ValidationResult::kWrongChainId;
            default:
                return ValidationResult::kInvalidSignature;
        }
    }
}  // namespace

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set,
                                       ActiveState& direct, const ChainConfig& config)
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
    return direct_.get_block_hash(block_.header, static_cast<uint64_t>(block_num));
}

evmone::state::Transaction ExecutionProcessor::to_evmone(const Transaction& txn) const noexcept {
    evmone::state::Transaction evm1_txn{
        .type = static_cast<evmone::state::Transaction::Type>(txn.type),
        // Non-owning view; source outlives the evmone transaction
        .data = txn.data,
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
    return evm1_txn;
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    const auto evm1_txn = to_evmone(txn);
    // No block budget to check against: the caller has validated the transaction.
    constexpr auto kNoLimit = std::numeric_limits<int64_t>::max();
    const auto tx_props = evmone::state::validate_transaction(evm1_block_, evm1_txn, revision(),
                                                              kNoLimit, kNoLimit, kNoLimit);
    execute_transaction(txn, evm1_txn, std::get<evmone::state::TransactionProperties>(tx_props),
                        receipt);
}

void ExecutionProcessor::execute_transaction(const Transaction& txn,
                                             const evmone::state::Transaction& evm1_txn,
                                             const evmone::state::TransactionProperties& tx_props,
                                             Receipt& receipt) noexcept {
    ActiveStateView evm1_state_view{direct_};
    BlockHashes evm1_block_hashes{*this};

    for (const auto& authorization : txn.authorizations) {
        // The authorization's delegation marker, kept by its hash before the transaction runs:
        // evmone sets it on the authority inside the transaction, and a same-marker read there may
        // find the bytes omitted from the witness (EIP-8025 optional proofs). Address zero clears
        // and writes no marker.
        if (!evmc::is_zero(authorization.address)) {
            uint8_t marker[23];
            std::memcpy(marker, eip7702::kDelegationBytes, 3);
            std::memcpy(marker + 3, authorization.address.bytes, 20);
            direct_.note_created_code(ByteView{marker, sizeof(marker)});
        }
    }

    const auto rev = revision();
    auto evm1_receipt = evmone::state::transition(
        evm1_state_view, evm1_block_, evm1_block_hashes, evm1_txn, rev, vm_, tx_props);

    const auto gas_used = static_cast<uint64_t>(evm1_receipt.gas_used);
    cumulative_gas_used_ += gas_used;
    if (rev >= EVMC_AMSTERDAM) {
        // The execution dimension is the block gas less the state one (EIP-8037).
        sum_regular_block_gas_ += evm1_receipt.block_gas_used - evm1_receipt.state_gas_used;
        sum_state_block_gas_ += evm1_receipt.state_gas_used;
        // EIP-7928: the diff lists the reads; recorded against the state before it is applied.
        bal_builder_.record_diff(static_cast<uint32_t>(tx_index_ + 1), evm1_receipt.state_diff,
                                 evm1_state_view);
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
    logs_bloom(receipt.bloom, receipt.logs);

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
        ActiveStateView state_view{direct_};
        BlockHashes block_hashes{*this};
        auto diff = evmone::state::system_call_block_start(
            state_view, evm1_block_, block_hashes, rev, vm_);
        if (rev >= EVMC_AMSTERDAM)
            bal_builder_.record_diff(0, diff, state_view);
        apply_state_diff(diff);
    }

    if (rev >= EVMC_SPURIOUS_DRAGON) {
        direct_.destruct_dead_among(direct_.touched());
    }

    cumulative_gas_used_ = 0;

#if defined(AIRBENDER) || defined(SP1)
    // Recover all senders up front so that their signatures share inversions; validation and
    // execution then read the cached results (identical to recovering each one lazily).
    Transaction::recover_senders(block_.transactions);
#endif

    receipts.resize(block_.transactions.size());
    auto receipt_it{receipts.begin()};

    // The block's blob gas is checked against its header, not per transaction.
    constexpr auto kNoBlobGasLimit = std::numeric_limits<int64_t>::max();
    const auto block_gas_limit = static_cast<int64_t>(block_.header.gas_limit);

    for (const auto& txn : block_.transactions) {
        if (!txn.sender()) {
            return ValidationResult::kInvalidSignature;
        }
        const auto evm1_txn = to_evmone(txn);

        // Amsterdam checks the gas limit against both dimensions of the block gas (EIP-8037).
        const auto block_gas_left = rev >= EVMC_AMSTERDAM
                                        ? block_gas_limit - sum_regular_block_gas_
                                        : static_cast<int64_t>(available_gas());
        const auto block_state_gas_left = block_gas_limit - sum_state_block_gas_;
        const auto tx_props = evmone::state::validate_transaction(
            evm1_block_, evm1_txn, rev, block_gas_left, block_state_gas_left, kNoBlobGasLimit);
        if (const auto* ec = std::get_if<std::error_code>(&tx_props)) {
            return to_validation_result(*ec);
        }
        if (const auto ec = evmone::state::validate_transaction_with_state(ActiveStateView{direct_}, evm1_txn)) {
            return to_validation_result(ec);
        }

        execute_transaction(txn, evm1_txn, std::get<evmone::state::TransactionProperties>(tx_props),
                            *receipt_it);
        ++receipt_it;
    }

    direct_.clear_touched();

    // EIP-7928: the withdrawals and the block-end system calls share the last index.
    const auto post_block_index = static_cast<uint32_t>(block_.transactions.size() + 1);
    if (rev >= EVMC_AMSTERDAM) {
        // Finalize via evmone so withdrawals and the EIP-161 sweep produce a
        // StateDiff the BAL can record; rule_set_.finalize mutates DirectState
        // in place and leaves nothing to record. Amsterdam is always
        // post-merge, so the block reward is absent. The withdrawals are applied
        // before the block-end system calls.
        ActiveStateView state_view{direct_};
        const auto fin_diff =
            evmone::state::finalize(state_view, rev, block_.header.beneficiary,
                                    /*block_reward=*/std::nullopt, evm1_block_.ommers,
                                    evm1_block_.withdrawals);
        bal_builder_.record_diff(post_block_index, fin_diff, state_view);
        apply_state_diff(fin_diff);
    }

    // Block-end system calls (EIP-7002 withdrawals, EIP-7251 consolidations) + requests hash validation
    if (rev >= EVMC_PRAGUE && block_.header.requests_hash) {
        // Collect deposit requests from logs (EIP-6110), in block order: receipt by receipt, each
        // receipt's logs in order (the receipts own the logs; no block-wide copy of them is made).
        FlatRequests flat_requests;
        for (const Receipt& receipt : receipts) {
            if (!flat_requests.extract_deposits_from_logs(receipt.logs))
                return ValidationResult::kRequestsProcessingFailure;
        }

        ActiveStateView state_view{direct_};
        BlockHashes block_hashes{*this};
        auto block_end_result = evmone::state::system_call_block_end(
            state_view, evm1_block_, block_hashes, rev, vm_);
        const auto* requests_result = std::get_if<evmone::state::RequestsResult>(&block_end_result);
        if (requests_result == nullptr)
            return ValidationResult::kRequestsProcessingFailure;
        if (rev >= EVMC_AMSTERDAM)
            bal_builder_.record_diff(post_block_index, requests_result->state_diff, state_view);
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

    if (rev < EVMC_AMSTERDAM) {
        const auto finalization_result = rule_set_.finalize(direct_, block_);
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
        // execute_transaction sets the bloom of a receipt without logs to all zeros.
        if (!receipt.logs.empty()) {
            join(bloom, receipt.bloom);
        }
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
