// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <evmc/evmc.h>
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#ifdef Z6M_HASH_STATE
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

// Underlying type is int so consumers can store non-enumerator sentinel values.
enum class [[nodiscard]] ValidationResult : int {
    kOk,  // All checks passed

    kUnknownProtocolRuleSet,  // Unsupported protocol rule set
    kFutureBlock,             // Block has a timestamp in the future

    kWrongStateRoot,         // wrong Hr
    kWrongOmmersHash,        // wrong Ho
    kWrongTransactionsRoot,  // wrong Ht
    kWrongReceiptsRoot,      // wrong He
    kWrongLogsBloom,         // wrong Hb

    kUnknownParent,                 // P(H) = ∅ ∨ Hi ≠ P(H)Hi + 1
    kUnknownParentTotalDifficulty,  // failed to look up parent's total difficulty
    kWrongDifficulty,               // Hd ≠ D(H)
    kGasAboveLimit,                 // Hg > Hl
    kInvalidGasLimit,               // |Hl-P(H)Hl|≥P(H)Hl/1024 ∨ Hl<5000
    kInvalidTimestamp,              // Hs ≤ P(H)Hs
    kExtraDataTooLong,              // ‖Hx‖ > 32
    kWrongDaoExtraData,             // see EIP-779
    kInvalidSeal,                   // Nonce or mix_hash (invalid Proof of Work)

    kMissingField,     // e.g. missing withdrawals in a post-Shanghai block
    kFieldBeforeFork,  // e.g. withdrawals present in a pre-Shanghai block

    kSenderNoEOA,            // EIP-3607: σ[S(T)]c ≠ KEC( () )
    kWrongNonce,             // Tn ≠ σ[S(T)]n
    kIntrinsicGas,           // g0 > Tg
    kInsufficientFunds,      // v0 > σ[S(T)]b
    kBlockGasLimitExceeded,  // Tg > BHl - l(BR)u

    kTooManyOmmers,       // ‖BU‖ > 2
    kInvalidOmmerHeader,  // ¬V(U)
    kNotAnOmmer,          // ¬k(U, P(BH)H, 6)
    kDuplicateOmmer,      // not well covered by the YP actually

    kWrongBlockGas,  // BHg ≠ l(BR)u

    kInvalidSignature,            // EIP-2 violated or otherwise invalid signature
    kWrongChainId,                // EIP-155
    kUnsupportedTransactionType,  // EIP-2718
    kNonceTooHigh,                // Tn ≥ 2^64 - 1 (EIP-2681)

    // EIP-1559: Fee market change for ETH 1.0 chain
    kWrongBaseFee,
    kMaxFeeLessThanBase,            // max_fee_per_gas < base_fee_per_gas
    kMaxPriorityFeeGreaterThanMax,  // max_priority_fee_per_gas > max_fee_per_gas

    // EIP-3675: Upgrade consensus to Proof-of-Stake
    kInvalidNonce,  // Hn != 0 in a PoS block
    kPoSBlockBeforeMerge,
    kPoWBlockAfterMerge,

    // EIP-3860: Limit and meter initcode
    kMaxInitCodeSizeExceeded,

    // EIP-4895: Beacon chain push withdrawals as operations
    kWrongWithdrawalsRoot,

    // EIP-4844: Shard Blob Transactions
    kWrongBlobGasUsed,
    kWrongExcessBlobGas,
    kNoBlobs,
    kTooManyBlobs,
    kWrongBlobCommitmentVersion,
    kMaxFeePerBlobGasTooLow,  // max_fee_per_blob_gas < blob_gas_price

    // EIP-4844 and EIP 7702
    kProhibitedContractCreation,  // Blob and SetCode transactions cannot have the form of a create transaction

    // EIP-7702
    kEmptyAuthorizations,

    // EIP-7685: Requests root mismatch
    kRequestsRootMismatch,
    kRequestsProcessingFailure,

    // EIP-7623: Increase calldata cost
    kFloorCost,

    // EIP-7702 Set EOA account code
    kIncorrectAuthorization,

    // EIP-7825
    kMaxTransactionGasLimitExceeded,

    // EIP-7928: Block-Level Access Lists
    kBlockAccessListGasExceeded,   // BAL item count exceeds block.gas_limit / GAS_PER_ITEM
    kBlockAccessListHashMismatch,  // computed BAL hash != header.block_access_list_hash

    // Bor validation errors
    kMissingVanity,          // Block's extra-data section is shorter than 32 bytes, which is required to store the signer vanity
    kMissingSignature,       // Block's extra-data section doesn't seem to contain a 65 byte secp256k1 signature
    kInvalidMixDigest,       // Block's mix digest is non-zero
    kExtraValidators,        // Non-sprint-end block contains extra validator list
    kInvalidSpanValidators,  // Invalid validator list on sprint end block
};

namespace protocol {

    bool transaction_type_is_supported(TransactionType, evmc_revision);

    //! Pre-state checks; verifies the signature if the sender is not yet recovered.
    ValidationResult pre_validate_transaction(const Transaction& txn, evmc_revision revision, uint64_t chain_id,
                                              const std::optional<intx::uint256>& base_fee_per_gas,
                                              const std::optional<intx::uint256>& blob_gas_price);

    ValidationResult pre_validate_transactions(const Block& block, const ChainConfig& config);

    //! Needs state; pre_validate_transaction(txn) must have returned kOk.
    ValidationResult validate_transaction(const Transaction& txn, const ::zilkworm::ActiveState& state,
                                          uint64_t available_gas) noexcept;

    ValidationResult pre_validate_common_base(const Transaction& txn, evmc_revision revision, uint64_t chain_id,
                                              size_t non_zero_bytes) noexcept;

    ValidationResult pre_validate_common_forks(const Transaction& txn, evmc_revision rev,
                                               const std::optional<intx::uint256>& blob_gas_price,
                                               size_t non_zero_bytes) noexcept;

    //! \see EIP-1559: Fee market change for ETH 1.0 chain
    intx::uint256 expected_base_fee_per_gas(const BlockHeader& parent);

    //! \see EIP-4844: Shard Blob Transactions
    uint64_t calc_excess_blob_gas(const BlockHeader& header, const BlockHeader& parent, const ChainConfig& chain_config);

    evmc::bytes32 compute_transaction_root(const BlockBody& body);

    std::optional<evmc::bytes32> compute_withdrawals_root(const BlockBody& body);

    evmc::bytes32 compute_ommers_hash(const BlockBody& body);


}  // namespace protocol

}  // namespace silkworm
