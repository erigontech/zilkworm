// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone/test/state/block.hpp>
#include <evmone/test/state/state_diff.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/state/intra_block_state.hpp>
#include <zilk_core/core/state/state.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/receipt.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

class ExecutionProcessor {
  public:
    ExecutionProcessor(const ExecutionProcessor&) = delete;
    ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

    ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set, State& state, const ChainConfig& config);

    /**
     * Execute a transaction, but do not write to the DB yet.
     * Precondition: transaction must be valid.
     */
    void execute_transaction(const Transaction& txn, Receipt& receipt) noexcept;

    //! \brief Execute the block.
    //! \remarks Warning: This method does not verify state root; pre-Byzantium receipt root isn't validated either.
    //! \pre RuleSet's validate_block_header & pre_validate_block_body must return kOk.
    ValidationResult execute_block(std::vector<Receipt>& receipts) noexcept;

    //! \brief Flush IntraBlockState into cumulative State.
    void flush_state();

    uint64_t available_gas() const noexcept;

    IntraBlockState& intra_block_state() { return state_; }
    const IntraBlockState& intra_block_state() const { return state_; }

    evmc_revision revision() const noexcept;

    evmc::bytes32 get_block_hash(int64_t block_num) noexcept;

    void reset();

  private:
    ValidationResult execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept;

    /// Apply an evmone StateDiff to state_.
    void apply_state_diff(const evmone::state::StateDiff& diff);

    uint64_t cumulative_gas_used_{0};
    IntraBlockState state_;
    protocol::RuleSet& rule_set_;
    const Block& block_;
    const ChainConfig& config_;
    evmc::address beneficiary_;
    evmc::VM vm_;
    evmone::state::BlockInfo evm1_block_;
    std::vector<evmc::bytes32> block_hashes_{};
};

}  // namespace silkworm
