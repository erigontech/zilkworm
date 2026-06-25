// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone/test/state/block.hpp>
#include <evmone/test/state/state_diff.hpp>
#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/receipt.hpp>
#include <zilk_core/core/types/transaction.hpp>

using ::zilkworm::DirectState;
using ::zilkworm::DirectStateView;

namespace silkworm {

class ExecutionProcessor {
  public:
    ExecutionProcessor(const ExecutionProcessor&) = delete;
    ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

    ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set,
                       DirectState& direct, const ChainConfig& config);

    ~ExecutionProcessor();

    /**
     * Execute a transaction, but do not write to the DB yet.
     * Precondition: transaction must be valid.
     */
    void execute_transaction(const Transaction& txn, Receipt& receipt) noexcept;

    //! \brief Execute the block.
    //! \remarks Warning: This method does not verify state root; pre-Byzantium receipt root isn't validated either.
    //! \pre RuleSet's validate_block_header & pre_validate_block_body must return kOk.
    ValidationResult execute_block(std::vector<Receipt>& receipts) noexcept;

    uint64_t available_gas() const noexcept;

  public:
    //! Look up an ancestor block hash via the witness-side header store.
    //! Public so the file-local BlockHashes adapter (evmone callback) can forward.
    evmc::bytes32 get_block_hash_for_evm(int64_t block_num) const noexcept;

  private:
    //! Evaluate the chain's revision at the current block's number/timestamp.
    evmc_revision revision() const noexcept;

    /// Apply an evmone StateDiff to DirectState.
    void apply_state_diff(const evmone::state::StateDiff& diff);
    ValidationResult execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept;

    uint64_t cumulative_gas_used_{0};
    DirectState& direct_;
    protocol::RuleSet& rule_set_;
    const Block& block_;
    const ChainConfig& config_;
    evmc::address beneficiary_;
    evmc::VM vm_;
    evmone::state::BlockInfo evm1_block_;
};

}  // namespace silkworm
