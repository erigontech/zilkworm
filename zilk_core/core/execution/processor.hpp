// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone/test/state/bal.hpp>
#include <evmone/test/state/block.hpp>
#include <evmone/test/state/state_diff.hpp>
#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#ifdef Z6M_HASH_STATE
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/receipt.hpp>
#include <zilk_core/core/types/transaction.hpp>

using ::zilkworm::ActiveState;
using ::zilkworm::ActiveStateView;

namespace silkworm {

class ExecutionProcessor {
  public:
    ExecutionProcessor(const ExecutionProcessor&) = delete;
    ExecutionProcessor& operator=(const ExecutionProcessor&) = delete;

    ExecutionProcessor(const Block& block, protocol::RuleSet& rule_set,
                       ActiveState& direct, const ChainConfig& config);

    ~ExecutionProcessor();

    /// Executes a valid transaction without writing to the DB.
    void execute_transaction(const Transaction& txn, Receipt& receipt) noexcept;

    //! Requires validated header and body; verifies neither the state root nor the pre-Byzantium receipt root.
    ValidationResult execute_block(std::vector<Receipt>& receipts) noexcept;

    uint64_t available_gas() const noexcept;

  public:
    //! Public so the file-local BlockHashes adapter can forward.
    evmc::bytes32 get_block_hash_for_evm(int64_t block_num) const noexcept;

  private:
    evmc_revision revision() const noexcept;

    void apply_state_diff(const evmone::state::StateDiff& diff);
    ValidationResult execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept;

    uint64_t cumulative_gas_used_{0};
    // Amsterdam per-dimension block gas (EIP-7778/8037).
    int64_t sum_regular_block_gas_{0};
    int64_t sum_state_block_gas_{0};
    evmone::state::BalBuilder bal_builder_{};
    size_t tx_index_{0};
    ActiveState& direct_;
    protocol::RuleSet& rule_set_;
    const Block& block_;
    const ChainConfig& config_;
    evmc::address beneficiary_;
    evmc::VM vm_;
    evmone::state::BlockInfo evm1_block_;
};

}  // namespace silkworm
