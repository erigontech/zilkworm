// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "merge_rule_set.hpp"

#include <optional>
#include <utility>

#include <zilk_core/core/common/assert.hpp>

#include "param.hpp"

namespace silkworm::protocol {

MergeRuleSet::MergeRuleSet(RuleSetPtr pre_merge_rule_set, const ChainConfig& chain_config)
    : RuleSet{chain_config, /*prohibit_ommers=*/true},
      terminal_total_difficulty_{chain_config.terminal_total_difficulty.value_or(intx::uint256{0})},
      pre_merge_rule_set_{std::move(pre_merge_rule_set)} {}

ValidationResult MergeRuleSet::pre_validate_block_body(const Block& block, const BlockState& state) {
    if (block.header.difficulty != 0) {
        if (!pre_merge_rule_set_) {
            return ValidationResult::kUnknownProtocolRuleSet;
        }
        return pre_merge_rule_set_->pre_validate_block_body(block, state);
    }
    return RuleSet::pre_validate_block_body(block, state);
}

inline ValidationResult MergeRuleSet::validate_block_header(const BlockHeader& header, const BlockState& state,
                                                     bool with_future_timestamp_check) {
    return RuleSet::validate_block_header(header, state, with_future_timestamp_check);
}

ValidationResult MergeRuleSet::validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader&) {
    // SILKWORM_ASSERT(header.difficulty == 0);
    return header.nonce == BlockHeader::NonceType{} ? ValidationResult::kOk : ValidationResult::kInvalidNonce;
}

void MergeRuleSet::initialize(IntraBlockState& state, const Block& block) {
    if (block.header.difficulty != 0) {
        if (pre_merge_rule_set_) {
            pre_merge_rule_set_->initialize(state, block);
        }
        return;
    }
    // Post-merge system calls are handled by ExecutionProcessor
    // using evmone's system_call_block_start().
}

ValidationResult MergeRuleSet::finalize(IntraBlockState& state, const Block& block, const std::vector<Log>& logs) {
    if (block.header.difficulty != 0) {
        if (pre_merge_rule_set_) {
            return pre_merge_rule_set_->finalize(state, block, logs);
        }
    }

    if (block.withdrawals) {
        // See EIP-4895: Beacon chain push withdrawals as operations
        for (const Withdrawal& w : *block.withdrawals) {
            const auto amount_in_wei{intx::uint256{w.amount} * intx::uint256{kGiga}};
            state.add_to_balance(w.address, amount_in_wei);
            state.destruct_touched_dead();
        }
    }

    return ValidationResult::kOk;
}

evmc::address MergeRuleSet::get_beneficiary(const BlockHeader& header) {
    if (header.difficulty != 0 && pre_merge_rule_set_) {
        return pre_merge_rule_set_->get_beneficiary(header);
    }
    return RuleSet::get_beneficiary(header);
}

ValidationResult MergeRuleSet::validate_ommers(const Block& block, const BlockState& state) {
    if (block.header.difficulty != 0) {
        if (!pre_merge_rule_set_) {
            return ValidationResult::kUnknownProtocolRuleSet;
        }
        return pre_merge_rule_set_->validate_ommers(block, state);
    }
    return RuleSet::validate_ommers(block, state);
}

BlockReward MergeRuleSet::compute_reward(const Block& block) {
    if (block.header.difficulty != 0 && pre_merge_rule_set_) {
        return pre_merge_rule_set_->compute_reward(block);
    }
    return RuleSet::compute_reward(block);
}

}  // namespace silkworm::protocol
