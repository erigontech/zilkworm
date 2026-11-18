// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>

#include <zilk_core/core/protocol/rule_set.hpp>

namespace silkworm::protocol {

class EthashRuleSet : public RuleSet {
  public:
    explicit EthashRuleSet(const ChainConfig& chain_config) : RuleSet(chain_config, /*prohibit_ommers=*/false) {}

    void initialize(const Block& block, ActiveState& direct) override;

    ValidationResult finalize(ActiveState& direct, const Block& block) override;

    BlockReward compute_reward(const Block& block) override;

    // Canonical PoW difficulty (EIP-2, 100, 649, 1234, 2384, 3554, 4345).
    static intx::uint256 difficulty(
        uint64_t block_num,
        uint64_t block_timestamp,
        const intx::uint256& parent_difficulty,
        uint64_t parent_timestamp,
        bool parent_has_uncles,
        const ChainConfig& config);

  protected:
    ValidationResult validate_extra_data(const BlockHeader& header) const override;

    ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) override;

  private:
};

}  // namespace silkworm::protocol
