// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <ostream>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/state/block_state.hpp>
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#ifdef Z6M_HASH_STATE
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/receipt.hpp>

using ::zilkworm::ActiveState;

namespace silkworm::protocol {

struct BlockReward {
    intx::uint256 miner;
    std::vector<intx::uint256> ommers;

    std::string to_string() const;
};

std::ostream& operator<<(std::ostream& out, const BlockReward& reward);

class RuleSet {
  public:
    RuleSet(const RuleSet& other) = delete;
    RuleSet& operator=(const RuleSet& other) = delete;

    virtual ~RuleSet() = default;

    //! Checks that need neither sender recovery nor execution; not for the genesis block.
    virtual ValidationResult pre_validate_block_body(const Block& block, const BlockState& state);

    //! Not for the genesis block; with_future_timestamp_check rejects headers ahead of the host clock.
    virtual ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check);

    virtual ValidationResult validate_ommers(const Block& block, const BlockState& state);

    virtual void initialize(const Block& block, ActiveState& direct) = 0;

    virtual ValidationResult finalize(ActiveState& direct, const Block& block) = 0;

    virtual evmc::address get_beneficiary(const BlockHeader& header);

    virtual BlockReward compute_reward(const Block& block);

  protected:
    explicit RuleSet(const ChainConfig& chain_config, bool prohibit_ommers)
        : chain_config_{chain_config}, prohibit_ommers_{prohibit_ommers} {}

    virtual ValidationResult validate_extra_data(const BlockHeader& header) const;

    virtual ValidationResult validate_difficulty_and_seal(const BlockHeader& header, const BlockHeader& parent) = 0;

    static std::optional<BlockHeader> get_parent_header(const BlockState& state, const BlockHeader& header);

    const ChainConfig& chain_config_;

  private:
    static bool is_kin(const BlockHeader& branch_header, const BlockHeader& mainline_header,
                       const evmc::bytes32& mainline_hash, unsigned int n, const BlockState& state,
                       std::vector<BlockHeader>& old_ommers);

    bool prohibit_ommers_{false};
};

using RuleSetPtr = std::unique_ptr<RuleSet>;

RuleSetPtr rule_set_factory(const ChainConfig& chain_config);

}  // namespace silkworm::protocol
