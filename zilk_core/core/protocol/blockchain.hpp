// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <unordered_map>
#include <vector>

#include <evmc/evmc.h>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#ifdef Z6M_HASH_STATE
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif
#include <zilk_core/core/types/receipt.hpp>

using ::zilkworm::ActiveState;

namespace silkworm::protocol {

class Blockchain {
  public:
    Blockchain(ActiveState& direct, const ChainConfig& config, const Block& genesis_block);

    Blockchain(const Blockchain&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;

    ValidationResult insert_block(Block& block, bool check_state_root);
    inline const ChainConfig& config() { return config_;}

  private:
    ValidationResult execute_block(const Block& block, bool check_state_root);

    void prime_state_with_genesis(const Block& genesis_block);

    ActiveState& direct_;
    const ChainConfig& config_;
    RuleSetPtr rule_set_;
    std::vector<Receipt> receipts_;
};

}  // namespace silkworm::protocol
