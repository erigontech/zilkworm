// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <unordered_map>
#include <vector>

#include <evmc/evmc.h>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types/receipt.hpp>

using ::zilkworm::DirectState;

namespace silkworm::protocol {

/**
 * Reference implementation of Ethereum blockchain logic.
 * Used for running Ethereum EL tests; the real node will use staged sync instead
 * (https://github.com/erigontech/erigon/blob/main/eth/stagedsync/README.md)
 */
class Blockchain {
  public:
    //! Creates a new instance of Blockchain.
    /**
     * In the beginning the state must have the genesis allocation.
     * Later on the state may only be modified by the created instance of Blockchain.
     */
    Blockchain(DirectState& direct, const ChainConfig& config, const Block& genesis_block);

    // Not copyable nor movable
    Blockchain(const Blockchain&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;

    ValidationResult insert_block(Block& block, bool check_state_root);
    inline const ChainConfig& config() { return config_;}

  private:
    ValidationResult execute_block(const Block& block, bool check_state_root);

    void prime_state_with_genesis(const Block& genesis_block);

    DirectState& direct_;
    const ChainConfig& config_;
    RuleSetPtr rule_set_;
    std::vector<Receipt> receipts_;
};

}  // namespace silkworm::protocol
