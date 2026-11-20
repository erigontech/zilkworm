// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "blockchain.hpp"

#include <zilk_core/core/common/assert.hpp>
#include <zilk_core/core/execution/processor.hpp>

namespace silkworm::protocol {

Blockchain::Blockchain(ActiveState& direct, const ChainConfig& config, const Block& genesis_block)
    : direct_{direct}, config_{config}, rule_set_{rule_set_factory(config)} {
    prime_state_with_genesis(genesis_block);
}

ValidationResult Blockchain::insert_block(Block& block, bool check_state_root) {
    ValidationResult err{rule_set_->validate_block_header(block.header, direct_, /*with_future_timestamp_check=*/false)};
    if (err != ValidationResult::kOk) {
        return err;
    }
#if defined(AIRBENDER) || defined(SP1)
    // From Amsterdam, intrinsic gas reads senders in pre_validate_block_body(): batch-recover them first.
    if (config_.revision(block.header.number, block.header.timestamp) >= EVMC_AMSTERDAM) {
        Transaction::recover_senders(block.transactions);
    }
#endif
    err = rule_set_->pre_validate_block_body(block, direct_);
    if (err != ValidationResult::kOk) {
        return err;
    }
    return execute_block(block, check_state_root);
}

ValidationResult Blockchain::execute_block(const Block& block, bool check_state_root) {
    ExecutionProcessor processor{block, *rule_set_, direct_, config_};

    if (const ValidationResult res = processor.execute_block(receipts_); res != ValidationResult::kOk) {
        return res;
    }

    if (check_state_root) {
        const auto state_root = direct_.state_root_hash();
        if (!state_root || *state_root != block.header.state_root) {
            return ValidationResult::kWrongStateRoot;
        }
    }

    return ValidationResult::kOk;
}

void Blockchain::prime_state_with_genesis(const Block& genesis_block) {
    direct_.insert_header(genesis_block.header);
}

}  // namespace silkworm::protocol
