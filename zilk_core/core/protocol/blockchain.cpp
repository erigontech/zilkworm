// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "blockchain.hpp"

#include <zilk_core/core/common/assert.hpp>
#include <zilk_core/core/execution/processor.hpp>

namespace silkworm::protocol {

Blockchain::Blockchain(DirectState& direct, const ChainConfig& config, const Block& genesis_block)
    : direct_{direct}, config_{config}, rule_set_{rule_set_factory(config)} {
    prime_state_with_genesis(genesis_block);
}

ValidationResult Blockchain::insert_block(Block& block, bool check_state_root) {
    ValidationResult err{rule_set_->validate_block_header(block.header, direct_, /*with_future_timestamp_check=*/false)};
    if (err != ValidationResult::kOk) {
        return err;
    }
    err = rule_set_->pre_validate_block_body(block, direct_);
    if (err != ValidationResult::kOk) {
        return err;
    }
    // Single-block witness flow: no fork resolution / canonical-chain
    // bookkeeping. Just execute the block.
    return execute_block(block, check_state_root);

    /* --------------------------

    evmc::bytes32 hash{block.header.hash()};
    if (auto it{bad_blocks_.find(hash)}; it != bad_blocks_.end()) {
        return it->second;
    }

    uint64_t ancestor{canonical_ancestor(block.header, hash)};
    uint64_t current_canonical_block{state_.current_canonical_block()};
    unwind_last_changes(ancestor, current_canonical_block);

    uint64_t block_num = block.header.number;

    std::vector<BlockWithHash> chain{intermediate_chain(block_num - 1, block.header.parent_hash, ancestor)};
    chain.push_back({block, hash});

    size_t num_of_executed_chain_blocks{0};
    for (const BlockWithHash& x : chain) {
        err = execute_block(x.block, check_state_root);
        if (err != ValidationResult::kOk) {
            break;
        }
        ++num_of_executed_chain_blocks;
    }

    if (err != ValidationResult::kOk) {
        bad_blocks_[hash] = err;
        unwind_last_changes(ancestor, ancestor + num_of_executed_chain_blocks);
        re_execute_canonical_chain(ancestor, current_canonical_block);
        return err;
    }

    state_.insert_block(block, hash);

    intx::uint256 current_total_difficulty{
        *state_.total_difficulty(current_canonical_block, *state_.canonical_hash(current_canonical_block))};

    // Non-strict comparison because of the Merge
    if (state_.total_difficulty(block_num, hash) >= current_total_difficulty) {
        // canonize the new chain
        for (uint64_t i{current_canonical_block}; i > ancestor; --i) {
            state_.decanonize_block(i);
        }
        for (const BlockWithHash& x : chain) {
            state_.canonize_block(x.block.header.number, x.hash);
        }
    } else {
        unwind_last_changes(ancestor, ancestor + num_of_executed_chain_blocks);
        re_execute_canonical_chain(ancestor, current_canonical_block);
    }

    return ValidationResult::kOk;

     ---------------------------- */
}

ValidationResult Blockchain::execute_block(const Block& block, bool check_state_root) {
    ExecutionProcessor processor{block, *rule_set_, direct_, config_};

    if (const ValidationResult res = processor.execute_block(receipts_); res != ValidationResult::kOk) {
        return res;
    }

    if (check_state_root) {
        // DirectState-backed Yellow-Paper state root.
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
