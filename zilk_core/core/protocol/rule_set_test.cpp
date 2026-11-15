// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "rule_set.hpp"

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/protocol/param.hpp>

namespace silkworm::protocol {

TEST_CASE("Rule Set factory") {
    RuleSetPtr rule_set;
    rule_set = rule_set_factory(kMainnetConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(kHoleskyConfig);  // Merged from genesis
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(kSepoliaConfig);  // Ethash rule set
    CHECK(rule_set);
    CHECK(rule_set->compute_reward(Block{}).miner == 0);
    rule_set = rule_set_factory(test::kLondonConfig);  // Pre-merge chain: Ethash rules, no TTD
    CHECK(rule_set);
    // A pre-merge chain's block carries a difficulty, which routes compute_reward to the
    // Ethash rule set (merge_rule_set.cpp:89-94): the post-Byzantium 2 ETH reward.
    Block pow_block{};
    pow_block.header.difficulty = 1;
    CHECK(rule_set->compute_reward(pow_block).miner == 2000000000000000000);
    // The upstream `pre_merge_rule_set` selection is commented out and the factory always
    // returns MergeRuleSet(EthashRuleSet) (rule_set.cpp:267-275 since 47b3375), so the old
    // `CHECK(!rule_set)` for a NoPreMergeConfig tested code that is gone and is dropped.
}

}  // namespace silkworm::protocol
