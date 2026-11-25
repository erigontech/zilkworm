// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <optional>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/state/block_state.hpp>

namespace silkworm::protocol {

namespace {

class ParentOnly final : public BlockState {
  public:
    explicit ParentOnly(const BlockHeader& parent) : parent_{parent} {}

  private:
    std::optional<BlockHeader> read_header(BlockNum, const evmc::bytes32&) const noexcept override { return parent_; }
    bool read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept override { return false; }
    std::optional<intx::uint256> total_difficulty(uint64_t, const evmc::bytes32&) const noexcept override {
        return std::nullopt;
    }

    BlockHeader parent_;
};

ValidationResult validate_header(const ChainConfig& config, uint64_t timestamp, const intx::uint256& difficulty,
                                 BlockNum number = 100, std::optional<intx::uint256> parent_difficulty = std::nullopt) {
    BlockHeader parent;
    parent.ommers_hash = kEmptyListHash;
    parent.number = number - 1;
    parent.difficulty = parent_difficulty.value_or(difficulty);  // a proof-of-work child gets a proof-of-work parent
    parent.timestamp = timestamp - 12;
    parent.gas_limit = 30'000'000;
    parent.base_fee_per_gas = 1'000'000'000;

    BlockHeader header;
    header.parent_hash = parent.hash();
    header.ommers_hash = kEmptyListHash;
    header.number = number;
    header.timestamp = timestamp;
    header.gas_limit = parent.gas_limit;
    header.difficulty = difficulty;
    header.base_fee_per_gas = expected_base_fee_per_gas(parent);
    if (config.withdrawals_activated(timestamp)) {
        header.withdrawals_root = kEmptyRoot;
    }

    const ParentOnly state{parent};
    return rule_set_factory(config)->validate_block_header(header, state, /*with_future_timestamp_check=*/false);
}

}  // namespace

TEST_CASE("a post-merge header with a non-zero difficulty is rejected", "[merge_rule_set]") {
    const uint64_t mainnet_shanghai{*kMainnetConfig.shanghai_time + 1000};
    CHECK(validate_header(kMainnetConfig, mainnet_shanghai, 0) == ValidationResult::kOk);
    CHECK(validate_header(kMainnetConfig, mainnet_shanghai, 1) == ValidationResult::kPoWBlockAfterMerge);
    CHECK(validate_header(test::kShanghaiConfig, 1000, 1) == ValidationResult::kPoWBlockAfterMerge);
}

TEST_CASE("a config with no pre-merge rules is merged at genesis without a terminal total difficulty",
          "[merge_rule_set]") {
    ChainConfig config{test::kLondonConfig};
    config.rule_set_config = NoPreMergeConfig{};
    CHECK(validate_header(config, 1000, 0) == ValidationResult::kOk);
    CHECK(validate_header(config, 1000, 1) == ValidationResult::kPoWBlockAfterMerge);
}

TEST_CASE("an Ethash config with a terminal total difficulty of 0 is merged at genesis before Shanghai",
          "[merge_rule_set]") {
    ChainConfig config{test::kLondonConfig};
    config.terminal_total_difficulty = 0;
    CHECK(validate_header(config, 1000, 0) == ValidationResult::kOk);
    CHECK(validate_header(config, 1000, 1) == ValidationResult::kPoWBlockAfterMerge);
}

TEST_CASE("a child of a proof-of-stake parent with a non-zero difficulty is rejected before Shanghai",
          "[merge_rule_set]") {
    const uint64_t before_shanghai{*kMainnetConfig.shanghai_time - 1};
    CHECK(validate_header(kMainnetConfig, before_shanghai, 0, 17'000'000, 0) == ValidationResult::kOk);
    CHECK(validate_header(kMainnetConfig, before_shanghai, 1, 17'000'000, 0) == ValidationResult::kPoWBlockAfterMerge);
}

#ifdef Z6M_POST_MERGE_ONLY
TEST_CASE("without the pre-merge rules every non-zero difficulty is rejected", "[merge_rule_set]") {
    const uint64_t mainnet_shanghai{*kMainnetConfig.shanghai_time};
    CHECK(validate_header(kMainnetConfig, mainnet_shanghai - 1, 0, 18'000'000) == ValidationResult::kOk);
    CHECK(validate_header(kMainnetConfig, mainnet_shanghai - 1, 1, 18'000'000) == ValidationResult::kPoWBlockAfterMerge);
    CHECK(validate_header(kMainnetConfig, mainnet_shanghai - 1, 1, 13'000'000) == ValidationResult::kPoWBlockAfterMerge);
    CHECK(validate_header(test::kLondonConfig, 1000, 0x20000) == ValidationResult::kPoWBlockAfterMerge);
}
#else
TEST_CASE("a pre-merge header keeps its difficulty", "[merge_rule_set]") {
    CHECK(validate_header(test::kLondonConfig, 1000, 0x20000) == ValidationResult::kOk);
}
#endif

}  // namespace silkworm::protocol
