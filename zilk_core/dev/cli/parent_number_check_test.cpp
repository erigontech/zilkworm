// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for the missing parent-number consensus rule:
//
//   validate_block_header fetched the parent by hash alone (read_header
//   ignores block_num), so a block whose parent_hash names a header with a
//   number other than header.number - 1 passed every parent-relative check
//   (timestamp, gas-limit delta, base fee, excess blob gas). Nothing else
//   binds the numbers within one witness.
//
//   validate_block_header now rejects such a block with kUnknownParent: a
//   header the hash names that is not the parent by number is not the parent.
//
// Standalone test (no gtest); exit code = failure count. It runs the
// rule-set header validation directly over a ChainConfig-free path via
// RuleSet::validate_block_header with a tiny BlockState stub.

#include <cstdint>
#include <print>
#include <optional>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/types/block.hpp>

using namespace silkworm;
using silkworm::protocol::RuleSet;

namespace {

int g_failures = 0;

void expect_true(bool cond, const char* msg) {
    if (!cond) {
        std::println(stderr, "[FAIL] {}", msg);
        ++g_failures;
    } else {
        std::println("[ ok ] {}", msg);
    }
}

// A minimal BlockState: only read_header is reached for header validation.
class StubState final : public BlockState {
  public:
    std::optional<BlockHeader> parent;

  private:
    std::optional<BlockHeader> read_header(BlockNum, const evmc::bytes32&) const noexcept override {
        return parent;
    }
    [[nodiscard]] bool read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept override {
        return false;
    }
    std::optional<intx::uint256> total_difficulty(uint64_t, const evmc::bytes32&) const noexcept override {
        return std::nullopt;
    }
};

BlockHeader parent_header(uint64_t number) {
    BlockHeader h;
    h.number = number;
    h.timestamp = 1'700'000'000;
    h.gas_limit = 30'000'000;
    h.gas_used = 0;
    h.difficulty = 0;
    h.ommers_hash = silkworm::kEmptyListHash;
    h.extra_data = {};
    return h;
}

BlockHeader child_of(const BlockHeader& parent, uint64_t number) {
    BlockHeader h = parent_header(number);
    h.parent_hash = parent.hash();
    h.timestamp = 1'700'000'001;
    h.base_fee_per_gas = protocol::expected_base_fee_per_gas(parent);
    h.withdrawals_root = silkworm::kEmptyHash;
    h.blob_gas_used = 0;
    h.excess_blob_gas = 0;
    h.parent_beacon_block_root = silkworm::kEmptyHash;
    h.requests_hash = silkworm::kEmptyHash;
    h.block_access_list_hash = silkworm::kEmptyHash;
    h.slot_number = 0;
    return h;
}

}  // namespace

int main() {
    StubState state;
    const BlockHeader parent = parent_header(100);
    state.parent = parent;

    // A sequential child passes the number rule (other checks may still fire,
    // but not kUnknownParent-with-a-present-parent).
    const BlockHeader good = child_of(parent, 101);
    const auto r_good = protocol::rule_set_factory(silkworm::kMainnetConfig)->validate_block_header(good, state, false);
    expect_true(r_good != ValidationResult::kUnknownParent, "sequential child is not rejected as unknown-parent");

    // A child whose parent_hash names the header but whose number skips: rejected.
    const BlockHeader skip = child_of(parent, 105);
    const auto r_skip = protocol::rule_set_factory(silkworm::kMainnetConfig)->validate_block_header(skip, state, false);
    expect_true(r_skip == ValidationResult::kUnknownParent, "non-sequential child rejected with kUnknownParent");

    return g_failures;
}
