// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// EIP-7702 resets an authority's code and code hash; its storage must survive. The wipe in
// DirectState::apply_code_diff belongs to contract creation alone.
//
// A clear used to take the wipe whenever the delegation came from an earlier block, and the
// root still came out right unless the run had written, or later read, that storage. So these
// cases assert through mirror_check_root, whose `missing` count also covers the storage-trie
// walk the guest now performs on a clear.

#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/state_diff.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::Bytes;

namespace {

using evmc::bytes32;
using namespace evmc::literals;

constexpr evmc::address kAuthority = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01_address;
constexpr evmc::address kDelegate = 0xdddddddddddddddddddddddddddddddddddddd03_address;
constexpr evmc::address kOtherDelegate = 0xdddddddddddddddddddddddddddddddddddddd04_address;
constexpr bytes32 kSlot = 0x01_bytes32;
constexpr bytes32 kValue = 0x2a_bytes32;
// Absent from the pre-state, so a write to it can only land in overflow_slots_.
constexpr bytes32 kFreshSlot = 0x02_bytes32;
constexpr bytes32 kFreshValue = 0x5b_bytes32;

constexpr uint64_t kPreNonce = 7;
constexpr uint64_t kPostNonce = 8;
constexpr uint64_t kBalance = 1000;

using Slots = std::vector<std::pair<bytes32, bytes32>>;

Bytes designation(const evmc::address& to) {
    Bytes code{silkworm::eip7702::kDelegationPrefix};
    code.append(to.bytes, sizeof(to.bytes));
    return code;
}

struct Fixture {
    Prestate pre;
    std::unique_ptr<DirectState> state;

    explicit Fixture(Bytes code)
        : pre{build_prestate({{kAuthority, kPreNonce, kBalance, std::move(code), {{kSlot, kValue}}}})},
          state{std::make_unique<DirectState>(std::span<uint8_t>{pre.blob},
                                              std::span<uint8_t>{pre.nodestore})} {
        REQUIRE(state->sanitize());
        REQUIRE(state->read_storage(kAuthority, kSlot) == kValue);
    }

    void apply_diff(Bytes code, Slots storage = {}) {
        evmone::state::StateDiff diff;
        auto& e = diff.modified_accounts.emplace_back();
        e.addr = kAuthority;
        e.nonce = kPostNonce;
        e.balance = kBalance;
        e.code = std::move(code);
        e.modified_storage = std::move(storage);
        state->apply_state_diff(diff);
    }

    /// As the guest computes it: anchored per-account GridMPT, not account_storage_root().
    MirrorRoot mirror() { return mirror_check_root(*state, pre.prev_root); }
};

bytes32 expected_root(Bytes code, const Slots& storage) {
    return build_prestate({{kAuthority, kPostNonce, kBalance, std::move(code), storage}})
        .prev_root;
}

}  // namespace

TEST_CASE("clearing a pre-state EIP-7702 delegation preserves storage",
          "[state_zz][eip7702]") {
    Fixture f{designation(kDelegate)};
    f.apply_diff({});
    CHECK(f.state->read_storage(kAuthority, kSlot) == kValue);
    CHECK(f.state->read_code(kAuthority).empty());

    // slot_count > 0 now, so check_root walks the storage trie; `missing` proves it resolves.
    const MirrorRoot m = f.mirror();
    CHECK_FALSE(m.clashed);
    CHECK(m.missing == 0);
    CHECK(m.root == expected_root({}, {{kSlot, kValue}}));
}

TEST_CASE("clearing a delegation preserves slots written earlier in the same block",
          "[state_zz][eip7702]") {
    Fixture f{designation(kDelegate)};
    // The write lands in overflow_slots_ — the tier the wipe erases.
    f.apply_diff(designation(kDelegate), {{kFreshSlot, kFreshValue}});
    REQUIRE(f.state->read_storage(kAuthority, kFreshSlot) == kFreshValue);

    f.apply_diff({});
    CHECK(f.state->read_storage(kAuthority, kFreshSlot) == kFreshValue);
    CHECK(f.state->read_storage(kAuthority, kSlot) == kValue);

    const MirrorRoot m = f.mirror();
    CHECK(m.missing == 0);
    CHECK(m.root == expected_root({}, {{kSlot, kValue}, {kFreshSlot, kFreshValue}}));
}

TEST_CASE("replacing a pre-state EIP-7702 delegation preserves storage",
          "[state_zz][eip7702]") {
    Fixture f{designation(kDelegate)};
    f.apply_diff(designation(kOtherDelegate));
    CHECK(f.state->read_storage(kAuthority, kSlot) == kValue);
}

TEST_CASE("delegating an account that already has storage preserves it", "[state_zz][eip7702]") {
    Fixture f{Bytes{}};
    f.apply_diff(designation(kDelegate));
    CHECK(f.state->read_storage(kAuthority, kSlot) == kValue);
}

TEST_CASE("clearing a delegation set earlier in the same run preserves storage",
          "[state_zz][eip7702]") {
    Fixture f{Bytes{}};
    f.apply_diff(designation(kDelegate));
    f.apply_diff({});
    CHECK(f.state->read_storage(kAuthority, kSlot) == kValue);
}

TEST_CASE("deploying contract code wipes storage", "[state_zz][eip7702]") {
    Fixture f{Bytes{}};
    f.apply_diff(Bytes{0x60, 0x00, 0x60, 0x00, 0xf3});
    CHECK(f.state->read_storage(kAuthority, kSlot) == bytes32{});
}

TEST_CASE("deploying contract code wipes slots written earlier in the same block",
          "[state_zz][eip7702]") {
    Fixture f{Bytes{}};
    f.apply_diff({}, {{kFreshSlot, kFreshValue}});
    REQUIRE(f.state->read_storage(kAuthority, kFreshSlot) == kFreshValue);

    f.apply_diff(Bytes{0x60, 0x00, 0x60, 0x00, 0xf3});
    CHECK(f.state->read_storage(kAuthority, kFreshSlot) == bytes32{});
    CHECK(f.state->read_storage(kAuthority, kSlot) == bytes32{});
}
