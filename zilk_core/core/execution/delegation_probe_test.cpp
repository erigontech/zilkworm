// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// evmone::get_delegate_address() first copies one byte of the target's code and reads the 23-byte
// designation only when that byte is 0xEF. These tests compare it with the single 23-byte read it
// replaced, on a missing account, empty code, every code length up to 40 bytes with the first three
// bytes drawn from values next to the magic, truncated designations (the magic plus 0 to 19 address
// bytes, whose address is zero-padded) and full designations followed by more code.

#include <cstdint>
#include <optional>
#include <random>

#include <catch2/catch_test_macros.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/delegation.hpp>

namespace {

using namespace evmc::literals;

// get_delegate_address as it was before the one-byte probe.
std::optional<evmc::address> reference_delegate_address(const evmc::HostInterface& host,
                                                        const evmc::address& addr) {
    uint8_t buffer[std::size(evmone::DELEGATION_MAGIC) + sizeof(evmc::address)];
    const auto size = host.copy_code(addr, 0, buffer, std::size(buffer));
    const evmc::bytes_view designation{buffer, size};
    if (!evmone::is_code_delegated(designation)) {
        return std::nullopt;
    }
    evmc::address delegate;
    std::ranges::copy(designation.substr(std::size(evmone::DELEGATION_MAGIC)), delegate.bytes);
    return delegate;
}

constexpr evmc::address kTarget = 0x1234_address;

}  // namespace

TEST_CASE("get_delegate_address: missing account and empty code are not delegated") {
    evmc::MockedHost host;
    CHECK_FALSE(evmone::get_delegate_address(host, kTarget).has_value());
    host.accounts[kTarget].code = {};
    CHECK_FALSE(evmone::get_delegate_address(host, kTarget).has_value());
}

TEST_CASE("get_delegate_address: designations and near misses") {
    evmc::MockedHost host;
    const auto delegate = 0xdddddddddddddddddddddddddddddddddddddd03_address;
    evmc::bytes designation{0xef, 0x01, 0x00};
    designation.append(delegate.bytes, sizeof(delegate.bytes));

    host.accounts[kTarget].code = designation;
    CHECK(evmone::get_delegate_address(host, kTarget) == delegate);

    // Trailing code after a full designation is ignored.
    host.accounts[kTarget].code = designation + evmc::bytes{0x60, 0x00};
    CHECK(evmone::get_delegate_address(host, kTarget) == delegate);

    // A designation cut after the magic and 19 address bytes keeps the bytes it has.
    host.accounts[kTarget].code = designation.substr(0, 22);
    auto padded = delegate;
    padded.bytes[19] = 0;
    CHECK(evmone::get_delegate_address(host, kTarget) == padded);

    // The magic alone delegates to the zero address.
    host.accounts[kTarget].code = designation.substr(0, 3);
    CHECK(evmone::get_delegate_address(host, kTarget) == evmc::address{});

    // 0xEF first but not the magic: legacy code from before EIP-3541, or a cut magic.
    for (const evmc::bytes& code : {evmc::bytes{0xef}, evmc::bytes{0xef, 0x01}, evmc::bytes{0xef, 0x00, 0x00},
                                    evmc::bytes{0xef, 0x01, 0x01}, evmc::bytes{0xef, 0x02, 0x00, 0x11}}) {
        host.accounts[kTarget].code = code;
        CHECK_FALSE(evmone::get_delegate_address(host, kTarget).has_value());
    }
}

TEST_CASE("get_delegate_address: equals the full-prefix read on generated code") {
    evmc::MockedHost host;
    std::mt19937 rng{1};
    constexpr uint8_t kPick[]{0x00, 0x01, 0xef, 0xff, 0x02};
    constexpr uint8_t kMagic[]{0xef, 0x01, 0x00};
    size_t delegated = 0;
    const auto check = [&](const evmc::bytes& code) {
        host.accounts[kTarget].code = code;
        const auto expected = reference_delegate_address(host, kTarget);
        REQUIRE(evmone::get_delegate_address(host, kTarget) == expected);
        delegated += expected.has_value();
    };
    for (size_t len = 0; len <= 40; ++len) {
        evmc::bytes code(len, 0);
        // Every combination of the first three bytes from kPick, with a random tail.
        for (unsigned c = 0; c < 125; ++c) {
            for (auto& b : code) b = static_cast<uint8_t>(rng());
            for (size_t i = 0, cc = c; i < 3 && i < len; ++i, cc /= 5) code[i] = kPick[cc % 5];
            check(code);
        }
        // The magic (or as much of it as fits) with a random tail.
        for (unsigned r = 0; r < 50; ++r) {
            for (auto& b : code) b = static_cast<uint8_t>(rng());
            for (size_t i = 0; i < 3 && i < len; ++i) code[i] = kMagic[i];
            check(code);
        }
    }
    // The magic-prefixed codes of 3 to 40 bytes, plus the 0xef 0x01 0x00 picks among the 125 combinations.
    CHECK(delegated == 38 * 50 + 38);
}
