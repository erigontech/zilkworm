// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// evmone resolves an EIP-7702 call target by reading the delegate's code before the value
// transfer can light-fail, as execution-specs does (calculate_delegation_cost, then get_code).
// A stateless witness must therefore carry that code even when the call fails for balance.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>

namespace zilkworm {

namespace {

    using namespace evmc::literals;

    struct CodeReadHost : evmc::MockedHost {
        mutable std::vector<evmc::address> code_size_reads;

        size_t get_code_size(const evmc::address& addr) const noexcept override {
            code_size_reads.push_back(addr);
            return MockedHost::get_code_size(addr);
        }
    };

}  // namespace

TEST_CASE("delegated CALL failing for balance still reads the delegate's code", "[evmone][eip7702]") {
    constexpr auto caller = 0x00000000000000000000000000000000000000cc_address;
    constexpr auto callee = 0x00000000000000000000000000000000000000aa_address;
    constexpr auto delegate = 0x00000000000000000000000000000000000000bb_address;

    CodeReadHost host;
    host.accounts[caller].set_balance(0);
    host.accounts[callee].code = evmc::bytes{0xef, 0x01, 0x00} + evmc::bytes{delegate.bytes, sizeof(delegate)};
    host.accounts[delegate].code = evmc::bytes{0x00};  // STOP

    // CALL(gas, callee, value = 1, 0, 0, 0, 0), then return the success flag.
    evmc::bytes code{0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0x73};
    code += evmc::bytes{callee.bytes, sizeof(callee)};
    code += evmc::bytes{0x5a, 0xf1, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3};

    evmc_message msg{};
    msg.gas = 1'000'000;
    msg.recipient = caller;
    evmc::VM vm{evmc_create_evmone()};
    const auto result = vm.execute(host, EVMC_PRAGUE, msg, code.data(), code.size());

    REQUIRE(result.status_code == EVMC_SUCCESS);
    REQUIRE(result.output_size == 32);
    CHECK(std::all_of(result.output_data, result.output_data + 32, [](uint8_t b) { return b == 0; }));
    CHECK(host.recorded_calls.empty());
    CHECK(std::ranges::find(host.code_size_reads, delegate) != host.code_size_reads.end());
}

}  // namespace zilkworm
