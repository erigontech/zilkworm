// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// evmone::state::is_precompile rules out an address by its leading byte before it compares and indexes the
// availability table. The answers must stay those of the full rule: an address is a precompile in a revision
// iff it is one of the listed addresses (all below 2^16) and the revision is at least its first one. Checked
// for every revision over the addresses 0 to 0x1FFFF, and over addresses with a non-zero byte at each other
// position, whose last two bytes name a precompile (the table index uses only those two).

#include <cstdint>
#include <random>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmone/test/state/precompiles.hpp>

namespace {

struct Listed {
    uint32_t address;
    evmc_revision since;
};

constexpr Listed kListed[]{
    {0x0001, EVMC_FRONTIER}, {0x0002, EVMC_FRONTIER}, {0x0003, EVMC_FRONTIER}, {0x0004, EVMC_FRONTIER},
    {0x0005, EVMC_BYZANTIUM}, {0x0006, EVMC_BYZANTIUM}, {0x0007, EVMC_BYZANTIUM}, {0x0008, EVMC_BYZANTIUM},
    {0x0009, EVMC_ISTANBUL}, {0x000a, EVMC_CANCUN},
    {0x000b, EVMC_PRAGUE}, {0x000c, EVMC_PRAGUE}, {0x000d, EVMC_PRAGUE}, {0x000e, EVMC_PRAGUE},
    {0x000f, EVMC_PRAGUE}, {0x0010, EVMC_PRAGUE}, {0x0011, EVMC_PRAGUE},
    {0x0100, EVMC_OSAKA},
};

// The rule as the table encodes it, for an address given as its low 32 bits and a flag that the other
// 16 bytes are zero.
bool expected(evmc_revision rev, uint32_t low, bool high_zero) {
    if (!high_zero)
        return false;
    for (const auto& l : kListed)
        if (l.address == low)
            return rev >= l.since;
    return false;
}

evmc::address make(uint32_t low) {
    evmc::address a{};
    a.bytes[16] = static_cast<uint8_t>(low >> 24);
    a.bytes[17] = static_cast<uint8_t>(low >> 16);
    a.bytes[18] = static_cast<uint8_t>(low >> 8);
    a.bytes[19] = static_cast<uint8_t>(low);
    return a;
}

}  // namespace

TEST_CASE("is_precompile: every revision over addresses 0..0x1FFFF", "[precompile_lookup]") {
    for (int r = 0; r <= EVMC_MAX_REVISION; ++r) {
        const auto rev = static_cast<evmc_revision>(r);
        for (uint32_t low = 0; low <= 0x1FFFF; ++low)
            REQUIRE(evmone::state::is_precompile(rev, make(low)) == expected(rev, low, true));
    }
}

TEST_CASE("is_precompile: a non-zero byte anywhere else rules the address out", "[precompile_lookup]") {
    std::mt19937_64 rng{0xADD7ULL};
    for (int r = 0; r <= EVMC_MAX_REVISION; ++r) {
        const auto revision = static_cast<evmc_revision>(r);
        for (const auto& l : kListed) {
            // Last two bytes of a precompile, one other byte non-zero (every position, every value).
            for (size_t pos = 0; pos < 18; ++pos)
                for (unsigned v = 1; v <= 255; ++v) {
                    evmc::address a = make(l.address);
                    a.bytes[pos] = static_cast<uint8_t>(v);
                    REQUIRE_FALSE(evmone::state::is_precompile(revision, a));
                }
            // Random non-zero high bytes with the same last two bytes.
            for (int i = 0; i < 50; ++i) {
                evmc::address a = make(l.address);
                bool any = false;
                for (size_t pos = 0; pos < 18; ++pos) {
                    a.bytes[pos] = static_cast<uint8_t>(rng());
                    any = any || a.bytes[pos] != 0;
                }
                if (any)
                    REQUIRE_FALSE(evmone::state::is_precompile(revision, a));
            }
        }
        // Entirely random addresses.
        for (int i = 0; i < 2000; ++i) {
            evmc::address a{};
            for (auto& b : a.bytes)
                b = static_cast<uint8_t>(rng());
            REQUIRE(evmone::state::is_precompile(revision, a) == false);
        }
    }
}
