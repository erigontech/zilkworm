// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// DIV and MOD handlers against intx's / and %, on divisors chosen to break the rv32 front end:
// a power of two becomes a word shift only if the top word has one bit and every word below it
// is zero, so 2^k + 2^j and 2^k - 1 must divide. The native build sets
// -DEVMONE_RV32_DISPATCH_TEST, which compiles that front end on the host.

#include <array>
#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/instructions.hpp>

namespace {

using intx::uint256;

constexpr uint64_t kPoison = 0xa5a5a5a5a5a5a5a5;

// The stack of an instruction under test: x on top, then v (and m), with a poisoned slot below
// that an instruction must not touch.
struct Slots {
    alignas(32) std::array<uint256, 4> s;

    Slots() {
        for (auto& slot : s) slot = uint256{kPoison, kPoison, kPoison, kPoison};
    }
    evmone::StackTop stack() { return evmone::StackTop{s.data() + 4}; }
};

void check_poison(const Slots& f, size_t below) {
    for (size_t i = 0; i < below; ++i)
        REQUIRE(f.s[i] == uint256(kPoison, kPoison, kPoison, kPoison));
}

uint256 pow2(unsigned k) { return uint256{1} << k; }

std::vector<uint256> divisors(std::mt19937_64& rng) {
    std::vector<uint256> out{1, 2, 3, 0xffffffffffffffff, uint256{1} << 64, ~uint256{0}};
    for (unsigned k = 0; k < 256; ++k) {
        out.push_back(pow2(k));
        out.push_back(pow2(k) - 1);
        out.push_back(pow2(k) + 1);
        // A second bit in the same word and in lower ones.
        const unsigned same = (k & ~31u) + rng() % 32;
        out.push_back(pow2(k) | pow2(same));
        out.push_back(pow2(k) | pow2(rng() % (k + 1)));
        out.push_back(pow2(k) | pow2(rng() % 32));
        // Words below the top one set to 0xffffffff.
        out.push_back(pow2(k) | (pow2(k & ~31u) - 1));
    }
    for (int i = 0; i < 400; ++i) {
        uint256 v;
        const unsigned words = 1 + rng() % 8;
        for (unsigned w = 0; w < words; ++w) {
            const auto r = static_cast<uint32_t>(rng());
            reinterpret_cast<uint32_t*>(&v)[w] = (rng() & 3) ? r : 0;
        }
        out.push_back(v);
    }
    return out;
}

std::vector<uint256> dividends(const uint256& v, std::mt19937_64& rng) {
    std::vector<uint256> out{0, 1, v, v - 1, v + 1, ~uint256{0}, pow2(255), pow2(128) - 1};
    out.push_back(uint256{rng(), rng(), rng(), rng()});
    out.push_back(uint256{rng(), rng(), 0, 0});
    out.push_back(uint256{rng(), 0, 0, 0});
    return out;
}

}  // namespace

TEST_CASE("DIV and MOD handlers match intx on powers of two and their neighbours") {
    std::mt19937_64 rng{19};
    for (const auto& v : divisors(rng)) {
        for (const auto& x : dividends(v, rng)) {
            Slots d;
            d.s[3] = x;
            d.s[2] = v;
            evmone::instr::core::div(d.stack());
            REQUIRE(d.s[2] == (v == 0 ? uint256{0} : x / v));
            REQUIRE(d.s[3] == x);
            check_poison(d, 2);

            Slots m;
            m.s[3] = x;
            m.s[2] = v;
            evmone::instr::core::mod(m.stack());
            REQUIRE(m.s[2] == (v == 0 ? uint256{0} : x % v));
            REQUIRE(m.s[3] == x);
            check_poison(m, 2);
        }
    }
}

TEST_CASE("DIV and MOD handlers by zero give zero") {
    const uint256 x{0x0123456789abcdef, 0xfedcba9876543210, 0x1111111111111111, 0x2222222222222222};
    Slots d;
    d.s[3] = x;
    d.s[2] = 0;
    evmone::instr::core::div(d.stack());
    REQUIRE(d.s[2] == 0);
    REQUIRE(d.s[3] == x);

    Slots m;
    m.s[3] = x;
    m.s[2] = 0;
    evmone::instr::core::mod(m.stack());
    REQUIRE(m.s[2] == 0);
    REQUIRE(m.s[3] == x);
}

TEST_CASE("MULMOD handler matches intx") {
    std::mt19937_64 rng{23};
    for (const auto& m : divisors(rng)) {
        const uint256 x{rng(), rng(), rng(), rng()};
        const uint256 y = (rng() & 1) ? uint256{rng(), rng(), rng(), rng()} : m - 1;
        Slots f;
        f.s[3] = x;
        f.s[2] = y;
        f.s[1] = m;
        evmone::instr::core::mulmod(f.stack());
        REQUIRE(f.s[1] == (m == 0 ? uint256{0} : intx::mulmod(x, y, m)));
        REQUIRE(f.s[3] == x);
        REQUIRE(f.s[2] == y);
        REQUIRE(f.s[0] == uint256(kPoison, kPoison, kPoison, kPoison));
    }
}
