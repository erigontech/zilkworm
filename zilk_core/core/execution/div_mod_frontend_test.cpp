// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// DIV, MOD, SDIV and SMOD handlers against intx's general division (/, % and sdivrem), on
// operands chosen to break their fast paths. A power of two becomes a word shift or mask only if
// the top word of the divisor has one bit and every word below it is zero, so 2^k + 2^j and
// 2^k - 1 must divide. A one-word divisor below 2^32 divides 32-bit digits, one of 2^32 or more
// does not; a four-word modulus above the dividend's top word is the dividend. SDIV and SMOD run
// DIV and MOD on the absolute values. The default native build compiles the front end of SP1's
// handlers (the generic one); -DEVMONE_RV32_DISPATCH_TEST (the rv32-paths CI job) compiles
// Airbender's.

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

uint256 pow2(unsigned k) { return uint256{1} << k; }

std::vector<uint256> divisors(std::mt19937_64& rng) {
    std::vector<uint256> out{1, 2, 3, 0xffffffffffffffff, uint256{1} << 64, ~uint256{0}};
    // The moduli MULMOD reduces in closed form on rv32 (see mulmod_sparse_test.cpp), and BN254's.
    out.push_back(intx::from_string<uint256>(
        "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));
    out.push_back(intx::from_string<uint256>(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"));
    out.push_back(intx::from_string<uint256>(
        "0x800000000000011000000000000000000000000000000000000000000000001"));
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
        // Built with shifts: stores through a uint32_t* into the uint64_t words of a uint256
        // break strict aliasing, and -O3 may drop them.
        uint256 v;
        const unsigned words = 1 + rng() % 8;
        for (unsigned w = 0; w < words; ++w) {
            const auto r = static_cast<uint32_t>(rng());
            // Into the 64-bit words: a store through uint32_t* need not be seen by their reads.
            if (rng() & 3) v[w / 2] |= uint64_t{r} << (32 * (w % 2));
        }
        out.push_back(v);
    }
    return out;
}

std::vector<uint256> dividends(const uint256& v, std::mt19937_64& rng) {
    std::vector<uint256> out{0, 1, v, v - 1, v + 1, ~uint256{0}, pow2(255), pow2(128) - 1};
    out.push_back(uint256{rng(), rng(), rng(), rng()});
    out.push_back(uint256{rng(), rng(), rng(), 0});
    out.push_back(uint256{rng(), rng(), 0, 0});
    out.push_back(uint256{rng(), 0, 0, 0});
    // Just below and above a multiple of v.
    const uint256 k{rng(), rng() & 0xff, 0, 0};
    out.push_back(v * k - 1);
    out.push_back(v * k + 1);
    return out;
}

// One-word divisors around 2^32, where the digit division ends, and common decimal ones.
std::vector<uint256> word_divisors(std::mt19937_64& rng) {
    std::vector<uint256> out{1, 2, 3, 7, 10, 1000, 10000, 1000000, 1000000000000000000,
        0xfffffffe, 0xffffffff, uint256{1} << 32, (uint256{1} << 32) + 1, 0x1ffffffff,
        0x8000000000000000, 0xffffffffffffffff};
    for (int i = 0; i < 8; ++i) {
        out.push_back(rng() >> 32);
        out.push_back(rng() >> (rng() % 32));
    }
    return out;
}

uint256 ref_div(const uint256& x, const uint256& v) { return v == 0 ? uint256{0} : x / v; }
uint256 ref_mod(const uint256& x, const uint256& v) { return v == 0 ? uint256{0} : x % v; }
uint256 ref_sdiv(const uint256& x, const uint256& v) {
    return v == 0 ? uint256{0} : intx::sdivrem(x, v).quot;
}
uint256 ref_smod(const uint256& x, const uint256& v) {
    return v == 0 ? uint256{0} : intx::sdivrem(x, v).rem;
}

// Runs a two-operand instruction on x (top) and v; returns the result in v's slot. DIV and MOD
// leave x's slot alone; SDIV and SMOD may change it (it is popped).
uint256 run(void (*op)(evmone::StackTop), const uint256& x, const uint256& v, bool keeps_x) {
    Slots f;
    f.s[3] = x;
    f.s[2] = v;
    op(f.stack());
    if (keeps_x && f.s[3] != x) FAIL("x's slot changed: 0x" << intx::hex(f.s[3]));
    const uint256 poison{kPoison, kPoison, kPoison, kPoison};
    if (f.s[0] != poison || f.s[1] != poison) FAIL("a slot below the operands changed");
    return f.s[2];
}

// The operands are formatted only for a failure: there are a million checks.
void expect(const char* op, const uint256& x, const uint256& v, const uint256& got,
    const uint256& want) {
    if (got != want)
        FAIL(op << " 0x" << intx::hex(x) << " 0x" << intx::hex(v) << ": 0x" << intx::hex(got)
                << ", expected 0x" << intx::hex(want));
}

void check_unsigned(const uint256& x, const uint256& v) {
    expect("DIV", x, v, run(evmone::instr::core::div, x, v, true), ref_div(x, v));
    expect("MOD", x, v, run(evmone::instr::core::mod, x, v, true), ref_mod(x, v));
}

void check_signed(const uint256& x, const uint256& v) {
    expect("SDIV", x, v, run(evmone::instr::core::sdiv, x, v, false), ref_sdiv(x, v));
    expect("SMOD", x, v, run(evmone::instr::core::smod, x, v, false), ref_smod(x, v));
}

// All four, with the signed ones also on the negated operands.
void check_all(const uint256& x, const uint256& v) {
    check_unsigned(x, v);
    check_signed(x, v);
    check_signed(-x, v);
    check_signed(x, -v);
    check_signed(-x, -v);
}

}  // namespace

TEST_CASE("DIV, MOD, SDIV and SMOD handlers match intx on powers of two and their neighbours") {
    std::mt19937_64 rng{19};
    for (const auto& v : divisors(rng))
        for (const auto& x : dividends(v, rng)) check_all(x, v);
}

TEST_CASE("DIV, MOD, SDIV and SMOD handlers match intx on one-word divisors") {
    std::mt19937_64 rng{29};
    for (const auto& v : word_divisors(rng)) {
        for (const auto& x : dividends(v, rng)) check_all(x, v);
        for (int i = 0; i < 64; ++i) {
            // Dividends of one to four words, and with zero words in between.
            uint256 x;
            for (unsigned w = 0; w < 4; ++w)
                if (rng() & 1) x[w] = rng() >> (rng() % 64);
            check_all(x, v);
        }
    }
}

TEST_CASE("DIV, MOD, SDIV and SMOD handlers match intx on powers of two as dividends") {
    std::mt19937_64 rng{31};
    std::vector<uint256> divs = word_divisors(rng);
    for (unsigned k = 0; k < 256; ++k) divs.push_back(pow2(k));
    divs.push_back(pow2(64) + 1);
    divs.push_back(~uint256{0});
    divs.push_back(intx::from_string<uint256>("1000000000000000000000000000"));  // 10^27
    divs.push_back(intx::from_string<uint256>(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"));
    for (const auto& v : divs) {
        for (unsigned j = 0; j < 256; ++j) {
            check_unsigned(pow2(j), v);
            check_unsigned(pow2(j) - 1, v);
            check_unsigned(pow2(j) + 1, v);
            check_signed(pow2(j), v);
            check_signed(-pow2(j), v);
        }
    }
}

TEST_CASE("DIV, MOD, SDIV and SMOD handlers by zero give zero") {
    const uint256 x{0x0123456789abcdef, 0xfedcba9876543210, 0x1111111111111111, 0x2222222222222222};
    for (const auto& a : {x, -x, uint256{0}, uint256{1}, ~uint256{0}, pow2(255)}) {
        REQUIRE(run(evmone::instr::core::div, a, 0, true) == 0);
        REQUIRE(run(evmone::instr::core::mod, a, 0, true) == 0);
        REQUIRE(run(evmone::instr::core::sdiv, a, 0, false) == 0);
        REQUIRE(run(evmone::instr::core::smod, a, 0, false) == 0);
    }
}

TEST_CASE("SDIV and SMOD handlers on the signed edge cases") {
    const auto neg = [](uint64_t a) { return -uint256{a}; };
    const auto min = pow2(255);  // -2^255
    const auto max = pow2(255) - 1;
    const auto sdiv = [](const uint256& x, const uint256& v) {
        return run(evmone::instr::core::sdiv, x, v, false);
    };
    const auto smod = [](const uint256& x, const uint256& v) {
        return run(evmone::instr::core::smod, x, v, false);
    };
    // -2^255 / -1 overflows to -2^255.
    REQUIRE(sdiv(min, neg(1)) == min);
    REQUIRE(smod(min, neg(1)) == 0);
    REQUIRE(sdiv(min, 1) == min);
    REQUIRE(smod(min, 1) == 0);
    REQUIRE(sdiv(min, min) == 1);
    REQUIRE(smod(min, min) == 0);
    REQUIRE(sdiv(min, 2) == -pow2(254));
    REQUIRE(smod(min, 2) == 0);
    REQUIRE(sdiv(min, max) == neg(1));
    REQUIRE(smod(min, max) == neg(1));
    REQUIRE(sdiv(max, min) == 0);
    REQUIRE(smod(max, min) == max);
    REQUIRE(sdiv(max, neg(1)) == -max);
    REQUIRE(sdiv(min + 1, neg(1)) == max);
    // Rounding toward zero; the remainder takes the dividend's sign.
    REQUIRE(sdiv(neg(1), 2) == 0);
    REQUIRE(smod(neg(1), 2) == neg(1));
    REQUIRE(sdiv(neg(7), 2) == neg(3));
    REQUIRE(smod(neg(7), 2) == neg(1));
    REQUIRE(sdiv(7, neg(2)) == neg(3));
    REQUIRE(smod(7, neg(2)) == 1);
    REQUIRE(sdiv(neg(7), neg(2)) == 3);
    REQUIRE(smod(neg(7), neg(2)) == neg(1));
    REQUIRE(sdiv(neg(8), 4) == neg(2));
    REQUIRE(smod(neg(8), 4) == 0);
    REQUIRE(smod(neg(9), 256) == neg(9));
    REQUIRE(smod(neg(0x1234), 0x100) == neg(0x34));
    REQUIRE(sdiv(neg(0x1234), 0x100) == neg(0x12));
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
