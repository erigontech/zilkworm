// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The EXP handler against intx::exp and the EIP-160 gas rule, on the bases and exponents that break
// its rv32 word-store paths: a power of two 2^j with j < 32 becomes a word write only if the other
// seven words are zero, base 1 must give 1 for every exponent, base 0 is not a power of two, and
// the product j*e must not be formed for an exponent that wraps 32 bits (base 256, e = 2^29). The
// native build sets -DEVMONE_RV32_DISPATCH_TEST, which compiles those paths on the host.

#include <array>
#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/instructions.hpp>

namespace {

using intx::uint256;

constexpr uint64_t kPoison = 0xa5a5a5a5a5a5a5a5;
constexpr uint256 kPoison256{kPoison, kPoison, kPoison, kPoison};

// The stack of an EXP under test: the base on top, the exponent below it, and a poisoned slot
// beneath that, which the instruction must not touch.
struct Slots {
    alignas(32) std::array<uint256, 3> s;

    Slots(const uint256& base, const uint256& exponent) {
        s[0] = kPoison256;
        s[1] = exponent;
        s[2] = base;
    }
    evmone::StackTop stack() { return evmone::StackTop{s.data() + 3}; }
};

evmone::ExecutionState& state_at(evmc_revision rev) {
    static const auto st = std::make_unique<evmone::ExecutionState>();
    st->rev = rev;
    return *st;
}

uint256 pow2(unsigned k) { return uint256{1} << k; }

// The significant bytes of e, counted without intx.
int significant_bytes(const uint256& e) {
    for (unsigned b = 32; b > 0; --b)
        if (static_cast<uint8_t>(e[(b - 1) / 8] >> (8 * ((b - 1) % 8))) != 0)
            return static_cast<int>(b);
    return 0;
}

constexpr evmc_revision kRevs[] = {EVMC_FRONTIER, EVMC_TANGERINE_WHISTLE, EVMC_SPURIOUS_DRAGON,
    EVMC_CANCUN, EVMC_OSAKA};

// One EXP: the result against intx::exp, the gas left against the EIP-160 rule, the base slot
// unchanged, the poison untouched; and the out-of-gas edge (one unit short) on the same inputs.
void check_exp(const uint256& base, const uint256& e, evmc_revision rev, int64_t spare) {
    const int64_t cost = significant_bytes(e) * (rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10);
    const int64_t gas = cost + spare;

    Slots f{base, e};
    const auto r = evmone::instr::core::exp(f.stack(), gas, state_at(rev));
    REQUIRE(r.status == EVMC_SUCCESS);
    REQUIRE(r.gas_left == spare);
    REQUIRE(f.s[1] == intx::exp(base, e));
    REQUIRE(f.s[2] == base);
    REQUIRE(f.s[0] == kPoison256);

    if (cost > 0) {
        Slots g{base, e};
        const auto o = evmone::instr::core::exp(g.stack(), cost - 1, state_at(rev));
        REQUIRE(o.status == EVMC_OUT_OF_GAS);
        REQUIRE(o.gas_left == -1);
        REQUIRE(g.s[0] == kPoison256);
        REQUIRE(g.s[2] == base);
    }
}

std::vector<uint256> bases(std::mt19937_64& rng) {
    std::vector<uint256> out{0, 1, 2, 3, 10, 255, 256, 257, 0x101, 0x7fffffff, 0xffffffff,
        0x100000000, 0xffffffffffffffff, ~uint256{0}};
    for (unsigned k = 0; k < 256; ++k) {
        out.push_back(pow2(k));
        out.push_back(pow2(k) - 1);
        out.push_back(pow2(k) + 1);
        // A second bit in the same word and in lower ones: not a power of two.
        const unsigned same = (k & ~31u) + rng() % 32;
        out.push_back(pow2(k) | pow2(same));
        out.push_back(pow2(k) | pow2(rng() % (k + 1)));
        out.push_back(pow2(k) | pow2(rng() % 32));
        // A single bit in a high word with word 0 holding a small power of two or one more.
        out.push_back(pow2(k) | pow2(8));
        out.push_back(pow2(k) | 1);
        // Word 0 a power of two below 2^32 with one stray bit in some higher word.
        out.push_back(pow2(k % 32) | pow2(32 + rng() % 224));
        // Words below the top one set to 0xffffffff.
        out.push_back(pow2(k) | (pow2(k & ~31u) - 1));
    }
    out.push_back(pow2(40) + 256);
    for (int i = 0; i < 300; ++i) {
        uint256 v;
        const unsigned words = 1 + rng() % 8;
        for (unsigned w = 0; w < words; ++w) {
            const auto r = static_cast<uint32_t>(rng());
            if (rng() & 3) v[w / 2] |= uint64_t{r} << (32 * (w % 2));
        }
        out.push_back(v);
    }
    return out;
}

std::vector<uint256> exponents(std::mt19937_64& rng) {
    std::vector<uint256> out;
    for (unsigned i = 0; i <= 600; ++i) out.push_back(i);
    for (const unsigned k : {29u, 31u, 32u, 63u, 64u, 128u, 255u}) {
        out.push_back(pow2(k) - 1);
        out.push_back(pow2(k));
        out.push_back(pow2(k) + 1);
    }
    out.push_back(138547333);  // 31 * e wraps to 27
    out.push_back(0x1fffffff);
    out.push_back(0x20000001);
    out.push_back(0xffffffff);
    out.push_back(0x100000001);
    out.push_back(~uint256{0});
    out.push_back(pow2(255) | 5);
    // High word only: low word zero, so a wrap of the low-word product would be seen as 0.
    out.push_back(pow2(32));
    out.push_back(pow2(224));
    for (int i = 0; i < 150; ++i) {
        uint256 v;
        const unsigned words = 1 + rng() % 8;
        for (unsigned w = 0; w < words; ++w)
            v[w / 2] |= uint64_t{static_cast<uint32_t>(rng())} << (32 * (w % 2));
        out.push_back(v);
        // A multiple of 2^k/j for the wrap: e such that j*e is 2^32 or 2^32 + small.
        const unsigned j = 1 + rng() % 31;
        out.push_back(uint256{((uint64_t{1} << 32) + (rng() % 300)) / j});
    }
    return out;
}

}  // namespace

TEST_CASE("EXP handler matches intx on powers of two, their neighbours and every exponent shape") {
    std::mt19937_64 rng{41};
    const auto es = exponents(rng);
    size_t i = 0;
    for (const auto& b : bases(rng)) {
        for (const auto& e : es) {
            ++i;
            // Revision and spare gas vary over the sweep; the full revision list is run for the
            // power-of-two bases below.
            check_exp(b, e, kRevs[i % std::size(kRevs)], static_cast<int64_t>(i % 3) * 7);
        }
    }
}

TEST_CASE("EXP handler: every 2^j, every revision, short exponents, gas edge") {
    for (unsigned k = 0; k < 256; ++k) {
        for (unsigned e = 0; e <= 300; ++e)
            for (const auto rev : kRevs) check_exp(pow2(k), e, rev, 0);
    }
}

TEST_CASE("EXP handler: exponents that wrap a 32-bit product") {
    // j * e0 reaches 2^32 or 2^32 + small for these: a product formed in 32 bits would see 0 or a
    // small value and give 2^(j*e mod 2^32), not 0.
    for (unsigned j = 1; j < 32; ++j) {
        const uint256 b = pow2(j);
        for (const uint64_t e : {uint64_t{1} << 29, (uint64_t{1} << 29) + 1,
                 ((uint64_t{1} << 32) + 7) / j, (uint64_t{1} << 32) / j, (uint64_t{1} << 32) / j + 1,
                 uint64_t{138547333}, uint64_t{0xffffffff}, uint64_t{0x100000000}}) {
            Slots f{b, uint256{e}};
            const auto r = evmone::instr::core::exp(f.stack(), 1000, state_at(EVMC_CANCUN));
            REQUIRE(r.status == EVMC_SUCCESS);
            REQUIRE(f.s[1] == intx::exp(b, uint256{e}));
            // The true value: 2^(j*e) with j*e >= 256 is 0 unless e is below 256.
            REQUIRE((f.s[1] == 0) == (e >= 256 || j * e >= 256));
        }
    }
}

TEST_CASE("EXP handler: base 1 and base 0 for every exponent length") {
    for (unsigned bytes = 0; bytes <= 32; ++bytes) {
        const uint256 e = bytes == 0 ? uint256{0} : (pow2(8 * bytes - 1) | 3);
        Slots one{1, e};
        auto r = evmone::instr::core::exp(one.stack(), 100000, state_at(EVMC_CANCUN));
        REQUIRE(r.status == EVMC_SUCCESS);
        REQUIRE(one.s[1] == 1);

        Slots zero{0, e};
        r = evmone::instr::core::exp(zero.stack(), 100000, state_at(EVMC_CANCUN));
        REQUIRE(r.status == EVMC_SUCCESS);
        REQUIRE(zero.s[1] == (bytes == 0 ? 1 : 0));
    }
}

TEST_CASE("EXP handler: spot values") {
    const auto run = [](const uint256& b, const uint256& e) {
        Slots f{b, e};
        const auto r = evmone::instr::core::exp(f.stack(), 100000, state_at(EVMC_CANCUN));
        REQUIRE(r.status == EVMC_SUCCESS);
        return f.s[1];
    };
    REQUIRE(run(256, 31) == pow2(248));
    REQUIRE(run(256, 32) == 0);
    REQUIRE(run(2, 255) == pow2(255));
    REQUIRE(run(2, 256) == 0);
    REQUIRE(run(pow2(31), 8) == pow2(248));
    REQUIRE(run(pow2(31), 9) == 0);
    REQUIRE(run(pow2(31), 7) == pow2(217));
    REQUIRE(run(pow2(16), 15) == pow2(240));
    REQUIRE(run(pow2(16), 16) == 0);
    REQUIRE(run(1, ~uint256{0}) == 1);
    REQUIRE(run(0, 0) == 1);
    REQUIRE(run(0, 1) == 0);
    REQUIRE(run(pow2(256 - 1), 2) == 0);
    REQUIRE(run(pow2(40) + 256, 2) == pow2(80) + pow2(49) + pow2(16));
    REQUIRE(run(256, pow2(29)) == 0);
}
