// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// intx::count_significant_bytes(uint64_t) on rv32 counts by comparisons on the significant 32-bit
// half instead of through a leading-zero count (a libgcc call there). Every RLP length and integer
// encoding and EXP's gas charge depend on it, so the comparison form is checked here against the
// leading-zero formula the host uses: around every byte and bit boundary of both halves, and on
// random values. The host build compiles the leading-zero form into count_significant_bytes itself,
// so the comparison form is called by name. EXP's bit width, taken on rv32 from that byte count and
// the top byte, is checked against intx::bit_width() as well.

#include <bit>
#include <cstdint>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include <evmone/instructions.hpp>
#include <intx/intx.hpp>

namespace {

constexpr unsigned by_clz(uint64_t x) noexcept {
    return (64 - static_cast<unsigned>(std::countl_zero(x)) + 7) / 8;
}

constexpr unsigned by_compare(uint64_t x) noexcept {
    return intx::internal::count_significant_bytes_by_compare(x);
}

static_assert(by_compare(0) == 0);
static_assert(by_compare(1) == 1);
static_assert(by_compare(0xff) == 1);
static_assert(by_compare(0x100) == 2);
static_assert(by_compare(0xffffffff) == 4);
static_assert(by_compare(uint64_t{1} << 32) == 5);
static_assert(by_compare(~uint64_t{0}) == 8);

// Counts the inputs on which the two forms differ and keeps the first one for the report.
struct Mismatches {
    uint64_t count = 0;
    uint64_t first = 0;

    void check(uint64_t x) noexcept {
        if (by_compare(x) != by_clz(x) && count++ == 0) first = x;
    }
};

}  // namespace

TEST_CASE("count_significant_bytes by comparison: boundaries of both halves") {
    Mismatches m;
    // Every value of the low 20 bits, alone and under each high half of interest: the high half
    // decides on its own once it is non-zero, whatever the low half holds.
    for (uint64_t v = 0; v < (uint64_t{1} << 20); ++v) {
        m.check(v);
        m.check(v << 32);
        m.check((v << 32) | 1);
        m.check((v << 32) | 0xffffffff);
    }
    // 2^k and its neighbours at every bit position, which include every byte boundary.
    for (unsigned k = 0; k < 64; ++k) {
        const uint64_t p = uint64_t{1} << k;
        for (const uint64_t x : {p, p - 1, p + 1, p | (p - 1), ~p, ~(p - 1)})
            m.check(x);
    }
    // Each half at each byte boundary, in every combination.
    constexpr uint32_t kEdges[]{0,        1,         0x7f,      0x80,       0xff,      0x100,
                                0xffff,   0x10000,   0xffffff,  0x1000000,  0x7fffffff, 0x80000000,
                                0xffffffff};
    for (const uint32_t hi : kEdges)
        for (const uint32_t lo : kEdges)
            m.check((uint64_t{hi} << 32) | lo);
    INFO("first mismatch: " << m.first);
    REQUIRE(m.count == 0);
}

TEST_CASE("count_significant_bytes by comparison: random values of every length") {
    Mismatches m;
    std::mt19937_64 rng{0x5eed};
    for (int i = 0; i < 4'000'000; ++i)
        m.check(rng() >> (rng() % 64));
    INFO("first mismatch: " << m.first);
    REQUIRE(m.count == 0);
}

#ifdef EVMONE_RV32_DISPATCH_TEST
namespace {

using intx::uint256;

// EXP's bit width from the byte count of its gas charge, against intx's.
struct BitWidthMismatches {
    uint64_t count = 0;
    uint256 first;

    void check(const uint256& x) noexcept {
        const auto n = intx::count_significant_bytes(x);
        if (evmone::instr::core::bit_width_by_bytes(x, n) != intx::bit_width(x) && count++ == 0) first = x;
    }
};

}  // namespace

TEST_CASE("EXP bit width by bytes: powers of two and their neighbours at every position") {
    BitWidthMismatches m;
    m.check(0);
    for (unsigned k = 0; k < 256; ++k) {
        const uint256 p = uint256{1} << k;
        m.check(p);
        m.check(p - 1);
        m.check(p + 1);
        m.check(p | (p - 1));
        m.check(~p);
        m.check(~(p - 1));
    }
    // Every value of the top significant byte at each of the 32 byte positions, over a low part
    // of zeros, ones and a pattern: the byte that carries the width is the only one that counts.
    for (unsigned pos = 0; pos < 32; ++pos) {
        for (unsigned b = 0; b < 256; ++b) {
            const uint256 top = uint256{b} << (8 * pos);
            const uint256 below = (uint256{1} << (8 * pos)) - 1;
            m.check(top);
            m.check(top | below);
            m.check(top | (below & uint256{0x5555555555555555, 0x5555555555555555, 0x5555555555555555,
                                           0x5555555555555555}));
        }
    }
    INFO("first mismatch: " << intx::hex(m.first));
    CHECK(m.count == 0);
}

TEST_CASE("EXP bit width by bytes: random values of every length") {
    BitWidthMismatches m;
    std::mt19937_64 rng{0xe4b};
    for (int i = 0; i < 1'000'000; ++i) {
        uint256 x{rng(), rng(), rng(), rng()};
        x >>= static_cast<unsigned>(rng() % 256);
        m.check(x);
    }
    INFO("first mismatch: " << intx::hex(m.first));
    CHECK(m.count == 0);
}
#endif
