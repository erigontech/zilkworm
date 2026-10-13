// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// ADDMOD handler against (x + y) mod m computed in 512 bits and against intx::addmod (the code
// the handler falls back to). The rv32 fast path takes x < m and y < m: it adds over 32-bit
// words and subtracts m once into m's own stack slot, so the cases below aim at its edges: a
// carry out of bit 256, x + y equal to m, m - 1 and 2m - 1, equal top words with random words
// below, carry and borrow chains across every word boundary, m of one to 256 bits, and
// operands at or above m (which it must decline, leaving m untouched). The native build sets
// -DEVMONE_RV32_DISPATCH_TEST, which compiles that path on the host.

#include <array>
#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/instructions.hpp>

namespace {

using intx::uint256;

constexpr uint64_t kPoison = 0xa5a5a5a5a5a5a5a5;
const uint256 kPoisonSlot{kPoison, kPoison, kPoison, kPoison};

// The stack of an instruction under test: x on top, then y, then m, with a poisoned slot below
// that the instruction must not touch.
struct Slots {
    alignas(32) std::array<uint256, 4> s;

    Slots(const uint256& x, const uint256& y, const uint256& m) {
        s[0] = kPoisonSlot;
        s[1] = m;
        s[2] = y;
        s[3] = x;
    }
    evmone::StackTop stack() { return evmone::StackTop{s.data() + 4}; }
};

uint256 ref_addmod(const uint256& x, const uint256& y, const uint256& m) {
    if (m == 0) return 0;
    const auto s = intx::addc(x, y);
    intx::uint<512> w = s.value;
    w[4] = s.carry;
    return static_cast<uint256>(w % intx::uint<512>{m});
}

uint256 rnd256(std::mt19937_64& rng) { return uint256{rng(), rng(), rng(), rng()}; }

uint256 rnd_bits(std::mt19937_64& rng, unsigned bits) {
    if (bits == 0) return 0;
    uint256 x = rnd256(rng);
    if (bits < 256) x &= (uint256{1} << bits) - 1;
    return x | (uint256{1} << (bits - 1));
}

// A value built from 32-bit words drawn from the edges of the word range, so that carries and
// borrows travel through every word boundary.
uint256 patterned(std::mt19937_64& rng) {
    static constexpr uint32_t pool[] = {0, 1, 2, 0x7fffffff, 0x80000000, 0x80000001, 0xfffffffe,
        0xffffffff};
    uint256 v;
    for (unsigned w = 0; w < 8; ++w) {
        const uint32_t r = (rng() % 4 == 0) ? static_cast<uint32_t>(rng()) : pool[rng() % 8];
        v[w / 2] |= uint64_t{r} << (32 * (w % 2));
    }
    return v;
}

std::vector<uint256> moduli(std::mt19937_64& rng) {
    std::vector<uint256> out{0, 1, 2, 3, 0xffffffff, uint256{1} << 32, 0xffffffffffffffff,
        uint256{1} << 64, ~uint256{0}, ~uint256{0} - 1, ~uint256{0} - 3, uint256{1} << 255,
        (uint256{1} << 255) + 1, (uint256{1} << 255) - 1, uint256{1} << 192,
        (uint256{1} << 192) + 1, (uint256{1} << 192) - 1};
    for (unsigned k = 0; k < 256; ++k) {
        out.push_back(uint256{1} << k);
        out.push_back((uint256{1} << k) - 1);
        out.push_back(rnd_bits(rng, k + 1));
    }
    for (int i = 0; i < 300; ++i) out.push_back(patterned(rng));
    return out;
}

std::vector<uint256> operands(const uint256& m, std::mt19937_64& rng) {
    std::vector<uint256> out{0, 1, 2, ~uint256{0}, ~uint256{0} - 1, m, m + 1, m - 1, m - 2, m + 7,
        m - 8, m >> 1, (m >> 1) + 1};
    // Equal top 32-bit word, random words below: the compare falls through to a lower word.
    {
        uint256 v = rnd256(rng);
        v[3] = m[3];
        out.push_back(v);
        v = rnd256(rng);
        v[3] = (m[3] & 0xffffffff00000000) | (v[3] & 0xffffffff);
        out.push_back(v);
        v = m;
        v[0] ^= 1;
        out.push_back(v);
        v = m;
        v[1] ^= uint64_t{1} << 63;
        out.push_back(v);
    }
    if (m != 0) {
        out.push_back(rnd256(rng) % m);
        out.push_back(rnd256(rng) % m);
        out.push_back(patterned(rng) % m);
        out.push_back(patterned(rng) % m);
    }
    out.push_back(rnd256(rng));
    out.push_back(patterned(rng));
    return out;
}

// Second operands that land the sum on the edges of the reduction, given x.
std::vector<uint256> partners(const uint256& x, const uint256& m, std::mt19937_64& rng) {
    std::vector<uint256> out;
    if (m != 0) {
        const uint256 r = x % m;
        out.push_back(m - r);              // x + y == m (mod 2^256 when x < m)
        out.push_back(m - 1 - r);          // x + y == m - 1
        out.push_back(m - 2 - r);          // x + y == m - 2
        out.push_back(m - 1 + (m - r));    // x + y == 2m - 1 (carry for a large m)
        out.push_back(m - 1);              // largest reduced y
        out.push_back(m - 1 - (rng() % 4));
    }
    return out;
}

struct Counts {
    long calls = 0, reduced = 0, carry = 0, sum_eq_m = 0, declined = 0;
};

// One ADDMOD through the handler, checked against both references.
void check_handler(const uint256& x, const uint256& y, const uint256& m, Counts& c) {
    Slots f{x, y, m};
    evmone::instr::core::addmod(f.stack());
    const uint256 want = ref_addmod(x, y, m);
    INFO("x=" << intx::hex(x) << " y=" << intx::hex(y) << " m=" << intx::hex(m));
    REQUIRE(f.s[1] == want);
    if (m != 0) REQUIRE(f.s[1] == intx::addmod(x, y, m));
    // The two popped operands stay as they were; nothing below the result is touched.
    REQUIRE(f.s[3] == x);
    REQUIRE(f.s[2] == y);
    REQUIRE(f.s[0] == kPoisonSlot);
    ++c.calls;
    if (m != 0 && x < m && y < m) {
        ++c.reduced;
        c.carry += intx::addc(x, y).carry;
        c.sum_eq_m += (intx::addc(x, y).value == m);
    } else
        ++c.declined;
}

#if defined(EVMONE_RV32_DISPATCH_TEST) || (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32)
#if !(defined(SP1TURBO) || defined(SP1))
#define ADDMOD_WORDS_PATH 1
#endif
#endif

#ifdef ADDMOD_WORDS_PATH
// addmod_reduced on its own: true exactly for x < m and y < m (so never for m == 0), then m
// holds the sum mod m; false leaves m, x and y untouched.
void check_reduced(const uint256& x, const uint256& y, const uint256& m) {
    alignas(32) uint256 ms = m, xs = x, ys = y;
    const bool took = evmone::instr::core::addmod_reduced(reinterpret_cast<evmone::word32*>(&ms),
        reinterpret_cast<const evmone::word32*>(&xs), reinterpret_cast<const evmone::word32*>(&ys));
    INFO("x=" << intx::hex(x) << " y=" << intx::hex(y) << " m=" << intx::hex(m));
    REQUIRE(took == (x < m && y < m));
    REQUIRE(xs == x);
    REQUIRE(ys == y);
    REQUIRE(ms == (took ? ref_addmod(x, y, m) : m));
}
#endif

}  // namespace

TEST_CASE("ADDMOD handler matches (x + y) mod m on edge moduli and operands") {
    std::mt19937_64 rng{101};
    Counts c;
    for (const auto& m : moduli(rng)) {
        for (const auto& x : operands(m, rng)) {
            for (const auto& y : operands(m, rng)) check_handler(x, y, m, c);
            for (const auto& y : partners(x, m, rng)) {
                check_handler(x, y, m, c);
                check_handler(y, x, m, c);
            }
        }
    }
    // The test must reach the cases it is written for.
    REQUIRE(c.reduced > 100000);
    REQUIRE(c.carry > 1000);
    REQUIRE(c.sum_eq_m > 100);
    REQUIRE(c.declined > 1000);
}

TEST_CASE("ADDMOD handler matches (x + y) mod m on random operands") {
    std::mt19937_64 rng{102};
    Counts c;
    for (int i = 0; i < 300000; ++i) {
        uint256 m;
        switch (rng() % 6) {
            case 0: m = rnd_bits(rng, 1 + rng() % 256); break;
            case 1: m = rnd_bits(rng, 193 + rng() % 64); break;
            case 2: m = patterned(rng); break;
            case 3: m = ~uint256{0} - (rng() % 4); break;
            case 4: m = rng() % 3; break;
            default: m = (uint256{1} << (192 + rng() % 64)) + (rng() % 3); break;
        }
        const auto xs = operands(m, rng);
        const uint256 x = xs[rng() % xs.size()];
        const uint256 y = (rng() % 4 == 0) ? xs[rng() % xs.size()] : rnd256(rng) % (m == 0 ? 1 : m);
        check_handler(x, y, m, c);
    }
    REQUIRE(c.reduced > 100000);
    REQUIRE(c.carry > 1000);
}

TEST_CASE("ADDMOD by zero gives zero and an unreduced operand takes the fallback") {
    const uint256 x{0x0123456789abcdef, 0xfedcba9876543210, 0x1111111111111111, 0x2222222222222222};
    const uint256 y{~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}};
    Counts c;
    check_handler(x, y, 0, c);
    check_handler(0, 0, 0, c);
    check_handler(x, y, 1, c);
    check_handler(x, y, 2, c);
    check_handler(y, y, y, c);  // x == y == m
    check_handler(y, y, y - 1, c);
    check_handler(x, 0, x, c);  // x == m, y == 0
    check_handler(0, x, x, c);
    check_handler(x, y, uint256{1} << 255, c);
}

#ifdef ADDMOD_WORDS_PATH
TEST_CASE("addmod_reduced takes exactly x < m and y < m, and leaves m alone otherwise") {
    std::mt19937_64 rng{103};
    for (const auto& m : moduli(rng)) {
        for (const auto& x : operands(m, rng)) {
            for (const auto& y : operands(m, rng)) check_reduced(x, y, m);
            for (const auto& y : partners(x, m, rng)) check_reduced(x, y, m);
        }
    }
    for (int i = 0; i < 300000; ++i) {
        const uint256 m = (rng() % 3) ? patterned(rng) : rnd_bits(rng, 1 + rng() % 256);
        const uint256 x = (rng() % 2) ? patterned(rng) : rnd256(rng);
        const uint256 y = (rng() % 2) ? patterned(rng) : rnd256(rng);
        check_reduced(x, y, m);
        if (m != 0) check_reduced(x % m, y % m, m);  // the domain it is written for
    }
}
#endif
