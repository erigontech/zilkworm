// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 MULMOD reduction (intx div32::mulmod_reduce and its closed forms for the NIST P-256
// prime, 2^256 - 1 and powers of two) against intx's generic mulmod on the host. The guest's
// handler cannot run here (its MUL_LOW and MUL_HIGH are CSR writes), so the test hands the
// reduction the product it would find: umul(x, y) in an aligned 512-bit object, and the modulus
// in a slot between two poisoned ones, which must keep their values like the product does.
// INTX_DIV32_TEST compiles div32 on the host.
//
// ZILK_MULMOD_STRESS=n multiplies the number of random cases by n (the default runs in a second).

#ifndef INTX_DIV32_TEST
#define INTX_DIV32_TEST
#endif

#include <array>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <intx/intx.hpp>

namespace {

using intx::uint256;
using intx::uint512;
namespace d32 = intx::internal::div32;

uint256 from_hex(const char* s) { return intx::from_string<uint256>(s); }

const uint256 kP256 = from_hex("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
const uint256 kOnes = ~uint256{0};
const uint256 kBn254R =
    from_hex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
const uint256 kBn254P =
    from_hex("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
const uint256 kStark = from_hex("0x800000000000011000000000000000000000000000000000000000000000001");
const uint256 kSecpP =
    from_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const uint256 kSecpN =
    from_hex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const uint256 kP256N =
    from_hex("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

constexpr uint64_t kPoison = 0xa5a5a5a5a5a5a5a5;
const uint256 kGuard{kPoison, kPoison, kPoison, kPoison};

unsigned stress() {
    const char* e = std::getenv("ZILK_MULMOD_STRESS");
    const long n = e ? std::strtol(e, nullptr, 10) : 1;
    return n > 0 ? static_cast<unsigned>(n) : 1;
}

uint32_t word(const uint256& v, unsigned i) {
    return static_cast<uint32_t>(v[i / 2] >> (32 * (i % 2)));
}

uint256 with_word(uint256 v, unsigned i, uint32_t w) {
    uint64_t& q = v[i / 2];
    const unsigned s = 32 * (i % 2);
    q = (q & ~(uint64_t{0xffffffff} << s)) | (uint64_t{w} << s);
    return v;
}

uint512 from_words16(const uint32_t (&w)[16]) {
    uint512 t;
    for (unsigned i = 0; i < 8; ++i) t[i] = uint64_t{w[2 * i]} | (uint64_t{w[2 * i + 1]} << 32);
    return t;
}

uint256 pow2(unsigned k) { return uint256{1} << k; }

struct Rng {
    std::mt19937_64 g;
    explicit Rng(uint64_t seed) : g(seed) {}
    uint64_t operator()() { return g(); }
    uint256 any() { return uint256{g(), g(), g(), g()}; }
    // A value of exactly b bits (b in 0..256).
    uint256 bits(unsigned b) {
        if (b == 0) return 0;
        uint256 v = any();
        if (b < 256) v &= pow2(b) - 1;
        return v | pow2(b - 1);
    }
    // A 32-bit word that favors the values that break carries.
    uint32_t edge_word() {
        switch (g() % 8) {
            case 0: return 0;
            case 1: return 1;
            case 2: return 0xffffffffu;
            case 3: return 0x80000000u;
            case 4: return 0x7fffffffu;
            case 5: return 0xfffffffeu;
            default: return static_cast<uint32_t>(g());
        }
    }
};

long g_checks = 0;

// m != 0. Runs the front end on x * y and m and compares with the generic mulmod and with the
// base's 3-argument urem on the same product (the code mulmod_reduce replaced).
void check(const uint256& x, const uint256& y, const uint256& m) {
    REQUIRE(m != 0);
    alignas(32) uint512 p = intx::umul(x, y);
    const uint512 p0 = p;
    alignas(32) std::array<uint256, 3> slots{kGuard, m, kGuard};
    d32::mulmod_reduce(p, slots[1]);
    ++g_checks;
    const uint256 want = intx::mulmod(x, y, m);
    bool ok = slots[1] == want && slots[0] == kGuard && slots[2] == kGuard && p == p0;
    if (ok) {
        alignas(32) uint256 base = m;
        d32::urem(p, base, base);
        ok = base == want;
    }
    if (!ok) {
        INFO("x=" << intx::hex(x) << " y=" << intx::hex(y) << " m=" << intx::hex(m));
        INFO("got=" << intx::hex(slots[1]) << " want=" << intx::hex(want));
        REQUIRE(slots[1] == want);
        REQUIRE(slots[0] == kGuard);
        REQUIRE(slots[2] == kGuard);
        REQUIRE(p == p0);
        FAIL("the base urem disagrees with the generic mulmod");
    }
}

// The moduli the front end special-cases, their near misses, and a spread of others.
std::vector<uint256> moduli(Rng& rng) {
    std::vector<uint256> out{kP256, kOnes, kBn254R, kBn254P, kStark, kSecpP, kSecpN, kP256N,
        1, 2, 3, 0xffffffffffffffff, pow2(64), pow2(255) + 1, pow2(255) - 1};
    // One word changed by one bit, in either half, in the two moduli matched by their words.
    for (unsigned w = 0; w < 8; ++w) {
        for (const uint32_t d : {1u, 2u, 0x80000000u, 0x40000000u}) {
            out.push_back(with_word(kP256, w, word(kP256, w) ^ d));
            out.push_back(with_word(kOnes, w, word(kOnes, w) ^ d));
        }
        // P-256's other words in place of one, and 2^256 - 1 with a word cleared.
        out.push_back(with_word(kOnes, w, 0));
        out.push_back(with_word(kP256, w, 0xffffffffu));
        out.push_back(with_word(kP256, w, 0));
    }
    // P-256 and 2^256 - 1 shifted by whole words and bits: not the matched constants.
    out.push_back(kP256 >> 1);
    out.push_back(kOnes >> 1);
    out.push_back(kOnes - 1);
    out.push_back(kP256 + 1);
    out.push_back(kP256 - 1);
    for (unsigned k = 0; k < 256; ++k) {
        out.push_back(pow2(k));
        if (k) {
            out.push_back(pow2(k) + 1);
            out.push_back(pow2(k) - 1);
            out.push_back(pow2(k) | pow2(rng() % k));                  // 2^k + 2^j
            out.push_back(pow2(k) | pow2((k & ~31u) + rng() % 32));    // a second bit in its word
            out.push_back(pow2(k) | (pow2(k & ~31u) - 1));             // words below all ones
            out.push_back(pow2(k) | pow2(rng() % 32));                 // a bit in word 0
        }
    }
    for (unsigned b = 1; b <= 256; ++b) out.push_back(rng.bits(b));
    return out;
}

}  // namespace

TEST_CASE("mulmod_reduce matches intx::mulmod on crafted operands") {
    Rng rng{101};
    const auto mods = moduli(rng);
    for (const auto& m : mods) {
        const uint256 specials[] = {0, 1, 2, 3, m - 1, m, m + 1, m + 2, m - 2, kOnes, kOnes - 1,
            pow2(255), pow2(255) - 1, pow2(128), pow2(128) - 1, kP256, kP256 - 1, kP256 + 1,
            kBn254R - 1, kStark - 1, m >> 1, (m >> 1) + 1, m << 1, ~m};
        for (const auto& a : specials)
            for (const auto& b : specials) check(a, b, m);
        // x = m -+ d with y = 1 straddles the a * b < m shortcut, and the factorings of m - 1, m
        // and m + 1 put the product just on either side of it.
        for (const uint256 d : {uint256{0}, uint256{1}, uint256{2}, uint256{3}, uint256{0xffffffff},
                 uint256{0x100000000}}) {
            check(m - d, 1, m);
            check(m + d, 1, m);
            check(1, m - d, m);
            check(1, m + d, m);
        }
        for (const uint256 f : {uint256{2}, uint256{3}, uint256{5}, uint256{0xffffffff}}) {
            const uint256 q = m / f;
            for (const uint256 e : {uint256{0}, uint256{1}, uint256{2}}) {
                check(f, q + e, m);
                check(f, q - e, m);
                check(q, f, m);
            }
        }
    }
}

TEST_CASE("mulmod_reduce matches intx::mulmod on the largest products") {
    // (2^256 - 1)^2, p^2 - 1, (p - 1)^2, p * (2^256 - 1), 2^511 - ish: every product length from 9
    // to 16 words, for the moduli that take a closed form and a few that do not.
    const uint256 big[] = {kOnes, kP256, kP256 - 1, kP256 + 1, pow2(255), pow2(255) | 1,
        kOnes - 1, kOnes ^ pow2(255), kBn254R, kStark, kSecpP};
    for (const uint256& m :
        {kP256, kOnes, kBn254R, kStark, kSecpP, kP256N, pow2(255), pow2(128), pow2(96) , pow2(32),
            uint256{2}, uint256{1}})
        for (const auto& a : big)
            for (const auto& b : big) check(a, b, m);
    // Products of exactly 9..16 words.
    Rng rng{102};
    for (const uint256& m : {kP256, kOnes, kBn254R, kStark, pow2(200)}) {
        for (unsigned total = 250; total <= 512; ++total) {
            const unsigned xb = std::min(256u, std::max(total - 256u, total / 2));
            const unsigned yb = std::min(256u, total - xb + 1);
            for (int i = 0; i < 6; ++i) {
                check(rng.bits(xb), rng.bits(yb), m);
                check(rng.bits(yb), rng.bits(xb), m);
            }
        }
    }
}

TEST_CASE("mulmod_reduce matches intx::mulmod on random operands") {
    Rng rng{103};
    const auto mods = moduli(rng);
    const unsigned rounds = 300 * stress();
    for (unsigned r = 0; r < rounds; ++r) {
        for (const auto& m : mods) {
            uint256 x, y;
            switch (rng() % 7) {
                case 0: x = rng.any(); y = rng.any(); break;
                case 1: x = rng.any() % m; y = rng.any() % m; break;
                case 2: x = rng.any() % m; y = rng() & 0xffffffffu; break;
                case 3: x = rng.bits(rng() % 257); y = rng.bits(rng() % 257); break;
                case 4: x = rng.bits(rng() % 129); y = rng.bits(rng() % 129); break;
                case 5: {
                    // Words from the carry-breaking set.
                    for (unsigned w = 0; w < 8; ++w) {
                        x = with_word(x, w, rng.edge_word());
                        y = with_word(y, w, rng.edge_word());
                    }
                    break;
                }
                default: x = rng.any() % m; y = rng.bits(rng() % 257); break;
            }
            check(x, y, m);
        }
    }
    // Random moduli of every width: none of them is sparse, so these are the fallback path.
    const unsigned rounds2 = 20000 * stress();
    for (unsigned r = 0; r < rounds2; ++r) {
        const uint256 m = rng.bits(1 + rng() % 256);
        check(rng.any(), rng.any(), m);
        check(rng.bits(rng() % 257), rng.bits(rng() % 257), m);
    }
}

TEST_CASE("the P-256, 2^256 - 1 and power-of-two closed forms reduce any 512-bit value") {
    Rng rng{104};
    const uint512 p256{kP256};
    const uint512 ones{kOnes};
    const auto draw = [&](uint32_t (&t)[16], unsigned live) {
        for (unsigned i = 0; i < 16; ++i) t[i] = i < live ? rng.edge_word() : 0;
    };
    const unsigned rounds = 200000 * stress();
    for (unsigned r = 0; r < rounds; ++r) {
        uint32_t t[16];
        // The long product lengths, and the odd ones: the short fold takes up to 9 words.
        const unsigned live = (r % 3 == 0) ? 16 : 9 + rng() % 8;
        draw(t, live);
        if (r % 11 == 0)
            for (auto& w : t) w = 0xffffffffu;
        if (r % 13 == 0)
            for (unsigned i = 0; i < 16; ++i) t[i] = (rng() & 1) ? 0xffffffffu : 0;
        const uint512 v = from_words16(t);

        uint32_t out[8];
        d32::p256_reduce(out, t);
        uint256 got;
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == v % p256);

        d32::ones_fold(out, t);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == v % ones);

        uint32_t s[16];
        for (unsigned i = 0; i < 16; ++i) s[i] = i < 9 ? t[i] : 0;
        const uint512 sv = from_words16(s);
        d32::p256_reduce_short(out, s);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == sv % p256);
        // And the full form on the same short value.
        d32::p256_reduce(out, s);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == sv % p256);
    }

    // The extremes of every column: 2^512 - 1 and each word alone at its maximum.
    uint32_t t[16];
    uint32_t out[8];
    uint256 got;
    for (unsigned hot = 0; hot <= 16; ++hot) {
        for (unsigned i = 0; i < 16; ++i) t[i] = (hot == 16 || i == hot) ? 0xffffffffu : 0;
        const uint512 v = from_words16(t);
        d32::p256_reduce(out, t);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == v % p256);
        d32::ones_fold(out, t);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == v % ones);
    }
    // Multiples of p: the reduction must give 0, with k at its largest and smallest.
    for (unsigned k = 0; k < 4000; ++k) {
        const uint512 v = uint512{kP256} * (k < 2000 ? uint512{k} : uint512{rng.any()});
        uint32_t w[16];
        for (unsigned i = 0; i < 16; ++i)
            w[i] = static_cast<uint32_t>(v[i / 2] >> (32 * (i % 2)));
        d32::p256_reduce(out, w);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(got == 0);
        // And one either side: p * q +- 1.
        const uint512 up = v + 1;
        for (unsigned i = 0; i < 16; ++i)
            w[i] = static_cast<uint32_t>(up[i / 2] >> (32 * (i % 2)));
        d32::p256_reduce(out, w);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(uint512{got} == up % p256);
        if (v != 0) {
            const uint512 dn = v - 1;
            for (unsigned i = 0; i < 16; ++i)
                w[i] = static_cast<uint32_t>(dn[i / 2] >> (32 * (i % 2)));
            d32::p256_reduce(out, w);
            for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
            REQUIRE(uint512{got} == dn % p256);
        }
    }
    // Multiples of 2^256 - 1 likewise (all ones maps to 0, never to 2^256 - 1).
    for (unsigned k = 0; k < 4000; ++k) {
        const uint512 v = uint512{kOnes} * (k < 2000 ? uint512{k} : uint512{rng.any()});
        uint32_t w[16];
        for (unsigned i = 0; i < 16; ++i)
            w[i] = static_cast<uint32_t>(v[i / 2] >> (32 * (i % 2)));
        d32::ones_fold(out, w);
        for (unsigned i = 0; i < 8; ++i) got = with_word(got, i, out[i]);
        REQUIRE(got == 0);
    }
}

TEST_CASE("pow2_mask keeps the low k bits") {
    Rng rng{105};
    for (unsigned k = 0; k < 256; ++k) {
        for (int i = 0; i < 20; ++i) {
            uint32_t t[16];
            for (auto& w : t) w = rng.edge_word();
            const uint512 v = from_words16(t);
            uint32_t out[8];
            d32::pow2_mask(out, t, k);
            uint256 got;
            for (unsigned j = 0; j < 8; ++j) got = with_word(got, j, out[j]);
            REQUIRE(uint512{got} == v % uint512{pow2(k)});
        }
    }
}
