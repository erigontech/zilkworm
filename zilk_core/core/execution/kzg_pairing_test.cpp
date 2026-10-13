// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// KZG point evaluation against two independent pairing checks. kzg_verify_proof() tests
// e(C + [z]π - [y]₁, [1]₂) = e(π, [s]₂) in a single Miller loop over the precomputed lines of [1]₂
// and [s]₂, evaluating the [s]₂ lines at -π so that both products share their squarings. The
// reference evaluates the textbook equation e(C - [y]₁, [1]₂) = e(π, [s - z]₂) with blst's generic
// Miller loop on the G2 points themselves. The base check runs the same rearranged equation as
// kzg_verify_proof() with two separate blst_miller_loop_lines() calls and blst_fp12_finalverify(),
// as the code did before the loops were merged. The proofs that matter have π ≠ O: with π = O the
// [s]₂ side is 1, and a lost sign, swapped line tables or a wrong loop schedule would all go unseen.

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>

#include <blst.h>
#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/kzg_precomputed_lines.hpp>
#include <evmone_precompiles/sha256.hpp>

namespace {

using Bytes32 = std::array<uint8_t, 32>;
using Bytes48 = std::array<uint8_t, 48>;

// g1_monomial[1] and g2_monomial[1] of the Ethereum mainnet trusted setup: [s]₁ and [s]₂.
constexpr Bytes48 kSetupG1{
    0xad, 0x3e, 0xb5, 0x01, 0x21, 0x13, 0x9a, 0xa3, 0x4d, 0xb1, 0xd5, 0x45, 0x09, 0x3a, 0xc9, 0x37,
    0x4a, 0xb7, 0xbc, 0xa2, 0xc0, 0xf3, 0xbf, 0x28, 0xe2, 0x7c, 0x8d, 0xcd, 0x8f, 0xc7, 0xcb, 0x42,
    0xd2, 0x59, 0x26, 0xfc, 0x0c, 0x97, 0xb3, 0x36, 0xe9, 0xf0, 0xfb, 0x35, 0xe5, 0xa0, 0x4c, 0x81};
constexpr std::array<uint8_t, 96> kSetupG2{
    0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3, 0x89,
    0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8, 0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d,
    0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2, 0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72,
    0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 0x73, 0x44, 0x29, 0xb7, 0xb3, 0x86, 0x08, 0xe2,
    0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9, 0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b,
    0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed, 0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2};

struct Input {
    Bytes32 z{};
    Bytes32 y{};
    Bytes48 c{};
    Bytes48 pi{};
};

blst_p1_affine uncompress_g1(const Bytes48& b) {
    blst_p1_affine p;
    REQUIRE(blst_p1_uncompress(&p, b.data()) == BLST_SUCCESS);
    return p;
}

blst_p1 g1_mul(const blst_p1& p, const blst_fr& k) {
    blst_scalar s;
    blst_scalar_from_fr(&s, &k);
    blst_p1 r;
    blst_p1_mult(&r, &p, s.b, 255);
    return r;
}

Bytes48 compress(const blst_p1& p) {
    Bytes48 b;
    blst_p1_compress(b.data(), &p);
    return b;
}

Bytes32 to_bytes(const blst_fr& v) {
    blst_scalar s;
    blst_scalar_from_fr(&s, &v);
    Bytes32 b;
    blst_bendian_from_scalar(b.data(), &s);
    return b;
}

blst_fr from_bytes(const Bytes32& b) {
    blst_scalar s;
    blst_scalar_from_bendian(&s, b.data());
    blst_fr v;
    blst_fr_from_scalar(&v, &s);
    return v;
}

blst_fr fr_u64(uint64_t x) {
    const uint64_t limbs[4]{x, 0, 0, 0};
    blst_fr v;
    blst_fr_from_uint64(&v, limbs);
    return v;
}

blst_fr fr_add(const blst_fr& a, const blst_fr& b) {
    blst_fr r;
    blst_fr_add(&r, &a, &b);
    return r;
}

blst_fr fr_mul(const blst_fr& a, const blst_fr& b) {
    blst_fr r;
    blst_fr_mul(&r, &a, &b);
    return r;
}

blst_fr random_fr(std::mt19937_64& rng) {
    std::array<uint8_t, 32> b;
    for (auto& x : b) x = static_cast<uint8_t>(rng());
    b[31] &= 0x3f;  // below 2^254 < r
    blst_scalar s;
    blst_scalar_from_lendian(&s, b.data());
    blst_fr v;
    blst_fr_from_scalar(&v, &s);
    return v;
}

bool verify(const Input& in) {
    std::array<std::byte, 32> hash;
    evmone::crypto::sha256(hash.data(), reinterpret_cast<const std::byte*>(in.c.data()), 48);
    hash[0] = evmone::crypto::VERSIONED_HASH_VERSION_KZG;
    return evmone::crypto::kzg_verify_proof(
        hash.data(), reinterpret_cast<const std::byte*>(in.z.data()),
        reinterpret_cast<const std::byte*>(in.y.data()),
        reinterpret_cast<const std::byte*>(in.c.data()),
        reinterpret_cast<const std::byte*>(in.pi.data()));
}

// e(P, Q), up to the final exponentiation, with e(O, Q) = e(P, O) = 1.
blst_fp12 miller_loop(const blst_p2& q, const blst_p1& p) {
    blst_fp12 f = *blst_fp12_one();
    if (!blst_p1_is_inf(&p) && !blst_p2_is_inf(&q)) {
        blst_p1_affine pa;
        blst_p1_to_affine(&pa, &p);
        blst_p2_affine qa;
        blst_p2_to_affine(&qa, &q);
        blst_miller_loop(&f, &qa, &pa);
    }
    return f;
}

// e(C - [y]₁, [1]₂) = e(π, [s - z]₂) for valid encodings.
bool reference_verify(const Input& in) {
    blst_p1 c;
    const auto ca = uncompress_g1(in.c);
    blst_p1_from_affine(&c, &ca);
    blst_p1 pi;
    const auto pia = uncompress_g1(in.pi);
    blst_p1_from_affine(&pi, &pia);

    blst_p1 y_g1 = g1_mul(*blst_p1_generator(), from_bytes(in.y));
    blst_p1_cneg(&y_g1, true);
    blst_p1 lhs;
    blst_p1_add_or_double(&lhs, &c, &y_g1);

    blst_p2_affine s2a;
    REQUIRE(blst_p2_uncompress(&s2a, kSetupG2.data()) == BLST_SUCCESS);
    blst_p2 s2;
    blst_p2_from_affine(&s2, &s2a);
    blst_scalar z;
    blst_scalar_from_bendian(&z, in.z.data());
    blst_p2 z_g2;
    blst_p2_mult(&z_g2, blst_p2_generator(), z.b, 255);
    blst_p2_cneg(&z_g2, true);
    blst_p2 s_minus_z;
    blst_p2_add_or_double(&s_minus_z, &s2, &z_g2);

    const blst_fp12 left = miller_loop(*blst_p2_generator(), lhs);
    const blst_fp12 right = miller_loop(s_minus_z, pi);
    return blst_fp12_finalverify(&left, &right);
}

// The pairing check as it was before the Miller loops were merged: the same rearranged equation
// e(C + [z]π - [y]₁, [1]₂) = e(π, [s]₂) with one loop per side over the precomputed lines.
bool base_verify(const Input& in) {
    blst_p1 c;
    const auto ca = uncompress_g1(in.c);
    blst_p1_from_affine(&c, &ca);
    blst_p1 pi;
    const auto pia = uncompress_g1(in.pi);
    blst_p1_from_affine(&pi, &pia);

    const blst_p1 z_pi = g1_mul(pi, from_bytes(in.z));
    blst_p1 y_g1 = g1_mul(*blst_p1_generator(), from_bytes(in.y));
    blst_p1_cneg(&y_g1, true);
    blst_p1 lhs;
    blst_p1_add_or_double(&lhs, &c, &z_pi);
    blst_p1_add_or_double(&lhs, &lhs, &y_g1);

    blst_p1_affine a1;
    blst_p1_to_affine(&a1, &lhs);
    blst_fp12 left;
    blst_fp12 right;
    blst_miller_loop_lines(&left, evmone::crypto::g2_gen_lines(), &a1);
    blst_miller_loop_lines(&right, evmone::crypto::kzg_setup_g2_1_lines(), &pia);
    return blst_fp12_finalverify(&left, &right);
}

// Checks the verdict against the reference, the base check and the one the construction gives.
void check(const Input& in, bool expected) {
    CHECK(reference_verify(in) == expected);
    CHECK(base_verify(in) == expected);
    CHECK(verify(in) == expected);
}

}  // namespace

TEST_CASE("kzg point evaluation with a non-trivial proof") {
    std::mt19937_64 rng{4844};
    blst_p1 s1;
    const auto s1a = uncompress_g1(kSetupG1);
    blst_p1_from_affine(&s1, &s1a);
    const blst_p1& g1 = *blst_p1_generator();
    const blst_fr zero = fr_u64(0);
    const blst_fr one = fr_u64(1);
    blst_fr minus_one;
    blst_fr_sub(&minus_one, &zero, &one);

    for (int i = 0; i < 24; ++i) {
        // f(X) = a + bX: C = [a]₁ + [b][s]₁, y = f(z), and the quotient (f(X) - y) / (X - z) = b
        // gives π = [b]₁.
        const blst_fr a = i == 0 ? zero : random_fr(rng);
        const blst_fr b = i == 1 ? one : i == 2 ? minus_one : random_fr(rng);
        const blst_fr z = i == 3 ? zero : i == 4 ? minus_one : random_fr(rng);
        blst_p1 c;
        const blst_p1 a_g1 = g1_mul(g1, a);
        const blst_p1 b_s1 = g1_mul(s1, b);
        blst_p1_add_or_double(&c, &a_g1, &b_s1);
        const blst_p1 pi = g1_mul(g1, b);

        Input in;
        in.z = to_bytes(z);
        in.y = to_bytes(fr_add(a, fr_mul(b, z)));
        in.c = compress(c);
        in.pi = compress(pi);
        check(in, true);

        Input neg_pi = in;
        neg_pi.pi[0] ^= 0x20;  // the sign flag of the compressed form
        check(neg_pi, false);

        Input y_plus_one = in;
        y_plus_one.y = to_bytes(fr_add(from_bytes(in.y), one));
        check(y_plus_one, false);

        Input z_plus_one = in;
        z_plus_one.z = to_bytes(fr_add(z, one));
        check(z_plus_one, false);

        Input pi_plus_g1 = in;
        blst_p1 p;
        blst_p1_add_or_double(&p, &pi, &g1);
        pi_plus_g1.pi = compress(p);
        check(pi_plus_g1, false);

        // C = [y]₁ - [z]π makes the left argument O while π ≠ O.
        Input lhs_inf = in;
        blst_p1 z_pi = g1_mul(pi, z);
        blst_p1_cneg(&z_pi, true);
        const blst_p1 y_g1 = g1_mul(g1, from_bytes(in.y));
        blst_p1_add_or_double(&p, &y_g1, &z_pi);
        lhs_inf.c = compress(p);
        check(lhs_inf, false);

        // C = O with π ≠ O.
        Input c_inf = in;
        c_inf.c = compress(blst_p1{});
        check(c_inf, false);

        // A constant polynomial: π = O, the [s]₂ side drops out.
        Input constant;
        constant.z = in.z;
        constant.y = to_bytes(a);
        constant.c = compress(a_g1);
        constant.pi = compress(blst_p1{});
        check(constant, true);
        constant.y = to_bytes(fr_add(a, one));
        check(constant, false);
    }
}

TEST_CASE("kzg point evaluation of random inputs agrees with the base check") {
    std::mt19937_64 rng{1559};
    const blst_p1& g1 = *blst_p1_generator();
    for (int i = 0; i < 64; ++i) {
        // Arbitrary commitments and proofs, some of them O: nearly all verdicts are false, and the
        // three checks must still agree on every one of them.
        Input in;
        in.z = to_bytes(random_fr(rng));
        in.y = to_bytes(random_fr(rng));
        in.c = compress(i % 8 == 0 ? blst_p1{} : g1_mul(g1, random_fr(rng)));
        in.pi = compress(i % 8 == 1 ? blst_p1{} : g1_mul(g1, random_fr(rng)));
        const bool base = base_verify(in);
        CHECK(reference_verify(in) == base);
        CHECK(verify(in) == base);
    }
}
