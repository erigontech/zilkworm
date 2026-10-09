// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// ecc::ProjPoint takes the 1 of its default y, and of the z of a point built from an affine point,
// from ONE, a constant folded at compile time, where it used to compute FE::one() at run time (on
// the guest a CSR multiplication per point). Every curve the precompiles use must see the same
// value: the default point is the point at infinity (0 : 1 : 0) and the bn254 and P-256
// accumulators start from it. The run-time 1 is built from a value the compiler cannot see, so
// the comparison is not folded into a tautology.
//
// The second half is a differential test against the code before the change: mul() and msm() are
// reproduced here with the accumulator started from a point whose y is the run-time 1 (what the
// default ProjPoint used to be), and must agree bit for bit with ecc::mul() and ecc::msm() on
// crafted and random scalars and points (zero, the group order and its neighbours, equal and
// opposite points), and with an affine double-and-add reference that uses neither ONE nor the
// Jacobian formulas.

#include <array>
#include <cstdint>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <evmone_precompiles/secp256r1.hpp>

namespace {

using namespace evmone::crypto;

template <typename Curve>
void check_one() {
    using FE = typename Curve::Fp;
    using Point = ecc::ProjPoint<Curve>;
    volatile uint64_t one_word = 1;
    const FE one_at_run_time{typename Curve::uint_type{one_word}};

    CHECK(Point::ONE == one_at_run_time);
    CHECK(Point::ONE == FE::one());

    const Point inf;
    CHECK(inf.x == FE{});
    CHECK(inf.y == one_at_run_time);
    CHECK(inf.z == FE{});
    const bool at_infinity = inf == 0;
    CHECK(at_infinity);

    const ecc::AffinePoint<Curve> a{FE{typename Curve::uint_type{one_word + 1}},
                                    FE{typename Curve::uint_type{one_word + 2}}};
    const Point p{a};
    CHECK(p.x == a.x);
    CHECK(p.y == a.y);
    CHECK(p.z == one_at_run_time);
    const auto back = ecc::to_affine(p);
    CHECK(back.x == a.x);
    CHECK(back.y == a.y);
}

// The point at infinity as the base code built it: y is the 1 computed at run time.
template <typename Curve>
ecc::ProjPoint<Curve> base_infinity() {
    using FE = typename Curve::Fp;
    volatile uint64_t one_word = 1;
    return {FE{}, FE{typename Curve::uint_type{one_word}}, FE{}};
}

// ecc::mul() from before the change.
template <typename Curve>
ecc::ProjPoint<Curve> mul_base(const ecc::AffinePoint<Curve>& p, typename Curve::uint_type c) {
    while (true) {
        const auto [reduced_c, less_than] = subc(c, Curve::ORDER);
        if (less_than)
            break;
        c = reduced_c;
    }
    auto r = base_infinity<Curve>();
    for (size_t i = bit_width(c); i != 0; --i) {
        r = ecc::dbl(r);
        if (intx::bit_test(c, i - 1))
            r = ecc::add(r, p);
    }
    return r;
}

// ecc::msm() from before the change.
template <typename Curve>
ecc::ProjPoint<Curve> msm_base(const typename Curve::uint_type& u, const ecc::AffinePoint<Curve>& p,
    const typename Curve::uint_type& v, const ecc::AffinePoint<Curve>& q) {
    auto r = base_infinity<Curve>();
    const auto width = intx::bit_width(u | v);
    if (width == 0)
        return r;
    const auto h = ecc::add_affine(p, q);
    const ecc::AffinePoint<Curve>* const points[]{nullptr, &p, &q, &h};
    for (auto i = width; i != 0; --i) {
        r = ecc::dbl(r);
        const auto idx = 2 * size_t{intx::bit_test(v, i - 1)} + size_t{intx::bit_test(u, i - 1)};
        if (idx == 0)
            continue;
        r = ecc::add(r, *points[idx]);
    }
    return r;
}

// The same coordinates, not just the same point.
template <typename Curve>
bool same_coordinates(const ecc::ProjPoint<Curve>& a, const ecc::ProjPoint<Curve>& b) {
    return a.x == b.x && a.y == b.y && a.z == b.z;
}

// k P by affine double-and-add, k used as is (the group order is that of the curve).
template <typename Curve>
ecc::AffinePoint<Curve> mul_reference(
    const ecc::AffinePoint<Curve>& p, const typename Curve::uint_type& k) {
    ecc::AffinePoint<Curve> r;
    for (size_t i = intx::bit_width(k); i != 0; --i) {
        r = ecc::add_affine(r, r);
        if (intx::bit_test(k, i - 1))
            r = ecc::add_affine(r, p);
    }
    return r;
}

struct Rng {
    uint64_t s;
    uint64_t next() {
        uint64_t z = (s += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }
    intx::uint256 scalar() {
        // Mixed widths: full, short (as the GLV halves are) and sparse scalars.
        const intx::uint256 w{next(), next(), next(), next()};
        switch (next() % 4) {
        case 0: return w;
        case 1: return w >> (next() % 256);
        case 2: return w & intx::uint256{next(), 0, 0, 0};
        default: return intx::uint256{next() % 64};
        }
    }
};

template <typename Curve>
void check_differential(const ecc::AffinePoint<Curve>& g) {
    using FE = typename Curve::Fp;
    using U = typename Curve::uint_type;
    using Point = ecc::ProjPoint<Curve>;
    const U n = Curve::ORDER;

    std::vector<U> scalars{0, 1, 2, 3, 7, 15, n - 2, n - 1, n, n + 1, 2 * n, ~U{0}, U{1} << 255,
        (U{1} << 128) - 1, U{1} << 128};
    Rng rng{0x6e647069};
    for (int i = 0; i < 40; ++i)
        scalars.push_back(rng.scalar());

    // Points: G, random multiples, and the negation of G.
    std::vector<ecc::AffinePoint<Curve>> points{g, -g};
    for (int i = 0; i < 6; ++i) {
        const auto k = rng.scalar();
        const auto a = ecc::to_affine(mul_base<Curve>(g, k));
        if (a != ecc::AffinePoint<Curve>{})
            points.push_back(a);
    }

    // The default point is the base infinity.
    CHECK(same_coordinates(Point{}, base_infinity<Curve>()));

    size_t at_infinity = 0;
    for (const auto& p : points) {
        for (const auto& k : scalars) {
            const auto now = ecc::mul(p, k);
            const auto before = mul_base<Curve>(p, k);
            REQUIRE(same_coordinates(now, before));
            const auto affine = ecc::to_affine(now);
            REQUIRE(affine == mul_reference<Curve>(p, k));
            if (now == 0)
                ++at_infinity;
        }
    }
    CHECK(at_infinity > 0);  // k = 0 and k = N reach the point at infinity.

    for (size_t i = 0; i < points.size(); ++i) {
        for (size_t j = 0; j < points.size(); ++j) {
            const auto& p = points[i];
            const auto& q = points[j];  // i == j: P == Q; the first two are G and -G: P == -Q.
            for (int t = 0; t < 8; ++t) {
                const U u = t == 0 ? U{0} : t == 1 ? n : rng.scalar();
                const U v = t == 2 ? U{0} : t == 3 ? n - 1 : rng.scalar();
                const auto now = ecc::msm(u, p, v, q);
                const auto before = msm_base<Curve>(u, p, v, q);
                REQUIRE(same_coordinates(now, before));
                const auto ref = ecc::add_affine(mul_reference<Curve>(p, u), mul_reference<Curve>(q, v));
                REQUIRE(ecc::to_affine(now) == ref);
            }
        }
    }
    // Both scalars zero: msm() returns the default point.
    CHECK(same_coordinates(ecc::msm(U{0}, g, U{0}, g), base_infinity<Curve>()));

    // add()/dbl() on the point at infinity and a point built from an affine point.
    const Point inf;
    const Point from_g{g};
    CHECK(same_coordinates(from_g, Point{g.x, g.y, FE{typename Curve::uint_type{1}}}));
    CHECK(same_coordinates(ecc::dbl(inf), ecc::dbl(base_infinity<Curve>())));
    CHECK(same_coordinates(ecc::add(inf, g), ecc::add(base_infinity<Curve>(), g)));
    CHECK(same_coordinates(ecc::add(inf, from_g), from_g));
    CHECK(same_coordinates(ecc::add(from_g, inf), from_g));
    CHECK(same_coordinates(ecc::add(from_g, ecc::AffinePoint<Curve>{}), from_g));
}

}  // namespace

TEST_CASE("ProjPoint ONE is the field's one") {
    check_one<secp256k1::Curve>();
    check_one<secp256r1::Curve>();
    check_one<bn254::Curve>();
}

TEST_CASE("ProjPoint ONE on the bn254 twist is the Fq2 one") {
    using Point = ecc::ProjPoint<bn254::E2>;
    volatile uint64_t one_word = 1;
    bn254::Fq2 one_at_run_time{};
    one_at_run_time.coeffs[0] = bn254::Fq{intx::uint256{one_word}};

    CHECK(Point::ONE == one_at_run_time);
    const Point inf;
    CHECK(inf.y == one_at_run_time);
    CHECK(inf.z == bn254::Fq2{});
}

TEST_CASE("mul and msm agree with the base code and an affine reference: secp256k1") {
    using namespace secp256k1;
    check_differential<Curve>(AffinePoint{
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256});
}

TEST_CASE("mul and msm agree with the base code and an affine reference: secp256r1") {
    check_differential<secp256r1::Curve>(secp256r1::G);
}

TEST_CASE("mul and msm agree with the base code and an affine reference: bn254") {
    check_differential<bn254::Curve>(bn254::AffinePoint{intx::uint256{1}, intx::uint256{2}});
}
