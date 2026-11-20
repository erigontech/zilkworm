// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// ECMUL's scalar multiplication against the plain double-and-add of ecc::mul().

#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/bn254.hpp>

namespace {

using namespace evmone::crypto;
using bn254::AffinePoint;
using bn254::Curve;
using bn254::Fq;
using intx::uint256;

AffinePoint reference_mul(const AffinePoint& p, const uint256& c) {
    return ecc::to_affine(ecc::mul<Curve>(p, c));
}

uint256 random_uint256(std::mt19937_64& rng) { return uint256{rng(), rng(), rng(), rng()}; }

std::vector<uint256> scalars(std::mt19937_64& rng) {
    const auto n = Curve::ORDER;
    std::vector<uint256> out{1, 2, 3, 15, 16, 17, 31, 32, 33, n - 1, n + 1, n - 2, ~uint256{0},
                             ~uint256{0} - 1, uint256{1} << 255, uint256{1} << 128,
                             (uint256{1} << 128) - 1, uint256{1} << 127, Curve::LAMBDA,
                             n - Curve::LAMBDA, Curve::X1, Curve::X2, Curve::Y2, Curve::MINUS_Y1,
                             Curve::FIELD_PRIME, Curve::FIELD_PRIME - 1};
    for (uint64_t m = 1; m <= 5; ++m) {
        for (uint64_t d = 0; d <= 8; ++d) {
            out.push_back(m * n + d);
            out.push_back(m * n - d);
        }
    }
    for (int i = 0; i < 400; ++i) {
        out.push_back(random_uint256(rng));
        out.push_back(random_uint256(rng) >> (rng() % 256));
    }
    return out;
}

}  // namespace

TEST_CASE("bn254 mul equals double-and-add") {
    std::mt19937_64 rng{196};
    const AffinePoint g{Fq{1}, Fq{2}};
    std::vector<AffinePoint> points{g, reference_mul(g, Curve::ORDER - 1)};
    for (int i = 0; i < 6; ++i) points.push_back(reference_mul(g, random_uint256(rng)));

    for (const auto& c : scalars(rng)) {
        const auto& p = points[rng() % points.size()];
        REQUIRE(bn254::mul(p, c) == reference_mul(p, c));
    }
    for (const auto& p : points) {
        for (uint64_t m = 1; m <= 5; ++m) REQUIRE(bn254::mul(p, m * Curve::ORDER) == AffinePoint{});
    }
    REQUIRE(bn254::mul(g, 0) == AffinePoint{});
    REQUIRE(bn254::mul(AffinePoint{}, 7) == AffinePoint{});
}
