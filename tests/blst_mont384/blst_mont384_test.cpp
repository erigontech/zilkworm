// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The guest's blst mul_mont_384 forms one 768-bit product and reduces it in two Montgomery
// rounds (cmake/patch_blst_airbender.sh in evmone). That code only exists in the Airbender guest,
// so this test lifts the patch script's own text out at build time, runs it on a host emulation of
// the BigInt delegation and compares it with the single-round version it replaced (a frozen copy)
// and with an exact model: the edge values 0, 1, p-1, RR and the 64- and 256-bit boundaries, then
// random, structured, near-p and trailing-zero operands, with ret aliasing an operand and for
// sqr_mont_384. See blst_mont384_diff.c for the domain.

#include <algorithm>

#include <catch2/catch_test_macros.hpp>

#include "blst_mont384_diff.h"

namespace {

blst_mont384_stats run(long n, unsigned long long seed) {
    blst_mont384_stats st{};
    char msg[512];
    const int failed = blst_mont384_difftest(n, seed, &st, msg, sizeof msg);
    INFO("seed " << seed << ": " << msg);
    REQUIRE(failed == 0);
    return st;
}

}  // namespace

TEST_CASE("blst mul_mont_384: two-round reduction equals the single-round base", "[blst][airbender]") {
    blst_mont384_stats total{};
    total.base_min_csr = ~0ul;
    for (const unsigned long long seed : {1ull, 2ull, 3ull}) {
        const auto st = run(100000, seed);
        total.in_domain += st.in_domain;
        total.sub_path += st.sub_path;
        total.t_low64_zero += st.t_low64_zero;
        total.t_low256_zero += st.t_low256_zero;
        total.base_csr_sum += st.base_csr_sum;
        total.cand_csr_sum += st.cand_csr_sum;
        total.base_min_csr = std::min(total.base_min_csr, st.base_min_csr);
        total.cand_max_csr = std::max(total.cand_max_csr, st.cand_max_csr);
    }
    // The cases reach the paths that matter, so a pass is not vacuous: the final subtraction,
    // a product that is zero modulo 2^64 and modulo 2^256 (round 1 adds no carry).
    CHECK(total.in_domain > 250000);
    CHECK(total.sub_path > 10000);
    CHECK(total.t_low64_zero > 1000);
    CHECK(total.t_low256_zero > 100);
}

TEST_CASE("blst mul_mont_384: the two-round reduction delegates less", "[blst][airbender]") {
    const auto st = run(20000, 7);
    // Delegation calls are guest cycles: even the dearest new multiplication stays below the
    // cheapest old one, and the mean falls by about a quarter.
    CHECK(st.cand_max_csr < st.base_min_csr);
    CHECK(st.cand_csr_sum * 4 < st.base_csr_sum * 3);
}
