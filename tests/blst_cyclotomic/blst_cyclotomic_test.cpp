// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The guest's blst cyclotomic squaring forms each of its twelve outputs (3*t - 2*a or 3*t + 2*a)
// with one CSR sum and one reduction instead of three modular operations (cmake/
// patch_blst_airbender.sh in evmone). That code only exists in the Airbender guest, so this test
// lifts the patch script's own text out at build time, runs it on a host emulation of the BigInt
// delegation and compares it with blst's original three-operation chain (also lifted from the
// script) and with an exact big-number model: the edge values around 0, p, 2^256 and 2^352, values
// whose sum lands next to a multiple of p, a quotient threshold or the 2^256 split, random and
// structured operands, with ret aliasing an input, and the whole function with the t values
// injected. See blst_cyclotomic_diff.c for the domain.

#include <catch2/catch_test_macros.hpp>

#include "blst_cyclotomic_diff.h"

namespace {

blst_cyc_stats run(long n, unsigned long long seed) {
    blst_cyc_stats st{};
    char msg[512];
    const int failed = blst_cyc_difftest(n, seed, &st, msg, sizeof msg);
    INFO("seed " << seed << ": " << msg);
    REQUIRE(failed == 0);
    return st;
}

}  // namespace

TEST_CASE("blst cyclotomic outputs: one fused sum and reduction equals the modular chain",
          "[blst][airbender]") {
    blst_cyc_stats total{};
    for (const unsigned long long seed : {1ull, 2ull, 3ull}) {
        const auto st = run(10000, seed);
        total.core_cases += st.core_cases;
        total.wrap_cases += st.wrap_cases;
        total.reduce_calls += st.reduce_calls;
        total.reduce_taken += st.reduce_taken;
        for (int i = 0; i < 5; ++i) total.q_hist[i] += st.q_hist[i];
    }
    // The cases reach the paths that matter, so a pass is not vacuous: every quotient estimate
    // 0..4, and the out-of-line subtraction both entered and taken (it is entered without
    // subtracting when the estimate was exact and the value is just below p).
    CHECK(total.core_cases > 1000000);
    CHECK(total.wrap_cases > 4000);
    for (int i = 0; i < 5; ++i) CHECK(total.q_hist[i] > 1000);
    CHECK(total.reduce_taken > 10000);
    CHECK(total.reduce_calls > total.reduce_taken);
}

TEST_CASE("blst cyclotomic outputs: the fused outputs delegate less", "[blst][airbender]") {
    const auto st = run(2000, 7);
    // Per output: 5 BigInt calls for 3t - 2a and 3 for 3t + 2a, plus one for the reduction; per
    // squaring 6 * 6 + 6 * 4 = 60, against about 99 for the three modular operations.
    CHECK(st.max_csr_sub <= 6);
    CHECK(st.max_csr_add <= 4);
    CHECK(st.max_csr_wrap <= 60);
}
