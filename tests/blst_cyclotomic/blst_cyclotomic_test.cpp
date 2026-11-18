// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// The guest's blst cyclotomic squaring forms each of its twelve outputs.

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
    CHECK(total.core_cases > 1000000);
    CHECK(total.wrap_cases > 4000);
    for (int i = 0; i < 5; ++i) CHECK(total.q_hist[i] > 1000);
    CHECK(total.reduce_taken > 10000);
    CHECK(total.reduce_calls > total.reduce_taken);
}

TEST_CASE("blst cyclotomic outputs: the fused outputs delegate less", "[blst][airbender]") {
    const auto st = run(2000, 7);
    CHECK(st.max_csr_sub <= 6);
    CHECK(st.max_csr_add <= 4);
    CHECK(st.max_csr_wrap <= 60);
}
