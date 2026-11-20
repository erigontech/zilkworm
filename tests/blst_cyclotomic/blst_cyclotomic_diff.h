// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blst_cyc_stats {
    unsigned long core_cases;
    unsigned long wrap_cases;
    unsigned long reduce_calls;
    unsigned long reduce_taken;
    unsigned long q_hist[5];
    unsigned long max_csr_sub;
    unsigned long max_csr_add;
    unsigned long max_csr_wrap;
};

// Compares the fused cyclotomic outputs with an exact model and with the three modular operations of blst's original.
int blst_cyc_difftest(long n, unsigned long long seed, struct blst_cyc_stats* st, char* msg,
                      size_t msg_cap);

#ifdef __cplusplus
}
#endif
