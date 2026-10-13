// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blst_cyc_stats {
    unsigned long core_cases;       // (t, a, sub/add) triples compared
    unsigned long wrap_cases;       // whole cyclotomic squarings compared
    unsigned long reduce_calls;     // the out-of-line subtraction was entered
    unsigned long reduce_taken;     // ... and subtracted p
    unsigned long q_hist[5];        // how often each quotient estimate q = 0..4 was used
    unsigned long max_csr_sub;      // most BigInt calls of one 3t - 2a
    unsigned long max_csr_add;      // most BigInt calls of one 3t + 2a
    unsigned long max_csr_wrap;     // most BigInt calls of one squaring (output stage only)
};

// Compares the fused cyclotomic outputs with an exact model and with the three modular operations
// of blst's original, on the fixed edge matrix, crafted values near the multiples of p and the
// quotient thresholds, and n random rounds from seed. Returns 0 when everything agrees, otherwise
// nonzero with the first failing case in msg.
int blst_cyc_difftest(long n, unsigned long long seed, struct blst_cyc_stats* st, char* msg,
                      size_t msg_cap);

#ifdef __cplusplus
}
#endif
