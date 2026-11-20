// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blst_mont384_stats {
    unsigned long in_domain;
    unsigned long out_of_domain;
    unsigned long out_of_domain_diff;
    unsigned long sub_path;
    unsigned long top_word_ties;
    unsigned long t_low64_zero;
    unsigned long t_low256_zero;
    unsigned long base_min_csr;
    unsigned long cand_max_csr;
    unsigned long base_csr_sum;
    unsigned long cand_csr_sum;
};

// Runs the fixed edge matrix and n random cases from seed.
int blst_mont384_difftest(long n, unsigned long long seed, struct blst_mont384_stats* st, char* msg,
                          size_t msg_cap);

#ifdef __cplusplus
}
#endif
