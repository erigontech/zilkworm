// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct blst_mont384_stats {
    unsigned long in_domain;           // cases compared (at least one operand below p)
    unsigned long out_of_domain;       // both operands >= p: counted only
    unsigned long out_of_domain_diff;  // ... of which the two versions differ (expected)
    unsigned long sub_path;            // the quotient needed the final subtraction of p
    unsigned long top_word_ties;       // quotient's top word equals p's
    unsigned long t_low64_zero;        // product == 0 mod 2^64
    unsigned long t_low256_zero;       // product == 0 mod 2^256 (the round-1 carry-free branch)
    unsigned long base_min_csr;        // fewest BigInt calls of one base multiplication
    unsigned long cand_max_csr;        // most BigInt calls of one new multiplication
    unsigned long base_csr_sum;
    unsigned long cand_csr_sum;
};

// Runs the fixed edge matrix and n random cases from seed; returns 0 when the new mul_mont_384
// equals the base and the exact model on all of them (also with ret aliasing an operand, and
// sqr_mont_384), otherwise nonzero with the operands of the first failing case in msg.
int blst_mont384_difftest(long n, unsigned long long seed, struct blst_mont384_stats* st, char* msg,
                          size_t msg_cap);

#ifdef __cplusplus
}
#endif
