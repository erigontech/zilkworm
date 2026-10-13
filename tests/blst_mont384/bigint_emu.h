// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Host emulation of the Airbender BigInt delegation (CSR 0x7CA) for the blst Montgomery blocks,
// following riscv_transpiler/src/vm/delegations/bigint.rs, including its assertions: the two
// operands are distinct, 32-byte aligned 256-bit values, exactly one operation bit is set, and
// the result of the operation replaces the first operand while x12 carries the overflow flag.
// Also the blst types the blocks use, as on a 32-bit-limb target.
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t limb_t;
typedef unsigned long long llimb_t;
#define LIMB_T_BITS 32
typedef limb_t vec384[12];
typedef limb_t vec384x[2][12];

extern unsigned long mont384_emu_calls;

static void emu_fail(const char* what, uintptr_t x10, uintptr_t x11, limb_t mask)
{
    fprintf(stderr, "delegation assert: %s (x10=%#lx x11=%#lx mask=%#x)\n", what, (unsigned long)x10,
            (unsigned long)x11, mask);
    abort();
}

static inline limb_t emu_csr(limb_t* mut, const limb_t* immut, limb_t mask)
{
    uintptr_t x10 = (uintptr_t)mut, x11 = (uintptr_t)immut;
    mont384_emu_calls++;
    if (x10 == x11) emu_fail("x10 == x11", x10, x11, mask);
    if (x10 % 32 || x11 % 32) emu_fail("unaligned", x10, x11, mask);
    if (mask >= 256) emu_fail("mask too large", x10, x11, mask);
    if (__builtin_popcount(mask & ~0x40u) != 1) emu_fail("not exactly one op bit", x10, x11, mask);
    limb_t carry = (mask >> 6) & 1;
    limb_t a[8], b[8], r[8];
    memcpy(a, mut, 32);
    memcpy(b, immut, 32);
    limb_t of = 0;
    if (mask & 0x01) {  // ADD, with carry-in
        llimb_t c = carry;
        for (int i = 0; i < 8; i++) { c += (llimb_t)a[i] + b[i]; r[i] = (limb_t)c; c >>= 32; }
        of = (limb_t)c;
    } else if (mask & 0x02) {  // SUB: a - b
        limb_t bw = carry;
        for (int i = 0; i < 8; i++) { llimb_t d = (llimb_t)a[i] - b[i] - bw; r[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
        of = bw;
    } else if (mask & 0x04) {  // SUB reversed: b - a
        limb_t bw = carry;
        for (int i = 0; i < 8; i++) { llimb_t d = (llimb_t)b[i] - a[i] - bw; r[i] = (limb_t)d; bw = (limb_t)(d >> 63); }
        of = bw;
    } else if (mask & 0x18) {  // MUL_LOW (0x08) or MUL_HIGH (0x10)
        limb_t prod[16] = {0};
        for (int i = 0; i < 8; i++) {
            llimb_t c = 0;
            for (int j = 0; j < 8; j++) {
                c += (llimb_t)a[i] * b[j] + prod[i + j];
                prod[i + j] = (limb_t)c;
                c >>= 32;
            }
            prod[i + 8] = (limb_t)c;
        }
        if (mask & 0x08) {
            memcpy(r, prod, 32);
            of = 0;
            for (int i = 8; i < 16; i++) of |= prod[i];
            of = of != 0;
        } else {
            memcpy(r, prod + 8, 32);
            of = 0;
        }
    } else if (mask & 0x20) {  // EQ
        memcpy(r, a, 32);
        of = memcmp(a, b, 32) == 0;
    } else if (mask & 0x80) {  // MEMCOPY, with carry: b + 1
        if (carry) {
            limb_t c = 1;
            for (int i = 0; i < 8; i++) { llimb_t t = (llimb_t)b[i] + c; r[i] = (limb_t)t; c = (limb_t)(t >> 32); }
            of = c;
        } else {
            memcpy(r, b, 32);
            of = 0;
        }
    } else {
        emu_fail("unknown op", x10, x11, mask);
    }
    memcpy(mut, r, 32);
    return of;
}
