// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// rv64im has no Zbb, so GCC lowers __builtin_bswap64/32 to calls into libgcc's __bswapdi2 /
// __bswapsi2. Expand them inline instead: a call cannot share the mask constants between the
// four swaps of a uint256, which is where most of the guest's byte swapping comes from.
//
// Force-included for every C and C++ translation unit; see cmake/riscv64im-sp1.cmake.
#pragma once
#ifndef __ASSEMBLER__  // blst compiles its .S through the C driver, which sees this too.

#ifdef __cplusplus
#define Z6M_BSWAP_CONSTEXPR constexpr
#else
#define Z6M_BSWAP_CONSTEXPR
#endif

static __inline__ __attribute__((always_inline, unused)) Z6M_BSWAP_CONSTEXPR unsigned long long
z6m_bswap64(unsigned long long x)
{
    const unsigned long long a =
        ((x << 8) & 0xff00ff00ff00ff00ULL) | ((x >> 8) & 0x00ff00ff00ff00ffULL);
    const unsigned long long b =
        ((a << 16) & 0xffff0000ffff0000ULL) | ((a >> 16) & 0x0000ffff0000ffffULL);
    return (b << 32) | (b >> 32);  // The last step needs no mask.
}

static __inline__ __attribute__((always_inline, unused)) Z6M_BSWAP_CONSTEXPR unsigned int
z6m_bswap32(unsigned int x)
{
    const unsigned int a = ((x << 8) & 0xff00ff00U) | ((x >> 8) & 0x00ff00ffU);
    return (a << 16) | (a >> 16);
}

#define __builtin_bswap64(x) z6m_bswap64(x)
#define __builtin_bswap32(x) z6m_bswap32(x)

#endif  // __ASSEMBLER__
