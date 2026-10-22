// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0
//
// Guest-side profiling counters (enabled with -DZ6M_GUEST_PROFILE, profiling build only).
// Every SP1 ecall choke point bumps z6mprof::count_ecall(num); extern "C" runtime syscalls
// bump their own counters. main() prints the nonzero counters at exit; the prover log lines
// carry them out of the guest so a 1-block execute gives a per-syscall-type breakdown.

#pragma once

#include <cstdint>

#ifdef Z6M_GUEST_PROFILE

namespace z6mprof {

inline uint64_t ecall_counts[32]{};

// SP1 syscall numbers are sparse (0x00010109 etc.); fold to a dense index with a switch.
// Unmapped numbers land in slot 31.
inline void count_ecall(uint64_t num) noexcept
{
    switch (num)
    {
    case 0x00010107: ++ecall_counts[0]; break;  // ed_add
    case 0x00000108: ++ecall_counts[1]; break;  // ed_decompress
    case 0x0000010B: ++ecall_counts[2]; break;  // secp256k1_double
    case 0x0001010A: ++ecall_counts[3]; break;  // secp256k1_add
    case 0x0000012D: ++ecall_counts[4]; break;  // secp256r1_double
    case 0x0001012C: ++ecall_counts[5]; break;  // secp256r1_add
    case 0x0000010F: ++ecall_counts[6]; break;  // bn254_double
    case 0x0001010E: ++ecall_counts[7]; break;  // bn254_add
    case 0x0000011F: ++ecall_counts[8]; break;  // bls12381_double
    case 0x0001011E: ++ecall_counts[9]; break;  // bls12381_add
    case 0x00010109: ++ecall_counts[10]; break; // keccak_permute
    case 0x00010106: ++ecall_counts[11]; break; // sha256_compress
    case 0x00300105: ++ecall_counts[12]; break; // sha256_extend
    case 0x0001011D: ++ecall_counts[13]; break; // uint256_mulmod
    case 0x00010120: ++ecall_counts[14]; break; // bls12381_fp_addmod
    case 0x00010121: ++ecall_counts[15]; break; // bls12381_fp_submod
    case 0x00010122: ++ecall_counts[16]; break; // bls12381_fp_mulmod
    case 0x00010123: ++ecall_counts[17]; break; // bls12381_fp2_addmod
    case 0x00010124: ++ecall_counts[18]; break; // bls12381_fp2_submod
    case 0x00010125: ++ecall_counts[19]; break; // bls12381_fp2_mulmod
    case 0x00010126: ++ecall_counts[20]; break; // bn254_fp_addmod
    case 0x00010127: ++ecall_counts[21]; break; // bn254_fp_submod
    case 0x00010128: ++ecall_counts[22]; break; // bn254_fp_mulmod
    case 0x00010129: ++ecall_counts[23]; break; // bn254_fp2_addmod
    case 0x0001012A: ++ecall_counts[24]; break; // bn254_fp2_submod
    case 0x0001012B: ++ecall_counts[25]; break; // bn254_fp2_mulmod
    default: ++ecall_counts[31]; break;
    }
}

// Extern "C" runtime syscalls (sp1_runtime.cpp) use named slots 0+.
enum : unsigned
{
    S_WRITE = 0,
    S_UINT256_ADD_CARRY,
    S_UINT256_MUL_CARRY,
    S_U256X2048_MUL,
    S_READ_VEC,
    S_ALLOC_ALIGNED,
    S_VERIFY_SP1_PROOF,
    S_MPROTECT,
    S_ENTER_UNCONSTRAINED,
    S_EXIT_UNCONSTRAINED,
    S_NAMED_COUNT,
};

inline uint64_t named_counts[S_NAMED_COUNT]{};

inline void bump(unsigned slot) noexcept { ++named_counts[slot]; }

}  // namespace z6mprof

#define Z6M_PROF_BUMP(slot) ::z6mprof::bump(slot)
#define Z6M_PROF_ECALL(num) ::z6mprof::count_ecall(num)

#else

#define Z6M_PROF_BUMP(slot) ((void)0)
#define Z6M_PROF_ECALL(num) ((void)0)

#endif  // Z6M_GUEST_PROFILE
