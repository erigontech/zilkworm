// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// SP1 Hypercube syscall calibration guest: runs fixed-count loops of the hot
// syscalls inside cycle-tracker regions, so `z6m_profile_report --elf` can
// report cycles-per-syscall from report.cycle_tracker. Not part of the real
// guest; built only when Z6M_CALIBRATION_GUEST=ON (dev tool).

#include "include/sp1_syscalls.hpp"
#include <evmone_precompiles/keccak.hpp>

#include <cstdint>

// Build knobs: -DCALIB_<name> runs only that region; default (no defines) runs all.
// Region isolation lets z6m_profile_report attribute gas to a single syscall type by
// diffing prover_gas against a nop-only run.

extern "C" int main()
{
    constexpr uint32_t N = 1000;
    auto region = [](const char *name, auto &&body) noexcept {
        char buf[96];
        size_t n = 0;
        const char *pfx = "cycle-tracker-report-start: ";
        while (pfx[n]) { buf[n] = pfx[n]; ++n; }
        for (size_t i = 0; name[i]; ++i) { buf[n++] = name[i]; }
        buf[n++] = '\n';
        syscall_write(1, reinterpret_cast<const uint8_t *>(buf), n);
        body();
        n = 0;
        pfx = "cycle-tracker-report-end: ";
        while (pfx[n]) { buf[n] = pfx[n]; ++n; }
        for (size_t i = 0; name[i]; ++i) { buf[n++] = name[i]; }
        buf[n++] = '\n';
        syscall_write(1, reinterpret_cast<const uint8_t *>(buf), n);
    };

    uint64_t sink = 0;
#if !defined(CALIB_SEL) || defined(CALIB_nop)
    region("nop_loop", [&] {
        for (uint32_t i = 0; i < N; ++i) {
            asm volatile("" : "+r"(sink));
            sink += i;
        }
    });
#endif

#if !defined(CALIB_SEL) || defined(CALIB_keccak)
    region("keccak_permute", [&] {
        alignas(32) uint64_t state[25] = {};
        for (uint32_t i = 0; i < N; ++i) {
            state[0] = i;
            syscall_keccak_permute(state);
            sink ^= state[0];
        }
    });
#endif

#if !defined(CALIB_SEL) || defined(CALIB_keccakcalls)
    // Full ethash_keccak256() calls at trie-node-like sizes, to measure the C wrapper
    // cost around the permute syscalls (SP1 has no single-block fast path yet).
    {
        alignas(8) uint8_t in55[55];
        alignas(8) uint8_t in100[100];
        alignas(8) uint8_t in300[300];
        for (int i = 0; i < 55; ++i) in55[i] = static_cast<uint8_t>(i);
        for (int i = 0; i < 100; ++i) in100[i] = static_cast<uint8_t>(i * 3);
        for (int i = 0; i < 300; ++i) in300[i] = static_cast<uint8_t>(i * 7);
        region("keccak_call_55", [&] {
            for (uint32_t i = 0; i < N; ++i) {
                in55[0] = static_cast<uint8_t>(i);
                sink ^= ethash::keccak256(in55, 55).bytes[0];
            }
        });
        region("keccak_call_100", [&] {
            for (uint32_t i = 0; i < N; ++i) {
                in100[0] = static_cast<uint8_t>(i);
                sink ^= ethash::keccak256(in100, 100).bytes[0];
            }
        });
        region("keccak_call_300", [&] {
            for (uint32_t i = 0; i < N; ++i) {
                in300[0] = static_cast<uint8_t>(i);
                sink ^= ethash::keccak256(in300, 300).bytes[0];
            }
        });
        region("keccak_call_32", [&] {
            for (uint32_t i = 0; i < N; ++i) {
                in55[0] = static_cast<uint8_t>(i);
                sink ^= ethash::keccak256(in55, 32).bytes[0];
            }
        });
    }
#endif

#if !defined(CALIB_SEL) || defined(CALIB_u256)
    region("u256_mulmod", [&] {
        intx::uint256 x = 0xA1B2C3D4E5F60718293A4B5C6D7E8F9AULL;
        intx::uint256 m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FULL;
        intx::uint256 y = 0x123456789ABCDEF0FEDCBA9876543210ULL;
        const intx::uint256 ym[2] = {y, m};
        for (uint32_t i = 0; i < N; ++i) {
            sp1::mulmod(x, std::span<const intx::uint256, 2>{ym});
            sink ^= x[0];
        }
    });
#endif

#if !defined(CALIB_SEL) || defined(CALIB_cmul)
    // In-guest Montgomery multiplication mod p (no syscall): measures the C-only
    // alternative to syscall_uint256_mulmod for cycle and gas comparison.
    region("c_mulmod_mont", [&] {
        constexpr intx::uint256 P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FULL;
        constexpr uint64_t P0 = 0xFFFFFFFEFFFFFC2FULL;
        constexpr uint64_t NP0 = [] {
            uint64_t inv = 1;  // -P^-1 mod 2^64 via Newton iteration
            for (int i = 0; i < 6; ++i) inv *= 2 - P0 * inv;
            return 0 - inv;
        }();
        intx::uint256 a = 0xA1B2C3D4E5F60718293A4B5C6D7E8F9AULL;  // Montgomery domain
        intx::uint256 b = 0x123456789ABCDEF0FEDCBA9876543210ULL;
        for (uint32_t i = 0; i < N; ++i) {
            const intx::uint512 T = intx::umul(a, b);
            const intx::uint256 T_lo{T[0], T[1], T[2], T[3]};
            const intx::uint256 T_hi{T[4], T[5], T[6], T[7]};
            const intx::uint256 m = T_lo * intx::uint256{NP0};  // mod R by truncation
            const intx::uint512 mP = intx::umul(m, P);
            const intx::uint256 lo = T_lo + intx::uint256{mP[0], mP[1], mP[2], mP[3]};
            const intx::uint256 hi = T_hi + intx::uint256{mP[4], mP[5], mP[6], mP[7]} +
                                     (lo < T_lo ? 1u : 0u);
            intx::uint256 res = hi;  // < 2P
            if (res >= P) res -= P;
            a = res;
            sink ^= a[0];
        }
    });
#endif

    // Generator of secp256k1, regular (non-Montgomery) coordinates: words [0..3) = x,
    // [4..8) = y, little-endian limbs (sp1_AffinePoint layout).
    alignas(32) uint64_t G[8] = {
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
        0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL,
    };
#if !defined(CALIB_SEL) || defined(CALIB_secpadd)
    region("secp_add", [&] {
        alignas(32) uint64_t p[8];
        __builtin_memcpy(p, G, sizeof(p));
        for (uint32_t i = 0; i < N; ++i) {
            syscall_secp256k1_add(p, G);
            sink ^= p[0];
        }
    });
#endif
#if !defined(CALIB_SEL) || defined(CALIB_secpdbl)
    region("secp_double", [&] {
        alignas(32) uint64_t p[8];
        __builtin_memcpy(p, G, sizeof(p));
        for (uint32_t i = 0; i < N; ++i) {
            syscall_secp256k1_double(p);
            sink ^= p[0];
        }
    });
#endif
#if !defined(CALIB_SEL) || defined(CALIB_sha)
    region("sha_compress", [&] {
        alignas(32) uint64_t w[64] = {};
        alignas(32) uint64_t st[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
        };
        for (uint32_t i = 0; i < N; ++i) {
            w[0] = i;
            syscall_sha256_compress(w, st);
            sink ^= st[0];
        }
    });
#endif
#if !defined(CALIB_SEL) || defined(CALIB_pvwrite)
    region("pv_write_64", [&] {
        uint8_t buf[64] = {};
        for (uint32_t i = 0; i < N; ++i) {
            buf[0] = static_cast<uint8_t>(i);
            syscall_write(SP1_FD_PUBLIC_VALUES, buf, 64);
        }
    });
#endif

    // Sink guard so nothing is optimized away (volatile asm above already forces it).
    char out[32];
    size_t n = 0;
    uint64_t v = sink;
    while (v) { out[n++] = '0' + (v & 1); v >>= 1; }
    out[n++] = '\n';
    syscall_write(SP1_FD_PUBLIC_VALUES, reinterpret_cast<const uint8_t *>(out), n);
    return 0;
}
