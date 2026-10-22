// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// SP1 Hypercube syscall calibration guest: runs fixed-count loops of the hot
// syscalls inside cycle-tracker regions, so `z6m_profile_report --elf` can
// report cycles-per-syscall from report.cycle_tracker. Not part of the real
// guest; built only when Z6M_CALIBRATION_GUEST=ON (dev tool).

#include "include/sp1_syscalls.hpp"

#include <cstdint>

extern "C" int main()
{
    constexpr uint32_t N = 1000;
    auto region = [](const char *name, auto &&body) noexcept {
        char buf[96];
        size_t n = 0;
        const char *pfx = "cycle-tracker-start: ";
        while (pfx[n]) { buf[n] = pfx[n]; ++n; }
        for (size_t i = 0; name[i]; ++i) { buf[n++] = name[i]; }
        buf[n++] = '\n';
        syscall_write(1, reinterpret_cast<const uint8_t *>(buf), n);
        body();
        n = 0;
        pfx = "cycle-tracker-end: ";
        while (pfx[n]) { buf[n] = pfx[n]; ++n; }
        for (size_t i = 0; name[i]; ++i) { buf[n++] = name[i]; }
        buf[n++] = '\n';
        syscall_write(1, reinterpret_cast<const uint8_t *>(buf), n);
    };

    uint64_t sink = 0;
    region("nop_loop", [&] {
        for (uint32_t i = 0; i < N; ++i) {
            asm volatile("" : "+r"(sink));
            sink += i;
        }
    });

    region("keccak_permute", [&] {
        alignas(32) uint64_t state[25] = {};
        for (uint32_t i = 0; i < N; ++i) {
            state[0] = i;
            syscall_keccak_permute(state);
            sink ^= state[0];
        }
    });

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

    // Generator of secp256k1, regular (non-Montgomery) coordinates: words [0..3) = x,
    // [4..8) = y, little-endian limbs (sp1_AffinePoint layout).
    alignas(32) uint64_t G[8] = {
        0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL, 0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL,
        0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL, 0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL,
    };
    region("secp_add", [&] {
        alignas(32) uint64_t p[8];
        __builtin_memcpy(p, G, sizeof(p));
        for (uint32_t i = 0; i < N; ++i) {
            syscall_secp256k1_add(p, G);
            sink ^= p[0];
        }
    });
    region("secp_double", [&] {
        alignas(32) uint64_t p[8];
        __builtin_memcpy(p, G, sizeof(p));
        for (uint32_t i = 0; i < N; ++i) {
            syscall_secp256k1_double(p);
            sink ^= p[0];
        }
    });

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

    region("pv_write_64", [&] {
        uint8_t buf[64] = {};
        for (uint32_t i = 0; i < N; ++i) {
            buf[0] = static_cast<uint8_t>(i);
            syscall_write(SP1_FD_PUBLIC_VALUES, buf, 64);
        }
    });

    // Sink guard so nothing is optimized away (volatile asm above already forces it).
    char out[32];
    size_t n = 0;
    uint64_t v = sink;
    while (v) { out[n++] = '0' + (v & 1); v >>= 1; }
    out[n++] = '\n';
    syscall_write(SP1_FD_PUBLIC_VALUES, reinterpret_cast<const uint8_t *>(out), n);
    return 0;
}
