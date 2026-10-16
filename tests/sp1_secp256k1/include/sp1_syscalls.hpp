// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// A host stand-in for prover/guest_hypercube/src/include/sp1_syscalls.hpp, for the test that
// builds evmone's SP1 secp256k1 paths on the host (secp256k1_sp1_test.cpp): the syscalls those
// paths use, computed in software, with the preconditions of SP1's precompiles checked, since the
// guest relies on them and a violation there fails the proof, not the execution. secp256k1_add
// takes two affine points of the curve with different x (neither the point at infinity, which the
// guest encodes as zeros, nor a doubling), secp256k1_double one affine point of the curve, and
// uint256_mulmod's x must not overlap its y or modulus. A violation aborts the test.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>

#include <intx/intx.hpp>

using sp1_AffinePoint = uint64_t[8];

namespace sp1_host {

using intx::uint256;

inline constexpr uint256 kP{0xfffffffefffffc2f, ~uint64_t{0}, ~uint64_t{0}, ~uint64_t{0}};

/// How many of each syscall ran, for the tests to tell which path a recovery took.
struct Counters {
    uint64_t add{0};
    uint64_t dbl{0};
    uint64_t mulmod{0};
};
inline Counters counters;

[[noreturn]] inline void violated(const char* what) noexcept {
    std::fprintf(stderr, "SP1 precompile precondition violated: %s\n", what);
    std::abort();
}

inline uint256 load(const uint64_t* p) noexcept { return uint256{p[0], p[1], p[2], p[3]}; }

inline void store(uint64_t* p, const uint256& v) noexcept {
    for (size_t i = 0; i < 4; ++i) p[i] = v[i];
}

inline uint256 mul(const uint256& a, const uint256& b) noexcept { return intx::mulmod(a, b, kP); }

inline uint256 sub(const uint256& a, const uint256& b) noexcept { return a >= b ? a - b : a + (kP - b); }

/// x / 2 mod p.
inline uint256 half(const uint256& x) noexcept { return (x & 1) == 0 ? x >> 1 : (x >> 1) + (kP >> 1) + 1; }

/// 1/a mod p for a in [1, p), by the binary extended Euclid: much faster than a power on a Debug build.
inline uint256 inv(const uint256& a) noexcept {
    uint256 u{a};
    uint256 v{kP};
    uint256 x1{1};
    uint256 x2{0};
    while (u != 1 && v != 1) {
        while ((u & 1) == 0) {
            u >>= 1;
            x1 = half(x1);
        }
        while ((v & 1) == 0) {
            v >>= 1;
            x2 = half(x2);
        }
        if (u >= v) {
            u -= v;
            x1 = sub(x1, x2);
        } else {
            v -= u;
            x2 = sub(x2, x1);
        }
    }
    return u == 1 ? x1 : x2;
}

inline void require_point(const uint64_t* p, const char* what) noexcept {
    const auto x{load(p)};
    const auto y{load(p + 4)};
    if (x >= kP || y >= kP || mul(y, y) != intx::addmod(mul(mul(x, x), x), uint256{7}, kP)) violated(what);
}

}  // namespace sp1_host

inline void syscall_secp256k1_add(uint64_t* p, const uint64_t* q) noexcept {
    using namespace sp1_host;
    require_point(p, "secp256k1_add: p is not an affine point of the curve");
    require_point(q, "secp256k1_add: q is not an affine point of the curve");
    const auto x1{load(p)};
    const auto y1{load(p + 4)};
    const auto x2{load(q)};
    const auto y2{load(q + 4)};
    if (x1 == x2) violated("secp256k1_add: p and q have the same x");
    const auto l{mul(sub(y2, y1), inv(sub(x2, x1)))};
    const auto x3{sub(sub(mul(l, l), x1), x2)};
    store(p, x3);
    store(p + 4, sub(mul(l, sub(x1, x3)), y1));
    ++counters.add;
}

inline void syscall_secp256k1_double(uint64_t* p) noexcept {
    using namespace sp1_host;
    require_point(p, "secp256k1_double: p is not an affine point of the curve");
    const auto x{load(p)};
    const auto y{load(p + 4)};
    const auto xx{mul(x, x)};
    const auto l{mul(intx::addmod(intx::addmod(xx, xx, kP), xx, kP), inv(intx::addmod(y, y, kP)))};
    const auto x3{sub(sub(mul(l, l), x), x)};
    store(p, x3);
    store(p + 4, sub(mul(l, sub(x, x3)), y));
    ++counters.dbl;
}

inline void syscall_uint256_mulmod(uint64_t* x, const uint64_t* ym) noexcept {
    using namespace sp1_host;
    if (x < ym + 8 && ym < x + 4) violated("uint256_mulmod: x overlaps y or the modulus");
    const auto m{load(ym + 4)};
    store(x, m == 0 ? load(x) * load(ym) : intx::mulmod(load(x), load(ym), m));
    ++counters.mulmod;
}

// modarith.hpp's BN254 paths name these; the secp256k1 paths never call them.
inline void syscall_bn254_fp_mulmod(uint64_t*, const uint64_t*) noexcept { sp1_host::violated("bn254_fp_mulmod"); }
inline void syscall_bn254_fp_addmod(uint64_t*, const uint64_t*) noexcept { sp1_host::violated("bn254_fp_addmod"); }
inline void syscall_bn254_fp_submod(uint64_t*, const uint64_t*) noexcept { sp1_host::violated("bn254_fp_submod"); }

namespace sp1 {
inline void mulmod(intx::uint256& x, std::span<const intx::uint256, 2> ym) noexcept {
    syscall_uint256_mulmod(reinterpret_cast<uint64_t*>(&x), reinterpret_cast<const uint64_t*>(ym.data()));
}
}  // namespace sp1

inline bool is_zero(const sp1_AffinePoint p) noexcept {
    uint64_t fold{0};
    for (size_t i = 0; i < 8; ++i) fold |= p[i];
    return fold == 0;
}

inline void sp1_point_from_bytes(sp1_AffinePoint r, const uint8_t bytes[64]) noexcept {
    for (size_t i = 0; i < 4; ++i) r[i] = intx::be::unsafe::load<uint64_t>(&bytes[32 - (i + 1) * 8]);
    for (size_t i = 0; i < 4; ++i) r[i + 4] = intx::be::unsafe::load<uint64_t>(&bytes[64 - (i + 1) * 8]);
}

inline void sp1_point_to_bytes(uint8_t bytes[64], const sp1_AffinePoint r) noexcept {
    for (size_t i = 0; i < 4; ++i) intx::be::unsafe::store(&bytes[32 - (i + 1) * 8], r[i]);
    for (size_t i = 0; i < 4; ++i) intx::be::unsafe::store(&bytes[64 - (i + 1) * 8], r[i + 4]);
}
