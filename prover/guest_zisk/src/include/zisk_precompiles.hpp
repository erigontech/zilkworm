// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t, uint64_t
#include <cstring> // memcpy, memset

#include <intx/intx.hpp>

#include "zisk_syscalls.hpp" // zisk_abort

namespace zisk {

using intx::uint256;
using intx::uint384;

/* ───────── Precompile params (#[repr(C)], 8-aligned) ───────── */

struct Arith256Params
{
    const uint64_t* a;
    const uint64_t* b;
    const uint64_t* c;
    uint64_t* dl;
    uint64_t* dh;
};

struct ArithModParams
{
    const uint64_t* a;
    const uint64_t* b;
    const uint64_t* c;
    const uint64_t* module;
    uint64_t* d;
};

struct Add256Params
{
    const uint64_t* a;
    const uint64_t* b;
    uint64_t cin;
    uint64_t* c;
};

struct InOutParams
{
    uint64_t* p1;
    const uint64_t* p2;
};

struct Blake2bRoundParams
{
    uint64_t index;
    uint64_t* state;
    const uint64_t* input;
};

static_assert(sizeof(Arith256Params) == 40 && alignof(Arith256Params) == 8);
static_assert(sizeof(ArithModParams) == 40 && alignof(ArithModParams) == 8);
static_assert(sizeof(Add256Params) == 32 && offsetof(Add256Params, cin) == 16);
static_assert(sizeof(InOutParams) == 16 && alignof(InOutParams) == 8);
static_assert(sizeof(Blake2bRoundParams) == 24 && offsetof(Blake2bRoundParams, state) == 8);
static_assert(alignof(uint256) == 8 && alignof(uint384) == 8);

template <uint16_t Csr>
[[gnu::always_inline]] inline void csrs(const void* p) noexcept
{
    asm volatile("csrs %0, %1" : : "i"(Csr), "r"(p) : "memory");
}

/* ───────── Raw precompiles (LE u64 limbs) ───────── */

[[gnu::always_inline]] inline void keccakf(uint64_t state[25]) noexcept
{
    csrs<0x800>(state);
}

[[gnu::always_inline]] inline void arith256(const uint64_t a[4], const uint64_t b[4],
    const uint64_t c[4], uint64_t dl[4], uint64_t dh[4]) noexcept
{
    Arith256Params p{a, b, c, dl, dh};
    csrs<0x801>(&p);
}

[[gnu::always_inline]] inline void arith256_mod(const uint64_t a[4], const uint64_t b[4],
    const uint64_t c[4], const uint64_t m[4], uint64_t d[4]) noexcept
{
    ArithModParams p{a, b, c, m, d};
    csrs<0x802>(&p);
}

[[gnu::always_inline]] inline void secp256k1_add(uint64_t p1[8], const uint64_t p2[8]) noexcept
{
    InOutParams p{p1, p2};
    csrs<0x803>(&p);
}

[[gnu::always_inline]] inline void secp256k1_dbl(uint64_t p[8]) noexcept
{
    csrs<0x804>(p);
}

[[gnu::always_inline]] inline void sha256f(uint64_t state[4], const uint64_t input[8]) noexcept
{
    InOutParams p{state, input};
    csrs<0x805>(&p);
}

[[gnu::always_inline]] inline void bn254_curve_add(uint64_t p1[8], const uint64_t p2[8]) noexcept
{
    InOutParams p{p1, p2};
    csrs<0x806>(&p);
}

[[gnu::always_inline]] inline void bn254_curve_dbl(uint64_t p[8]) noexcept
{
    csrs<0x807>(p);
}

[[gnu::always_inline]] inline void bn254_complex_add(uint64_t f1[8], const uint64_t f2[8]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x808>(&p);
}

[[gnu::always_inline]] inline void bn254_complex_sub(uint64_t f1[8], const uint64_t f2[8]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x809>(&p);
}

[[gnu::always_inline]] inline void bn254_complex_mul(uint64_t f1[8], const uint64_t f2[8]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x80A>(&p);
}

[[gnu::always_inline]] inline void arith384_mod(const uint64_t a[6], const uint64_t b[6],
    const uint64_t c[6], const uint64_t m[6], uint64_t d[6]) noexcept
{
    ArithModParams p{a, b, c, m, d};
    csrs<0x80B>(&p);
}

[[gnu::always_inline]] inline void bls12_381_curve_add(uint64_t p1[12], const uint64_t p2[12]) noexcept
{
    InOutParams p{p1, p2};
    csrs<0x80C>(&p);
}

[[gnu::always_inline]] inline void bls12_381_curve_dbl(uint64_t p[12]) noexcept
{
    csrs<0x80D>(p);
}

[[gnu::always_inline]] inline void bls12_381_complex_add(uint64_t f1[12], const uint64_t f2[12]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x80E>(&p);
}

[[gnu::always_inline]] inline void bls12_381_complex_sub(uint64_t f1[12], const uint64_t f2[12]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x80F>(&p);
}

[[gnu::always_inline]] inline void bls12_381_complex_mul(uint64_t f1[12], const uint64_t f2[12]) noexcept
{
    InOutParams p{f1, f2};
    csrs<0x810>(&p);
}

// Early-clobber: transpiler needs rd != rs1.
[[gnu::always_inline]] inline uint64_t add256(
    const uint64_t a[4], const uint64_t b[4], uint64_t cin, uint64_t c[4]) noexcept
{
    Add256Params p{a, b, cin, c};
    uint64_t cout;
    asm volatile("csrrs %0, 0x811, %1" : "=&r"(cout) : "r"(&p) : "memory");
    return cout;
}

[[gnu::always_inline]] inline void secp256r1_add(uint64_t p1[8], const uint64_t p2[8]) noexcept
{
    InOutParams p{p1, p2};
    csrs<0x817>(&p);
}

[[gnu::always_inline]] inline void secp256r1_dbl(uint64_t p[8]) noexcept
{
    csrs<0x818>(p);
}

[[gnu::always_inline]] inline void blake2b_round(
    uint64_t index, uint64_t state[16], const uint64_t input[16]) noexcept
{
    Blake2bRoundParams p{index, state, input};
    csrs<0x819>(&p);
}

/* ───────── intx helpers (outputs never alias inputs) ───────── */

[[gnu::always_inline]] inline uint256 arith256_mod(
    const uint256& a, const uint256& b, const uint256& c, const uint256& m) noexcept
{
    uint256 d;
    arith256_mod(&a[0], &b[0], &c[0], &m[0], &d[0]);
    return d;
}

[[gnu::always_inline]] inline uint384 arith384_mod(
    const uint384& a, const uint384& b, const uint384& c, const uint384& m) noexcept
{
    uint384 d;
    arith384_mod(&a[0], &b[0], &c[0], &m[0], &d[0]);
    return d;
}

inline constexpr uint256 kZero256{};
inline constexpr uint256 kOne256{1};
inline constexpr uint384 kZero384{};

// m != 0 (H8); full 512-bit intermediate.
[[gnu::always_inline]] inline uint256 addmod256(
    const uint256& x, const uint256& y, const uint256& m) noexcept
{
    return arith256_mod(x, kOne256, y, m);
}

[[gnu::always_inline]] inline uint256 mulmod256(
    const uint256& x, const uint256& y, const uint256& m) noexcept
{
    return arith256_mod(x, y, kZero256, m);
}

// h and block are not 8-aligned (H9).
[[gnu::always_inline]] inline void sha256f(uint32_t h[8], const uint8_t block[64]) noexcept
{
    alignas(8) uint64_t st[4];
    alignas(8) uint64_t in[8];
    std::memcpy(st, h, sizeof(st));
    std::memcpy(in, block, sizeof(in));
    sha256f(st, in);
    std::memcpy(h, st, sizeof(st));
}

/* ───────── Checked curve add (H5); all-zero is infinity ───────── */

template <size_t Limbs, void (*Add)(uint64_t*, const uint64_t*), void (*Dbl)(uint64_t*)>
[[gnu::always_inline]] inline void add_checked(uint64_t r[], const uint64_t p[]) noexcept
{
    uint64_t pz = 0, rz = 0, dx = 0, dy = 0;
    for (size_t i = 0; i < Limbs; ++i)
    {
        pz |= p[i] | p[Limbs + i];
        rz |= r[i] | r[Limbs + i];
        dx |= r[i] ^ p[i];
        dy |= r[Limbs + i] ^ p[Limbs + i];
    }
    if (pz == 0) [[unlikely]]
        return;
    if (rz == 0) [[unlikely]]
    {
        std::memcpy(r, p, 2 * Limbs * sizeof(uint64_t));
        return;
    }
    if (dx == 0) [[unlikely]]
    {
        if (dy == 0)
            Dbl(r);
        else
            std::memset(r, 0, 2 * Limbs * sizeof(uint64_t));
        return;
    }
    Add(r, p);
}

[[gnu::always_inline]] inline void secp256k1_add_checked(uint64_t r[8], const uint64_t p[8]) noexcept
{
    add_checked<4, secp256k1_add, secp256k1_dbl>(r, p);
}

[[gnu::always_inline]] inline void secp256r1_add_checked(uint64_t r[8], const uint64_t p[8]) noexcept
{
    add_checked<4, secp256r1_add, secp256r1_dbl>(r, p);
}

[[gnu::always_inline]] inline void bn254_curve_add_checked(uint64_t r[8], const uint64_t p[8]) noexcept
{
    add_checked<4, bn254_curve_add, bn254_curve_dbl>(r, p);
}

[[gnu::always_inline]] inline void bls12_381_curve_add_checked(
    uint64_t r[12], const uint64_t p[12]) noexcept
{
    add_checked<6, bls12_381_curve_add, bls12_381_curve_dbl>(r, p);
}

/* ───────── Field moduli ───────── */

inline constexpr auto kSecp256k1P = intx::from_string<uint256>(
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
inline constexpr auto kSecp256k1N = intx::from_string<uint256>(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
inline constexpr auto kSecp256r1N = intx::from_string<uint256>(
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
inline constexpr auto kBn254P = intx::from_string<uint256>(
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47");
inline constexpr auto kBls12381P = intx::from_string<uint384>(
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");

// First quadratic non-residue mod secp256k1 p.
inline constexpr uint256 kSecp256k1Nqr{3};

/* ───────── Free-input calls (untrusted hints, H1) ───────── */

inline constexpr unsigned kFcallSecp256k1FpInv = 1;
inline constexpr unsigned kFcallSecp256k1FnInv = 2;
inline constexpr unsigned kFcallSecp256k1FpSqrt = 3;
inline constexpr unsigned kFcallSecp256r1FnInv = 5;
inline constexpr unsigned kFcallBn254FpInv = 6;
inline constexpr unsigned kFcallBls12381FpInv = 10;
inline constexpr unsigned kFcallUint256Div = 19;

namespace detail {

template <unsigned Id>
[[gnu::always_inline]] inline uint256 fcall_inv256(const uint256& x) noexcept
{
    uint256 r;
    asm volatile(
        "csrs 0x8F2, %4\n\t"
        "csrwi %5, %6\n\t"
        "csrr %0, 0xFFE\n\t"
        "csrr %1, 0xFFE\n\t"
        "csrr %2, 0xFFE\n\t"
        "csrr %3, 0xFFE"
        : "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3])
        : "r"(&x[0]), "i"(0x8C0 + (Id >> 5)), "i"(Id & 31)
        : "memory");
    return r;
}

// Port 0x8F3 reads 8 words: pad.
[[gnu::always_inline]] inline uint384 fcall_bls12_381_fp_inv(const uint384& x) noexcept
{
    alignas(8) uint64_t in[8]{x[0], x[1], x[2], x[3], x[4], x[5], 0, 0};
    uint384 r;
    asm volatile(
        "csrs 0x8F3, %6\n\t"
        "csrwi 0x8C0, %7\n\t"
        "csrr %0, 0xFFE\n\t"
        "csrr %1, 0xFFE\n\t"
        "csrr %2, 0xFFE\n\t"
        "csrr %3, 0xFFE\n\t"
        "csrr %4, 0xFFE\n\t"
        "csrr %5, 0xFFE"
        : "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3]), "=r"(r[4]), "=r"(r[5])
        : "r"(in), "i"(kFcallBls12381FpInv)
        : "memory");
    return r;
}

// v1.3.1 ABI: params x, parity; 5 results.
[[gnu::always_inline]] inline uint64_t fcall_secp256k1_fp_sqrt(
    const uint256& x, uint64_t parity, uint256& y) noexcept
{
    uint64_t is_qr;
    asm volatile(
        "csrs 0x8F2, %5\n\t"
        "csrs 0x8F0, %6\n\t"
        "csrwi 0x8C0, %7\n\t"
        "csrr %0, 0xFFE\n\t"
        "csrr %1, 0xFFE\n\t"
        "csrr %2, 0xFFE\n\t"
        "csrr %3, 0xFFE\n\t"
        "csrr %4, 0xFFE"
        : "=r"(is_qr), "=r"(y[0]), "=r"(y[1]), "=r"(y[2]), "=r"(y[3])
        : "r"(&x[0]), "r"(parity), "i"(kFcallSecp256k1FpSqrt)
        : "memory");
    return is_qr;
}

[[gnu::always_inline]] inline void fcall_uint256_div(
    const uint256& a, const uint256& b, uint256& q, uint256& r) noexcept
{
    asm volatile(
        "csrs 0x8F2, %8\n\t"
        "csrs 0x8F2, %9\n\t"
        "csrwi 0x8C0, %10\n\t"
        "csrr %0, 0xFFE\n\t"
        "csrr %1, 0xFFE\n\t"
        "csrr %2, 0xFFE\n\t"
        "csrr %3, 0xFFE\n\t"
        "csrr %4, 0xFFE\n\t"
        "csrr %5, 0xFFE\n\t"
        "csrr %6, 0xFFE\n\t"
        "csrr %7, 0xFFE"
        : "=r"(q[0]), "=r"(q[1]), "=r"(q[2]), "=r"(q[3]),
          "=r"(r[0]), "=r"(r[1]), "=r"(r[2]), "=r"(r[3])
        : "r"(&a[0]), "r"(&b[0]), "i"(kFcallUint256Div)
        : "memory");
}

// Hint checks; any mismatch aborts (H1).
[[gnu::always_inline]] inline void verify_inv256(
    const uint256& x, const uint256& inv, const uint256& m) noexcept
{
    if (inv >= m || arith256_mod(x, inv, kZero256, m) != 1) [[unlikely]]
        zisk_abort();
}

[[gnu::always_inline]] inline void verify_inv384(
    const uint384& x, const uint384& inv, const uint384& m) noexcept
{
    if (inv >= m || arith384_mod(x, inv, kZero384, m) != 1) [[unlikely]]
        zisk_abort();
}

[[gnu::always_inline]] inline bool verify_secp256k1_fp_sqrt(
    const uint256& x, bool odd, uint64_t is_qr, const uint256& y) noexcept
{
    if (y >= kSecp256k1P) [[unlikely]]
        zisk_abort();
    const uint256 d = mulmod256(y, y, kSecp256k1P);
    if (is_qr == 1)
    {
        if (d != x || (y[0] & 1) != uint64_t{odd}) [[unlikely]]
            zisk_abort();
        return true;
    }
    if (is_qr != 0 || d != mulmod256(x, kSecp256k1Nqr, kSecp256k1P)) [[unlikely]]
        zisk_abort();
    return false;
}

[[gnu::always_inline]] inline void verify_udivrem(
    const uint256& a, const uint256& b, const uint256& q, const uint256& r) noexcept
{
    uint256 dl, dh;
    arith256(&q[0], &b[0], &r[0], &dl[0], &dh[0]);
    if (r >= b || dl != a || dh != 0) [[unlikely]]
        zisk_abort();
}

// Precondition x < m; zero skips oracle.
template <unsigned Id>
[[gnu::always_inline]] inline uint256 inv_mod256(const uint256& x, const uint256& m) noexcept
{
    if (x == 0) [[unlikely]]
        return 0;
    const uint256 inv = fcall_inv256<Id>(x);
    verify_inv256(x, inv, m);
    return inv;
}

}  // namespace detail

/* ───────── Verified hint helpers (H2–H4) ───────── */

inline uint256 secp256k1_fp_inv(const uint256& x) noexcept
{
    return detail::inv_mod256<kFcallSecp256k1FpInv>(x, kSecp256k1P);
}

inline uint256 secp256k1_fn_inv(const uint256& x) noexcept
{
    return detail::inv_mod256<kFcallSecp256k1FnInv>(x, kSecp256k1N);
}

inline uint256 secp256r1_fn_inv(const uint256& x) noexcept
{
    return detail::inv_mod256<kFcallSecp256r1FnInv>(x, kSecp256r1N);
}

inline uint256 bn254_fp_inv(const uint256& x) noexcept
{
    return detail::inv_mod256<kFcallBn254FpInv>(x, kBn254P);
}

inline uint384 bls12_381_fp_inv(const uint384& x) noexcept
{
    if (x == 0) [[unlikely]]
        return 0;
    const uint384 inv = detail::fcall_bls12_381_fp_inv(x);
    detail::verify_inv384(x, inv, kBls12381P);
    return inv;
}

// Requires x < p (H7).
inline bool secp256k1_fp_sqrt(const uint256& x, bool odd, uint256& y) noexcept
{
    // Zero would pass the non-residue check.
    if (x == 0) [[unlikely]]
    {
        y = 0;
        return !odd;
    }
    const uint64_t is_qr = detail::fcall_secp256k1_fp_sqrt(x, odd, y);
    return detail::verify_secp256k1_fp_sqrt(x, odd, is_qr, y);
}

// b == 0 gives EVM's {0, 0}.
inline intx::div_result<uint256> udivrem(const uint256& a, const uint256& b) noexcept
{
    if (b == 0) [[unlikely]]
        return {0, 0};
    uint256 q, r;
    detail::fcall_uint256_div(a, b, q, r);
    detail::verify_udivrem(a, b, q, r);
    return {q, r};
}

}  // namespace zisk

/* ───────── SP1-compatible names for shared evmone sites ───────── */

using sp1_AffinePoint = uint64_t[8];

[[gnu::always_inline]] inline bool is_zero(const sp1_AffinePoint p) noexcept
{
    uint64_t fold = 0;
    for (size_t i = 0; i < 8; ++i)
        fold |= p[i];
    return fold == 0;
}

[[gnu::always_inline]] inline bool eq(const sp1_AffinePoint p, const sp1_AffinePoint q) noexcept
{
    uint64_t fold = 0;
    for (size_t i = 0; i < 8; ++i)
        fold |= p[i] ^ q[i];
    return fold == 0;
}

[[gnu::always_inline]] inline void sp1_point_from_bytes(sp1_AffinePoint r, const uint8_t bytes[64]) noexcept
{
    const auto x = &bytes[0];
    const auto y = &bytes[32];
    for (size_t i = 0; i < 4; ++i)
        r[i] = intx::be::unsafe::load<uint64_t>(&x[32 - (i + 1) * 8]);
    for (size_t i = 0; i < 4; ++i)
        r[i + 4] = intx::be::unsafe::load<uint64_t>(&y[32 - (i + 1) * 8]);
}

[[gnu::always_inline]] inline void sp1_point_to_bytes(uint8_t bytes[64], const sp1_AffinePoint r) noexcept
{
    const auto x = &bytes[0];
    const auto y = &bytes[32];
    for (size_t i = 0; i < 4; ++i)
        intx::be::unsafe::store(&x[32 - (i + 1) * 8], r[i]);
    for (size_t i = 0; i < 4; ++i)
        intx::be::unsafe::store<uint64_t>(&y[32 - (i + 1) * 8], r[i + 4]);
}

[[gnu::always_inline]] inline void syscall_secp256k1_add(uint64_t* p, const uint64_t* q) noexcept
{
    zisk::secp256k1_add(p, q);
}

[[gnu::always_inline]] inline void syscall_secp256k1_double(uint64_t* p) noexcept
{
    zisk::secp256k1_dbl(p);
}

[[gnu::always_inline]] inline void syscall_bn254_add(uint64_t* p, const uint64_t* q) noexcept
{
    zisk::bn254_curve_add(p, q);
}

[[gnu::always_inline]] inline void syscall_bn254_double(uint64_t* p) noexcept
{
    zisk::bn254_curve_dbl(p);
}

[[gnu::always_inline]] inline void syscall_bn254_fp2_addmod(uint64_t* p, const uint64_t* q) noexcept
{
    zisk::bn254_complex_add(p, q);
}

[[gnu::always_inline]] inline void syscall_bn254_fp2_submod(uint64_t* p, const uint64_t* q) noexcept
{
    zisk::bn254_complex_sub(p, q);
}

[[gnu::always_inline]] inline void syscall_bn254_fp2_mulmod(uint64_t* p, const uint64_t* q) noexcept
{
    zisk::bn254_complex_mul(p, q);
}
