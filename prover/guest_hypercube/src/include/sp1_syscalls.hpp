// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include <intx/intx.hpp>

// Layout matches Rust's #[repr(C)] ReadVecResult.
struct ReadVecResult
{
    uint8_t *ptr;
    size_t len;
    size_t capacity;
};

using uintType = uint64_t;

#define SP1_ECALL_2ARG(name, num)                                              \
    [[gnu::always_inline]] inline void name(                                   \
        uint64_t *_p, const uint64_t *_q) noexcept {                           \
        register uint64_t t0 asm("t0") = (num);                               \
        register uint64_t *a0 asm("a0") = _p;                                 \
        register const uint64_t *a1 asm("a1") = _q;                           \
        asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");       \
    }

#define SP1_ECALL_1ARG(name, num)                                              \
    [[gnu::always_inline]] inline void name(                                   \
        uint64_t *_p) noexcept {                                               \
        register uint64_t t0 asm("t0") = (num);                               \
        register uint64_t *a0 asm("a0") = _p;                                 \
        register uint64_t a1 asm("a1") = 0;                                   \
        asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");       \
    }
    
constexpr uint32_t SP1_FD_PUBLIC_VALUES = 13;

extern "C"
{
    [[noreturn]] void syscall_halt(uint8_t exit_code);

    void syscall_write(uint64_t fd, const uint8_t *write_buf, size_t nbytes);

    bool syscall_enter_unconstrained();

    void syscall_exit_unconstrained();

    uint8_t *sys_alloc_aligned(size_t bytes, size_t align);

    ReadVecResult read_vec_raw() noexcept;

    void syscall_verify_sp1_proof(const uint64_t vk_digest[4],
                                  const uint64_t pv_digest[4]);

    void syscall_mprotect(const uint8_t *addr, uint8_t prot);

    void syscall_u256x2048_mul(const uint64_t x[4],
                               const uint64_t y[32],
                               uint64_t lo[32],
                               uint64_t hi[4]);

    void syscall_uint256_add_with_carry(const uint64_t a[4],
                                        const uint64_t b[4],
                                        const uint64_t c[4],
                                        uint64_t d[4],
                                        uint64_t e[4]);

    void syscall_uint256_mul_with_carry(const uint64_t a[4],
                                        const uint64_t b[4],
                                        const uint64_t c[4],
                                        uint64_t d[4],
                                        uint64_t e[4]);

}

SP1_ECALL_2ARG(syscall_ed_add, 0x00010107)
SP1_ECALL_2ARG(syscall_secp256k1_add, 0x0001010A)
SP1_ECALL_2ARG(syscall_secp256r1_add, 0x0001012C)
SP1_ECALL_2ARG(syscall_bn254_add, 0x0001010E)
SP1_ECALL_2ARG(syscall_bls12381_add, 0x0001011E)

SP1_ECALL_2ARG(syscall_sha256_compress, 0x00010106)

SP1_ECALL_2ARG(syscall_uint256_mulmod, 0x0001011D)

// BLS12-381 field syscalls do plain modular arithmetic, not Montgomery.
SP1_ECALL_2ARG(syscall_bls12381_fp_addmod, 0x00010120)
SP1_ECALL_2ARG(syscall_bls12381_fp_submod, 0x00010121)
SP1_ECALL_2ARG(syscall_bls12381_fp_mulmod, 0x00010122)
SP1_ECALL_2ARG(syscall_bls12381_fp2_addmod, 0x00010123)
SP1_ECALL_2ARG(syscall_bls12381_fp2_submod, 0x00010124)
SP1_ECALL_2ARG(syscall_bls12381_fp2_mulmod, 0x00010125)
SP1_ECALL_2ARG(syscall_bn254_fp_addmod, 0x00010126)
SP1_ECALL_2ARG(syscall_bn254_fp_submod, 0x00010127)
SP1_ECALL_2ARG(syscall_bn254_fp_mulmod, 0x00010128)
SP1_ECALL_2ARG(syscall_bn254_fp2_addmod, 0x00010129)
SP1_ECALL_2ARG(syscall_bn254_fp2_submod, 0x0001012A)
SP1_ECALL_2ARG(syscall_bn254_fp2_mulmod, 0x0001012B)

// 1-arg syscalls must set a1=0.
SP1_ECALL_1ARG(syscall_sha256_extend, 0x00300105)
SP1_ECALL_1ARG(syscall_ed_decompress, 0x00000108)
SP1_ECALL_1ARG(syscall_secp256k1_double, 0x0000010B)
SP1_ECALL_1ARG(syscall_secp256r1_double, 0x0000012D)
SP1_ECALL_1ARG(syscall_bn254_double, 0x0000010F)
SP1_ECALL_1ARG(syscall_bls12381_double, 0x0000011F)
SP1_ECALL_1ARG(syscall_keccak_permute, 0x00010109)

[[gnu::always_inline]] static inline void sys_print(const char *s) noexcept
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(s), std::strlen(s));
}
[[gnu::always_inline]] static inline void sys_println(const char *s) noexcept
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(s), std::strlen(s));
    syscall_write(1, reinterpret_cast<const uint8_t *>("\n"), 1);
}
[[gnu::always_inline]] static inline void sys_println(std::string_view s) noexcept
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(s.data()), s.size());
    syscall_write(1, reinterpret_cast<const uint8_t *>("\n"), 1);
}

namespace sp1 {
inline void mulmod(intx::uint256 &x, std::span<const intx::uint256, 2> ym) noexcept {
    static_assert(sizeof(size_t) == 8, "mulmod wrapper assumes rv64im (8-byte size_t)");
    syscall_uint256_mulmod(reinterpret_cast<size_t *>(&x),
                           reinterpret_cast<const size_t *>(ym.data()));
}
}

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
