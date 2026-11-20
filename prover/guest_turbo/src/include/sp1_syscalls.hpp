// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <intx/intx.hpp>

// Layout matches Rust's #[repr(C)] ReadVecResult.
struct ReadVecResult
{
    uint8_t *ptr;
    size_t len;
    size_t capacity;
};

extern "C"
{

    [[noreturn]] void syscall_halt(uint8_t exit_code);

    void syscall_write(uint32_t fd, const uint8_t *write_buf, size_t nbytes);

    void syscall_read(uint32_t fd, uint8_t *read_buf, size_t nbytes);

    void syscall_sha256_extend(uint32_t w[64]);

    void syscall_sha256_compress(uint32_t w[64], uint32_t state[8]);

    void syscall_ed_add(uint32_t (*p)[16], const uint32_t (*q)[16]);

    void syscall_ed_decompress(uint8_t (*point)[64]);

    void syscall_secp256k1_add(uint32_t p[16], const uint32_t q[16]);

    void syscall_secp256k1_double(uint32_t p[16]);

    void syscall_secp256k1_decompress(uint8_t point[64], bool is_odd);

    void syscall_secp256r1_add(uint32_t p[16], const uint32_t q[16]);

    void syscall_secp256r1_double(uint32_t p[16]);

    void syscall_secp256r1_decompress(uint8_t point[64], bool is_odd);

    void syscall_bn254_add(uint32_t p[16], const uint32_t q[16]);

    void syscall_bn254_double(uint32_t p[16]);

    void syscall_bls12381_add(uint32_t (*p)[24], const uint32_t (*q)[24]);

    void syscall_bls12381_double(uint32_t (*p)[24]);

    void syscall_keccak_permute(uint64_t (*state)[25]);

    void syscall_uint256_mulmod(uint32_t x[8], const uint32_t y[8]);

    void syscall_u256x2048_mul(const uint32_t (*x)[8],
                               const uint32_t (*y)[64],
                               uint32_t (*lo)[64],
                               uint32_t (*hi)[8]);

    bool syscall_enter_unconstrained();

    void syscall_exit_unconstrained();

    void syscall_verify_sp1_proof(const uint32_t (*vk_digest)[8],
                                  const uint8_t (*pv_digest)[32]);

    size_t syscall_hint_len();

    void syscall_hint_read(uint8_t *ptr, size_t len);

    uint8_t *sys_alloc_aligned(size_t bytes, size_t align);

    void syscall_bls12381_decompress(uint8_t (*point)[96], bool is_odd);

    void sys_bigint(uint32_t result[8],
                    uint32_t op,
                    const uint32_t x[8],
                    const uint32_t y[8],
                    const uint32_t modulus[8]);

    void syscall_bls12381_fp_addmod(uint32_t *p, const uint32_t *q);

    void syscall_bls12381_fp_submod(uint32_t *p, const uint32_t *q);

    void syscall_bls12381_fp_mulmod(uint32_t *p, const uint32_t *q);

    void syscall_bls12381_fp2_addmod(uint32_t *p, const uint32_t *q);

    void syscall_bls12381_fp2_submod(uint32_t *p, const uint32_t *q);

    void syscall_bls12381_fp2_mulmod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp_addmod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp_submod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp_mulmod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp2_addmod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp2_submod(uint32_t *p, const uint32_t *q);

    void syscall_bn254_fp2_mulmod(uint32_t *p, const uint32_t *q);

    ReadVecResult read_vec_raw();
}

static inline void sys_print(std::string_view v)
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(v.data()), v.size());
}

static inline void sys_println(std::string_view v)
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(v.data()), v.size());
    syscall_write(1, reinterpret_cast<const uint8_t *>("\n"), 1);
}

using sp1_AffinePoint = uint32_t[16];

inline bool is_zero(const sp1_AffinePoint p) noexcept
{
    uint32_t fold = 0;
    for (size_t i = 0; i < 16; ++i)
        fold |= p[i];
    return fold == 0;
}

inline bool eq(const sp1_AffinePoint p, const sp1_AffinePoint q) noexcept
{
    uint32_t fold = 0;
    for (size_t i = 0; i < 16; ++i)
        fold |= p[i] ^ q[i];
    return fold == 0;
}

inline void sp1_point_from_bytes(sp1_AffinePoint r, const uint8_t bytes[64]) noexcept
{
    const auto x = &bytes[0];
    const auto y = &bytes[32];
    for (size_t i = 0; i < 8; ++i)
        r[i] = intx::be::unsafe::load<uint32_t>(&x[32 - (i + 1) * 4]);
    for (size_t i = 0; i < 8; ++i)
        r[i + 8] = intx::be::unsafe::load<uint32_t>(&y[32 - (i + 1) * 4]);
}

inline void sp1_point_to_bytes(uint8_t bytes[64], const sp1_AffinePoint r ) noexcept
{
    const auto x = &bytes[0];
    const auto y = &bytes[32];
    for (size_t i = 0; i < 8; ++i)
        intx::be::unsafe::store(&x[32 - (i + 1) * 4], r[i]);
    for (size_t i = 0; i < 8; ++i)
         intx::be::unsafe::store<uint32_t>(&y[32 - (i + 1) * 4], r[i + 8]);
}
