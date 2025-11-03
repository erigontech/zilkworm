#pragma once
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t, uint64_t

// Notes:
// - Rust `usize` <-> C++ `size_t`
// - Rust `u8/u32/u64` <-> C++ uint8_t/uint32_t/uint64_t
// - Rust pointer to fixed-size array like `*mut [u32; 16]`
//     becomes `uint32_t (*)[16]` (pointer to array-of-16)
// - Rust `bool` in FFI is 1 byte (0 or 1). C++ `bool` is typically ABI-compatible,
//   but if you want to be extra cautious, you can swap `bool` for `uint8_t`.

// Rust: #[repr(C)]
struct ReadVecResult
{
    uint8_t *ptr;
    size_t len;
    size_t capacity;
};

extern "C"
{

    // pub fn syscall_halt(exit_code: u8) -> !
    [[noreturn]] void syscall_halt(uint8_t exit_code);

    // pub fn syscall_write(fd: u32, write_buf: *const u8, nbytes: usize)
    void syscall_write(uint32_t fd, const uint8_t *write_buf, size_t nbytes);

    // pub fn syscall_read(fd: u32, read_buf: *mut u8, nbytes: usize)
    void syscall_read(uint32_t fd, uint8_t *read_buf, size_t nbytes);

    // pub fn syscall_sha256_extend(w: *mut [u32; 64])
    void syscall_sha256_extend(uint32_t (*w)[64]);

    // pub fn syscall_sha256_compress(w: *mut [u32; 64], state: *mut [u32; 8])
    void syscall_sha256_compress(uint32_t (*w)[64], uint32_t (*state)[8]);

    // pub fn syscall_ed_add(p: *mut [u32; 16], q: *const [u32; 16])
    void syscall_ed_add(uint32_t (*p)[16], const uint32_t (*q)[16]);

    // pub fn syscall_ed_decompress(point: &mut [u8; 64])
    void syscall_ed_decompress(uint8_t (*point)[64]);

    // pub fn syscall_secp256k1_add(p: *mut [u32; 16], q: *const [u32; 16])
    void syscall_secp256k1_add(uint32_t (*p)[16], const uint32_t (*q)[16]);

    // pub fn syscall_secp256k1_double(p: *mut [u32; 16])
    void syscall_secp256k1_double(uint32_t (*p)[16]);

    // pub fn syscall_secp256k1_decompress(point: &mut [u8; 64], is_odd: bool)
    void syscall_secp256k1_decompress(uint8_t (*point)[64], bool is_odd);
    // If you prefer maximum safety for FFI: replace `bool` with `uint8_t`.

    // pub fn syscall_secp256r1_add(p: *mut [u32; 16], q: *const [u32; 16])
    void syscall_secp256r1_add(uint32_t (*p)[16], const uint32_t (*q)[16]);

    // pub fn syscall_secp256r1_double(p: *mut [u32; 16])
    void syscall_secp256r1_double(uint32_t (*p)[16]);

    // pub fn syscall_secp256r1_decompress(point: &mut [u8; 64], is_odd: bool)
    void syscall_secp256r1_decompress(uint8_t (*point)[64], bool is_odd);
    // (Same note as above regarding `bool`.)

    // pub fn syscall_bn254_add(p: *mut [u32; 16], q: *const [u32; 16])
    void syscall_bn254_add(uint32_t (*p)[16], const uint32_t (*q)[16]);

    // pub fn syscall_bn254_double(p: *mut [u32; 16])
    void syscall_bn254_double(uint32_t (*p)[16]);

    // pub fn syscall_bls12381_add(p: *mut [u32; 24], q: *const [u32; 24])
    void syscall_bls12381_add(uint32_t (*p)[24], const uint32_t (*q)[24]);

    // pub fn syscall_bls12381_double(p: *mut [u32; 24])
    void syscall_bls12381_double(uint32_t (*p)[24]);

    // pub fn syscall_keccak_permute(state: *mut [u64; 25])
    void syscall_keccak_permute(uint64_t (*state)[25]);

    // pub fn syscall_uint256_mulmod(x: *mut [u32; 8], y: *const [u32; 8])
    void syscall_uint256_mulmod(uint32_t (*x)[8], const uint32_t (*y)[8]);

    // pub fn syscall_u256x2048_mul(
    //     x: *const [u32; 8], y: *const [u32; 64], lo: *mut [u32; 64], hi: *mut [u32; 8])
    void syscall_u256x2048_mul(const uint32_t (*x)[8],
                               const uint32_t (*y)[64],
                               uint32_t (*lo)[64],
                               uint32_t (*hi)[8]);

    // pub fn syscall_enter_unconstrained() -> bool
    bool syscall_enter_unconstrained();
    // (Swap to `uint8_t` if you want stricter control over ABI.)

    // pub fn syscall_exit_unconstrained()
    void syscall_exit_unconstrained();

    // pub fn syscall_verify_sp1_proof(vk_digest: &[u32; 8], pv_digest: &[u8; 32])
    void syscall_verify_sp1_proof(const uint32_t (*vk_digest)[8],
                                  const uint8_t (*pv_digest)[32]);

    // pub fn syscall_hint_len() -> usize
    size_t syscall_hint_len();

    // pub fn syscall_hint_read(ptr: *mut u8, len: usize)
    void syscall_hint_read(uint8_t *ptr, size_t len);

    // pub fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8
    uint8_t *sys_alloc_aligned(size_t bytes, size_t align);

    // pub fn syscall_bls12381_decompress(point: &mut [u8; 96], is_odd: bool)
    void syscall_bls12381_decompress(uint8_t (*point)[96], bool is_odd);

    // pub fn sys_bigint(
    //   result:*mut [u32;8], op:u32, x:*const [u32;8], y:*const [u32;8], modulus:*const [u32;8])
    void sys_bigint(uint32_t (*result)[8],
                    uint32_t op,
                    const uint32_t (*x)[8],
                    const uint32_t (*y)[8],
                    const uint32_t (*modulus)[8]);

    // Field/Fp and Fp2 ops for BLS12-381 (operands are limb pointers; sizes defined by the ABI)
    // pub fn syscall_bls12381_fp_addmod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp_addmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bls12381_fp_submod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp_submod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bls12381_fp_mulmod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp_mulmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bls12381_fp2_addmod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp2_addmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bls12381_fp2_submod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp2_submod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bls12381_fp2_mulmod(p: *mut u32, q: *const u32)
    void syscall_bls12381_fp2_mulmod(uint32_t *p, const uint32_t *q);

    // Field/Fp and Fp2 ops for BN254
    // pub fn syscall_bn254_fp_addmod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp_addmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bn254_fp_submod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp_submod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bn254_fp_mulmod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp_mulmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bn254_fp2_addmod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp2_addmod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bn254_fp2_submod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp2_submod(uint32_t *p, const uint32_t *q);

    // pub fn syscall_bn254_fp2_mulmod(p: *mut u32, q: *const u32)
    void syscall_bn254_fp2_mulmod(uint32_t *p, const uint32_t *q);

    // pub fn read_vec_raw() -> ReadVecResult
    ReadVecResult read_vec_raw();
} // extern "C"

static inline void sys_print(const char *s)
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(s), std::strlen(s));
}
static inline void sys_println(const char *s)
{
    syscall_write(1, reinterpret_cast<const uint8_t *>(s), std::strlen(s));
    syscall_write(1, reinterpret_cast<const uint8_t *>("\n"), 1);
}