// sp1_syscalls_tests_simple.cpp
#include "../include/sp1_syscalls.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>

static inline void sys_print(const char* s) {
    syscall_write(1, reinterpret_cast<const uint8_t*>(s), std::strlen(s));
}
static inline void sys_println(const char* s) {
    syscall_write(1, reinterpret_cast<const uint8_t*>(s), std::strlen(s));
    syscall_write(1, reinterpret_cast<const uint8_t*>("\n"), 1);
}


// void test_syscall_read_zero() {
//     uint8_t dummy{};
//     syscall_read(0, &dummy, 0); // zero-length read: should be a no-op
//     sys_println("[read] zero-byte read OK");
// }

void test_sha256_extend() {
    uint32_t W[64];
    for (uint32_t i = 0; i < 64; ++i) W[i] = i;
    syscall_sha256_extend(&W);
    sys_println("[sha256_extend] called");
}

void test_sha256_compress() {
    uint32_t W[64] = {};
    uint32_t S[8]  = {};
    syscall_sha256_compress(&W, &S);
    sys_println("[sha256_compress] called");
}

void test_keccak_permute() {
    uint64_t st[25] = {};
    syscall_keccak_permute(&st);
    sys_println("[keccak_permute] called");
}

void test_u256x2048_mul_zero() {
    uint32_t x[8]   = {};  // 256-bit
    uint32_t y[64]  = {};  // 2048-bit
    uint32_t lo[64] = {};
    uint32_t hi[8]  = {};
    syscall_u256x2048_mul(&x, &y, &lo, &hi);
    sys_println("[u256x2048_mul] zero * zero called");
}

void test_read_vec_raw_metadata_only() {
    ReadVecResult r = read_vec_raw();
    (void)r; // Not dereferencing; just ensuring call works.
    sys_println("[read_vec_raw] called (ptr/len/cap captured)");
}

static inline void fill_u32(uint32_t* a, size_t n, uint32_t start) {
    for (size_t i = 0; i < n; ++i) a[i] = start + static_cast<uint32_t>(i);
}
static inline void fill_u8(uint8_t* a, size_t n, uint8_t start) {
    for (size_t i = 0; i < n; ++i) a[i] = static_cast<uint8_t>(start + i);
}

void test_ed_add() {
    uint32_t P[16]; fill_u32(P, 16, 1);
    uint32_t Q[16]; fill_u32(Q, 16, 101);
    syscall_ed_add(&P, &Q); // result in P
    sys_println("[ed_add] called");
}

void test_ed_decompress() {
    uint8_t pt[64]; fill_u8(pt, 64, 7);
    syscall_ed_decompress(&pt);
    sys_println("[ed_decompress] called");
}

void test_secp256k1_ops() {
    uint32_t P[16]; fill_u32(P, 16, 5);
    uint32_t Q[16]; fill_u32(Q, 16, 77);
    syscall_secp256k1_add(&P, &Q);
    syscall_secp256k1_double(&P);
    uint8_t C[64];  fill_u8(C, 64, 9);
    syscall_secp256k1_decompress(&C, /*is_odd=*/true);
    sys_println("[secp256k1] add/double/decompress called");
}

void test_secp256r1_ops() {
    uint32_t P[16]; fill_u32(P, 16, 11);
    uint32_t Q[16]; fill_u32(Q, 16, 33);
    syscall_secp256r1_add(&P, &Q);
    syscall_secp256r1_double(&P);
    uint8_t C[64];  fill_u8(C, 64, 4);
    syscall_secp256r1_decompress(&C, /*is_odd=*/false);
    sys_println("[secp256r1] add/double/decompress called");
}

void test_bn254_ops() {
    uint32_t P[16]; fill_u32(P, 16, 2);
    uint32_t Q[16]; fill_u32(Q, 16, 50);
    syscall_bn254_add(&P, &Q);
    syscall_bn254_double(&P);
    sys_println("[bn254] add/double called");
}

void test_bn254_add_extended() {
    alignas(4) std::array<uint32_t,16> P{};
    alignas(4) std::array<uint32_t,16> Q{};

    // Values taken from Erigon's bn254 test data
    P[0] = 0x2243525c;
    // P[1] = 0x5efd4b9c;
    P[2] = 0x3d3c45ac;
    P[3] = 0x0ca3fe4d;
    P[4] = 0xd85e830a;
    // P[5] = 0x4ce6b65f;
    P[6] = 0xa1eeaee2;
    P[7] = 0x02839703;
    P[8] = 0x301d1d33;
    // P[9] = 0xbe6da8e5;
    P[10] = 0x09df21cc;
    P[11] = 0x35964723;
    // P[12] = 0x180eed75;
    P[13] = 0x32537db9;
    P[14] = 0xae5e7d48;
    // P[15] = 0xf195c915;
    Q[0] = 0x18b18acf;
    Q[1] = 0xb4c2c302;
    Q[2] = 0x76db5411;
    Q[3] = 0x368e7185;
    // Q[4] = 0xb311dd12;
    Q[5] = 0x4691610c;
    Q[6] = 0x5d3b7403;
    Q[7] = 0x4e093dc9;
    Q[8] = 0x063c909c;
    Q[9] = 0x4720840c;
    // Q[10] = 0xb5134cb9;
    Q[11] = 0xf59fa749;
    Q[12] = 0x75579681;
    // Q[13] = 0x9658d32e;
    Q[14] = 0xfc0d2881;
    // Q[15] = 0x98f37266;
    syscall_bn254_add(reinterpret_cast<uint32_t (*)[16]>(P.data()),
                      reinterpret_cast<const uint32_t (*)[16]>(Q.data()));
    
    sys_println("[bn254] add result: " + P[0]);

}

void test_bls12381_ops() {
    uint32_t P[24]; fill_u32(P, 24, 1);
    uint32_t Q[24]; fill_u32(Q, 24, 2);
    syscall_bls12381_add(&P, &Q);
    syscall_bls12381_double(&P);
    uint8_t C[96];  fill_u8(C, 96, 0xAA);
    syscall_bls12381_decompress(&C, /*is_odd=*/true);
    sys_println("[bls12-381] add/double/decompress called");
}

void test_uint256_mulmod_placeholder() {
    uint32_t x[8]; fill_u32(x, 8, 3);
    uint32_t y[8]; fill_u32(y, 8, 7);
    syscall_uint256_mulmod(&x, &y); // modifies x in-place
    sys_println("[uint256_mulmod] called");
}

void test_sys_bigint_placeholder() {
    uint32_t result[8] = {};
    uint32_t X[8]; fill_u32(X, 8, 1);
    uint32_t Y[8]; fill_u32(Y, 8, 2);
    uint32_t M[8]; fill_u32(M, 8, 3);
    uint32_t op = 0; // host-defined; replace with a real opcode
    sys_bigint(&result, op, &X, &Y, &M);
    sys_println("[sys_bigint] called (placeholder op)");
}

// Field/Fp/Fp2 ops — sizes are ABI-defined. Using 8-limb placeholders.
// Confirm limb counts for your host before enabling.
void test_field_ops_placeholders() {
    uint32_t A[8] = {1};
    uint32_t B[8] = {2};

    syscall_bls12381_fp_addmod(A, B);
    syscall_bls12381_fp_submod(A, B);
    syscall_bls12381_fp_mulmod(A, B);
    syscall_bls12381_fp2_addmod(A, B);
    syscall_bls12381_fp2_submod(A, B);
    syscall_bls12381_fp2_mulmod(A, B);

    syscall_bn254_fp_addmod(A, B);
    syscall_bn254_fp_submod(A, B);
    syscall_bn254_fp_mulmod(A, B);
    syscall_bn254_fp2_addmod(A, B);
    syscall_bn254_fp2_submod(A, B);
    syscall_bn254_fp2_mulmod(A, B);

    sys_println("[field ops] placeholders called (confirm limb sizes!)");
}



void run_sp1_basic_smoke_tests() {
    sys_println("== running basic SP1 syscall smoke tests ==");
    test_sha256_extend();
    test_sha256_compress();
    test_keccak_permute();
    test_u256x2048_mul_zero();
    test_read_vec_raw_metadata_only();
    sys_println("== basic smoke tests done ==");
}

void run_sp1_crypto_shape_tests() {
    sys_println("== running crypto shape tests (inputs NOT validated) ==");
    test_ed_add();
    // test_ed_decompress();
    // test_secp256k1_ops();
    test_secp256r1_ops();
    test_bn254_ops();
    test_bn254_add_extended();
    test_bls12381_ops();
    test_uint256_mulmod_placeholder();
    // test_sys_bigint_placeholder();
    // test_field_ops_placeholders();
    sys_println("== crypto shape tests done ==");
}