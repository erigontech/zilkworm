// Airbender zkVM CSR interface — syscalls, UART, and input reading.
#pragma once

#include <cstddef>
#include <cstdint>
#include <new>
#include <string_view>
#include <utility>

namespace airbender {

// --- CSR addresses ---
constexpr uint32_t CSR_NON_DETERMINISM = 0x7C0;
constexpr uint32_t CSR_BLAKE2S = 0x7C7;
constexpr uint32_t CSR_BIGINT = 0x7CA;
constexpr uint32_t CSR_KECCAK_SPECIAL5 = 0x7CB;

// --- Basic CSR read/write ---

inline void csr_write_word(uint32_t value) {
    asm volatile("csrrw x0, 0x7C0, %0" :: "r"(value) : "memory");
}

inline uint32_t csr_read_word() {
    uint32_t out = 0;
    asm volatile("csrrw %0, 0x7C0, x0" : "=r"(out) :: "memory");
    return out;
}

// --- Input reading ---

/// Read input blob from CSR non-determinism oracle.
/// Protocol: first word = byte count, then ceil(n/4) LE words.
inline std::pair<uint8_t*, size_t> read_input_from_csr()
{
    uint32_t num_bytes = csr_read_word();
    uint8_t* buf = static_cast<uint8_t*>(::operator new(num_bytes));
    uint32_t* dst = reinterpret_cast<uint32_t*>(buf);

    size_t full_words = num_bytes / 4;
    for (size_t i = 0; i < full_words; ++i)
        dst[i] = csr_read_word();

    size_t written = full_words * 4;
    if (written < num_bytes) {
        uint32_t word = csr_read_word();
        uint8_t* tail = buf + written;
        while (written < num_bytes) {
            *tail++ = static_cast<uint8_t>(word & 0xFFu);
            word >>= 8;
            ++written;
        }
    }
    return {buf, num_bytes};
}

// --- UART output (QuasiUART protocol) ---

namespace detail {

inline uint32_t pack_le_u32(const uint8_t b[4]) {
    return uint32_t(b[0]) | (uint32_t(b[1]) << 8) |
           (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
}

inline size_t strlen_(const char* s) {
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}

inline void uart_write_str(const char* data, size_t len) {
    constexpr uint32_t kHelloMarker = 0xFFFFFFFFu;
    csr_write_word(kHelloMarker);
    size_t words = (len + 3) / 4;
    csr_write_word(static_cast<uint32_t>(words + 1));
    csr_write_word(static_cast<uint32_t>(len));

    uint8_t buf[4] = {};
    size_t buf_len = 0;
    for (size_t i = 0; i < len; ++i) {
        buf[buf_len++] = static_cast<uint8_t>(data[i]);
        if (buf_len == 4) {
            csr_write_word(pack_le_u32(buf));
            buf_len = 0;
        }
    }
    if (buf_len > 0) {
        for (size_t i = buf_len; i < 4; ++i) buf[i] = 0;
        csr_write_word(pack_le_u32(buf));
    }
}

}  // namespace detail

// --- Blake2s ---

inline void blake_trigger_reduced_rounds(uint32_t* state, const uint32_t* input, uint32_t mask) {
    register uintptr_t x10 asm("x10") = reinterpret_cast<uintptr_t>(state);
    register uintptr_t x11 asm("x11") = reinterpret_cast<uintptr_t>(input);
    register uint32_t x12 asm("x12") = mask;
    asm volatile(
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n"
        : "+r"(x12) : "r"(x10), "r"(x11) : "memory"
    );
    (void)x12;
}

inline void blake_trigger_full_rounds(uint32_t* state, const uint32_t* input, uint32_t mask) {
    register uintptr_t x10 asm("x10") = reinterpret_cast<uintptr_t>(state);
    register uintptr_t x11 asm("x11") = reinterpret_cast<uintptr_t>(input);
    register uint32_t x12 asm("x12") = mask;
    asm volatile(
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        "csrrw x0, 0x7C7, x0\n" "csrrw x0, 0x7C7, x0\n"
        : "+r"(x12) : "r"(x10), "r"(x11) : "memory"
    );
    (void)x12;
}

// --- BigInt U256 ---

[[gnu::always_inline]] inline uint32_t bigint_trigger(
    uint32_t* mut_ptr, const uint32_t* immut_ptr, uint32_t mask) {
    register uintptr_t x10 asm("x10") = reinterpret_cast<uintptr_t>(mut_ptr);
    register uintptr_t x11 asm("x11") = reinterpret_cast<uintptr_t>(immut_ptr);
    register uint32_t x12 asm("x12") = mask;
    asm volatile(
        "csrrw x0, 0x7CA, x0"
        : "+r"(x12) : "r"(x10), "r"(x11) : "memory"
    );
    return x12;
}

// --- Keccak-f[1600] ---

/// 649 delegated CSR writes. State: 31 × u64 at 256-byte-aligned address.
inline void keccak_f1600_delegate(uint64_t state[25]) {
    uint64_t __attribute__((aligned(256))) buf[32];
    for (int i = 0; i < 25; i++) buf[i] = state[i];
    for (int i = 25; i < 31; i++) buf[i] = 0;

    register uint32_t ctrl asm("x10") = 0;
    register void*    sptr asm("x11") = static_cast<void*>(buf);
    asm volatile(
        "li t0, 649\n"
        "1:\n"
        "  csrrw x0, 0x7CB, x0\n"
        "  addi t0, t0, -1\n"
        "  bnez t0, 1b\n"
        : "+r"(ctrl) : "r"(sptr) : "t0", "memory"
    );
    for (int i = 0; i < 25; i++) state[i] = buf[i];
}

// --- Program termination ---

[[noreturn]] inline void finish_error() {
    asm volatile("csrrw x0, cycle, x0" ::: "memory");
    asm volatile("1: j 1b\n");
    __builtin_unreachable();
}

[[gnu::noinline]] [[noreturn]] inline void finish_success_extended(const uint32_t data[16]) {
    const uint32_t* ptr = data;
    asm volatile(
        "lw x10, 0(%0)\n"  "lw x11, 4(%0)\n"
        "lw x12, 8(%0)\n"  "lw x13, 12(%0)\n"
        "lw x14, 16(%0)\n" "lw x15, 20(%0)\n"
        "lw x16, 24(%0)\n" "lw x17, 28(%0)\n"
        "lw x18, 32(%0)\n" "lw x19, 36(%0)\n"
        "lw x20, 40(%0)\n" "lw x21, 44(%0)\n"
        "lw x22, 48(%0)\n" "lw x23, 52(%0)\n"
        "lw x24, 56(%0)\n" "lw x25, 60(%0)\n"
        :: "r"(ptr), "m"(*reinterpret_cast<const uint32_t (*)[16]>(ptr))
        : "x10","x11","x12","x13","x14","x15","x16","x17",
          "x18","x19","x20","x21","x22","x23","x24","x25","memory"
    );
    asm volatile("1: j 1b\n");
    __builtin_unreachable();
}

[[noreturn]] inline void finish_success(const uint32_t data[8]) {
    uint32_t extended[16] = {};
    for (int i = 0; i < 8; ++i) extended[i] = data[i];
    finish_success_extended(extended);
}

}  // namespace airbender

// Global sys_print / sys_println — matches zilk_core/airbender_print.hpp interface.
inline void sys_print(const char* msg) {
    airbender::detail::uart_write_str(msg, airbender::detail::strlen_(msg));
}

inline void sys_println(std::string_view s) {
    airbender::detail::uart_write_str(s.data(), s.size());
}
