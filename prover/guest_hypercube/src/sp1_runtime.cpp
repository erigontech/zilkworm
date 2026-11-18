// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// SP1 zkVM runtime for the pure C++ guest: entry point, multi-step syscalls, public-values buffering and hashing, bare-metal stubs.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "include/sp1_syscalls.hpp"
#include <evmone_precompiles/sha256.hpp>

// The prebuilt libnosys.a _sbrk always returns -1, so provide a bump allocator for newlib malloc.

extern "C" {
extern char _end;
}

static char *_heap_ptr = nullptr;

// Set once in __start() so the hot path needs no null check.
extern "C" void *_sbrk(ptrdiff_t incr) noexcept {
    char *prev = _heap_ptr;
    _heap_ptr += incr;
    return prev;
}

// Input region for read_vec_raw, as in Rust's EMBEDDED_RESERVED_INPUT_PTR: the top 16 GB (1<<34) of the 1<<48 address space.
static constexpr uintptr_t INPUT_REGION_SIZE  = uintptr_t(1) << 34;
static constexpr uintptr_t MAX_MEMORY         = uintptr_t(1) << 37;
static constexpr uintptr_t INPUT_REGION_START = MAX_MEMORY - INPUT_REGION_SIZE;
static uintptr_t _input_ptr = INPUT_REGION_START;

/* Required by crtbegin / atexit infrastructure */
extern "C" { void *__dso_handle = nullptr; }

// Weak unwind stubs: the prebuilt libstdc++ may reference them though the guest is built with -fno-exceptions.
extern "C" __attribute__((weak)) void _Unwind_Resume(void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int __gxx_personality_v0(
    int, int, uint64_t, void *, void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
extern "C" __attribute__((weak)) void __cxa_pure_virtual() { __builtin_trap(); }

static constexpr uint32_t SC_HALT                   = 0x00000000;
static constexpr uint32_t SC_WRITE                  = 0x00000002;
static constexpr uint32_t SC_ENTER_UNCONSTRAINED    = 0x00000003;
static constexpr uint32_t SC_EXIT_UNCONSTRAINED     = 0x00000004;
static constexpr uint32_t SC_COMMIT                 = 0x00000010;
static constexpr uint32_t SC_COMMIT_DEFERRED_PROOFS = 0x0000001A;
static constexpr uint32_t SC_HINT_LEN               = 0x000000F0;
static constexpr uint32_t SC_HINT_READ              = 0x000000F1;

/* File descriptors (LOWEST_ALLOWED_FD = 10, offset from there). */

// Uses evmone's SP1-accelerated SHA-256; PV data is buffered and hashed once at halt.

static constexpr size_t PV_BUF_INITIAL_CAP = 4096;
static uint8_t *g_pv_buf = nullptr;
static size_t   g_pv_len = 0;
static size_t   g_pv_cap = 0;

__attribute__((cold)) static void pv_buf_init() {
    g_pv_buf = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(PV_BUF_INITIAL_CAP)));
    g_pv_len = 0;
    g_pv_cap = PV_BUF_INITIAL_CAP;
}

static void pv_buf_append(const uint8_t *data, size_t len) {
    if (g_pv_len + len > g_pv_cap) [[unlikely]] {
        // Grow via _sbrk; the old buffer is abandoned (short-lived guest).
        size_t new_cap = g_pv_cap;
        while (new_cap < g_pv_len + len)
            new_cap *= 2;
        uint8_t *new_buf = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>(new_cap)));
        std::memcpy(new_buf, g_pv_buf, g_pv_len);
        g_pv_buf = new_buf;
        g_pv_cap = new_cap;
    }
    std::memcpy(g_pv_buf + g_pv_len, data, len);
    g_pv_len += len;
}

extern "C" __attribute__((noinline)) void syscall_write(uint64_t fd, const uint8_t *write_buf, size_t nbytes) {
    register uint64_t t0 asm("t0") = SC_WRITE;
    register uint64_t a0 asm("a0") = fd;
    register uint64_t a1 asm("a1") = reinterpret_cast<uint64_t>(write_buf);
    register uint64_t a2 asm("a2") = nbytes;
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1), "r"(a2) : "memory");

    if (fd == SP1_FD_PUBLIC_VALUES) [[unlikely]] {
        pv_buf_append(write_buf, nbytes);
    }
}

/* Emit 8 COMMIT ecalls for a given syscall number, sending word[i] for each i. */
static void commit_words(uint32_t syscall_num, const uint32_t words[8]) {
    for (uint64_t i = 0; i < 8; i++) {
        register uint64_t t0 asm("t0") = syscall_num;
        register uint64_t a0 asm("a0") = i;
        register uint64_t a1 asm("a1") = words[i];
        asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
    }
}

extern "C" __attribute__((noinline)) [[noreturn]] void syscall_halt(uint8_t exit_code) {
    uint32_t digest_words[8];
    evmone::crypto::sha256(reinterpret_cast<std::byte *>(digest_words),
                           reinterpret_cast<const std::byte *>(g_pv_buf), g_pv_len);

    commit_words(SC_COMMIT, digest_words);

    // COMMIT_DEFERRED_PROOFS: 8 zero words, no proof verification.
    static constexpr uint32_t zeros[8] = {};
    commit_words(SC_COMMIT_DEFERRED_PROOFS, zeros);

    {
        register uint64_t t0 asm("t0") = SC_HALT;
        register uint64_t a0 asm("a0") = exit_code;
        asm volatile("ecall" : : "r"(t0), "r"(a0));
    }
    __builtin_unreachable();
}

extern "C" void syscall_u256x2048_mul(const uint64_t x[4], const uint64_t y[32],
                                       uint64_t lo[32], uint64_t hi[4]) {
    register uint64_t t0 asm("t0") = 0x0001012F;
    register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(x);
    register uint64_t a1 asm("a1") = reinterpret_cast<uint64_t>(y);
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
    (void)lo; (void)hi;
}

extern "C" void syscall_uint256_add_with_carry(const uint64_t a[4], const uint64_t b[4],
                                                const uint64_t c[4], uint64_t d[4], uint64_t e[4]) {
    register uint64_t t0 asm("t0") = 0x00010130;
    register uint64_t ra0 asm("a0") = reinterpret_cast<uint64_t>(a);
    register uint64_t ra1 asm("a1") = reinterpret_cast<uint64_t>(b);
    asm volatile("ecall" : "+r"(t0) : "r"(ra0), "r"(ra1) : "memory");
    (void)c; (void)d; (void)e;
}

extern "C" void syscall_uint256_mul_with_carry(const uint64_t a[4], const uint64_t b[4],
                                                const uint64_t c[4], uint64_t d[4], uint64_t e[4]) {
    register uint64_t t0 asm("t0") = 0x00010131;
    register uint64_t ra0 asm("a0") = reinterpret_cast<uint64_t>(a);
    register uint64_t ra1 asm("a1") = reinterpret_cast<uint64_t>(b);
    asm volatile("ecall" : "+r"(t0) : "r"(ra0), "r"(ra1) : "memory");
    (void)c; (void)d; (void)e;
}

extern "C" bool syscall_enter_unconstrained() {
    register uint64_t t0 asm("t0") = SC_ENTER_UNCONSTRAINED;
    asm volatile("ecall" : "+r"(t0) : : "memory");
    return static_cast<bool>(t0);
}

extern "C" void syscall_exit_unconstrained() {
    register uint64_t t0 asm("t0") = SC_EXIT_UNCONSTRAINED;
    asm volatile("ecall" : "+r"(t0) : : "memory");
}

extern "C" void syscall_verify_sp1_proof(const uint64_t vk_digest[4],
                                          const uint64_t pv_digest[4]) {
    register uint64_t t0 asm("t0") = 0x0000001B;
    register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(vk_digest);
    register uint64_t a1 asm("a1") = reinterpret_cast<uint64_t>(pv_digest);
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
}

extern "C" void syscall_mprotect(const uint8_t *addr, uint8_t prot) {
    register uint64_t t0 asm("t0") = 0x00000132;
    register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(addr);
    register uint64_t a1 asm("a1") = prot;
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
}

// Ecalls are inlined and allocation bypasses _sbrk, like the Rust entrypoint's read_vec_raw.

extern "C" ReadVecResult read_vec_raw() noexcept {
    size_t len;
    {
        register uint64_t t0 asm("t0") = SC_HINT_LEN;
        asm volatile("ecall" : "+r"(t0) : : "memory");
        len = static_cast<size_t>(t0);
    }

    /* usize::MAX means the hint stream is exhausted. */
    if (len == SIZE_MAX) [[unlikely]] {
        return {nullptr, 0, 0};
    }

    /* Round up to 8-byte alignment for rv64im ld/sd. */
    size_t capacity = (len + 7) & ~size_t(7);

    // Bump-allocate from the input region (grows upward from INPUT_REGION_START), not _sbrk.
    uint8_t *ptr = reinterpret_cast<uint8_t *>(_input_ptr);
    _input_ptr += capacity;

    {
        register uint64_t t0 asm("t0") = SC_HINT_READ;
        register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(ptr);
        register uint64_t a1 asm("a1") = len;
        asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
    }

    return {ptr, len, capacity};
}

extern "C" __attribute__((cold)) [[noreturn]] void sys_panic(const uint8_t *msg_ptr, size_t len) {
    syscall_write(2, msg_ptr, len);
    syscall_halt(1);
}


extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

extern "C" int main();

extern "C" void __start() {
    // Align _end up to 8 bytes: rv64im ld/sd must be 8-aligned.
    _heap_ptr = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(&_end) + 7) & ~uintptr_t(7));

    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
        (*p)();
    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();

    pv_buf_init();

    main();

    syscall_halt(0);
}
