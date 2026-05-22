// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* SP1 zkVM runtime for pure C++ guest.
 *
 * Provides: entry point (__start), SP1 syscall implementations,
 *           public-values buffering + hashing, and bare-metal runtime stubs.
 *
 * Simple ecall wrappers (sha256, keccak, curve ops, field arithmetic) are
 * always_inline in sp1_syscalls.hpp.  This file only contains complex
 * multi-step implementations that cannot be expressed as a single ecall. */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "include/sp1_syscalls.hpp"
#include <evmone_precompiles/sha256.hpp>

/* ───────── Bare-metal _sbrk (heap allocator for newlib malloc) ───────── */
/* The prebuilt libnosys.a stub always returns -1, so malloc fails.
   We provide a real bump-allocator _sbrk so newlib malloc works. */

extern "C" {
extern char _end;  /* linker-provided end of BSS */
}

static char *_heap_ptr = nullptr;

/* _heap_ptr is initialised once in __start() (see bottom of file) so the
   null check on the hot path is eliminated. */
extern "C" void *_sbrk(ptrdiff_t incr) noexcept {
    char *prev = _heap_ptr;
    _heap_ptr += incr;
    return prev;
}

/* Dedicated input-region pointer for read_vec_raw.  Mirrors Rust's
   EMBEDDED_RESERVED_INPUT_PTR so hint-stream reads bypass _sbrk entirely.
   SP1 HyperCube address space goes up to 1<<48; we carve the top 16 GB
   (1<<34) as an input region, matching SP1's default configs. */
static constexpr uintptr_t INPUT_REGION_SIZE  = uintptr_t(1) << 34;
static constexpr uintptr_t MAX_MEMORY         = uintptr_t(1) << 37;
static constexpr uintptr_t INPUT_REGION_START = MAX_MEMORY - INPUT_REGION_SIZE;
static uintptr_t _input_ptr = INPUT_REGION_START;

/* ───────── Bare-metal runtime stubs ───────── */

/* Required by crtbegin / atexit infrastructure */
extern "C" { void *__dso_handle = nullptr; }

/* Unwind stubs – the guest is compiled with -fno-exceptions but prebuilt
   libstdc++ may reference these.  Marked weak to avoid clashing with
   the toolchain's libgcc_eh if it gets pulled in. */
extern "C" __attribute__((weak)) void _Unwind_Resume(void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int __gxx_personality_v0(
    int, int, uint64_t, void *, void *) { __builtin_trap(); }
extern "C" __attribute__((weak)) int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
extern "C" __attribute__((weak)) void __cxa_pure_virtual() { __builtin_trap(); }

/* ───────── SP1 Syscall Numbers ───────── */
static constexpr uint32_t SC_HALT                   = 0x00000000;
static constexpr uint32_t SC_WRITE                  = 0x00000002;
static constexpr uint32_t SC_ENTER_UNCONSTRAINED    = 0x00000003;
static constexpr uint32_t SC_EXIT_UNCONSTRAINED     = 0x00000004;
static constexpr uint32_t SC_COMMIT                 = 0x00000010;
static constexpr uint32_t SC_COMMIT_DEFERRED_PROOFS = 0x0000001A;
static constexpr uint32_t SC_HINT_LEN               = 0x000000F0;
static constexpr uint32_t SC_HINT_READ              = 0x000000F1;

/* File descriptors (LOWEST_ALLOWED_FD = 10, offset from there). */

/* ───────── SHA-256 for public-values hashing ───────── */
/* Uses evmone's SHA-256 (which already has SP1 syscall acceleration).
   PV data is buffered and hashed in one shot at halt time. */

/* ───────── Global public-values buffer ───────── */
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
        /* Grow: allocate a new buffer via _sbrk (bump allocator, old memory is
           simply abandoned — acceptable for this short-lived guest). */
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

/* ───────── Complex syscall implementations (multi-step / special register setups) ───────── */

extern "C" __attribute__((noinline)) void syscall_write(uint64_t fd, const uint8_t *write_buf, size_t nbytes) {
    register uint64_t t0 asm("t0") = SC_WRITE;
    register uint64_t a0 asm("a0") = fd;
    register uint64_t a1 asm("a1") = reinterpret_cast<uint64_t>(write_buf);
    register uint64_t a2 asm("a2") = nbytes;
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1), "r"(a2) : "memory");

    /* If writing to public-values fd, buffer the bytes for later hashing. */
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
    /* 1. Hash all buffered public-values bytes using evmone's SHA-256
          (SP1-accelerated via syscall_sha256_extend/compress). */
    uint32_t digest_words[8];
    evmone::crypto::sha256(reinterpret_cast<std::byte *>(digest_words),
                           reinterpret_cast<const std::byte *>(g_pv_buf), g_pv_len);

    /* 2. COMMIT 8 PV digest words. */
    commit_words(SC_COMMIT, digest_words);

    /* 3. COMMIT_DEFERRED_PROOFS – 8 zero words (no proof verification). */
    static constexpr uint32_t zeros[8] = {};
    commit_words(SC_COMMIT_DEFERRED_PROOFS, zeros);

    /* 4. HALT ecall. */
    {
        register uint64_t t0 asm("t0") = SC_HALT;
        register uint64_t a0 asm("a0") = exit_code;
        asm volatile("ecall" : : "r"(t0), "r"(a0));
    }
    __builtin_unreachable();
}

/* ───────── Multi-arg syscalls with special register setups ───────── */

extern "C" void syscall_u256x2048_mul(const uint64_t x[4], const uint64_t y[32],
                                       uint64_t lo[32], uint64_t hi[4]) {
    register uint64_t t0 asm("t0") = 0x0001012F;
    register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(x);
    register uint64_t a1 asm("a1") = reinterpret_cast<uint64_t>(y);
    asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
    (void)lo; (void)hi; /* passed via a0/a1 convention + memory */
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

/* ───────── read_vec_raw: Read a buffer from the SP1 hint stream ───────── */
/* Optimised version: ecalls are inlined (no function-call overhead),
   allocation uses the dedicated input-region pointer (no _sbrk calls).
   This mirrors the Rust SP1 entrypoint's read_vec_raw which is a
   near-leaf function with zero function calls in the happy path. */

extern "C" ReadVecResult read_vec_raw() noexcept {
    /* 1. Inline HINT_LEN ecall — avoids jal/ret to syscall_hint_len. */
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

    /* Bump-allocate from the dedicated input region (not _sbrk).
       The region starts at INPUT_REGION_START and grows upward. */
    uint8_t *ptr = reinterpret_cast<uint8_t *>(_input_ptr);
    _input_ptr += capacity;

    /* 2. Inline HINT_READ ecall — avoids jal/ret to syscall_hint_read. */
    {
        register uint64_t t0 asm("t0") = SC_HINT_READ;
        register uint64_t a0 asm("a0") = reinterpret_cast<uint64_t>(ptr);
        register uint64_t a1 asm("a1") = len;
        asm volatile("ecall" : "+r"(t0) : "r"(a0), "r"(a1) : "memory");
    }

    return {ptr, len, capacity};
}

/* ───────── sys_alloc_aligned: SP1 memory allocation stub ───────── */

// Currently not needed, leaving for potential future use of bump allocator.
// extern "C" uint8_t *sys_alloc_aligned(size_t bytes, size_t align) noexcept {
//     /* Bump-allocate directly from _heap_ptr with explicit alignment.
//        Avoids calling _sbrk twice (once for query, once for bump). */
//     if (align < 8) [[likely]] align = 8;
//     uintptr_t addr = reinterpret_cast<uintptr_t>(_heap_ptr);
//     uintptr_t aligned = (addr + align - 1) & ~(align - 1);
//     _heap_ptr = reinterpret_cast<char *>(aligned + bytes);
//     return reinterpret_cast<uint8_t *>(aligned);
// }

extern "C" __attribute__((cold)) [[noreturn]] void sys_panic(const uint8_t *msg_ptr, size_t len) {
    syscall_write(2, msg_ptr, len);
    syscall_halt(1);
}


/* ───────── Global constructors (linker-provided arrays) ───────── */

extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

/* The guest's main function (main.cpp). */
extern "C" int main();

extern "C" void __start() {
    /* 0. Initialise _heap_ptr once, so _sbrk never needs a null check.
       Align _end up to 8-byte boundary for rv64im ld/sd safety. */
    _heap_ptr = reinterpret_cast<char *>(
        (reinterpret_cast<uintptr_t>(&_end) + 7) & ~uintptr_t(7));

    /* 1. Run C++ global constructors (static initialisers, atexit
       registrations, etc.).  Without this, any translation unit with
       file-scope objects that have non-trivial constructors will fail. */
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
        (*p)();
    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();

    /* 2. Initialise the public-values buffer (hashed at halt time). */
    pv_buf_init();

    /* 3. Call the guest program. */
    main();

    /* 4. Halt with success (never returns). */
    syscall_halt(0);
}
