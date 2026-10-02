// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

/* ZisK zkVM runtime for pure C++ guest. */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include "include/zisk_syscalls.hpp"
#ifdef Z6M_ZISK_HEAP_STATS
#include <format>
#endif

/* ───────── Heap (_sbrk under newlib malloc) ───────── */

extern "C" {
extern char _heap_bottom, _heap_top;  /* PROVIDEd by zisk.ld */
}

static char *heap_ptr = nullptr;
static char *heap_end = nullptr;
#ifdef Z6M_ZISK_HEAP_STATS
static char *heap_peak = nullptr;
#endif

static char *align_up(char *p, uintptr_t align) noexcept {
    return reinterpret_cast<char *>((reinterpret_cast<uintptr_t>(p) + align - 1) & ~(align - 1));
}

/* Bounded: float-lib RAM sits right above. */
extern "C" void *_sbrk(ptrdiff_t incr) noexcept {
    char *prev = heap_ptr;
    if (incr > heap_end - heap_ptr) [[unlikely]] {
        sys_println("[zisk] out of memory");
        zisk_abort();
    }
    heap_ptr += incr;
#ifdef Z6M_ZISK_HEAP_STATS
    if (heap_ptr > heap_peak)
        heap_peak = heap_ptr;
#endif
    return prev;
}

/* ───────── Halt / exit ───────── */

/* All-ones word decodes to CHalt: unprovable halt. */
extern "C" [[noreturn]] void zisk_abort() {
    asm volatile(".4byte 0xffffffff" : : : "memory");
    __builtin_unreachable();
}

/* Exit code is ignored; BIOS publishes OUTPUT. */
[[noreturn]] static void zisk_exit() {
    register uint64_t a0 asm("a0") = 0;
    register uint64_t a7 asm("a7") = 93;
    /* Halt word guards against ecall returning. */
    asm volatile("ecall\n\t.4byte 0xffffffff" : : "r"(a0), "r"(a7) : "memory");
    __builtin_unreachable();
}

extern "C" [[noreturn]] void syscall_halt(uint8_t exit_code) {
    if (exit_code == 0)
        zisk_exit();
    zisk_abort();
}

/* Overrides libnosys _exit, which spins forever. */
extern "C" [[noreturn]] void _exit(int code) {
    syscall_halt(code == 0 ? 0 : 1);
}

/* ───────── Bare-metal runtime stubs ───────── */

/* Required by crtbegin / atexit infrastructure */
extern "C" { void *__dso_handle = nullptr; }

/* Weak: prebuilt libstdc++ may reference these. */
extern "C" __attribute__((weak)) void _Unwind_Resume(void *) { zisk_abort(); }
extern "C" __attribute__((weak)) int __gxx_personality_v0(
    int, int, uint64_t, void *, void *) { zisk_abort(); }
extern "C" __attribute__((weak)) int __cxa_atexit(void (*)(void *), void *, void *) { return 0; }
extern "C" __attribute__((weak)) void __cxa_pure_virtual() { zisk_abort(); }

/* ───────── Input / public output ───────── */

/* Input region is read-only; envelope is mutated. */
extern "C" ZiskInput zisk_read_input() noexcept {
    constexpr uintptr_t kLenAddr = zisk::kInputAddr + 8;
    zisk::fcall_input_ready(kLenAddr + 7);
    const uint64_t len = *reinterpret_cast<const volatile uint64_t *>(kLenAddr);
    if (len == 0)
        return {nullptr, 0};
    zisk::fcall_input_ready(kLenAddr + 8 + len - 1);

    heap_ptr = align_up(heap_ptr, 64);
    auto *dst = static_cast<uint8_t *>(_sbrk(static_cast<ptrdiff_t>((len + 63) & ~uint64_t{63})));
    std::memcpy(dst, reinterpret_cast<const void *>(kLenAddr + 8), len);
    return {dst, len};
}

extern "C" void zisk_commit_public(const uint8_t *bytes, size_t len) noexcept {
    auto *out = reinterpret_cast<volatile uint32_t *>(zisk::kOutputAddr);
    for (size_t i = 0; i < len / 4; ++i) {
        uint32_t w;
        std::memcpy(&w, bytes + 4 * i, 4);
        out[i] = w;
    }
}

/* ───────── Global constructors (linker-provided arrays) ───────── */

/* zisk.ld has no .preinit_array. */
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

extern "C" int main();

extern "C" [[noreturn]] void __start() {
    heap_ptr = align_up(&_heap_bottom, 64);
    heap_end = &_heap_top;
#ifdef Z6M_ZISK_HEAP_STATS
    heap_peak = heap_ptr;
#endif

    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();

    /* Failure is signalled via public values. */
    main();

#ifdef Z6M_ZISK_HEAP_STATS
    sys_println(std::format("[zisk] heap high-water: {} bytes", heap_peak - &_heap_bottom));
#endif
    syscall_halt(0);
}
