// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint64_t, uintptr_t
#include <cstring> // strlen
#include <string_view>

namespace zisk {

// ZisK v1.3.1 memory map (core/src/mem.rs).
inline constexpr uintptr_t kInputAddr = 0x4000'0000;
inline constexpr uintptr_t kUartAddr = 0xA040'0200;
inline constexpr uintptr_t kOutputAddr = 0xA041'0000;
inline constexpr size_t kPublicSlots = 64;

[[gnu::always_inline]] inline void uart_write(const char* s, size_t n) noexcept
{
    auto* u = reinterpret_cast<volatile uint8_t*>(kUartAddr);
    for (size_t i = 0; i < n; ++i)
        *u = static_cast<uint8_t>(s[i]);
}

// FCALL_INPUT_READY (23); required before streamed input reads.
[[gnu::always_inline]] inline void fcall_input_ready(uint64_t last_byte_addr) noexcept
{
    asm volatile("csrs 0x8F0, %0\n\tcsrwi 0x8C0, 23" : : "r"(last_byte_addr) : "memory");
}

}  // namespace zisk

struct ZiskInput
{
    uint8_t* ptr;
    size_t len;
};

/* Defined in zisk_runtime.cpp */
extern "C"
{
    [[noreturn]] void syscall_halt(uint8_t exit_code);
    [[noreturn]] void zisk_abort();
    ZiskInput zisk_read_input() noexcept;
    void zisk_commit_public(const uint8_t* bytes, size_t len) noexcept;
}

inline void sys_print(std::string_view s) noexcept
{
    zisk::uart_write(s.data(), s.size());
}
inline void sys_print(const char* s) noexcept
{
    zisk::uart_write(s, std::strlen(s));
}
inline void sys_println(std::string_view s) noexcept
{
    sys_print(s);
    zisk::uart_write("\n", 1);
}
inline void sys_println(const char* s) noexcept
{
    sys_print(s);
    zisk::uart_write("\n", 1);
}
