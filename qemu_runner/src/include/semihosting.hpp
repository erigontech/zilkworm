// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

static inline void sys_print(const char* s)
{
    register long a0 asm("a0") = 0x04;     // SYS_WRITE0
    register const char* a1 asm("a1") = s;
    asm volatile(
        ".option push       \n"
        ".option norvc      \n" // avoid C extension in the magic sequence
        "slli x0, x0, 0x1f  \n"
        "ebreak             \n"
        "srai x0, x0, 0x7   \n"
        ".option pop        \n"
        : "+r"(a0) : "r"(a1) : "memory");
}

static inline void sys_println(std::string_view s)
{
    sys_print(s.data());
    sys_print("\n");
}

namespace sh
{

    constexpr int SYS_READ = 0x06;
    constexpr int SYS_READC = 0x07;
    constexpr int SYS_OPEN = 0x01;
    constexpr int SYS_FLEN = 0x0C;
    // constexpr int SYS_EXIT = 0x18;      // Not used as it always returns code 1 on exit
    constexpr int SYS_EXIT_EXTENDED = 0x20;

    // RISC-V semihosting call: a0=reason, a1=argptr, magic EBREAK sequence.
    inline long call(int reason, void* arg)
    {
        register long a0 asm("a0") = reason;
        register void* a1 asm("a1") = arg;
        asm volatile(
            " .option push      \n"
            " .option norvc     \n"
            " slli x0, x0, 0x1f \n"
            " ebreak            \n"
            " srai x0, x0, 0x07 \n"
            " .option pop       \n"
            : "+r"(a0) : "r"(a1) : "memory");
        return a0;
    }


    constexpr uint32_t ADP_Stopped_ApplicationExit = 0x20026;

    // Terminates QEMU with `code` via SYS_EXIT_EXTENDED.
    [[noreturn]] inline void exit(int code)
    {
        uintptr_t args[2] = {ADP_Stopped_ApplicationExit, static_cast<uintptr_t>(code)};
        call(SYS_EXIT_EXTENDED, args);
        __builtin_unreachable();
    }


    inline int readc()
    {
        return static_cast<int>(call(SYS_READC, nullptr));
    }



    inline bool read_exact(void* buf, std::size_t n)
    {
        char* p = static_cast<char*>(buf);
        for (std::size_t i = 0; i < n; ++i)
        {
            int c = readc();
            if (c < 0)
                return false;
            p[i] = static_cast<char>(c);
        }
        return true;
    }

    // Parse an unsigned decimal uint32 from stdin; skips leading whitespace, stops at the first non-digit.
    inline std::size_t read_u32_from_stdin(std::uint32_t& out)
    {
        int c;
        std::size_t len = 0;
        do
        {
            c = readc();
            ++len;
        } while (c == ' ' || c == '\t' || c == '\r' || c == '\n');
        if (c < '0' || c > '9')
            return 0;

        std::uint32_t v = 0;
        for (;;)
        {
            if (c < '0' || c > '9')
                break;
            std::uint32_t d = static_cast<std::uint32_t>(c - '0');
            if (v > (UINT32_MAX - d) / 10u)
                return 0;
            v = v * 10u + d;
            c = readc();
            ++len;
        }
        out = v;
        return len;
    }

    // Open ":tt" (console). mode 0 = read.
    inline int open_tty_read()
    {
        struct Args
        {
            const char* name;
            std::size_t mode;     // must be pointer-sized for rv64
            std::size_t name_len; // must be pointer-sized for rv64
        } a{ ":tt", 0, 3 };
        long h = call(SYS_OPEN, &a);
        return static_cast<int>(h);
    }

    inline int open_file_read(std::string path)
    {
        struct Args
        {
            const char* name;
            std::size_t mode;     // must be pointer-sized for rv64
            std::size_t name_len; // must be pointer-sized for rv64
        } a{ path.c_str(), 0, static_cast<std::size_t>(path.size())};

        long h = call(SYS_OPEN, &a);
        return static_cast<int>(h);
    }

    // SYS_READ returns the number of bytes NOT read; the handle must be opened first (0/1/2 are stdin/stdout/stderr).
    inline std::size_t read_handle(int handle, void *buf, std::size_t len)
    {
        struct Args
        {
            std::size_t fd; // must be pointer-sized for rv64
            void* buf;
            std::size_t len;
        } a{ static_cast<std::size_t>(handle), buf, len };
        long not_read = call(SYS_READ, &a);
        return len - static_cast<std::size_t>(not_read);
    }

    inline long flen(int handle)
    {
        long h = static_cast<long>(handle);
        return call(SYS_FLEN, &h);
    }

    inline std::size_t read_exact_handle(int handle, void* buf, std::size_t n)
    {
        std::size_t off = 0;
        std::size_t block_size = 4096;
        while (off < n)
        {
            std::size_t len = (n - off) >= block_size ? block_size : (n - off);
            std::size_t got = read_handle(handle, static_cast<char*>(buf) + off, len);

            off += got;
        }
        return off;
    }

} // namespace sh

[[noreturn]] inline void syscall_halt(uint8_t exit_code)
{
    sh::exit(exit_code);
}
