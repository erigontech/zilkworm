#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

static inline void sys_print(const char* s)
{
    register long a0 asm("a0") = 0x04;     // SYS_WRITE0
    register const char* a1 asm("a1") = s; // pointer to 0-terminated string
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

    // Semihosting opcodes we need
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
            " slli x0, x0, 0x1f \n" // marker
            " ebreak            \n"
            " srai x0, x0, 0x07 \n" // marker
            " .option pop       \n"
            : "+r"(a0) : "r"(a1) : "memory");
        return a0; // return value in a0
    }


    // Exit codes for SYS_EXIT / SYS_EXIT_EXTENDED
    constexpr uint32_t ADP_Stopped_ApplicationExit = 0x20026;

    // Terminate the QEMU emulator with an exit code
    // Uses SYS_EXIT_EXTENDED (0x20) which accepts a two-word argument block
    // on 32-bit systems to pass both reason code and exit status.
    // See: https://github.com/ARM-software/abi-aa/blob/main/semihosting/semihosting.rst
    [[noreturn]] inline void exit(int code)
    {
        // SYS_EXIT_EXTENDED argument block:
        // field 1: reason code (ADP_Stopped_ApplicationExit for normal exit)
        // field 2: exit status code
        uintptr_t args[2] = {ADP_Stopped_ApplicationExit, static_cast<uintptr_t>(code)};
        call(SYS_EXIT_EXTENDED, args);
        __builtin_unreachable();
    }


    // Blocking getchar() from host stdin
    inline int readc()
    {
        return static_cast<int>(call(SYS_READC, nullptr));
    }



    inline bool read_exact(void* buf, std::size_t n)
    {
        char* p = static_cast<char*>(buf);
        for (std::size_t i = 0; i < n; ++i)
        {
            int c = readc(); // blocks until a char is available
            if (c < 0)
                return false; // (rare) error
            p[i] = static_cast<char>(c);
        }
        return true;
    }

    // Parse unsigned decimal uint32 from stdin; skips leading whitespace.
    // Stops at first non-digit. Returns true on success.
    inline std::size_t read_u32_from_stdin(std::uint32_t& out)
    {
        int c;
        std::size_t len = 0;
        // skip leading spaces/newlines/tabs
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
                return 0; // overflow
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
        return static_cast<int>(h); // -1 on failure
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

    // =================  SYS_READ ==========================
    // SYS_READ (0x06) = “read N bytes from a file handle”
    // NOTE: Does not work without opening a file handle
    // Args: pointer to a struct { int fd; void* buf; size_t len; }
    // Return: number of bytes NOT read (weird but that’s the spec)
    // So bytes_read = len - return_value
    // Handles: 0 = stdin, 1 = stdout, 2 = stderr; or a handle you opened (e.g., ":tt" for console)
    // Blocking: yes, but may return partial reads
    // EOF detection: yes—when bytes_read == 0 (return value equals len)
    // Use when: you need to read a known amount of data (like your n bytes of JSON), handle pipes, or detect EOF/short reads.
    // =======================================================

    // Read up to len from a semihosting handle; returns bytes actually read.
    inline std::size_t read_handle(int handle, void *buf, std::size_t len)
    {
        struct Args
        {
            std::size_t fd; // must be pointer-sized for rv64
            void* buf;
            std::size_t len;
        } a{ static_cast<std::size_t>(handle), buf, len };
        long not_read = call(SYS_READ, &a); // returns bytes NOT read
        return len - static_cast<std::size_t>(not_read);
    }

    // SYS_FLEN: total length in bytes of the open file handle.
    inline long flen(int handle)
    {
        long h = static_cast<long>(handle);
        return call(SYS_FLEN, &h);
    }

    // Read EXACTLY n bytes from :tt
    inline std::size_t read_exact_handle(int handle, void* buf, std::size_t n)
    {
        std::size_t off = 0;
        std::size_t block_size = 4096;
        while (off < n)
        {
            std::size_t len = (n - off) >= block_size ? block_size : (n - off);
            std::size_t got = read_handle(handle, static_cast<char*>(buf) + off, len);

            // if (got == 0)
            // {
            //     sys_println("read_exact_tty - got 0, probable EOF");
            //     continue;
            //     // break;
            // }
            off += got;
        }
        return off;
    }

} // namespace sh
