// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Tests for the guests' memcpy, memmove, memset and memcmp (mem_builtins.cpp), compiled into the
// native test binary at both word sizes, 8 bytes as on SP1 and 4 as on Airbender, and compared
// against libc. Beyond the right bytes they must survive the overlapping copies memmove() forwards
// to memcpy(), and never touch a word that holds no byte of the ranges, which is what keeps the
// masked ends safe; guard pages on either side of a page check that. The build adds the alignment
// sanitizer, which stands in for the guests' trap on a misaligned word access. Airbender's CSR
// MEMCOPY blocks are tested apart, in zilk_core/dev/cli/mem_builtins_test.cpp.

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <utility>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define Z6M_HAVE_GUARD_PAGES 1
#endif

#define ZILK_MEM_NAME(name) z6m_mem64_##name
#define ZILK_MEM_WORD uint64_t
namespace w64
{
#include "mem_builtins.cpp"
}
#undef ZILK_MEM_NAME
#undef ZILK_MEM_WORD

#define ZILK_MEM_NAME(name) z6m_mem32_##name
#define ZILK_MEM_WORD uint32_t
namespace w32
{
#include "mem_builtins.cpp"
}
#undef ZILK_MEM_NAME
#undef ZILK_MEM_WORD

namespace
{
/// One build of the functions.
struct Mem
{
    const char* name;
    size_t word;
    void* (*memcpy)(void*, const void*, size_t) noexcept;
    void* (*memmove)(void*, const void*, size_t) noexcept;
    void* (*memset)(void*, int, size_t) noexcept;
    int (*memcmp)(const void*, const void*, size_t) noexcept;
};

const Mem MEMS[] = {
    {"8-byte words", 8, w64::z6m_mem64_memcpy, w64::z6m_mem64_memmove, w64::z6m_mem64_memset,
        w64::z6m_mem64_memcmp},
    {"4-byte words", 4, w32::z6m_mem32_memcpy, w32::z6m_mem32_memmove, w32::z6m_mem32_memset,
        w32::z6m_mem32_memcmp},
};

constexpr size_t PAD = 64;  // Padding whose content must survive the call.

/// Returns a pointer at least @p base whose address is @p want modulo 8 (the larger word size).
template <typename T>
T* at_phase(T* base, size_t want)
{
    const auto have = reinterpret_cast<uintptr_t>(base) % 8;
    return base + (want - have) % 8;
}

int sign(int v)
{
    return (v > 0) - (v < 0);
}

#ifdef Z6M_HAVE_GUARD_PAGES
/// A page between two guard pages: anything before or beyond it faults.
struct GuardedPage
{
    size_t size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    uint8_t* base = static_cast<uint8_t*>(
        mmap(nullptr, 3 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    uint8_t* data = base + size;

    GuardedPage()
    {
        REQUIRE(base != MAP_FAILED);
        REQUIRE(mprotect(base, size, PROT_NONE) == 0);
        REQUIRE(mprotect(base + 2 * size, size, PROT_NONE) == 0);
        std::memset(data, 0xAB, size);
    }
    ~GuardedPage() { munmap(base, 3 * size); }
};
#endif
}  // namespace

TEST_CASE("guest mem builtins: memcpy of every size and alignment matches libc", "[mem_builtins]")
{
    // Past 32 words the aligned copy loops 16 words at a time; 640 bytes run that loop several
    // times, ending in every remainder.
    std::mt19937_64 rng{12345};
    for (const auto& m : MEMS)
    {
        INFO(m.name);
        for (size_t n = 0; n <= 640; ++n)
        {
            for (size_t src_phase = 0; src_phase < 8; ++src_phase)
            {
                for (size_t dst_phase = 0; dst_phase < 8; ++dst_phase)
                {
                    const size_t span = PAD + 8 + n + PAD + 8;
                    std::vector<uint8_t> src(span), dst(span), ref(span);
                    for (size_t i = 0; i < span; ++i)
                    {
                        src[i] = static_cast<uint8_t>(rng());
                        dst[i] = ref[i] = static_cast<uint8_t>(rng());
                    }

                    const auto* s = at_phase(src.data() + PAD, src_phase);
                    auto* d = at_phase(dst.data() + PAD, dst_phase);
                    auto* r = ref.data() + (d - dst.data());

                    REQUIRE(m.memcpy(d, s, n) == d);
                    std::memcpy(r, s, n);

                    // The copied bytes, and nothing else in the destination buffer, must match.
                    if (std::memcmp(dst.data(), ref.data(), span) != 0)
                        FAIL("n=" << n << " src+" << src_phase << " dst+" << dst_phase);
                }
            }
        }
    }
}

TEST_CASE("guest mem builtins: memmove in either direction matches libc", "[mem_builtins]")
{
    // dest below src (and up to dest == src) goes to memcpy(), which must read each source word
    // before the store that can clobber it; dest above src goes backward.
    std::mt19937_64 rng{6789};
    for (const auto& m : MEMS)
    {
        INFO(m.name);
        for (size_t n = 0; n <= 400; ++n)
        {
            for (int delta = -40; delta <= 40; ++delta)
            {
                for (size_t phase = 0; phase < 8; ++phase)
                {
                    const size_t span = PAD + 8 + 40 + n + 40 + PAD + 8;
                    std::vector<uint8_t> buf(span), ref(span);
                    for (size_t i = 0; i < span; ++i)
                        buf[i] = ref[i] = static_cast<uint8_t>(rng());

                    auto* s = at_phase(buf.data() + PAD + 40, phase);
                    auto* d = s + delta;
                    const auto off_s = s - buf.data(), off_d = d - buf.data();

                    REQUIRE(m.memmove(d, s, n) == d);
                    std::memmove(ref.data() + off_d, ref.data() + off_s, n);
                    if (std::memcmp(buf.data(), ref.data(), span) != 0)
                        FAIL("n=" << n << " delta=" << delta << " src+" << phase);

                    // memcpy() itself, where a forward copy is right.
                    if (delta <= 0)
                    {
                        REQUIRE(m.memcpy(d, s, n) == d);
                        std::memmove(ref.data() + off_d, ref.data() + off_s, n);
                        if (std::memcmp(buf.data(), ref.data(), span) != 0)
                            FAIL("memcpy n=" << n << " delta=" << delta << " src+" << phase);
                    }
                }
            }
        }
        // Large moves, the backward ones word by word.
        std::vector<uint8_t> buf(70000), ref(70000);
        for (size_t n : {size_t{4096}, size_t{5000}, size_t{65536}})
        {
            for (int delta : {-37, -8, -4, 1, 4, 8, 13, 64})
            {
                for (auto& x : buf)
                    x = static_cast<uint8_t>(rng());
                ref = buf;
                auto* s = buf.data() + 2000;
                auto* r = ref.data() + 2000;
                REQUIRE(m.memmove(s + delta, s, n) == s + delta);
                std::memmove(r + delta, r, n);
                if (buf != ref)
                    FAIL("large n=" << n << " delta=" << delta);
            }
        }
    }
}

TEST_CASE("guest mem builtins: memset of every size and alignment matches libc", "[mem_builtins]")
{
    // Past 64 words the fill loops 16 words at a time; 640 bytes run that loop several times,
    // ending in every remainder.
    std::mt19937_64 rng{1357};
    for (const auto& m : MEMS)
    {
        INFO(m.name);
        for (size_t n = 0; n <= 640; ++n)
        {
            for (size_t phase = 0; phase < 8; ++phase)
            {
                for (const int c : {0, 0xA5, 0x80, 0x1FF, -1})
                {
                    const size_t span = PAD + 8 + n + PAD;
                    std::vector<uint8_t> buf(span), ref(span);
                    for (size_t i = 0; i < span; ++i)
                        buf[i] = ref[i] = static_cast<uint8_t>(rng());

                    auto* d = at_phase(buf.data() + PAD, phase);
                    auto* r = ref.data() + (d - buf.data());

                    REQUIRE(m.memset(d, c, n) == d);
                    std::memset(r, c, n);

                    // The filled bytes, and nothing else in the buffer, must match.
                    if (std::memcmp(buf.data(), ref.data(), span) != 0)
                        FAIL("n=" << n << " phase=" << phase << " c=" << c);
                }
            }
        }
    }
}

TEST_CASE("guest mem builtins: memcmp of every size, alignment and difference matches libc",
    "[mem_builtins]")
{
    std::mt19937_64 rng{2468};
    std::vector<uint8_t> a(320 + 8), b(a.size());
    for (auto& x : a)
        x = static_cast<uint8_t>(rng());
    for (const auto& m : MEMS)
    {
        INFO(m.name);
        for (size_t n = 0; n <= 320; ++n)
        {
            for (size_t a_phase = 0; a_phase < 8; ++a_phase)
            {
                for (size_t b_phase = 0; b_phase < 8; ++b_phase)
                {
                    const auto* p = at_phase(a.data(), a_phase);
                    auto* q = at_phase(b.data(), b_phase);

                    // Equal, then the first difference at each position (a sample of them past
                    // 72 bytes) and random bytes after it, either operand the greater.
                    for (size_t pos = 0; pos <= n; pos += (n <= 72 || pos + 9 >= n) ? 1 : 7)
                    {
                        std::memcpy(q, p, n);
                        if (pos < n)
                        {
                            q[pos] = static_cast<uint8_t>(p[pos] + 1 + rng() % 255);
                            for (size_t i = pos + 1; i < n; ++i)
                                q[i] = static_cast<uint8_t>(rng());
                        }
                        const auto expected = sign(std::memcmp(p, q, n));
                        if (sign(m.memcmp(p, q, n)) != expected ||
                            sign(m.memcmp(q, p, n)) != -expected)
                            FAIL("n=" << n << " phases " << a_phase << "/" << b_phase
                                      << " pos=" << pos);
                    }
                }
            }
        }
    }
}

#ifdef Z6M_HAVE_GUARD_PAGES
TEST_CASE("guest mem builtins: no access to a word outside the ranges", "[mem_builtins]")
{
    GuardedPage src, dst;
    const auto page = src.size;

    // The last byte flush against the guard page after, then the first byte in the first word of
    // the page, on either side; an access to a word before or past the ones holding the ranges
    // would raise SIGSEGV.
    for (const auto& m : MEMS)
    {
        for (size_t n = 1; n <= 640; ++n)
        {
            for (size_t phase = 0; phase < 8; ++phase)
            {
                m.memcpy(dst.data + 1024 + phase, src.data + page - n, n);
                m.memcpy(dst.data + page - n, src.data + 1024 + phase, n);
                m.memmove(dst.data + page - n, dst.data + page - n - phase, n);
                CHECK(m.memcmp(dst.data + 1024 + phase, src.data + page - n, n) == 0);
                for (size_t first = 0; first < 8; ++first)
                {
                    m.memcpy(dst.data + 1024 + phase, src.data + first, n);
                    m.memcpy(dst.data + first, src.data + 1024 + phase, n);
                    m.memmove(dst.data + first + phase, dst.data + first, n);
                    CHECK(m.memcmp(src.data + first, dst.data + 1024 + phase, n) == 0);
                    m.memset(dst.data + first, 0, n);
                    m.memset(dst.data + page - n - first, 0x5A, n);
                }
                std::memset(dst.data, 0xAB, page);
            }
            // memcmp() resolves a difference by bytes: the last one, against the guard page.
            std::memcpy(dst.data + page - n, src.data + 1024, n);
            dst.data[page - 1] ^= 1;
            CHECK(m.memcmp(dst.data + page - n, src.data + 1024, n) != 0);
            CHECK(m.memcmp(src.data + 1024, dst.data + page - n, n) != 0);
            std::memset(dst.data, 0xAB, page);
        }
    }
}
#endif
