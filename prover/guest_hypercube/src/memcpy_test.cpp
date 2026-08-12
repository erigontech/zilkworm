// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Tests for the guest's memcpy, compiled into the native test binary and compared against libc.
// Beyond producing the right bytes it must tolerate the overlapping ranges __wrap_memmove()
// forwards, and never touch a word holding no byte of the range -- what makes the masked ends safe.

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <random>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define Z6M_HAVE_GUARD_PAGES 1
#endif

#define __wrap_memcpy z6m_guest_memcpy
#include "memcpy.cpp"
#undef __wrap_memcpy

namespace
{
constexpr size_t PAD = 64;  // Padding whose content must survive the copy.

/// Returns a pointer at least @p base whose address is @p want modulo the word size.
template <typename T>
T* at_phase(T* base, size_t want)
{
    const auto have = reinterpret_cast<uintptr_t>(base) % WORD_SIZE;
    return base + (want - have) % WORD_SIZE;
}
}  // namespace

TEST_CASE("guest memcpy: every size and alignment matches libc")
{
    std::mt19937_64 rng{12345};
    for (size_t n = 0; n <= 264; ++n)
    {
        for (size_t src_phase = 0; src_phase < WORD_SIZE; ++src_phase)
        {
            for (size_t dst_phase = 0; dst_phase < WORD_SIZE; ++dst_phase)
            {
                const size_t span = PAD + WORD_SIZE + n + PAD + WORD_SIZE;
                std::vector<uint8_t> src(span), dst(span), ref(span);
                for (size_t i = 0; i < span; ++i)
                {
                    src[i] = static_cast<uint8_t>(rng());
                    dst[i] = ref[i] = static_cast<uint8_t>(rng());
                }

                const auto* s = at_phase(src.data() + PAD, src_phase);
                auto* d = at_phase(dst.data() + PAD, dst_phase);
                auto* r = ref.data() + (d - dst.data());

                REQUIRE(z6m_guest_memcpy(d, s, n) == d);
                std::memcpy(r, s, n);

                // The copied bytes, and nothing else in the destination buffer, must match.
                CHECK(std::memcmp(dst.data(), ref.data(), span) == 0);
            }
        }
    }
}

TEST_CASE("guest memcpy: forward-overlapping ranges behave like memmove")
{
    // __wrap_memmove() forwards ranges with dest <= src here, so the word loop must read each
    // source word before the store that can clobber it.
    std::mt19937_64 rng{6789};
    for (size_t n = 0; n <= 200; ++n)
    {
        for (size_t delta = 0; delta <= 24; ++delta)
        {
            for (size_t dst_phase = 0; dst_phase < WORD_SIZE; ++dst_phase)
            {
                const size_t span = PAD + WORD_SIZE + n + delta + PAD + WORD_SIZE;
                std::vector<uint8_t> buf(span), ref(span);
                for (size_t i = 0; i < span; ++i)
                    buf[i] = ref[i] = static_cast<uint8_t>(rng());

                auto* d = at_phase(buf.data() + PAD, dst_phase);
                auto* r = ref.data() + (d - buf.data());

                REQUIRE(z6m_guest_memcpy(d, d + delta, n) == d);
                std::memmove(r, r + delta, n);

                CHECK(std::memcmp(buf.data(), ref.data(), span) == 0);
            }
        }
    }
}

#ifdef Z6M_HAVE_GUARD_PAGES
TEST_CASE("guest memcpy: touches no word outside the copied range")
{
    const auto page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    const auto guarded = [page] {
        auto* p = static_cast<uint8_t*>(
            mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        REQUIRE(p != MAP_FAILED);
        REQUIRE(mprotect(p + page, page, PROT_NONE) == 0);  // Anything beyond faults.
        std::memset(p, 0xAB, page);
        return p;
    };
    auto* src_page = guarded();
    auto* dst_page = guarded();

    // Put the last copied byte flush against the guard page, first on the source side and then on
    // the destination side; an access past the containing word would raise SIGSEGV.
    for (size_t n = 1; n <= 300; ++n)
    {
        for (size_t phase = 0; phase < WORD_SIZE; ++phase)
        {
            z6m_guest_memcpy(dst_page + 128 + phase, src_page + page - n, n);
            z6m_guest_memcpy(dst_page + page - n, src_page + 128 + phase, n);
        }
    }
    CHECK(munmap(src_page, 2 * page) == 0);
    CHECK(munmap(dst_page, 2 * page) == 0);
}
#endif
