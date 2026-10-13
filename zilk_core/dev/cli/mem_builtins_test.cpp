// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Host tests of the Airbender guest's memcpy, memmove, memset and memcmp
// (prover/guest_airbender/src/mem_builtins.c, built for the host by mem_builtins_host.c).
//
// The guest cannot run here, so two things stand in for it. The oracle is the plain byte-by-byte
// semantics of each function, with canary bytes around every destination: a wrong byte, a store
// outside the range and an overrun all fail. The CSR MEMCOPY is csr_memcopy32() below, which
// fails the test when an operand is not 32-byte aligned or when dst == src: on the guest those
// are prover faults rather than wrong bytes, so a byte comparison alone would not see them.
// Word accesses at the wrong alignment are covered by building this test with
// -fsanitize=alignment (x86 would otherwise run them silently).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include <catch2/catch_test_macros.hpp>

extern "C" {
void* zilk_guest_memcpy(void* dest, const void* src, size_t n);
void* zilk_guest_memmove(void* dest, const void* src, size_t n);
void* zilk_guest_memset(void* dest, int c, size_t n);
int zilk_guest_memcmp(const void* a, const void* b, size_t n);
void csr_memcopy32(void* dst, const void* src);
}

namespace {

struct CsrLog {
    size_t calls{0};
    size_t violations{0};
};
CsrLog g_csr;

std::string g_first_failure;
size_t g_failures{0};

void fail(const std::string& what) {
    if (g_failures++ == 0) g_first_failure = what;
}

}  // namespace

// Reads all 32 bytes before it writes any, like the memmove() fast paths expect of an overlapping
// copy.
extern "C" void csr_memcopy32(void* dst, const void* src) {
    ++g_csr.calls;
    const auto d = reinterpret_cast<uintptr_t>(dst);
    const auto s = reinterpret_cast<uintptr_t>(src);
    if (((d | s) & 31) != 0) {
        ++g_csr.violations;
        fail("csr_memcopy32 operand not 32-byte aligned");
    }
    if (d == s) {
        ++g_csr.violations;
        fail("csr_memcopy32 with dst == src");
    }
    unsigned char tmp[32];
    std::memcpy(tmp, src, 32);
    std::memcpy(dst, tmp, 32);
}

namespace {

struct Rng {
    uint64_t x;
    uint64_t next() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        return x;
    }
    size_t below(size_t n) { return static_cast<size_t>(next() % n); }
};

constexpr size_t kArena = 8192 + 256;
alignas(64) unsigned char g_src[kArena];
alignas(64) unsigned char g_dst[kArena];
alignas(64) unsigned char g_pristine[kArena];
alignas(64) unsigned char g_expect[kArena];

void fill_random(unsigned char* p, size_t n, Rng& rng) {
    for (size_t i = 0; i < n; ++i) p[i] = static_cast<unsigned char>(rng.next() >> 24);
}

void reset_log() {
    g_csr = CsrLog{};
    g_failures = 0;
    g_first_failure.clear();
}

std::string describe(const char* fn, size_t n, size_t doff, size_t soff) {
    return std::string(fn) + " n=" + std::to_string(n) + " dst+" + std::to_string(doff) + " src+" +
           std::to_string(soff);
}

// Bytes guarded on each side of the destination range and compared after the call.
constexpr size_t kGuard = 64;

// CSR MEMCOPY calls memcpy() must make when it takes the large path at word alignment with both
// addresses in the same phase modulo 32: one per whole 32-byte chunk after the lead. n == 96 is
// copied inline by words, as are n <= 67; the other shapes are left unchecked (SIZE_MAX).
size_t expected_csr_calls(size_t n, size_t doff, size_t soff) {
    if ((doff & 3) != 0 || (soff & 3) != 0) return SIZE_MAX;
    if (n == 96) return 0;
    if (n <= 67 || ((doff ^ soff) & 31) != 0) return SIZE_MAX;
    const size_t lead = (32 - (doff & 31)) & 31;
    return (n - lead) / 32;
}

// One memcpy(dst + doff, src + soff, n) against the byte loop. g_dst and g_src are the arenas
// (64-byte aligned, so offsets are alignments); dst offsets start at kGuard.
void check_memcpy(size_t n, size_t doff, size_t soff) {
    const size_t dpos = kGuard + doff;
    const size_t total = dpos + n + kGuard;
    std::memcpy(g_dst, g_pristine, total);
    std::memcpy(g_expect, g_pristine, total);
    for (size_t i = 0; i < n; ++i) g_expect[dpos + i] = g_src[soff + i];

    g_csr.calls = 0;
    void* ret = zilk_guest_memcpy(g_dst + dpos, g_src + soff, n);
    if (ret != g_dst + dpos) fail(describe("memcpy returns dest", n, doff, soff));
    if (std::memcmp(g_dst, g_expect, total) != 0) fail(describe("memcpy bytes", n, doff, soff));
    const size_t want = expected_csr_calls(n, doff, soff);
    if (want != SIZE_MAX && g_csr.calls != want)
        fail(describe("memcpy CSR calls", n, doff, soff) + " got " + std::to_string(g_csr.calls) +
             " want " + std::to_string(want));
    if (g_csr.calls * 32 > n) fail(describe("memcpy CSR over-copy", n, doff, soff));
}

// memmove(arena + d, arena + s, n) against std::memmove on a copy of the arena.
alignas(64) unsigned char g_arena[kArena];
alignas(64) unsigned char g_arena_expect[kArena];

void check_memmove(size_t d, size_t s, size_t n) {
    std::memcpy(g_arena, g_pristine, kArena);
    std::memcpy(g_arena_expect, g_pristine, kArena);
    std::memmove(g_arena_expect + d, g_arena + s, n);
    void* ret = zilk_guest_memmove(g_arena + d, g_arena + s, n);
    if (ret != g_arena + d)
        fail(describe("memmove returns dest", n, d, s));
    if (std::memcmp(g_arena, g_arena_expect, kArena) != 0)
        fail(describe("memmove bytes", n, d, s));
}

void init_arenas(uint64_t seed) {
    Rng rng{seed};
    fill_random(g_src, kArena, rng);
    fill_random(g_pristine, kArena, rng);
}

}  // namespace

TEST_CASE("guest memcpy: every size 0..300 at every dst/src phase 0..31", "[mem_builtins]") {
    init_arenas(0x9e3779b97f4a7c15ULL);
    reset_log();
    for (size_t n = 0; n <= 300; ++n)
        for (size_t doff = 0; doff < 32; ++doff)
            for (size_t soff = 0; soff < 32; ++soff) check_memcpy(n, doff, soff);
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
    CHECK(g_csr.calls > 0);
}

TEST_CASE("guest memcpy: sizes to 2200 cross the 512-byte CSR loop and its remainder", "[mem_builtins]") {
    init_arenas(0x1234567887654321ULL);
    reset_log();
    constexpr std::array<size_t, 12> offs{0, 1, 2, 3, 4, 5, 8, 12, 16, 20, 28, 31};
    for (size_t n = 301; n <= 2200; ++n)
        for (size_t doff : offs)
            for (size_t soff : offs) check_memcpy(n, doff, soff);
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memcpy: boundary sizes and the inline paths", "[mem_builtins]") {
    init_arenas(0xdeadbeefcafef00dULL);
    reset_log();
    // Sizes where memcpy() changes path: <8, 8, 32, 64..68 (the inline word run ends at 67), 96,
    // and the first CSR chunk (lead up to 28 plus 32 is 60, but n > 67 only reaches it at 68).
    constexpr std::array<size_t, 24> sizes{0,  1,  3,  4,  7,  8,  12, 16, 31, 32, 33, 63,
                                           64, 65, 67, 68, 69, 95, 96, 97, 127, 128, 511, 512};
    for (size_t n : sizes)
        for (size_t doff = 0; doff < 64; ++doff)
            for (size_t soff = 0; soff < 64; ++soff) check_memcpy(n, doff, soff);
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memcpy: random sizes, offsets and contents", "[mem_builtins]") {
    init_arenas(0x0123456789abcdefULL);
    reset_log();
    Rng rng{0xfeedfacefeedfaceULL};
    for (int it = 0; it < 400000; ++it) {
        size_t n;
        switch (rng.below(4)) {
            case 0: n = rng.below(80); break;
            case 1: n = rng.below(600); break;
            case 2: n = rng.below(3000); break;
            default: n = 4000 + rng.below(3900); break;
        }
        size_t doff = rng.below(64);
        size_t soff = rng.below(64);
        if (rng.below(3) == 0) soff = doff;                    // same phase: the CSR path
        if (rng.below(4) == 0) { doff &= ~size_t{3}; soff &= ~size_t{3}; }  // word-aligned
        if (doff + n + 2 * kGuard > kArena || soff + n > kArena) continue;
        check_memcpy(n, doff, soff);
    }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memcpy: a copy onto itself never reaches the CSR", "[mem_builtins]") {
    init_arenas(0xabad1deaabad1deaULL);
    reset_log();
    // GCC may emit memcpy(p, p, n) for a self-assignment and memmove() forwards one for MCOPY with
    // equal offsets. The delegation requires x10 != x11, and csr_memcopy32() records a violation.
    for (size_t n = 0; n <= 700; ++n)
        for (size_t off : {size_t{0}, size_t{1}, size_t{2}, size_t{4}, size_t{32}, size_t{36}}) {
            std::memcpy(g_dst, g_pristine, kArena);
            zilk_guest_memcpy(g_dst + kGuard + off, g_dst + kGuard + off, n);
            if (std::memcmp(g_dst, g_pristine, kArena) != 0) fail(describe("memcpy onto itself", n, off, off));
            std::memcpy(g_dst, g_pristine, kArena);
            zilk_guest_memmove(g_dst + kGuard + off, g_dst + kGuard + off, n);
            if (std::memcmp(g_dst, g_pristine, kArena) != 0) fail(describe("memmove onto itself", n, off, off));
        }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
    CHECK(g_csr.calls == 0);
}

TEST_CASE("guest memmove: overlap in both directions at distances 0..80", "[mem_builtins]") {
    init_arenas(0x5555aaaa5555aaaaULL);
    reset_log();
    constexpr size_t kBase = 256;
    // d < s is forwarded to memcpy(), which must copy ascending; d > s goes backward.
    for (size_t n = 0; n <= 200; ++n)
        for (size_t aoff = 0; aoff < 8; ++aoff)
            for (int delta = -80; delta <= 80; ++delta) {
                const size_t s = kBase + aoff;
                const size_t d = static_cast<size_t>(static_cast<int64_t>(s) + delta);
                check_memmove(d, s, n);
            }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memmove: larger overlapping and disjoint moves", "[mem_builtins]") {
    init_arenas(0x7777333377773333ULL);
    reset_log();
    Rng rng{0x1111222233334444ULL};
    for (int it = 0; it < 200000; ++it) {
        size_t n;
        switch (rng.below(3)) {
            case 0: n = rng.below(100); break;
            case 1: n = rng.below(700); break;
            default: n = rng.below(2500); break;
        }
        const size_t s = 64 + rng.below(2048);
        size_t d;
        switch (rng.below(3)) {
            case 0: d = s + rng.below(130); break;                      // forward, overlapping
            case 1: d = s >= 130 ? s - rng.below(130) : s; break;       // backward, overlapping
            default: d = 64 + rng.below(2048); break;                   // anywhere
        }
        if (rng.below(3) == 0) d = (d & ~size_t{31}) | (s & 31);       // same phase modulo 32
        if (d + n > kArena || s + n > kArena) continue;
        check_memmove(d, s, n);
    }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memset: every size and alignment against the byte loop", "[mem_builtins]") {
    init_arenas(0x2468ace02468ace0ULL);
    reset_log();
    for (int c : {0, 0xff, 0x5a, 0x1a5 /* the int is truncated to a byte */})
        for (size_t n = 0; n <= 400; ++n)
            for (size_t off = 0; off < 36; ++off) {
                const size_t dpos = kGuard + off;
                const size_t total = dpos + n + kGuard;
                std::memcpy(g_dst, g_pristine, total);
                std::memcpy(g_expect, g_pristine, total);
                for (size_t i = 0; i < n; ++i) g_expect[dpos + i] = static_cast<unsigned char>(c);
                void* ret = zilk_guest_memset(g_dst + dpos, c, n);
                if (ret != g_dst + dpos || std::memcmp(g_dst, g_expect, total) != 0)
                    fail(describe("memset", n, off, static_cast<size_t>(c)));
            }
    for (size_t n : {size_t{511}, size_t{512}, size_t{513}, size_t{1000}, size_t{4096}, size_t{5000}})
        for (size_t off : {size_t{0}, size_t{1}, size_t{4}, size_t{28}, size_t{32}}) {
            const size_t dpos = kGuard + off;
            const size_t total = dpos + n + kGuard;
            std::memcpy(g_dst, g_pristine, total);
            std::memcpy(g_expect, g_pristine, total);
            std::memset(g_expect + dpos, 0, n);
            zilk_guest_memset(g_dst + dpos, 0, n);
            if (std::memcmp(g_dst, g_expect, total) != 0) fail(describe("memset large", n, off, 0));
        }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
    CHECK(g_csr.violations == 0);
}

TEST_CASE("guest memcmp: sign and first difference match the byte loop", "[mem_builtins]") {
    init_arenas(0x1357924680246813ULL);
    reset_log();
    Rng rng{0x0f0f0f0f12345678ULL};
    for (size_t n = 0; n <= 130; ++n)
        for (size_t aoff = 0; aoff < 5; ++aoff)
            for (size_t boff = 0; boff < 5; ++boff) {
                std::memcpy(g_dst + boff, g_src + aoff, n);
                const size_t flips[] = {n, n ? 0 : n, n ? n - 1 : n, n ? rng.below(n) : n};
                for (size_t at : flips) {
                    unsigned char saved = 0;
                    if (at < n) {
                        saved = g_dst[boff + at];
                        g_dst[boff + at] = static_cast<unsigned char>(saved + 1 + rng.below(255));
                    }
                    const int want = std::memcmp(g_src + aoff, g_dst + boff, n);
                    const int got = zilk_guest_memcmp(g_src + aoff, g_dst + boff, n);
                    if ((want > 0) != (got > 0) || (want < 0) != (got < 0))
                        fail(describe("memcmp", n, boff, aoff));
                    if (at < n) g_dst[boff + at] = saved;
                }
            }
    INFO(g_first_failure);
    CHECK(g_failures == 0);
}
