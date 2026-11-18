// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// memcpy, memmove, memset and memcmp for SP1 (rv64im) and Airbender (rv32im): aligned word accesses only, never touching a word outside the ranges; overlapping copies run lowest-first or read the source before storing.
//
// Compiled with -fno-builtin (else GCC turns the loops back into the calls they implement); SP1 links these as -Wl,--wrap targets, Airbender defines them directly; host tests set ZILK_MEM_NAME, ZILK_MEM_WORD and ZILK_MEM_BLOCK32.

#include <cstddef>
#include <cstdint>
#include <utility>

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "the word packing assumes little-endian");

#if defined(SP1) && !defined(ZILK_MEM_NAME)
#define ZILK_MEM_NAME(name) __wrap_##name
#endif
#if defined(AIRBENDER) && !defined(ZILK_MEM_BLOCK32)
#define ZILK_MEM_BLOCK32 1
#endif

#ifndef ZILK_MEM_NAME
#define ZILK_MEM_NAME(name) name
#endif
#ifndef ZILK_MEM_WORD
#define ZILK_MEM_WORD uintptr_t
#endif
#ifndef ZILK_MEM_BLOCK32
#define ZILK_MEM_BLOCK32 0
#endif

#if ZILK_MEM_BLOCK32 && !(defined(__riscv) && __riscv_xlen == 32)
// The host tests supply the CSR as a function that checks the delegation's operand rules.
extern "C" void csr_memcopy32(void* dst, const void* src);
#endif

namespace
{
/// One machine word; may_alias because words are read out of byte buffers.
using word_alias [[gnu::may_alias]] = ZILK_MEM_WORD;
using u32_alias [[gnu::may_alias]] = uint32_t;

constexpr auto WORD_SIZE = sizeof(word_alias);
constexpr auto WORD_BITS = WORD_SIZE * 8;
constexpr auto N32 = 32 / WORD_SIZE;
using N32_SEQ = std::make_index_sequence<N32>;

// The most words memcpy() copies by one jump into a run before looping: 256 bytes on SP1, 128 on Airbender.
constexpr size_t COPY_RUN_WORDS = 32;

// Fixed-count sequences are index-sequence folds: loops, even fully unrolled, cost SP1's memcpy() an instruction on some paths.

template <size_t... I>
[[gnu::always_inline]] inline void copy_n(
    word_alias* d, const word_alias* s, std::index_sequence<I...>) noexcept
{
    ((d[I] = s[I]), ...);
}

#if ZILK_MEM_BLOCK32
/// Copies 32 bytes, both ends 32-byte aligned and distinct, by Airbender's CSR MEMCOPY delegation.
[[gnu::always_inline]] inline void block32(void* dst, const void* src) noexcept
{
#if defined(__riscv) && __riscv_xlen == 32
    register uintptr_t a0 __asm__("x10") = reinterpret_cast<uintptr_t>(dst);
    register uintptr_t a1 __asm__("x11") = reinterpret_cast<uintptr_t>(src);
    register uint32_t a2 __asm__("x12") = 0x80;
    __asm__ __volatile__("csrrw x0, 0x7CA, x0" : "+r"(a2) : "r"(a0), "r"(a1) : "memory");
#else
    csr_memcopy32(dst, src);
#endif
}

/// The zero block the large zero fills copy from; link.x places it by mangled name next to the global pointer.
alignas(32) const word_alias zeros32[N32] = {};

/// Copies 0..MAX 32-byte blocks lowest first by a jump into a run of block32(); STEP 0 copies one block repeatedly.
template <size_t MAX, size_t STEP>
[[gnu::always_inline]] inline void blocks_upto(
    word_alias* d, const word_alias* s, size_t blocks) noexcept
{
    auto* de = reinterpret_cast<word_alias*>(
        reinterpret_cast<uintptr_t>(d) + blocks * 32 - MAX * 32);
    auto* se = s;
    if constexpr (STEP != 0)
        se = reinterpret_cast<const word_alias*>(
            reinterpret_cast<uintptr_t>(s) + blocks * 32 - MAX * 32);
    // clang-format off: a case a line would bury the runs.
    switch (blocks)
    {
#define CASE(k)                                                   \
    case k:                                                       \
        if constexpr (k <= MAX)                                   \
            block32(de + (MAX - k) * N32, se + (MAX - k) * STEP); \
        [[fallthrough]];
        CASE(16) CASE(15) CASE(14) CASE(13) CASE(12) CASE(11) CASE(10) CASE(9)
        CASE(8) CASE(7) CASE(6) CASE(5) CASE(4) CASE(3) CASE(2) CASE(1)
#undef CASE
    case 0:
        break;
    default:
        __builtin_unreachable();
    }
    // clang-format on
}

void* memcpy_rest(void* dest, const void* src, size_t n) noexcept;
#endif

/// Stores the low @p len (1..WORD_SIZE-1) bytes of @p v at the word-aligned @p d, leaving the rest of the word unchanged.
[[gnu::always_inline]] inline void scatter_aligned(uint8_t* d, word_alias v, size_t len) noexcept
{
    [[assume(len >= 1 && len < WORD_SIZE)]];  // Keeps the len * 8 shift inside the word.
    auto* w = reinterpret_cast<word_alias*>(d);

    const auto mask = (word_alias{1} << (len * 8)) - 1;
    w[0] = (w[0] & ~mask) | (v & mask);
}

/// Copies 0..MAX bytes lowest first by a jump into a run of byte copies.
template <size_t MAX>
[[gnu::always_inline]] inline void copy_bytes(uint8_t* d, const uint8_t* s, size_t n) noexcept
{
    d += n;
    s += n;
    // clang-format off: a case a line would bury the runs.
    switch (n)
    {
#define CASE(k)                 \
    case k:                     \
        if constexpr (k <= MAX) \
            d[-k] = s[-k];      \
        [[fallthrough]];
        CASE(15) CASE(14) CASE(13) CASE(12) CASE(11) CASE(10) CASE(9) CASE(8)
        CASE(7) CASE(6) CASE(5) CASE(4) CASE(3) CASE(2) CASE(1)
#undef CASE
    case 0:
        break;
    default:
        __builtin_unreachable();
    }
    // clang-format on
}

/// Copies @p words (<= MAX) words lowest first by a jump into a run.
template <size_t MAX>
[[gnu::always_inline]] inline void copy_words_upto(
    word_alias* d, const word_alias* s, size_t words) noexcept
{
    // For words < MAX the bases lie before d and s, and the run only reaches into [d, d + words).
    auto* de = reinterpret_cast<word_alias*>(
        reinterpret_cast<uintptr_t>(d) + words * WORD_SIZE - MAX * WORD_SIZE);
    const auto* se = reinterpret_cast<const word_alias*>(
        reinterpret_cast<uintptr_t>(s) + words * WORD_SIZE - MAX * WORD_SIZE);
    // clang-format off: a case a line would bury the runs.
    switch (words)
    {
#define CASE(k)                        \
    case k:                            \
        if constexpr (k <= MAX)        \
            de[MAX - k] = se[MAX - k]; \
        [[fallthrough]];
        CASE(32) CASE(31) CASE(30) CASE(29) CASE(28) CASE(27) CASE(26) CASE(25)
        CASE(24) CASE(23) CASE(22) CASE(21) CASE(20) CASE(19) CASE(18) CASE(17)
        CASE(16) CASE(15) CASE(14) CASE(13) CASE(12) CASE(11) CASE(10) CASE(9)
        CASE(8) CASE(7) CASE(6) CASE(5) CASE(4) CASE(3) CASE(2) CASE(1)
#undef CASE
    case 0:
        break;
    default:
        __builtin_unreachable();
    }
    // clang-format on
}

/// Copies any count of words (16 a loop iteration, the rest by a jump) and advances @p d and @p s.
[[gnu::always_inline]] inline void copy_words(
    word_alias*& d, const word_alias*& s, size_t words) noexcept
{
    // The empty asm hides where d and s come from; else GCC re-addresses from a copy of src, one instruction per call.
    asm("" : "+r"(d), "+r"(s));
    const auto* const end = d + (words & ~size_t{15});
#pragma GCC unroll 1
    while (d != end)
    {
#pragma GCC unroll 16
        for (size_t i = 0; i < 16; ++i)
            d[i] = s[i];
        d += 16;
        s += 16;
    }
    const auto rest = words % 16;
    copy_words_upto<15>(d, s, rest);
    d += rest;
    s += rest;
}

/// Stores re-laned words (high bytes of v[I], low bytes of v[I + 1], @p lo bits up) into dw[I + 1].
template <size_t... I>
[[gnu::always_inline]] inline void store_relaned(
    word_alias* dw, const word_alias* v, size_t lo, size_t hi, std::index_sequence<I...>) noexcept
{
    ((dw[I + 1] = (v[I] >> hi) | (v[I + 1] << lo)), ...);
}

/// Copies 32 bytes between ends not both word-aligned: re-lane the source words in registers, reading all before the first store (overlap-safe).
template <size_t... I>
[[gnu::always_inline]] inline void copy32_any(
    uint8_t* d, const uint8_t* s, std::index_sequence<I...>) noexcept
{
    const auto soff = reinterpret_cast<uintptr_t>(s) % WORD_SIZE;
    const auto* sw = reinterpret_cast<const word_alias*>(s - soff);
    word_alias v[N32];
    if (soff == 0)
        ((v[I] = sw[I]), ...);
    else  // One word more: the last holds the soff final source bytes.
    {
        const auto lo = soff * 8;
        const auto hi = WORD_BITS - lo;
        word_alias w[N32 + 1];
        ((w[I] = sw[I]), ...);
        w[N32] = sw[N32];
        ((v[I] = (w[I] >> lo) | (w[I + 1] << hi)), ...);
    }

    const auto doff = reinterpret_cast<uintptr_t>(d) % WORD_SIZE;
    auto* dw = reinterpret_cast<word_alias*>(d - doff);
    if (doff == 0)
    {
        ((dw[I] = v[I]), ...);
        return;
    }
    const auto lo = doff * 8;
    const auto hi = WORD_BITS - lo;
    const auto mask = ~word_alias{0} << lo;  // The bytes of dw[0] the copy covers.
    dw[0] = (dw[0] & ~mask) | (v[0] << lo);
    store_relaned(dw, v, lo, hi, std::make_index_sequence<N32 - 1>{});
    dw[N32] = (dw[N32] & mask) | (v[N32 - 1] >> hi);
}

/// Copies @p n >= 16 bytes between ends not both word-aligned: head bytes, whole words (re-laned if out of phase), a masked last word.
[[gnu::always_inline]] inline void* copy_unaligned(void* dest, const void* src, size_t n) noexcept
{
    auto* d = static_cast<uint8_t*>(dest);
    const auto* s = static_cast<const uint8_t*>(src);

    // 4-byte aligned ends on rv64, mostly 4 bytes past a word boundary on both sides: five aligned 4-byte copies.
    if (WORD_SIZE > 4 && n == 20 &&
        (reinterpret_cast<uintptr_t>(d) | reinterpret_cast<uintptr_t>(s)) % 4 == 0)
    {
        auto* dh = reinterpret_cast<u32_alias*>(d);
        const auto* sh = reinterpret_cast<const u32_alias*>(s);
        dh[0] = sh[0];
        dh[1] = sh[1];
        dh[2] = sh[2];
        dh[3] = sh[3];
        dh[4] = sh[4];
        return dest;
    }

    if (const auto phase = reinterpret_cast<uintptr_t>(d) % WORD_SIZE; phase != 0)
    {
        const auto head = WORD_SIZE - phase;
        copy_bytes<WORD_SIZE - 1>(d, s, head);
        d += head;
        s += head;
        n -= head;
    }

    // Middle: whole destination words; n >= 9 is left, so at least one.
    const auto words = n / WORD_SIZE;
    const auto rest = n % WORD_SIZE;
    auto* dw = reinterpret_cast<word_alias*>(d);
    if (const auto phase = reinterpret_cast<uintptr_t>(s) % WORD_SIZE; phase == 0)
    {
        const auto* sw = reinterpret_cast<const word_alias*>(s);
        copy_words(dw, sw, words);
        if (rest != 0)
            scatter_aligned(reinterpret_cast<uint8_t*>(dw), sw[0], rest);
        return dest;
    }
    else
    {
        // Source out of phase: re-lane aligned word pairs, never reading past the word holding the last copied byte; unrolled four-fold.
        const auto lo = phase * 8;
        const auto hi = WORD_BITS - lo;
        const auto* sw = reinterpret_cast<const word_alias*>(s - phase);
        auto w0 = sw[0];
        const auto* const end = dw + words;
#pragma GCC unroll 4
        while (dw != end)
        {
            const auto w1 = sw[1];
            *dw++ = (w0 >> lo) | (w1 << hi);
            ++sw;
            w0 = w1;
        }

        // The loop leaves the word holding the next source byte in w0.
        if (rest != 0)
        {
            auto v = w0 >> lo;
            if (phase + rest > WORD_SIZE)  // The tail continues into the next source word.
                v |= sw[1] << hi;
            scatter_aligned(reinterpret_cast<uint8_t*>(dw), v, rest);
        }
        return dest;
    }
}
}  // namespace

// Not __restrict: memmove() forwards overlapping ranges here, and __restrict lets GCC turn word loops into a memcpy call, recursive under -Wl,--wrap on SP1.
extern "C" void* ZILK_MEM_NAME(memcpy)(void* dest, const void* src, size_t n) noexcept
{
    auto* d = static_cast<uint8_t*>(dest);
    const auto* s = static_cast<const uint8_t*>(src);
    const auto both = reinterpret_cast<uintptr_t>(d) | reinterpret_cast<uintptr_t>(s);

    if (both % WORD_SIZE == 0)
    {
        auto* dw = reinterpret_cast<word_alias*>(d);
        const auto* sw = reinterpret_cast<const word_alias*>(s);
        if (n == 32) [[likely]]
        {
            copy_n(dw, sw, N32_SEQ{});
            return dest;
        }
        const auto words = n / WORD_SIZE;
        if (words <= COPY_RUN_WORDS)
        {
            copy_words_upto<COPY_RUN_WORDS>(dw, sw, words);
            dw += words;
            sw += words;
        }
        else
#if ZILK_MEM_BLOCK32
            return memcpy_rest(dest, src, n);
#else
            copy_words(dw, sw, words);
#endif
        if (const auto rest = n % WORD_SIZE; rest != 0)
            scatter_aligned(reinterpret_cast<uint8_t*>(dw), sw[0], rest);
        return dest;
    }

    if (n == 32)
    {
        copy32_any(d, s, N32_SEQ{});
        return dest;
    }

    // Short and unaligned: bytes; the word path costs more before its first whole word.
    if (n < 16)
    {
        copy_bytes<15>(d, s, n);
        return dest;
    }

#if ZILK_MEM_BLOCK32
    return memcpy_rest(dest, src, n);
#else
    return copy_unaligned(dest, src, n);
#endif
}

// Copies forward through memcpy() when that is correct (dest below src, or ranges apart); otherwise backward, in words where possible.
extern "C" void* ZILK_MEM_NAME(memmove)(void* dest, const void* src, size_t n) noexcept
{
    auto* d = static_cast<uint8_t*>(dest);
    const auto* s = static_cast<const uint8_t*>(src);
    if (d <= s || d >= s + n) [[likely]]
        return ZILK_MEM_NAME(memcpy)(dest, src, n);

    // From the end, so each source byte is read before the store that overwrites it.
    d += n;
    s += n;
    while (n != 0 && reinterpret_cast<uintptr_t>(d) % WORD_SIZE != 0)
    {
        *--d = *--s;
        --n;
    }
    if (const auto words = n / WORD_SIZE; words != 0)
    {
        auto* dw = reinterpret_cast<word_alias*>(d);
        if (const auto phase = reinterpret_cast<uintptr_t>(s) % WORD_SIZE; phase == 0)
        {
            const auto* sw = reinterpret_cast<const word_alias*>(s);
            const auto* const end4 = dw - (words & ~size_t{3});
#pragma GCC unroll 4
            while (dw != end4)
            {
                const auto w3 = sw[-1], w2 = sw[-2], w1 = sw[-3], w0 = sw[-4];
                dw[-1] = w3;
                dw[-2] = w2;
                dw[-3] = w1;
                dw[-4] = w0;
                dw -= 4;
                sw -= 4;
            }
#pragma GCC unroll 1
            for (auto i = words % 4; i != 0; --i)
                *--dw = *--sw;
        }
        else
        {
            const auto lo = phase * 8;
            const auto hi = WORD_BITS - lo;
            const auto* sw = reinterpret_cast<const word_alias*>(s - phase);
            auto w1 = *sw;
#pragma GCC unroll 4
            for (size_t i = 0; i < words; ++i)
            {
                const auto w0 = *--sw;
                *--dw = (w0 >> lo) | (w1 << hi);
                w1 = w0;
            }
        }
        d -= words * WORD_SIZE;
        s -= words * WORD_SIZE;
        n %= WORD_SIZE;
    }
    while (n-- != 0)
        *--d = *--s;
    return dest;
}

namespace
{
/// Stores @p v to words [0, @p words) (<= MAX) highest first by a jump into a run: Airbender's JIT fuses ascending store runs assuming no jump lands inside, unless RISCV_MERGE_WINDOW=0.
template <size_t MAX>
[[gnu::always_inline]] inline void fill_words_upto(
    word_alias* d, word_alias v, size_t words) noexcept
{
    // clang-format off: a case a line would bury the runs.
    switch (words)
    {
#define CASE(k)                 \
    case k:                     \
        if constexpr (k <= MAX) \
            d[k - 1] = v;       \
        [[fallthrough]];
        CASE(64) CASE(63) CASE(62) CASE(61) CASE(60) CASE(59) CASE(58) CASE(57)
        CASE(56) CASE(55) CASE(54) CASE(53) CASE(52) CASE(51) CASE(50) CASE(49)
        CASE(48) CASE(47) CASE(46) CASE(45) CASE(44) CASE(43) CASE(42) CASE(41)
        CASE(40) CASE(39) CASE(38) CASE(37) CASE(36) CASE(35) CASE(34) CASE(33)
        CASE(32) CASE(31) CASE(30) CASE(29) CASE(28) CASE(27) CASE(26) CASE(25)
        CASE(24) CASE(23) CASE(22) CASE(21) CASE(20) CASE(19) CASE(18) CASE(17)
        CASE(16) CASE(15) CASE(14) CASE(13) CASE(12) CASE(11) CASE(10) CASE(9)
        CASE(8) CASE(7) CASE(6) CASE(5) CASE(4) CASE(3) CASE(2) CASE(1)
#undef CASE
    case 0:
        break;
    default:
        __builtin_unreachable();
    }
    // clang-format on
}

constexpr size_t FILL_RUN_WORDS = 256 / WORD_SIZE;

/// Stores @p v to any count of words: a jump into a run up to 256 bytes, else 16 per loop iteration; zeros by blocks where there are blocks.
[[gnu::always_inline]] inline void fill_words(word_alias* d, word_alias v, size_t words) noexcept
{
    if (words <= FILL_RUN_WORDS)
    {
        fill_words_upto<FILL_RUN_WORDS>(d, v, words);
        return;
    }
#if ZILK_MEM_BLOCK32
    if (v == 0)
    {
        const auto lead = ((0 - reinterpret_cast<uintptr_t>(d)) % 32) / WORD_SIZE;
        fill_words_upto<N32 - 1>(d, 0, lead);
        d += lead;
        words -= lead;
        // In a register: GCC would form the address again before every block.
        const auto* z = zeros32;
        asm("" : "+r"(z));
        const auto blocks = words / N32;  // Taken % 16 below, the jump needs no bound check.
#pragma GCC unroll 1
        for (auto i = blocks / 16; i != 0; --i)
        {
            blocks_upto<16, 0>(d, z, 16);
            d += 16 * N32;
        }
        blocks_upto<15, 0>(d, z, blocks % 16);
        d += blocks % 16 * N32;
        fill_words_upto<N32 - 1>(d, 0, words % N32);
        return;
    }
#endif
    const auto* const end = d + (words & ~size_t{15});
#pragma GCC unroll 1
    while (d != end)
    {
#pragma GCC unroll 16
        for (size_t i = 0; i < 16; ++i)
            d[i] = v;
        d += 16;
    }
    fill_words_upto<15>(d, v, words % 16);
}

/// Stores the low @p len (1..WORD_SIZE-1) bytes of @p v at the word-aligned @p d, leaving the rest of the word unchanged.
[[gnu::always_inline]] inline void fill_partial(word_alias* d, word_alias v, size_t len) noexcept
{
    [[assume(len >= 1 && len < WORD_SIZE)]];  // Keeps the len * 8 shift inside the word.
    const auto mask = (word_alias{1} << (len * 8)) - 1;
    d[0] = (d[0] & ~mask) | (v & mask);
}

template <size_t... I>
[[gnu::always_inline]] inline void fill_n(
    word_alias* d, word_alias v, std::index_sequence<I...>) noexcept
{
    ((d[I] = v), ...);
}

[[gnu::always_inline]] inline void fill(uint8_t* d, word_alias v, size_t n) noexcept
{
    const auto phase = reinterpret_cast<uintptr_t>(d) % WORD_SIZE;
    if (phase == 0)
    {
        auto* dw = reinterpret_cast<word_alias*>(d);
        if (n == 32)
        {
            fill_n(dw, v, N32_SEQ{});
            return;
        }
        // On Airbender 64 bytes as well: 16 stores beat the jump into the run.
        if (WORD_SIZE == 4 && n == 64)
        {
            fill_n(dw, v, std::make_index_sequence<16>{});
            return;
        }
        const auto words = n / WORD_SIZE;
        if (words != 0)  // Spares the short ones the jump.
            fill_words(dw, v, words);
        if (const auto rest = n % WORD_SIZE; rest != 0)
            fill_partial(dw + words, v, rest);
        return;
    }

    if (n < 16)
    {
#pragma GCC unroll 1
        for (size_t i = 0; i < n; ++i)
            d[i] = static_cast<uint8_t>(v);
        return;
    }

    auto* dw = reinterpret_cast<word_alias*>(d - phase);
    const auto head_mask = ~word_alias{0} << (phase * 8);
    dw[0] = (dw[0] & ~head_mask) | (v & head_mask);
    ++dw;
    n -= WORD_SIZE - phase;
    const auto words = n / WORD_SIZE;
    fill_words(dw, v, words);
    if (const auto rest = n % WORD_SIZE; rest != 0)
        fill_partial(dw + words, v, rest);
}
}  // namespace

extern "C" void* ZILK_MEM_NAME(memset)(void* dest, int c, size_t n) noexcept
{
    // Zeros get a copy of fill() of their own, where v is the zero register.
    if (static_cast<uint8_t>(c) != 0) [[unlikely]]
        fill(static_cast<uint8_t*>(dest), static_cast<uint8_t>(c) * (~word_alias{0} / 0xff), n);
    else
        fill(static_cast<uint8_t*>(dest), 0, n);
    return dest;
}

namespace
{
/// Returns the memcmp() result at the first differing byte of the @p N at @p p and @p q (byte loads beat shifting two words apart).
template <size_t N = WORD_SIZE>
[[gnu::always_inline]] inline int first_difference(const uint8_t* p, const uint8_t* q) noexcept
{
#pragma GCC unroll 8
    for (size_t i = 0; i < N - 1; ++i)
    {
        if (p[i] != q[i])
            return static_cast<int>(p[i]) - static_cast<int>(q[i]);
    }
    return static_cast<int>(p[N - 1]) - static_cast<int>(q[N - 1]);
}

/// Returns the next WORD_SIZE bytes of an operand read in aligned words, advancing @p w; unaligned, @p cur carries the word @p w points to and @p lo is the operand's bit offset in it.
template <bool ALIGNED>
[[gnu::always_inline]] inline word_alias next(
    const word_alias*& w, word_alias& cur, unsigned lo) noexcept
{
    if constexpr (ALIGNED)
        return *w++;
    else
    {
        const auto nx = *++w;
        const auto v = (cur >> lo) | (nx << (WORD_BITS - lo));
        cur = nx;
        return v;
    }
}

/// Compares @p n bytes not both word-aligned: whole words re-laned (never from a word beyond the last byte compared), then bytes.
template <bool P_ALIGNED, bool Q_ALIGNED>
[[gnu::always_inline]] inline int compare_unaligned(
    const uint8_t* p, const uint8_t* q, size_t n) noexcept
{
    const auto plo = static_cast<unsigned>(reinterpret_cast<uintptr_t>(p) % WORD_SIZE) * 8;
    const auto qlo = static_cast<unsigned>(reinterpret_cast<uintptr_t>(q) % WORD_SIZE) * 8;
    const auto* pw = reinterpret_cast<const word_alias*>(p - plo / 8);
    const auto* qw = reinterpret_cast<const word_alias*>(q - qlo / 8);
    word_alias pc = P_ALIGNED ? 0 : pw[0];
    word_alias qc = Q_ALIGNED ? 0 : qw[0];
    const auto words = n / WORD_SIZE;
#pragma GCC unroll 1
    for (size_t i = 0; i < words; ++i)
    {
        const auto x = next<P_ALIGNED>(pw, pc, plo);
        const auto y = next<Q_ALIGNED>(qw, qc, qlo);
        if (x != y)
            return first_difference(p + i * WORD_SIZE, q + i * WORD_SIZE);
    }
    const auto done = n & ~(WORD_SIZE - 1);
    for (size_t i = done; i < n; ++i)
    {
        if (p[i] != q[i])
            return static_cast<int>(p[i]) - static_cast<int>(q[i]);
    }
    return 0;
}
}  // namespace

extern "C" int ZILK_MEM_NAME(memcmp)(const void* a, const void* b, size_t n) noexcept
{
    const auto* p = static_cast<const uint8_t*>(a);
    const auto* q = static_cast<const uint8_t*>(b);

    if (((reinterpret_cast<uintptr_t>(p) | reinterpret_cast<uintptr_t>(q)) % WORD_SIZE) == 0)
    {
        const auto* pw = reinterpret_cast<const word_alias*>(p);
        const auto* qw = reinterpret_cast<const word_alias*>(q);
        if (n == 32)
        {
#pragma GCC unroll 8
            for (size_t i = 0; i < N32; ++i)
            {
                if (pw[i] != qw[i])
                    return first_difference(p + i * WORD_SIZE, q + i * WORD_SIZE);
            }
            return 0;
        }
        if (n == 20)  // Addresses: 16 bytes in words, then a 4-byte half.
        {
#pragma GCC unroll 4
            for (size_t i = 0; i < 16 / WORD_SIZE; ++i)
            {
                if (pw[i] != qw[i])
                    return first_difference(p + i * WORD_SIZE, q + i * WORD_SIZE);
            }
            const auto x = reinterpret_cast<const u32_alias*>(p)[4];
            const auto y = reinterpret_cast<const u32_alias*>(q)[4];
            return x != y ? first_difference<4>(p + 16, q + 16) : 0;
        }

        const auto words = n / WORD_SIZE;
#pragma GCC unroll 1
        for (size_t i = 0; i < words; ++i)
        {
            if (pw[i] != qw[i])
                return first_difference(p + i * WORD_SIZE, q + i * WORD_SIZE);
        }
        if (const auto rest = n % WORD_SIZE; rest != 0)
        {
            const auto mask = (word_alias{1} << (rest * 8)) - 1;
            const auto x = pw[words] & mask;
            const auto y = qw[words] & mask;
            if (x != y)
                return first_difference(p + words * WORD_SIZE, q + words * WORD_SIZE);
        }
        return 0;
    }

    // Short and unaligned: bytes, ahead of the costlier word setup.
    if (n < 16)
    {
        for (size_t i = 0; i < n; ++i)
        {
            if (p[i] != q[i])
                return static_cast<int>(p[i]) - static_cast<int>(q[i]);
        }
        return 0;
    }
    if (reinterpret_cast<uintptr_t>(p) % WORD_SIZE == 0)
        return compare_unaligned<true, false>(p, q, n);
    if (reinterpret_cast<uintptr_t>(q) % WORD_SIZE == 0)
        return compare_unaligned<false, true>(p, q, n);
    return compare_unaligned<false, false>(p, q, n);
}

#if ZILK_MEM_BLOCK32
namespace
{
/// The out-of-line remainder of memcpy(): 32-byte-aligned ends by blocks, other large copies in words, and unaligned-end copies. One function, since block32() binds x10..x12 and two make GCC move memcpy()'s arguments on every call.
[[gnu::noinline]] void* memcpy_rest(void* dest, const void* src, size_t n) noexcept
{
    if ((reinterpret_cast<uintptr_t>(dest) | reinterpret_cast<uintptr_t>(src)) % WORD_SIZE != 0)
        return copy_unaligned(dest, src, n);

    auto* dw = static_cast<word_alias*>(dest);
    const auto* sw = static_cast<const word_alias*>(src);
    // block32() must not copy onto itself, which memmove() forwards for an EVM MCOPY with equal offsets.
    if (dest != src &&
        (reinterpret_cast<uintptr_t>(dw) ^ reinterpret_cast<uintptr_t>(sw)) % 32 == 0)
    {
        const auto lead = ((0 - reinterpret_cast<uintptr_t>(dw)) % 32) / WORD_SIZE;
        copy_words_upto<N32 - 1>(dw, sw, lead);
        dw += lead;
        sw += lead;
        n -= lead * WORD_SIZE;
        const auto blocks = n / 32;
#pragma GCC unroll 1
        for (auto i = blocks / 16; i != 0; --i)
        {
            blocks_upto<16, N32>(dw, sw, 16);
            dw += 16 * N32;
            sw += 16 * N32;
        }
        blocks_upto<15, N32>(dw, sw, blocks % 16);
        dw += blocks % 16 * N32;
        sw += blocks % 16 * N32;
        const auto words = n % 32 / WORD_SIZE;
        copy_words_upto<N32 - 1>(dw, sw, words);
        dw += words;
        sw += words;
    }
    else
        copy_words(dw, sw, n / WORD_SIZE);
    if (const auto rest = n % WORD_SIZE; rest != 0)
        scatter_aligned(reinterpret_cast<uint8_t*>(dw), sw[0], rest);
    return dest;
}
}  // namespace
#endif
