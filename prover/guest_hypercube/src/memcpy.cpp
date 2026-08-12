// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// memcpy for the SP1 zkVM. SP1 charges per machine-word memory record rather than per byte and
// rejects unaligned word access, so this never copies byte by byte: a masked read-modify-write
// aligns the destination, whole aligned words follow, a second masked write fills the tail.

#include <cstddef>
#include <cstdint>

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "the word packing assumes little-endian");

namespace
{
/// The unit every access here is done in: one machine word, which is what SP1 bills as one memory
/// record (8 bytes on rv64, 4 on rv32). may_alias because the words are read out of a byte buffer,
/// which strict aliasing would otherwise forbid; uintptr_t so the address arithmetic shares a type.
using word_alias [[gnu::may_alias]] = uintptr_t;

constexpr auto WORD_SIZE = sizeof(word_alias);
constexpr auto WORD_BITS = WORD_SIZE * 8;

/// Returns the @p len (1..WORD_SIZE-1) bytes at @p s in the low-order bytes of the result, reading
/// only the one or two aligned words that hold them.
[[gnu::always_inline]] inline word_alias gather(const uint8_t* s, size_t len) noexcept
{
    [[assume(len >= 1 && len < WORD_SIZE)]];
    const auto addr = reinterpret_cast<uintptr_t>(s);
    const auto off = addr % WORD_SIZE;
    const auto* w = reinterpret_cast<const word_alias*>(addr - off);

    auto v = w[0] >> (off * 8);
    if (off + len > WORD_SIZE)  // The range continues into the next word; off > 0 here.
        v |= w[1] << (WORD_BITS - off * 8);
    return v;
}

/// Stores the low-order @p len (1..WORD_SIZE-1) bytes of @p v at @p d, leaving the rest of the
/// destination word unchanged. The range must stay in one word: d % WORD_SIZE + len <= WORD_SIZE.
[[gnu::always_inline]] inline void scatter(uint8_t* d, word_alias v, size_t len) noexcept
{
    [[assume(len >= 1 && len < WORD_SIZE)]];  // Keeps the len * 8 shift inside the word.
    const auto addr = reinterpret_cast<uintptr_t>(d);
    const auto off = addr % WORD_SIZE;
    auto* w = reinterpret_cast<word_alias*>(addr - off);

    const auto mask = ((word_alias{1} << (len * 8)) - 1) << (off * 8);
    w[0] = (w[0] & ~mask) | ((v << (off * 8)) & mask);
}

/// scatter() for a word-aligned @p d (@p len is 1..WORD_SIZE-1), where the mask needs no rotation.
/// Separate because three quarters of the copies here are under 64 bytes, so the ends dominate.
[[gnu::always_inline]] inline void scatter_aligned(uint8_t* d, word_alias v, size_t len) noexcept
{
    [[assume(len >= 1 && len < WORD_SIZE)]];
    auto* w = reinterpret_cast<word_alias*>(d);

    const auto mask = (word_alias{1} << (len * 8)) - 1;
    w[0] = (w[0] & ~mask) | (v & mask);
}
}  // namespace

// Not __restrict, on purpose: __wrap_memmove() forwards forward-copyable overlapping ranges here,
// and __restrict also lets GCC turn the word loop into a call to memcpy that -Wl,--wrap makes
// recursive. It costs nothing -- the two spellings compile to an identical opcode mix.
extern "C" void* __wrap_memcpy(void* dest, const void* src, size_t n) noexcept
{
    auto* d = static_cast<uint8_t*>(dest);
    const auto* s = static_cast<const uint8_t*>(src);

    if (n == 0) [[unlikely]]
        return dest;

    // Head: bring the destination up to a word boundary with one masked write.
    if (const auto phase = reinterpret_cast<uintptr_t>(d) % WORD_SIZE; phase != 0)
    {
        const auto head = WORD_SIZE - phase < n ? WORD_SIZE - phase : n;
        scatter(d, gather(s, head), head);
        d += head;
        s += head;
        n -= head;
        if (n == 0)
            return dest;
    }

    // Middle: whole aligned destination words. The guard skips a copy shorter than a word (a
    // seventh of the calls) and keeps the out-of-phase branch from loading a word it would not use.
    const auto words = n / WORD_SIZE;
    if (words != 0)
    {
        auto* dw = reinterpret_cast<word_alias*>(d);
        if (const auto phase = reinterpret_cast<uintptr_t>(s) % WORD_SIZE; phase == 0)
        {
            const auto* sw = reinterpret_cast<const word_alias*>(s);
            size_t i = 0;
            for (; i + 4 <= words; i += 4)  // Unrolled, as the replaced assembly's bulk loop was.
            {
                dw[i] = sw[i];
                dw[i + 1] = sw[i + 1];
                dw[i + 2] = sw[i + 2];
                dw[i + 3] = sw[i + 3];
            }
            for (; i < words; ++i)
                dw[i] = sw[i];
        }
        else
        {
            // Source out of phase: read aligned words and re-lane each pair into one output word.
            // The last iteration reads the word holding the last copied byte, never one beyond.
            // Left rolled on purpose -- unrolling it 4x measures +0.3% cycles at these sizes.
            const auto lo = phase * 8;
            const auto hi = WORD_BITS - lo;
            const auto* sw = reinterpret_cast<const word_alias*>(s - phase);
            auto w0 = sw[0];
            for (size_t i = 0; i < words; ++i)
            {
                const auto w1 = sw[i + 1];
                dw[i] = (w0 >> lo) | (w1 << hi);
                w0 = w1;
            }

            // The loop leaves sw[words] in w0, which is the word the tail's gather() would reload.
            if (const auto rest = n % WORD_SIZE; rest != 0)
            {
                auto v = w0 >> lo;
                if (phase + rest > WORD_SIZE)  // The tail continues into the next source word.
                    v |= sw[words + 1] << hi;
                scatter_aligned(d + words * WORD_SIZE, v, rest);
            }
            return dest;
        }
    }

    // Tail: the partial last word. The destination is word-aligned by now.
    if (const auto rest = n % WORD_SIZE; rest != 0)
    {
        const auto done = words * WORD_SIZE;
        scatter_aligned(d + done, gather(s + done, rest), rest);
    }
    return dest;
}
