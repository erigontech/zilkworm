// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Counts the non-zero bytes one aligned word at a time, for targets with no byte-parallel instructions: W
// is uint32_t on the rv32 guest and uint64_t on the rv64 one. About half of calldata words are all zero
// (ABI padding), and those cost only the load and the branch. In any other word, bit 7 of each lane of
// ((w & 0x7F..) + 0x7F..) | w is set iff that byte is non-zero, and the add never carries out of its lane.
// Those bits, moved down to bit 0, are summed lane by lane: 8 instructions for such a word, one fewer than
// counting it on the spot with a multiply. The view is at any alignment, so the word loop starts at a word
// boundary (SP1 rejects a misaligned load, Airbender traps or fixes it up). Compiled on every host so the
// tests can compare both widths with the scalar loop.
template <typename W>
[[nodiscard]] inline size_t count_nonzero_bytes_words(silkworm::ByteView data) noexcept {
    static_assert(std::is_same_v<W, uint32_t> || std::is_same_v<W, uint64_t>);
    typedef W __attribute__((may_alias)) word_t;
    constexpr size_t kWord = sizeof(W);
    constexpr W k7F = static_cast<W>(0x7F7F7F7F7F7F7F7Fu);
    constexpr W k00FF = static_cast<W>(0x00FF00FF00FF00FFu);
    constexpr W k0001 = static_cast<W>(0x0001000100010001u);
    const uint8_t* p = data.data();
    const uint8_t* const end = p + data.size();
    size_t n = 0;
    // The head and the tail are shorter than a word; unrolled, each loop would first dispatch on the
    // view's size.
#pragma GCC unroll 1
    while (p != end && (reinterpret_cast<uintptr_t>(p) & (kWord - 1)) != 0)
        n += *p++ != 0;
    while (end - p >= static_cast<ptrdiff_t>(kWord)) {
        // Each lane gains at most 1 per word: 255 words keep every lane <= 255.
        const uint8_t* const stop = p + std::min(static_cast<size_t>(end - p) & ~(kWord - 1), 255 * kWord);
        W acc = 0;
        do {
            const word_t w = *reinterpret_cast<const word_t*>(p);
            // Unrolled by -funroll-loops, as the guests are built, the loop keeps the flags under this
            // branch; with an unroll pragma of 2 or 4 GCC computes them ahead of it, for zero words too.
            if (w != 0)
                acc += ((((w & k7F) + k7F) | w) & ~k7F) >> 7;
            p += kWord;
        } while (p != stop);
        // Sum the lanes pairwise into 16-bit lanes of at most 510, then those with a multiply by
        // 0x0001..0001: the total, at most 2040, lands in the top 16 bits.
        acc = (acc & k00FF) + ((acc >> 8) & k00FF);
        n += (acc * k0001) >> (8 * kWord - 16);
    }
#pragma GCC unroll 1
    while (p != end)
        n += *p++ != 0;
    return n;
}

// Number of non-zero bytes; the zero count is data.size() minus this.
[[nodiscard]] inline size_t count_nonzero_bytes(silkworm::ByteView data) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    return count_nonzero_bytes_words<uint32_t>(data);
#elif defined(__riscv) && __riscv_xlen == 64
    return count_nonzero_bytes_words<uint64_t>(data);
#else
    return static_cast<size_t>(std::ranges::count_if(data, [](uint8_t b) { return b != 0; }));
#endif
}

}  // namespace zilkworm
