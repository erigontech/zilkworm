// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Counts non-zero bytes a word at a time (W is uint32_t or uint64_t); the word loop starts at a word boundary because SP1 rejects misaligned loads.
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
#pragma GCC unroll 1
    while (p != end && (reinterpret_cast<uintptr_t>(p) & (kWord - 1)) != 0)
        n += *p++ != 0;
    while (end - p >= static_cast<ptrdiff_t>(kWord)) {
        // Each lane gains at most 1 per word: 255 words keep every lane <= 255.
        const uint8_t* const stop = p + std::min(static_cast<size_t>(end - p) & ~(kWord - 1), 255 * kWord);
        W acc = 0;
        do {
            const word_t w = *reinterpret_cast<const word_t*>(p);
            if (w != 0)
                acc += ((((w & k7F) + k7F) | w) & ~k7F) >> 7;
            p += kWord;
        } while (p != stop);
        // Sum lanes pairwise into 16-bit lanes (<= 510), then multiply by 0x0001..0001: the total (<= 2040) lands in the top 16 bits.
        acc = (acc & k00FF) + ((acc >> 8) & k00FF);
        n += (acc * k0001) >> (8 * kWord - 16);
    }
#pragma GCC unroll 1
    while (p != end)
        n += *p++ != 0;
    return n;
}

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
