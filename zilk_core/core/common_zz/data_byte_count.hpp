// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Counts the non-zero bytes four at a time, for targets with no byte-parallel instructions. Bit 7 of
// each lane of ((w & 0x7F..) + 0x7F..) | w is set iff that byte is non-zero, and the add never carries
// out of its lane. The view is at any alignment, so the word loop starts at a 4-byte boundary (the
// target traps or fixes up misaligned words). Compiled on every host so the tests can compare it with
// the scalar loop; only the rv32 guest selects it in count_nonzero_bytes.
[[nodiscard]] inline size_t count_nonzero_bytes_words(silkworm::ByteView data) noexcept {
    typedef uint32_t __attribute__((may_alias)) word_t;
    const uint8_t* p = data.data();
    const uint8_t* const end = p + data.size();
    size_t n = 0;
    while (p != end && (reinterpret_cast<uintptr_t>(p) & 3) != 0)
        n += *p++ != 0;
    while (end - p >= 8) {
        // Each lane gains at most 2 per pair of words: 127 pairs keep every lane <= 254.
        const uint8_t* const stop = p + std::min<size_t>(static_cast<size_t>(end - p) & ~size_t{7}, 127 * 8);
        uint32_t acc = 0;
        do {
            const word_t w0 = *reinterpret_cast<const word_t*>(p);
            const word_t w1 = *reinterpret_cast<const word_t*>(p + 4);
            acc += ((((w0 & 0x7F7F7F7Fu) + 0x7F7F7F7Fu) | w0) & 0x80808080u) >> 7;
            acc += ((((w1 & 0x7F7F7F7Fu) + 0x7F7F7F7Fu) | w1) & 0x80808080u) >> 7;
            p += 8;
        } while (p != stop);
        // The lane total can exceed 255, so sum the lanes pairwise (a multiply by 0x01010101
        // would wrap at 256). The largest reduced sum is 1016, so the 16-bit mask is safe.
        acc = (acc & 0x00FF00FFu) + ((acc >> 8) & 0x00FF00FFu);
        n += (acc + (acc >> 16)) & 0xFFFFu;
    }
    while (p != end)
        n += *p++ != 0;
    return n;
}

// Number of non-zero bytes; the zero count is data.size() minus this.
[[nodiscard]] inline size_t count_nonzero_bytes(silkworm::ByteView data) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    return count_nonzero_bytes_words(data);
#else
    return static_cast<size_t>(std::ranges::count_if(data, [](uint8_t b) { return b != 0; }));
#endif
}

}  // namespace zilkworm
