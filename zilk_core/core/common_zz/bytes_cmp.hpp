// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

// Inline fixed-size byte compares. Newlib memcmp costs a call plus an alignment
// preamble per invocation; these lower to a handful of full-width loads instead.
// Alignment contracts are hard requirements, and std::assume_aligned is what
// makes rv64im gcc emit ld/lw rather than per-byte lbu sequences (cf.
// zeroless_view); a misaligned pointer here is rejected by SP1 at runtime.

namespace zilkworm {

// Equality of 32 bytes; both pointers 8-aligned.
[[gnu::always_inline]] inline bool eq_bytes32(const uint8_t* a, const uint8_t* b) noexcept {
    uint64_t a0, a1, a2, a3, b0, b1, b2, b3;
    const uint8_t* pa = std::assume_aligned<8>(a);
    const uint8_t* pb = std::assume_aligned<8>(b);
    std::memcpy(&a0, pa + 0, 8);   std::memcpy(&b0, pb + 0, 8);
    std::memcpy(&a1, pa + 8, 8);   std::memcpy(&b1, pb + 8, 8);
    std::memcpy(&a2, pa + 16, 8);  std::memcpy(&b2, pb + 16, 8);
    std::memcpy(&a3, pa + 24, 8);  std::memcpy(&b3, pb + 24, 8);
    return ((a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3)) == 0;
}

// Equality of 20 bytes; both pointers 4-aligned (evmc_address is alignas(uint32_t)).
[[gnu::always_inline]] inline bool eq_bytes20_u32(const uint8_t* a, const uint8_t* b) noexcept {
    uint32_t a0, a1, a2, a3, a4, b0, b1, b2, b3, b4;
    const uint8_t* pa = std::assume_aligned<4>(a);
    const uint8_t* pb = std::assume_aligned<4>(b);
    std::memcpy(&a0, pa + 0, 4);   std::memcpy(&b0, pb + 0, 4);
    std::memcpy(&a1, pa + 4, 4);   std::memcpy(&b1, pb + 4, 4);
    std::memcpy(&a2, pa + 8, 4);   std::memcpy(&b2, pb + 8, 4);
    std::memcpy(&a3, pa + 12, 4);  std::memcpy(&b3, pb + 12, 4);
    std::memcpy(&a4, pa + 16, 4);  std::memcpy(&b4, pb + 16, 4);
    return ((a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3) | (a4 ^ b4)) == 0;
}

// Lexicographic less-than of 32 bytes; both pointers 8-aligned.
// Words are scanned for the first mismatch; the deciding byte inside it is then
// located branchlessly with the zeroless_view mask ladder — storage keys are
// mostly small integers, so the mismatch usually sits deep in the final word
// and a byte-at-a-time rescan would be the worst case, not the fast path.
[[gnu::always_inline]] inline bool lt_bytes32(const uint8_t* a, const uint8_t* b) noexcept {
    const uint8_t* pa = std::assume_aligned<8>(a);
    const uint8_t* pb = std::assume_aligned<8>(b);
    for (size_t i = 0; i < 32; i += 8) {
        uint64_t x, y;
        std::memcpy(&x, pa + i, 8);
        std::memcpy(&y, pb + i, 8);
        if (x != y) {
            // Little-endian: buffer byte j is the j-th low byte of x. The true
            // terms form a prefix whose length is the index of the first
            // differing byte (0..7); no 8th term, x != y bounds it.
            const uint64_t z = x ^ y;
            const unsigned k = static_cast<unsigned>(
                               ((z & 0xFFu)             == 0) +
                               ((z & 0xFFFFu)           == 0) +
                               ((z & 0xFFFFFFu)         == 0) +
                               ((z & 0xFFFFFFFFu)       == 0) +
                               ((z & 0xFFFFFFFFFFu)     == 0) +
                               ((z & 0xFFFFFFFFFFFFu)   == 0) +
                               ((z & 0xFFFFFFFFFFFFFFu) == 0));
            return static_cast<uint8_t>(x >> (8 * k)) < static_cast<uint8_t>(y >> (8 * k));
        }
    }
    return false;
}

}  // namespace zilkworm
