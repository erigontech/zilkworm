// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Number of non-zero bytes; the zero count is data.size() minus this.
[[nodiscard]] inline size_t count_nonzero_bytes(silkworm::ByteView data) noexcept {
    const uint8_t* p{data.data()};
    size_t n{data.size()};
    size_t non_zero{0};

    // 24 is a heuristic, not a correctness bound: the word path is valid for any
    // n >= 8 (the tail loop handles whatever the alignment fixup leaves). The
    // fixup below costs up to 7 scalar bytes, so requiring n >= 24 guarantees at
    // least 17 bytes (two full words) reach the SWAR path, enough to amortize
    // the fixup. Shorter inputs go straight to the scalar tail loop.
    if (n >= 24) {
        while ((reinterpret_cast<uintptr_t>(p) & 7u) != 0) {
            non_zero += *p++ != 0;
            --n;
        }
        constexpr uint64_t k7F{0x7F7F7F7F7F7F7F7Fu};
        constexpr uint64_t kOnes{0x0101010101010101u};
        // carry-free SWAR: bit7 set per non-zero byte
        const auto word_nz = [](const uint8_t* q) noexcept -> uint64_t {
            uint64_t w;
            std::memcpy(&w, std::assume_aligned<8>(q), sizeof(w));
            return ((((w & k7F) + k7F) | w) & ~k7F) >> 7;
        };
        // lane sum must stay < 256
        uint64_t lanes{0};
        if (n & 16u) {
            lanes += word_nz(p) + word_nz(p + 8);
            p += 16;
        }
        if (n & 8u) {
            lanes += word_nz(p);
            p += 8;
        }
        const uint8_t* const blocks_end{p + (n & ~size_t{31})};
        while (blocks_end - p >= 224) {
            const uint8_t* const chunk_end{p + 224};
            do {
                lanes += word_nz(p) + word_nz(p + 8) + word_nz(p + 16) + word_nz(p + 24);
                p += 32;
            } while (p != chunk_end);
            non_zero += (lanes * kOnes) >> 56;  // horizontal lane sum
            lanes = 0;
        }
#pragma GCC unroll 1
        while (p != blocks_end) {
            lanes += word_nz(p) + word_nz(p + 8) + word_nz(p + 16) + word_nz(p + 24);
            p += 32;
        }
        non_zero += (lanes * kOnes) >> 56;
        n &= 7u;
    }
    const uint8_t* const end{p + n};
    while (p != end) {
        non_zero += *p++ != 0;
    }
    return non_zero;
}

}  // namespace zilkworm
