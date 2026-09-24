// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include <intx/intx.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Number of non-zero bytes; the zero count is data.size() minus this.
[[nodiscard]] inline size_t count_nonzero_bytes(silkworm::ByteView data) noexcept {
    using Word = size_t;  // native register width: 8 bytes on rv64, 4 on rv32
    constexpr Word k7F{static_cast<Word>(0x7F7F7F7F7F7F7F7Fu)};
    constexpr Word k02{static_cast<Word>(0x0202020202020202u)};
    // High half of a * b: one mulhu on either width.
    const auto mulhi = [](Word a, Word b) noexcept -> Word {
        if constexpr (sizeof(Word) == 8) {
            return intx::umul(a, b)[1];
        } else {
            return static_cast<Word>((uint64_t{a} * b) >> 32);
        }
    };

    const uint8_t* p{data.data()};
    const uint8_t* const end{p + data.size()};
    size_t n{0};
    while (p != end && reinterpret_cast<uintptr_t>(p) % sizeof(Word) != 0) {
        n += *p++ != 0;
    }
    for (; end - p >= static_cast<ptrdiff_t>(sizeof(Word)); p += sizeof(Word)) {
        Word w;
        std::memcpy(&w, std::assume_aligned<sizeof(Word)>(p), sizeof(w));
        // All-zero words (about half of calldata) cost only the load and the branch.
        // Bit 7 of each byte is set iff the byte is non-zero (no carry crosses a byte);
        // times 0x0202..02 the flag count lands in the low byte of the high half.
        // Keep the whole computation inside the if: computed ahead of it, GCC hoists
        // the flag ops above the branch and zero words pay for them.
        if (w != 0) {
            n += mulhi((((w & k7F) + k7F) | w) & ~k7F, k02) & 0xFF;
        }
    }
    while (p != end) {
        n += *p++ != 0;
    }
    return n;
}

}  // namespace zilkworm
