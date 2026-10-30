// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>

namespace zilkworm {

/// a[0..32) < b[0..32) in memcmp order, both 4-aligned. With strict alignment (rv32 Airbender)
/// an ordering memcmp is a call; here the words are compared inline and the first differing byte
/// decides, as DirectState's key_below() does.
[[gnu::always_inline]] inline bool lt_bytes32(const uint8_t* a, const uint8_t* b) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    typedef uint32_t __attribute__((may_alias)) w32;
    const w32* const wa = reinterpret_cast<const w32*>(std::assume_aligned<4>(a));
    const w32* const wb = reinterpret_cast<const w32*>(std::assume_aligned<4>(b));
    for (int i = 0; i < 8; ++i) {
        const uint32_t x = wa[i];
        const uint32_t y = wb[i];
        if (x == y) continue;
        // Little-endian words: the first differing byte is the lowest nonzero byte of x ^ y.
        const uint32_t d = x ^ y;
        const uint32_t m = (d & 0xffu)       ? 0xffu
                           : (d & 0xffffu)   ? 0xffffu
                           : (d & 0xffffffu) ? 0xffffffu
                                             : ~uint32_t{0};
        return (x & m) < (y & m);
    }
    return false;
#else
    return std::memcmp(a, b, 32) < 0;
#endif
}

}  // namespace zilkworm
