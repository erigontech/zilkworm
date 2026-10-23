// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>

namespace zilkworm {

namespace detail {

template <bool Lanes>
[[gnu::always_inline]] inline int cmp_bytes32_core(const uint8_t* a, const uint8_t* b) noexcept {
    if constexpr (!Lanes) {
        return std::memcmp(a, b, 32);
    } else {
        typedef uint64_t __attribute__((may_alias)) w64;
        const w64* const wa = reinterpret_cast<const w64*>(a);
        const w64* const wb = reinterpret_cast<const w64*>(b);
        for (int i = 0; i < 4; ++i) {
            const uint64_t x = __builtin_bswap64(wa[i]);
            const uint64_t y = __builtin_bswap64(wb[i]);
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }
}

template <bool Lanes>
[[gnu::always_inline]] inline bool lt_bytes32_core(const uint8_t* a, const uint8_t* b) noexcept {
    if constexpr (!Lanes) {
        return std::memcmp(a, b, 32) < 0;
    } else {
        typedef uint64_t __attribute__((may_alias)) w64;
        const w64* const wa = reinterpret_cast<const w64*>(a);
        const w64* const wb = reinterpret_cast<const w64*>(b);
        for (int i = 0; i < 4; ++i) {
            const uint64_t x = __builtin_bswap64(wa[i]);
            const uint64_t y = __builtin_bswap64(wb[i]);
            if (x != y) return x < y;
        }
        return false;
    }
}

}  // namespace detail

/// memcmp order; inline on ZisK, avoiding DMA.
[[gnu::always_inline]] inline int cmp_bytes32(const uint8_t* a, const uint8_t* b) noexcept {
    // Host tests compile the lane path.
#if (defined(ZISK) && defined(__riscv) && __riscv_xlen == 64) || defined(EVMONE_RV64_LANE_TEST)
    return detail::cmp_bytes32_core<true>(a, b);
#else
    return std::memcmp(a, b, 32);
#endif
}

/// a[0..32) < b[0..32) in memcmp order, both 4-aligned. With strict alignment (rv32 Airbender)
/// an ordering memcmp is a call; here the words are compared inline and the first differing byte
/// decides. The native test build (EVMONE_RV32_DISPATCH_TEST) compiles it for the tests.
[[gnu::always_inline]] inline bool lt_bytes32(const uint8_t* a, const uint8_t* b) noexcept {
#if (defined(ZISK) && defined(__riscv) && __riscv_xlen == 64) || defined(EVMONE_RV64_LANE_TEST)
    return detail::lt_bytes32_core<true>(a, b);
#elif (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
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
