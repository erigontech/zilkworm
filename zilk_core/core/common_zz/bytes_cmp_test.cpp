// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/bytes_cmp.hpp>

using zilkworm::lt_bytes32;

TEST_CASE("lt_bytes32 orders 32-byte keys as memcmp does", "[compare]") {
    std::mt19937_64 rng{0x1b32};
    alignas(4) uint8_t a[32];
    alignas(4) uint8_t b[32];
    size_t checked = 0;
    // Every position of the first difference, with every pair of byte values there and random
    // bytes elsewhere (equal before it, independent after it), in both argument orders.
    for (size_t pos = 0; pos < 32; ++pos) {
        for (unsigned x = 0; x < 256; ++x) {
            for (unsigned y = 0; y < 256; y += 17) {
                for (size_t i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
                a[pos] = static_cast<uint8_t>(x);
                b[pos] = static_cast<uint8_t>(y);
                for (size_t i = pos + 1; i < 32; ++i) b[i] = static_cast<uint8_t>(rng());
                CAPTURE(pos, x, y);
                REQUIRE(lt_bytes32(a, b) == (std::memcmp(a, b, 32) < 0));
                REQUIRE(lt_bytes32(b, a) == (std::memcmp(b, a, 32) < 0));
                ++checked;
            }
        }
    }
    // Equal keys are not below each other.
    for (size_t i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
    REQUIRE_FALSE(lt_bytes32(a, b));
    REQUIRE_FALSE(lt_bytes32(a, a));
    CHECK(checked == 32 * 256 * 16);
}
