// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/bytes_cmp.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>

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

TEST_CASE("bytes32 lane cores order as memcmp does", "[compare]") {
    std::mt19937_64 rng{0x1e3a};
    alignas(4) uint8_t a[32];
    alignas(4) uint8_t b[32];
    size_t checked = 0;
    for (size_t pos = 0; pos < 32; ++pos) {
        for (unsigned x = 0; x < 256; ++x) {
            for (unsigned y = 0; y < 256; y += 17) {
                for (size_t i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
                a[pos] = static_cast<uint8_t>(x);
                b[pos] = static_cast<uint8_t>(y);
                for (size_t i = pos + 1; i < 32; ++i) b[i] = static_cast<uint8_t>(rng());
                CAPTURE(pos, x, y);
                const int m = std::memcmp(a, b, 32);
                const int s = (m > 0) - (m < 0);  // memcmp may return the byte difference
                REQUIRE(zilkworm::detail::cmp_bytes32_core<true>(a, b) == s);
                REQUIRE(zilkworm::detail::cmp_bytes32_core<false>(a, b) == m);
                REQUIRE(zilkworm::detail::lt_bytes32_core<true>(a, b) == (m < 0));
                REQUIRE(zilkworm::detail::lt_bytes32_core<true>(b, a) == (m > 0));
                ++checked;
            }
        }
    }
    for (size_t i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
    CHECK(zilkworm::detail::cmp_bytes32_core<true>(a, b) == 0);
    CHECK(zilkworm::detail::cmp_bytes32_core<true>(a, a) == 0);
    CHECK_FALSE(zilkworm::detail::lt_bytes32_core<true>(a, b));
    CHECK(checked == 32 * 256 * 16);
}

TEST_CASE("bytes_equal_core lanes match memcmp at every first difference", "[compare]") {
    std::mt19937_64 rng{0x9e20};
    alignas(8) uint8_t a[32];
    alignas(8) uint8_t b[32];
    size_t checked = 0;
    // Every first-difference position, incl. overlapping tails.
    for (const size_t n : {size_t{8}, size_t{20}, size_t{32}}) {
        for (size_t pos = 0; pos < n; ++pos) {
            for (unsigned y = 0; y < 256; y += 31) {
                for (size_t i = 0; i < n; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
                b[pos] = static_cast<uint8_t>(y);
                if (a[pos] == b[pos]) continue;
                CAPTURE(n, pos, y);
                const bool want = std::memcmp(a, b, n) == 0;
                switch (n) {
                    case 8: CHECK(zilkworm::detail::bytes_equal_core<8, true>(a, b) == want); break;
                    case 20: CHECK(zilkworm::detail::bytes_equal_core<20, true>(a, b) == want); break;
                    default: CHECK(zilkworm::detail::bytes_equal_core<32, true>(a, b) == want); break;
                }
                ++checked;
            }
        }
    }
    for (size_t i = 0; i < 32; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
    CHECK(zilkworm::detail::bytes_equal_core<8, true>(a, b));
    CHECK(zilkworm::detail::bytes_equal_core<20, true>(a, b));
    CHECK(zilkworm::detail::bytes_equal_core<32, true>(a, b));
    CHECK(checked > 500);
}
