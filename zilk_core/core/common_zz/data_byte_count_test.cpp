// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/data_byte_count.hpp>

using zilkworm::count_nonzero_bytes;

namespace {

void check_range(const uint8_t* p, size_t n) {
    size_t nz{0};
    for (size_t i = 0; i < n; ++i) {
        nz += p[i] != 0;
    }
    CHECK(count_nonzero_bytes(silkworm::ByteView{p, n}) == nz);
}

void check(const std::vector<uint8_t>& v) { check_range(v.data(), v.size()); }

std::vector<size_t> boundary_lengths() {
    std::vector<size_t> lens;
    for (size_t len = 0; len <= 40; ++len) {
        lens.push_back(len);
    }
    for (size_t base : {224u, 448u, 672u}) {
        for (size_t d : {0u, 1u, 7u, 8u, 9u}) {
            lens.push_back(base + d);
            if (d != 0) {
                lens.push_back(base - d);
            }
        }
    }
    for (size_t len : {247u, 248u, 249u, 255u, 256u, 257u, 1000u, 4096u + 5u, 65536u + 7u}) {
        lens.push_back(len);
    }
    return lens;
}

}  // namespace

TEST_CASE("count_nonzero_bytes tiny cases", "[datacount]") {
    check({});
    check({0x00});
    check({0x01});
    check({0x80});  // |w rescue path
    check({0xFF});
    check({0x00, 0x00, 0x00});
    check({0x01, 0x00, 0x80, 0xFF});
}

TEST_CASE("count_nonzero_bytes uniform patterns across lengths", "[datacount]") {
    for (size_t len = 0; len <= 300; ++len) {
        check(std::vector<uint8_t>(len, 0x00));  // all zero
        check(std::vector<uint8_t>(len, 0x01));  // all non-zero
        check(std::vector<uint8_t>(len, 0x80));  // all 0x80 (rescue)
        check(std::vector<uint8_t>(len, 0xFF));
    }
}

TEST_CASE("count_nonzero_bytes mixed patterns across lengths", "[datacount]") {
    for (size_t len = 0; len <= 600; ++len) {
        std::vector<uint8_t> v(len);
        for (size_t i = 0; i < len; ++i) {
            v[i] = static_cast<uint8_t>((i * 37u + 11u) & 0xFFu);
        }
        check(v);
        if (len != 0) {
            v[len / 2] = 0x00;  // force a zero to vary counts
            check(v);
        }
    }
}

TEST_CASE("count_nonzero_bytes chunk and block boundaries at every alignment", "[datacount]") {
    const std::vector<size_t> lens = boundary_lengths();
    std::vector<uint8_t> buf(65536u + 7u + 8u);
    for (size_t off = 0; off < 8; ++off) {
        for (size_t len : lens) {
            uint8_t* const p = buf.data() + off;
            std::fill(p, p + len, 0xFF);  // all non-zero: maximal lane sums
            check_range(p, len);
            std::fill(p, p + len, 0x00);
            check_range(p, len);
            for (size_t i = 0; i < len; ++i) {
                p[i] = (i % 3u == 0u) ? 0x7F : 0x00;
            }
            check_range(p, len);
            for (size_t i = 0; i < len; ++i) {
                p[i] = static_cast<uint8_t>((i * 13u + 7u) & 0xFFu);
            }
            check_range(p, len);
        }
    }
}

TEST_CASE("count_nonzero_bytes random buffers vs byte-loop oracle", "[datacount]") {
    std::mt19937 rng{0x5eedu};
    std::vector<uint8_t> buf(70000);
    for (int iter = 0; iter < 3000; ++iter) {
        const size_t len = (iter % 10 == 0) ? std::uniform_int_distribution<size_t>(4000, 69990)(rng)
                                            : std::uniform_int_distribution<size_t>(0, 1500)(rng);
        const size_t off = std::uniform_int_distribution<size_t>(0, 7)(rng);
        const unsigned zero_pct = std::uniform_int_distribution<unsigned>(0, 100)(rng);
        for (size_t i = 0; i < len; ++i) {
            const bool zero = std::uniform_int_distribution<unsigned>(0, 99)(rng) < zero_pct;
            buf[off + i] = zero ? 0u : static_cast<uint8_t>(std::uniform_int_distribution<unsigned>(1, 255)(rng));
        }
        check_range(buf.data() + off, len);
    }
}

TEST_CASE("count_nonzero_bytes with misaligned start pointer", "[datacount]") {
    std::vector<uint8_t> buf(700);
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((i * 13u + 7u) & 0xFFu);
    }
    for (size_t off = 0; off < 8; ++off) {
        for (size_t len : {0u, 1u, 7u, 8u, 23u, 24u, 25u, 31u, 32u, 40u, 100u, 300u}) {
            if (off + len > buf.size()) {
                continue;
            }
            check_range(buf.data() + off, len);
        }
    }
}
