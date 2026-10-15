// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// count_nonzero_bytes_words, the guests' calldata counter, is compared with the plain per-byte loop at both
// of its word widths: four bytes (the rv32 guest's) and eight (the rv64 guest's). The views start at every
// alignment of 0 to 7 and the sizes run through the head, the word steps, the 255-word blocks (1020 and 2040
// bytes) and the tail, with byte values chosen to hit the lane arithmetic: 0x80 (bit 7 only), 0x7F, 0x01,
// 0xFF, a single non-zero byte at every position, and all-non-zero inputs long enough to fill a lane past
// 255 if a block were longer than 255 words. The buffers that end or start at a protected page check that
// no byte outside the view is read.

#include "data_byte_count.hpp"

#include <algorithm>
#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define ZILK_GUARD_PAGES 1
#endif

namespace zilkworm {

namespace {

    size_t reference(const uint8_t* p, size_t n) {
        size_t count = 0;
        for (size_t i = 0; i < n; ++i)
            count += p[i] != 0;
        return count;
    }

    void require_count(silkworm::ByteView view, size_t want) {
        REQUIRE(count_nonzero_bytes_words<uint32_t>(view) == want);
        REQUIRE(count_nonzero_bytes_words<uint64_t>(view) == want);
    }

    void check_view(const uint8_t* p, size_t n) {
        const size_t want = reference(p, n);
        const silkworm::ByteView view{p, n};
        require_count(view, want);
        REQUIRE(count_nonzero_bytes(view) == want);
    }

    // The view at `offset` into `buf` (so that its alignment is the buffer's plus `offset`).
    void check_at(const std::vector<uint8_t>& buf, size_t offset, size_t n) {
        REQUIRE(offset + n <= buf.size());
        check_view(buf.data() + offset, n);
    }

    // Sizes that matter: all of 0..80, and around the first block boundaries of either width (1020 and 2040
    // bytes).
    std::vector<size_t> interesting_sizes() {
        std::vector<size_t> sizes;
        for (size_t n = 0; n <= 80; ++n)
            sizes.push_back(n);
        for (const size_t block : {size_t{1020}, size_t{2040}})
            for (size_t k = 1; k <= 3; ++k)
                for (int d = -10; d <= 10; ++d)
                    sizes.push_back(static_cast<size_t>(static_cast<int>(k * block) + d));
        for (const size_t n : {size_t{1023}, size_t{1024}, size_t{1025}, size_t{4096}, size_t{65535}, size_t{65536},
                               size_t{65536 + 7}})
            sizes.push_back(n);
        return sizes;
    }

}  // namespace

TEST_CASE("count_nonzero_bytes word scans: uniform fills at every alignment and size", "[data_byte_count]") {
    constexpr size_t kMax = 65536 + 16;
    for (const uint8_t fill : {uint8_t{0x00}, uint8_t{0x01}, uint8_t{0x7F}, uint8_t{0x80}, uint8_t{0xFF},
                               uint8_t{0x55}, uint8_t{0xAA}}) {
        const std::vector<uint8_t> buf(kMax + 8, fill);
        for (const size_t n : interesting_sizes())
            for (size_t offset = 0; offset < 8; ++offset)
                check_at(buf, offset, n);
    }
}

TEST_CASE("count_nonzero_bytes word scans: all-non-zero 64 KiB cannot overflow a lane or the reduction", "[data_byte_count]") {
    // A block longer than 255 words would carry a lane past 255 here, and a multiply-by-0x01..01 reduction
    // of the byte lanes would wrap; every value 1..255 is its own fill. Full blocks are 1020 and 2040 bytes.
    std::vector<uint8_t> buf(65536 + 8);
    for (unsigned v = 1; v <= 255; ++v) {
        std::fill(buf.begin(), buf.end(), static_cast<uint8_t>(v));
        for (size_t offset = 0; offset < 8; ++offset)
            for (const size_t n : {size_t{65536}, size_t{1020}, size_t{2040}, size_t{4080}, size_t{1024}})
                require_count({buf.data() + offset, n}, n);
    }
}

TEST_CASE("count_nonzero_bytes word scans: one non-zero byte at every position and value", "[data_byte_count]") {
    // 41 bytes: the head (up to 3, or 7 at eight bytes per word), several words and the tail at every
    // alignment.
    constexpr size_t kLen = 41;
    std::vector<uint8_t> buf(kLen + 8);
    for (size_t offset = 0; offset < 8; ++offset)
        for (size_t pos = 0; pos < kLen; ++pos)
            for (unsigned v = 0; v <= 255; ++v) {
                std::fill(buf.begin(), buf.end(), uint8_t{0});
                buf[offset + pos] = static_cast<uint8_t>(v);
                require_count({buf.data() + offset, kLen}, v != 0 ? 1u : 0u);
            }
    // The same with one zero byte in an all-non-zero view of 2100 bytes (across a block boundary of either
    // width).
    constexpr size_t kFull = 2100;
    std::vector<uint8_t> full(kFull + 8, uint8_t{0xFF});
    for (size_t offset = 0; offset < 8; ++offset)
        for (size_t pos = 0; pos < kFull; ++pos) {
            full[offset + pos] = 0;
            require_count({full.data() + offset, kFull}, kFull - 1);
            full[offset + pos] = 0xFF;
        }
}

TEST_CASE("count_nonzero_bytes word scans: lane edge values", "[data_byte_count]") {
    // Every byte pair of neighbours from the values that sit on the carry and the bit-7 boundaries, in
    // every lane of a word (a carry out of a lane would corrupt its neighbour).
    const uint8_t edge[]{0x00, 0x01, 0x02, 0x3F, 0x40, 0x7E, 0x7F, 0x80, 0x81, 0xBF, 0xC0, 0xFE, 0xFF};
    std::vector<uint8_t> buf(24 + 8);
    for (const uint8_t a : edge)
        for (const uint8_t b : edge)
            for (const uint8_t c : edge)
                for (size_t offset = 0; offset < 8; ++offset) {
                    for (size_t i = 0; i < 24; ++i)
                        buf[offset + i] = (i % 3 == 0) ? a : (i % 3 == 1) ? b : c;
                    check_view(buf.data() + offset, 24);
                    check_view(buf.data() + offset, 23);
                    check_view(buf.data() + offset, 9);
                }
}

TEST_CASE("count_nonzero_bytes word scans: every zero pattern of an aligned word", "[data_byte_count]") {
    // Each of the 256 patterns of zero and non-zero bytes in an aligned eight-byte word (two words at four
    // bytes per word), with the non-zero bytes at the carry and bit-7 edge values.
    alignas(8) uint8_t word[8];
    for (unsigned mask = 0; mask < 256; ++mask)
        for (const uint8_t v : {uint8_t{0x01}, uint8_t{0x7F}, uint8_t{0x80}, uint8_t{0xFF}}) {
            for (size_t i = 0; i < 8; ++i)
                word[i] = ((mask >> i) & 1) != 0 ? v : uint8_t{0};
            check_view(word, 8);
        }
}

TEST_CASE("count_nonzero_bytes word scans: random buffers", "[data_byte_count]") {
    std::mt19937_64 rng{0xCA11DA7AULL};
    std::vector<uint8_t> buf(70000 + 8);
    const std::vector<size_t> sizes = interesting_sizes();
    for (int round = 0; round < 3000; ++round) {
        // Density of non-zero bytes from nearly empty to full; the values are random non-zero bytes.
        const unsigned density = static_cast<unsigned>(rng() % 101);
        const size_t n = (round % 2 == 0) ? sizes[rng() % sizes.size()] : static_cast<size_t>(rng() % 3000);
        const size_t offset = static_cast<size_t>(rng() % 8);
        for (size_t i = 0; i < offset + n; ++i) {
            const bool nonzero = rng() % 100 < density;
            buf[i] = nonzero ? static_cast<uint8_t>(1 + rng() % 255) : uint8_t{0};
        }
        check_view(buf.data() + offset, n);
    }
    // Calldata-like: runs of zero padding around 32-byte words, as ABI encoding produces.
    for (int round = 0; round < 500; ++round) {
        const size_t words = static_cast<size_t>(rng() % 40);
        const size_t offset = static_cast<size_t>(rng() % 8);
        size_t n = 0;
        for (size_t w = 0; w < words; ++w) {
            const size_t significant = static_cast<size_t>(rng() % 33);
            for (size_t i = 0; i < 32; ++i)
                buf[offset + n + i] = i >= 32 - significant ? static_cast<uint8_t>(1 + rng() % 255) : uint8_t{0};
            n += 32;
        }
        n += static_cast<size_t>(rng() % 5);  // a 4-byte selector, or a stray tail
        for (size_t i = n >= 4 ? n - 4 : 0; i < n; ++i)
            buf[offset + i] = static_cast<uint8_t>(1 + rng() % 255);
        check_view(buf.data() + offset, n);
    }
}

#ifdef ZILK_GUARD_PAGES
TEST_CASE("count_nonzero_bytes word scans: reads nothing outside the view", "[data_byte_count]") {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    // Three pages; the outer two are inaccessible, so a read one byte before or after the view faults.
    void* const raw = mmap(nullptr, 3 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    REQUIRE(raw != MAP_FAILED);
    auto* const base = static_cast<uint8_t*>(raw);
    REQUIRE(mprotect(base, page, PROT_NONE) == 0);
    REQUIRE(mprotect(base + 2 * page, page, PROT_NONE) == 0);
    uint8_t* const mid = base + page;
    std::mt19937_64 rng{0xFEEDULL};
    for (size_t n = 0; n <= 300; ++n) {
        for (const bool at_end : {true, false}) {
            uint8_t* const start = at_end ? mid + page - n : mid;
            for (size_t i = 0; i < n; ++i)
                start[i] = (rng() & 3) == 0 ? uint8_t{0} : static_cast<uint8_t>(1 + rng() % 255);
            require_count({start, n}, reference(start, n));
        }
    }
    // A longer view that ends at the page boundary, with each start alignment.
    for (size_t shift = 0; shift < 8; ++shift) {
        const size_t n = page - 8 + shift;
        uint8_t* const start = mid + page - n;
        std::fill(start, start + n, uint8_t{0xFF});
        require_count({start, n}, n);
    }
    munmap(raw, 3 * page);
}
#endif

}  // namespace zilkworm
