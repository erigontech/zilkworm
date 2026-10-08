// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// eq_bytes32 / eq_bytes20_u32 / lt_bytes32 replace hot memcmp calls; each must
// agree with memcmp for every deciding byte position and honor the alignment
// contracts stated in bytes_cmp.hpp (the test buffers are aligned accordingly).

#include <array>
#include <cstring>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/bytes_cmp.hpp>

using namespace zilkworm;

namespace {

// Deterministic byte pattern; avoids all-equal words without libc rand.
void fill(uint8_t* p, size_t n, uint64_t seed) {
    for (size_t i = 0; i < n; ++i) {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = static_cast<uint8_t>(seed >> 56);
    }
}

}  // namespace

TEST_CASE("eq_bytes32 equality and every deciding byte") {
    alignas(8) std::array<uint8_t, 32> a{};
    alignas(8) std::array<uint8_t, 32> b{};
    fill(a.data(), a.size(), 1);
    b = a;
    CHECK(eq_bytes32(a.data(), b.data()));
    for (size_t i = 0; i < 32; ++i) {
        b = a;
        b[i] ^= 0x01;
        CHECK_FALSE(eq_bytes32(a.data(), b.data()));
        CHECK_FALSE(eq_bytes32(b.data(), a.data()));
    }
}

TEST_CASE("eq_bytes20_u32 equality and every deciding byte") {
    alignas(4) std::array<uint8_t, 20> a{};
    alignas(4) std::array<uint8_t, 20> b{};
    fill(a.data(), a.size(), 2);
    b = a;
    CHECK(eq_bytes20_u32(a.data(), b.data()));
    for (size_t i = 0; i < 20; ++i) {
        b = a;
        b[i] ^= 0x80;
        CHECK_FALSE(eq_bytes20_u32(a.data(), b.data()));
        CHECK_FALSE(eq_bytes20_u32(b.data(), a.data()));
    }
}

TEST_CASE("lt_bytes32 equal inputs are not less") {
    alignas(8) std::array<uint8_t, 32> a{};
    fill(a.data(), a.size(), 3);
    CHECK_FALSE(lt_bytes32(a.data(), a.data()));
}

TEST_CASE("lt_bytes32 first differing byte decides at every position") {
    for (size_t i = 0; i < 32; ++i) {
        alignas(8) std::array<uint8_t, 32> lo{};
        alignas(8) std::array<uint8_t, 32> hi{};
        fill(lo.data(), lo.size(), 4 + i);
        hi = lo;
        lo[i] = 0x10;
        hi[i] = 0x20;
        // Contradicting suffix: bytes after i must not influence the result.
        for (size_t j = i + 1; j < 32; ++j) {
            lo[j] = 0xFF;
            hi[j] = 0x00;
        }
        CHECK(lt_bytes32(lo.data(), hi.data()));
        CHECK_FALSE(lt_bytes32(hi.data(), lo.data()));
    }
}

TEST_CASE("lt_bytes32 agrees with memcmp on random and shared-prefix pairs") {
    alignas(8) std::array<uint8_t, 32> a{};
    alignas(8) std::array<uint8_t, 32> b{};
    for (uint64_t s = 0; s < 500; ++s) {
        fill(a.data(), a.size(), 2 * s);
        b = a;
        // Even rounds: fully random pair. Odd rounds: keep a shared prefix of
        // s % 32 bytes — the storage-key shape (small ints, late divergence).
        fill(b.data() + (s % 2 ? s % 32 : 0), b.size() - (s % 2 ? s % 32 : 0), 2 * s + 1);
        const int m = std::memcmp(a.data(), b.data(), 32);
        CHECK(lt_bytes32(a.data(), b.data()) == (m < 0));
        CHECK(lt_bytes32(b.data(), a.data()) == (m > 0));
    }
}
