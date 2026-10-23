// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The 64-bit hex-prefix tail packs the last <=8 bytes from one swapped region word instead of
// one nibbles64::at() extraction per byte. Every length, leaf flag and parity must match the
// byte-wise reference byte for byte, flag byte included, and leave nothing past the body written.

#define ENCODE_HP_WORD_TAIL_TEST 1  // compiles the 64-bit branch on the host

#include <array>
#include <cstring>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/trie_zz/rlp_sw.hpp>

using namespace zilkworm;

namespace {

// A verbatim copy of encode_hp_path's generic byte-wise body (its #else branch), flag byte
// excluded; returns the number of body bytes written.
size_t ref_hp_body(uint8_t* out, const nibbles64& path, size_t n) {
    size_t i = (n & 1) ? 1 : 0, w = 0;
    for (; i + 1 < n; i += 2) out[w++] = static_cast<uint8_t>((path.at(i) << 4) | path.at(i + 1));
    if (i < n) out[w++] = static_cast<uint8_t>(path.at(i) << 4);
    return w;
}

void check_one(const nibbles64& p, bool leaf) {
    const size_t n = p.len;
    std::array<uint8_t, 96> fast{}, slow{};
    fast.fill(0xA5);
    slow.fill(0xA5);
    uint8_t* const end = encode_hp_path(fast.data(), p, leaf);
    std::array<uint8_t, 96> ref{};
    const size_t rw = ref_hp_body(ref.data(), p, n);
    const size_t bw = static_cast<size_t>(end - fast.data()) - 1;
    CHECK(bw == rw);
    CHECK(bw == n / 2);  // flag byte merges nibble 0 of odd paths
    const uint8_t flag = static_cast<uint8_t>((leaf ? 2 : 0) | ((n & 1) ? 1 : 0));
    CHECK(fast[0] == static_cast<uint8_t>((flag << 4) | ((n & 1) ? p.at(0) : 0)));
    CHECK(std::memcmp(fast.data() + 1, ref.data(), rw) == 0);
    for (size_t j = 1 + rw; j < fast.size(); ++j)
        CHECK(fast[j] == 0xA5);  // nothing written past the path bytes
}

}  // namespace

TEST_CASE("word tail equals byte-wise hex-prefix encoding", "[trie][rlp][encode][nibble]") {
    std::mt19937 rng(75);
    for (int leaf = 0; leaf <= 1; ++leaf)
        for (size_t n = 0; n <= 64; ++n)
            for (int rep = 0; rep < 8; ++rep) {
                nibbles64 p;
                p.len = static_cast<uint8_t>(n);
                for (size_t i = 0; i < n; ++i) p.set(i, static_cast<uint8_t>(rng() & 0xF));
                check_one(p, leaf != 0);
            }
}

TEST_CASE("word tail matches byte-wise on fixed nibble patterns", "[trie][rlp][encode][nibble]") {
    for (int leaf = 0; leaf <= 1; ++leaf)
        for (size_t n = 0; n <= 64; ++n) {
            for (int pat = 0; pat < 4; ++pat) {
                nibbles64 p;
                p.len = static_cast<uint8_t>(n);
                for (size_t i = 0; i < n; ++i) {
                    const uint8_t v = pat == 0 ? 0xF : pat == 1 ? 0x0 : pat == 2 ? static_cast<uint8_t>(i & 0xF) : static_cast<uint8_t>((i * 7 + 3) & 0xF);
                    p.set(i, v);
                }
                check_one(p, leaf != 0);
            }
        }
}
