// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <array>
#include <cstdint>
#include <initializer_list>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm {

namespace {

bool decodes(std::initializer_list<uint8_t> path) {
    const std::vector<uint8_t> bytes{path};
    bool is_leaf{false};
    std::array<uint8_t, 64> nibbles{};
    uint8_t len{0};
    return hp_decode(silkworm::ByteView{bytes.data(), bytes.size()}, is_leaf, nibbles, len);
}

}  // namespace

TEST_CASE("hp_decode accepts only canonical hex-prefix paths", "[rlp_sw]") {
    CHECK(decodes({0x00, 0xab}));
    CHECK(decodes({0x1a, 0xbc}));
    CHECK(decodes({0x20, 0xab}));
    CHECK(decodes({0x3a, 0xbc}));
    CHECK_FALSE(decodes({0x40, 0xab}));
    CHECK_FALSE(decodes({0xf0, 0xab}));
    CHECK_FALSE(decodes({0x01, 0xab}));
    CHECK_FALSE(decodes({0x21, 0xab}));
}

}  // namespace zilkworm
