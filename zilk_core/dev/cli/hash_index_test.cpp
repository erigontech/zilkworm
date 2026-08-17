// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// HashIndex unit tests (zilkworm.tests target).
//
// HashIndex is the HashState backend's in-guest replacement for MphfMap on the SSZ
// input path: a plain open-addressed hash table instead of a serialized minimal
// perfect hash. It reuses the SAME key8 derivations (hash_key8 for 32-byte hashes,
// addr_key8 for 20-byte addresses) and the same mix64_body mixer, so two distinct keys
// can land in the same home bucket. The lookup's soundness therefore rests on the
// FULL-KEY memcmp performed at every occupied bucket the probe visits — a collision
// must never surface the wrong key's offset. The forced-collision cases below construct
// keys that share a key8 (and thus a home bucket) and confirm each still resolves to
// its own value, and that an absent key stops at the empty sentinel.

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/hash_index.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using zilkworm::HashIndex;
using zilkworm::addr_key8;
using zilkworm::hash_key8;

namespace {

// A 32-byte key: `first8` occupies the low 8 bytes (which is exactly what hash_key8
// reads), so keys that share `first8` share a key8 and a home bucket. `tail_fill`
// varies the remaining 24 bytes to make full keys distinct.
[[nodiscard]] std::array<uint8_t, 32> make_key32(uint64_t first8, uint8_t tail_fill) {
    std::array<uint8_t, 32> k{};
    std::memcpy(k.data(), &first8, 8);
    std::memset(k.data() + 8, tail_fill, 24);
    return k;
}

// A 20-byte address. addr_key8 mixes the low 7 bytes with byte 19, so keys sharing
// `low7` and `byte19` share a key8; the free middle bytes (7..18) carry `mid_fill`.
[[nodiscard]] std::array<uint8_t, 20> make_addr(uint64_t low7, uint8_t byte19, uint8_t mid_fill) {
    std::array<uint8_t, 20> a{};
    std::memcpy(a.data(), &low7, 7);
    std::memset(a.data() + 7, mid_fill, 12);  // bytes 7..18 do not feed addr_key8
    a[19] = byte19;
    return a;
}

[[nodiscard]] inline auto ref32(const std::array<uint8_t, 32>& a) -> const uint8_t (&)[32] {
    return reinterpret_cast<const uint8_t (&)[32]>(*a.data());
}
[[nodiscard]] inline auto ref20(const std::array<uint8_t, 20>& a) -> const uint8_t (&)[20] {
    return reinterpret_cast<const uint8_t (&)[20]>(*a.data());
}

}  // namespace

// Basic contract: distinct keys resolve to their own offsets, absent keys miss.
TEST_CASE("HashIndex basic insert and find (32-byte keys)", "[hash_index]") {
    HashIndex<32, &hash_key8> idx{16};

    std::array<std::array<uint8_t, 32>, 8> keys;
    for (uint32_t i = 0; i < keys.size(); ++i) keys[i] = make_key32(0x1000ULL + i, 0xCD);

    for (uint32_t i = 0; i < keys.size(); ++i)
        CHECK(idx.insert(ref32(keys[i]), i + 1u));  // offsets are 1-based (0 == empty)

    CHECK(idx.size() == keys.size());
    for (uint32_t i = 0; i < keys.size(); ++i) {
        auto off = idx.find(ref32(keys[i]));
        REQUIRE(off.has_value());
        CHECK(*off == i + 1u);
    }

    // A key never inserted misses.
    const auto absent = make_key32(0xDEAD0000ULL, 0xCD);
    CHECK_FALSE(idx.find(ref32(absent)).has_value());

    // offset 0 is the empty sentinel and is rejected by insert.
    const auto bad = make_key32(0x2000ULL, 0x01);
    CHECK_FALSE(idx.insert(ref32(bad), HashIndex<32, &hash_key8>::kEmptyOffset));
    CHECK_FALSE(idx.find(ref32(bad)).has_value());
}

// The safety gate: two keys sharing a key8 land on the same home bucket, are separated
// by linear probing, and the full-key memcmp routes each lookup to its own value — a
// collision never returns the other key's offset.
TEST_CASE("HashIndex forced collision resolved by probe + full-key compare", "[hash_index]") {
    HashIndex<32, &hash_key8> idx{16};

    const auto k1 = make_key32(0x51DE01ULL, 0x11);
    const auto k2 = make_key32(0x51DE01ULL, 0x22);  // same first8 -> same home bucket
    REQUIRE(idx.index_of(hash_key8(ref32(k1))) == idx.index_of(hash_key8(ref32(k2))));
    REQUIRE(std::memcmp(k1.data(), k2.data(), 32) != 0);  // but distinct full keys

    REQUIRE(idx.insert(ref32(k1), 111u));
    REQUIRE(idx.insert(ref32(k2), 222u));
    CHECK(idx.size() == 2u);

    auto o1 = idx.find(ref32(k1));
    auto o2 = idx.find(ref32(k2));
    REQUIRE(o1.has_value());
    REQUIRE(o2.has_value());
    CHECK(*o1 == 111u);  // full-key memcmp keeps k1 -> 111, never 222
    CHECK(*o2 == 222u);

    // A third key sharing the same home bucket but never inserted must probe past the
    // two occupied buckets, reach the empty sentinel, and miss.
    const auto k3 = make_key32(0x51DE01ULL, 0x33);
    CHECK_FALSE(idx.find(ref32(k3)).has_value());

    // Re-inserting an existing key overwrites its offset in place (no duplicate).
    REQUIRE(idx.insert(ref32(k1), 999u));
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref32(k1)) == 999u);
}

// A lookup whose home bucket is empty is a definitive miss, decided at the sentinel
// without scanning the rest of the table.
TEST_CASE("HashIndex not-found stops at the empty sentinel", "[hash_index]") {
    HashIndex<32, &hash_key8> empty{16};
    const auto k = make_key32(0x1234ULL, 0xAA);
    CHECK_FALSE(empty.find(ref32(k)).has_value());  // wholly empty table

    HashIndex<32, &hash_key8> idx{16};
    REQUIRE(idx.insert(ref32(k), 7u));
    // A key whose home bucket differs from k's lands on an untouched (empty) bucket.
    for (uint32_t seed = 0; seed < 256; ++seed) {
        const auto other = make_key32(0x9000ULL + seed, 0xBB);
        if (idx.index_of(hash_key8(ref32(other))) != idx.index_of(hash_key8(ref32(k)))) {
            CHECK_FALSE(idx.find(ref32(other)).has_value());
            return;
        }
    }
    FAIL("could not find a key mapping to a different home bucket");
}

// Home bucket at the very end of the table forces probing to wrap to bucket 0.
TEST_CASE("HashIndex probing wraps around the table end", "[hash_index]") {
    HashIndex<32, &hash_key8> idx{3};  // -> capacity 8, mask 0b111
    const uint32_t last = idx.capacity() - 1u;

    // Find a key8 whose home bucket is the last one, then build three keys that share
    // it (same first8) but differ in the tail, so they occupy last, 0, 1 (wrapping).
    uint64_t first8 = 0;
    for (uint64_t x = 1;; ++x) {
        if (idx.index_of(hash_key8(ref32(make_key32(x, 0)))) == last) {
            first8 = x;
            break;
        }
        REQUIRE(x < (1u << 20));  // mix64_body reaches every bucket well within this
    }

    const auto a = make_key32(first8, 0xA1);
    const auto b = make_key32(first8, 0xA2);
    const auto c = make_key32(first8, 0xA3);
    REQUIRE(idx.index_of(hash_key8(ref32(a))) == last);
    REQUIRE(idx.index_of(hash_key8(ref32(b))) == last);
    REQUIRE(idx.index_of(hash_key8(ref32(c))) == last);

    REQUIRE(idx.insert(ref32(a), 1u));
    REQUIRE(idx.insert(ref32(b), 2u));  // wraps to bucket 0
    REQUIRE(idx.insert(ref32(c), 3u));  // wraps to bucket 1
    CHECK(idx.size() == 3u);

    // Each still resolves to its own offset across the wrap.
    CHECK(*idx.find(ref32(a)) == 1u);
    CHECK(*idx.find(ref32(b)) == 2u);
    CHECK(*idx.find(ref32(c)) == 3u);
}

// Capacity is a power of two, at least kMinCapacity, and at least 2x the expected
// entry count, so the load factor after filling stays <= 0.5.
TEST_CASE("HashIndex load-factor sizing", "[hash_index]") {
    using Idx = HashIndex<32, &hash_key8>;
    for (uint32_t expected : {0u, 1u, 2u, 3u, 5u, 8u, 17u, 100u, 1000u}) {
        Idx idx{expected};
        const uint32_t cap = idx.capacity();
        CAPTURE(expected, cap);
        CHECK(std::has_single_bit(cap));       // power of two
        CHECK(cap >= Idx::kMinCapacity);
        if (expected != 0u) CHECK(cap >= 2u * expected);  // ~2x entries

        for (uint32_t i = 0; i < expected; ++i)
            REQUIRE(idx.insert(ref32(make_key32(0x30000ULL + i, 0xEE)), i + 1u));
        CHECK(idx.size() == expected);
        CHECK(2u * idx.size() <= cap);         // load factor <= 0.5
    }
}

// The same table over 20-byte addresses via addr_key8: basic resolution plus a forced
// collision (addresses sharing the addr_key8 low-7-bytes-and-byte-19 fingerprint).
TEST_CASE("HashIndex 20-byte address keys", "[hash_index]") {
    HashIndex<20, &addr_key8> idx{16};

    std::array<std::array<uint8_t, 20>, 6> addrs;
    for (uint32_t i = 0; i < addrs.size(); ++i) addrs[i] = make_addr(0x100ULL + i, 0x00, 0x77);
    for (uint32_t i = 0; i < addrs.size(); ++i) CHECK(idx.insert(ref20(addrs[i]), i + 1u));
    for (uint32_t i = 0; i < addrs.size(); ++i) {
        auto off = idx.find(ref20(addrs[i]));
        REQUIRE(off.has_value());
        CHECK(*off == i + 1u);
    }
    CHECK_FALSE(idx.find(ref20(make_addr(0xABCULL, 0x00, 0x77))).has_value());

    // Two addresses with an identical addr_key8 fingerprint (same low-7 + byte19,
    // different middle bytes) collide and are disambiguated by the full 20-byte compare.
    const auto c1 = make_addr(0x2200ULL, 0x5A, 0x01);
    const auto c2 = make_addr(0x2200ULL, 0x5A, 0x02);
    REQUIRE(addr_key8(ref20(c1)) == addr_key8(ref20(c2)));
    REQUIRE(std::memcmp(c1.data(), c2.data(), 20) != 0);
    REQUIRE(idx.insert(ref20(c1), 501u));
    REQUIRE(idx.insert(ref20(c2), 502u));
    CHECK(*idx.find(ref20(c1)) == 501u);
    CHECK(*idx.find(ref20(c2)) == 502u);
}
