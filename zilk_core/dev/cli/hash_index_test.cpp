// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// HashIndex unit tests (zilkworm.tests target): lookups, sizing, and full-key collision handling.
// See docs/hashstate.md, "HashIndex lookups and collisions".

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
using zilkworm::storage_key8;

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

// A 64-byte storage key addr_hash || slot_hash. storage_key8 is the XOR of the two
// halves' first 8 bytes, so keys whose (addr_prefix ^ slot_prefix) agree share a key8 and
// a home bucket; `fill` varies the other 48 bytes.
[[nodiscard]] std::array<uint8_t, 64> make_key64(uint64_t addr_prefix, uint64_t slot_prefix,
                                                 uint8_t fill) {
    std::array<uint8_t, 64> k{};
    std::memset(k.data(), fill, 64);
    std::memcpy(k.data(), &addr_prefix, 8);
    std::memcpy(k.data() + 32, &slot_prefix, 8);
    return k;
}

[[nodiscard]] inline auto ref32(const std::array<uint8_t, 32>& a) -> const uint8_t (&)[32] {
    return reinterpret_cast<const uint8_t (&)[32]>(*a.data());
}
[[nodiscard]] inline auto ref20(const std::array<uint8_t, 20>& a) -> const uint8_t (&)[20] {
    return reinterpret_cast<const uint8_t (&)[20]>(*a.data());
}
[[nodiscard]] inline auto ref64(const std::array<uint8_t, 64>& a) -> const uint8_t (&)[64] {
    return reinterpret_cast<const uint8_t (&)[64]>(*a.data());
}

// Every bucket starts 8-aligned, so sizeof pads the key + value up to a multiple of 8:
// 36 -> 40 for the account index's 32-byte key and u32 offset, 68 -> 72 for the storage
// index's 64-byte key, 24 for a 20-byte address key, and 48 unchanged for the node and
// code stores' 32-byte key with a 16-byte view value.
struct View16 {
    const uint8_t* data = nullptr;
    uint32_t size = 0;
    friend bool operator==(const View16&, const View16&) = default;
};
static_assert(HashIndex<32, &hash_key8>::bucket_bytes() == 40);
static_assert(HashIndex<64, &storage_key8>::bucket_bytes() == 72);
static_assert(HashIndex<20, &addr_key8>::bucket_bytes() == 24);
static_assert(HashIndex<32, &hash_key8, View16>::bucket_bytes() == 48);

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
    CHECK_FALSE(idx.insert(ref32(bad), HashIndex<32, &hash_key8>::kEmpty));
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
    CHECK(*o1 == 111u);  // the full-key compare keeps k1 -> 111, never 222
    CHECK(*o2 == 222u);
    // The raw-pointer lookup is the same probe.
    REQUIRE(idx.find_ptr(k1.data()).has_value());
    REQUIRE(idx.find_ptr(k2.data()).has_value());
    CHECK(*idx.find_ptr(k1.data()) == 111u);
    CHECK(*idx.find_ptr(k2.data()) == 222u);

    // A third key sharing the same home bucket but never inserted must probe past the
    // two occupied buckets, reach the empty sentinel, and miss.
    const auto k3 = make_key32(0x51DE01ULL, 0x33);
    CHECK_FALSE(idx.find(ref32(k3)).has_value());
    CHECK_FALSE(idx.find_ptr(k3.data()).has_value());

    // Re-inserting an existing key overwrites its offset in place (no duplicate): insert's
    // own full-key compare found the occupied bucket rather than claiming a new one.
    REQUIRE(idx.insert(ref32(k1), 999u));
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref32(k1)) == 999u);
    CHECK(*idx.find_ptr(k1.data()) == 999u);
    CHECK(*idx.find(ref32(k2)) == 222u);  // the colliding neighbour is untouched
}

// A lookup whose home bucket is empty is a definitive miss, decided at the sentinel
// without scanning the rest of the table.
TEST_CASE("HashIndex not-found stops at the empty sentinel", "[hash_index]") {
    HashIndex<32, &hash_key8> empty{16};
    const auto k = make_key32(0x1234ULL, 0xAA);
    CHECK_FALSE(empty.find(ref32(k)).has_value());  // wholly empty table
    CHECK_FALSE(empty.find_ptr(k.data()).has_value());

    HashIndex<32, &hash_key8> idx{16};
    REQUIRE(idx.insert(ref32(k), 7u));
    // A key whose home bucket differs from k's lands on an untouched (empty) bucket.
    for (uint32_t seed = 0; seed < 256; ++seed) {
        const auto other = make_key32(0x9000ULL + seed, 0xBB);
        if (idx.index_of(hash_key8(ref32(other))) != idx.index_of(hash_key8(ref32(k)))) {
            CHECK_FALSE(idx.find(ref32(other)).has_value());
            CHECK_FALSE(idx.find_ptr(other.data()).has_value());
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

    // Each still resolves to its own offset across the wrap, by array or by pointer.
    CHECK(*idx.find(ref32(a)) == 1u);
    CHECK(*idx.find(ref32(b)) == 2u);
    CHECK(*idx.find(ref32(c)) == 3u);
    CHECK(*idx.find_ptr(a.data()) == 1u);
    CHECK(*idx.find_ptr(b.data()) == 2u);
    CHECK(*idx.find_ptr(c.data()) == 3u);
}

// find_ptr reads the key in place from the caller's bytes at any alignment: from offsets
// 1, 3, 5 and 7 of an 8-aligned buffer it gives the same hit (and value) or miss as the
// array-reference find does from the key's own storage.
TEST_CASE("HashIndex find_ptr through an unaligned pointer", "[hash_index]") {
    HashIndex<32, &hash_key8> idx{16};
    const auto present = make_key32(0xA11CE000ULL, 0x5A);
    const auto absent = make_key32(0xA11CE000ULL, 0x5B);  // same home bucket, never inserted
    const auto elsewhere = make_key32(0xB0B0B0B0ULL, 0x5A);
    REQUIRE(idx.insert(ref32(present), 42u));
    REQUIRE(idx.insert(ref32(elsewhere), 43u));
    REQUIRE(idx.index_of(hash_key8(ref32(present))) == idx.index_of(hash_key8(ref32(absent))));

    for (const std::size_t off : {std::size_t{1}, std::size_t{3}, std::size_t{5}, std::size_t{7}}) {
        CAPTURE(off);
        alignas(8) std::array<uint8_t, 40> buf{};
        REQUIRE(reinterpret_cast<std::uintptr_t>(buf.data() + off) % 8 != 0);  // truly unaligned

        std::memcpy(buf.data() + off, present.data(), 32);
        const auto hit = idx.find_ptr(buf.data() + off);
        REQUIRE(hit.has_value());
        CHECK(*hit == 42u);
        CHECK(*hit == *idx.find(ref32(present)));

        std::memcpy(buf.data() + off, elsewhere.data(), 32);
        REQUIRE(idx.find_ptr(buf.data() + off).has_value());
        CHECK(*idx.find_ptr(buf.data() + off) == 43u);

        std::memcpy(buf.data() + off, absent.data(), 32);
        CHECK_FALSE(idx.find_ptr(buf.data() + off).has_value());
        CHECK_FALSE(idx.find(ref32(absent)).has_value());
    }
}

// The full-key gate compares every byte of the key, not only the words that feed the
// key8: a probe key differing from a stored key in any single bit, at any byte position,
// misses, by array and by pointer; the unchanged key hits.
TEST_CASE("HashIndex full-key compare covers every byte of a 32-byte key", "[hash_index]") {
    HashIndex<32, &hash_key8> idx{16};
    const auto base = make_key32(0xF00DF00DULL, 0x3C);
    REQUIRE(idx.insert(ref32(base), 5u));
    CHECK(*idx.find(ref32(base)) == 5u);
    CHECK(*idx.find_ptr(base.data()) == 5u);

    for (std::size_t pos = 0; pos < 32; ++pos) {
        for (const uint8_t bit : {uint8_t{0x01}, uint8_t{0x80}}) {
            CAPTURE(pos, bit);
            auto flipped = base;
            flipped[pos] = static_cast<uint8_t>(flipped[pos] ^ bit);
            CHECK_FALSE(idx.find(ref32(flipped)).has_value());
            CHECK_FALSE(idx.find_ptr(flipped.data()).has_value());
            // Nor does insert mistake it for the stored key: it claims its own bucket.
            HashIndex<32, &hash_key8> two{16};
            REQUIRE(two.insert(ref32(base), 5u));
            REQUIRE(two.insert(ref32(flipped), 6u));
            CHECK(two.size() == 2u);
            CHECK(*two.find(ref32(base)) == 5u);
            CHECK(*two.find(ref32(flipped)) == 6u);
        }
    }
}

// The storage index's 64-byte keys under storage_key8 (the XOR of the two halves' first 8
// bytes). Two keys with the same XOR share a key8 and a home bucket while their leading
// word differs, so a hit here proves the gate compares the stored key against the probe
// key (word by word, all eight words), never the stored key's first word against the key8.
TEST_CASE("HashIndex 64-byte storage keys", "[hash_index]") {
    HashIndex<64, &storage_key8> idx{16};

    const auto k1 = make_key64(0x1111ULL, 0x2222ULL, 0x01);
    const auto k2 = make_key64(0x1111ULL ^ 0xFFULL, 0x2222ULL ^ 0xFFULL, 0x01);  // same XOR
    REQUIRE(storage_key8(ref64(k1)) == storage_key8(ref64(k2)));
    REQUIRE(idx.index_of(storage_key8(ref64(k1))) == idx.index_of(storage_key8(ref64(k2))));
    REQUIRE(std::memcmp(k1.data(), k2.data(), 64) != 0);

    REQUIRE(idx.insert(ref64(k1), 11u));
    REQUIRE(idx.insert(ref64(k2), 22u));
    CHECK(idx.size() == 2u);

    REQUIRE(idx.find(ref64(k1)).has_value());
    REQUIRE(idx.find(ref64(k2)).has_value());
    CHECK(*idx.find(ref64(k1)) == 11u);
    CHECK(*idx.find(ref64(k2)) == 22u);
    CHECK(*idx.find_ptr(k1.data()) == 11u);
    CHECK(*idx.find_ptr(k2.data()) == 22u);

    // A third key on the same home bucket, never inserted, misses at the sentinel.
    const auto k3 = make_key64(0x1111ULL ^ 0xAAULL, 0x2222ULL ^ 0xAAULL, 0x01);
    REQUIRE(idx.index_of(storage_key8(ref64(k3))) == idx.index_of(storage_key8(ref64(k1))));
    CHECK_FALSE(idx.find(ref64(k3)).has_value());
    CHECK_FALSE(idx.find_ptr(k3.data()).has_value());

    // A single flipped bit anywhere in the 64 bytes (the slot half included) misses.
    for (std::size_t pos = 0; pos < 64; ++pos) {
        CAPTURE(pos);
        auto flipped = k1;
        flipped[pos] = static_cast<uint8_t>(flipped[pos] ^ 0x01);
        CHECK_FALSE(idx.find(ref64(flipped)).has_value());
        CHECK_FALSE(idx.find_ptr(flipped.data()).has_value());
    }

    // The same probe from an unaligned pointer.
    alignas(8) std::array<uint8_t, 72> buf{};
    std::memcpy(buf.data() + 3, k2.data(), 64);
    REQUIRE(idx.find_ptr(buf.data() + 3).has_value());
    CHECK(*idx.find_ptr(buf.data() + 3) == 22u);

    // Overwrite in place keeps a single entry.
    REQUIRE(idx.insert(ref64(k2), 33u));
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref64(k2)) == 33u);
    CHECK(*idx.find(ref64(k1)) == 11u);
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

// reserve pre-sizes an EMPTY table by the constructor's rule (a power of two, at least
// kMinCapacity and at least 2x the expected count, exactly the capacity the constructor
// would pick for that count), so the `expected` inserts that follow trigger no growth and
// end at load factor <= 0.5. It never shrinks, and it is a no-op once the table holds an
// entry.
TEST_CASE("HashIndex reserve pre-sizes an empty table", "[hash_index]") {
    using Idx = HashIndex<32, &hash_key8>;
    for (uint32_t expected : {0u, 1u, 2u, 3u, 5u, 8u, 17u, 100u, 1000u, 5000u}) {
        Idx idx{1};  // the smallest table (kMinCapacity) before the reserve
        REQUIRE(idx.capacity() == Idx::kMinCapacity);
        idx.reserve(expected);
        const uint32_t cap = idx.capacity();
        CAPTURE(expected, cap);
        CHECK(std::has_single_bit(cap));       // power of two
        CHECK(cap >= Idx::kMinCapacity);
        if (expected != 0u) CHECK(cap >= 2u * expected);  // ~2x entries
        CHECK(cap == Idx{expected}.capacity());  // the constructor's rule exactly

        // The `expected` inserts fit without a single growth: the table never shrinks, so
        // an unchanged capacity at the end proves no doubling happened on the way.
        for (uint32_t i = 0; i < expected; ++i)
            REQUIRE(idx.insert(ref32(make_key32(0x50000ULL + i, 0xEE)), i + 1u));
        CHECK(idx.capacity() == cap);
        CHECK(idx.size() == expected);
        CHECK(2u * idx.size() <= cap);         // load factor <= 0.5
        for (uint32_t i = 0; i < expected; ++i) {
            auto off = idx.find(ref32(make_key32(0x50000ULL + i, 0xEE)));
            REQUIRE(off.has_value());
            CHECK(*off == i + 1u);
        }
    }

    // Never shrinks: a smaller (or equal) reserve on an empty table keeps the capacity.
    Idx big{1};
    big.reserve(1000u);
    const uint32_t cap1000 = big.capacity();
    CHECK(cap1000 == Idx{1000u}.capacity());
    big.reserve(10u);
    CHECK(big.capacity() == cap1000);
    big.reserve(1000u);
    CHECK(big.capacity() == cap1000);
    big.reserve(0u);
    CHECK(big.capacity() == cap1000);

    // A no-op once the table holds an entry, even for a much larger count: the entry stays
    // where it is and findable.
    Idx used{1};
    const auto k = make_key32(0x7777ULL, 0x01);
    REQUIRE(used.insert(ref32(k), 1u));
    const uint32_t cap_used = used.capacity();
    used.reserve(10000u);
    CHECK(used.capacity() == cap_used);
    CHECK(used.size() == 1u);
    REQUIRE(used.find(ref32(k)).has_value());
    CHECK(*used.find(ref32(k)) == 1u);
}

// try_insert is first-wins: one probe either claims an empty bucket (kInserted) or finds
// the key present and leaves its value alone (kExisted), where insert overwrites. It keeps
// insert's sentinel rejection and growth backstop.
TEST_CASE("HashIndex try_insert is first-wins where insert overwrites", "[hash_index]") {
    using Idx = HashIndex<32, &hash_key8>;
    Idx idx{16};
    const auto k1 = make_key32(0x7E5701ULL, 0x11);
    const auto k2 = make_key32(0x7E5701ULL, 0x22);  // same home bucket, distinct full key
    REQUIRE(idx.index_of(hash_key8(ref32(k1))) == idx.index_of(hash_key8(ref32(k2))));
    REQUIRE(std::memcmp(k1.data(), k2.data(), 32) != 0);

    CHECK(idx.try_insert(ref32(k1), 111u) == Idx::Insert::kInserted);
    CHECK(idx.size() == 1u);
    CHECK(idx.try_insert(ref32(k1), 999u) == Idx::Insert::kExisted);  // first wins
    CHECK(idx.size() == 1u);
    REQUIRE(idx.find(ref32(k1)).has_value());
    CHECK(*idx.find(ref32(k1)) == 111u);

    // The colliding neighbour is a distinct key: claimed by probing past k1, never taken
    // for it, and its own repeat is first-wins too.
    CHECK(idx.try_insert(ref32(k2), 222u) == Idx::Insert::kInserted);
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref32(k1)) == 111u);
    CHECK(*idx.find(ref32(k2)) == 222u);
    CHECK(idx.try_insert(ref32(k2), 333u) == Idx::Insert::kExisted);
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref32(k2)) == 222u);

    // insert on a present key overwrites in place (its documented semantics, unchanged),
    // and try_insert afterwards still leaves that value alone.
    REQUIRE(idx.insert(ref32(k1), 555u));
    CHECK(idx.size() == 2u);
    CHECK(*idx.find(ref32(k1)) == 555u);
    CHECK(idx.try_insert(ref32(k1), 777u) == Idx::Insert::kExisted);
    CHECK(*idx.find(ref32(k1)) == 555u);

    // The empty sentinel is rejected and nothing is placed.
    const auto k3 = make_key32(0x7E5702ULL, 0x33);
    CHECK(idx.try_insert(ref32(k3), Idx::kEmpty) == Idx::Insert::kFull);
    CHECK(idx.size() == 2u);
    CHECK_FALSE(idx.find(ref32(k3)).has_value());

    // Growth backstop: filling past the hint doubles the table and every key stays
    // findable, with a repeat of each still reported as present.
    Idx small{1};  // kMinCapacity buckets
    const uint32_t cap0 = small.capacity();
    for (uint32_t i = 0; i < 20; ++i)
        REQUIRE(small.try_insert(ref32(make_key32(0x60000ULL + i, 0xAB)), i + 1u) ==
                Idx::Insert::kInserted);
    CHECK(small.capacity() > cap0);
    CHECK(small.size() == 20u);
    CHECK(2u * small.size() <= small.capacity());
    for (uint32_t i = 0; i < 20; ++i) {
        const auto k = make_key32(0x60000ULL + i, 0xAB);
        REQUIRE(small.find(ref32(k)).has_value());
        CHECK(*small.find(ref32(k)) == i + 1u);
        CHECK(small.try_insert(ref32(k), 0xFFu) == Idx::Insert::kExisted);
        CHECK(*small.find(ref32(k)) == i + 1u);
    }
    CHECK(small.size() == 20u);
}

// The same table over 20-byte addresses via addr_key8: basic resolution plus a forced
// collision (addresses sharing the addr_key8 low-7-bytes-and-byte-19 fingerprint).
// A bucket is claimed word by word from the probe key, and insert, try_insert and the
// growth rehash all go through that one claim: whatever the probe's alignment, the stored
// key must come out byte-exact in every word and the value whole. For the node store's
// shape (32-byte key, 16-byte view value) and the storage index's (64-byte key, u32
// value), every key claimed from an odd offset hits afterwards by array and by unaligned
// pointer with the value it was claimed with, a one-bit change in any word misses, and
// all of it survives a doubling of the table.
TEST_CASE("HashIndex claims a bucket byte-exact from an unaligned probe key", "[hash_index]") {
    SECTION("32-byte key, 16-byte view value") {
        using Idx = HashIndex<32, &hash_key8, View16>;
        Idx idx{1};  // kMinCapacity buckets: the 24 claims below force a growth rehash
        const uint32_t cap0 = idx.capacity();
        static const uint8_t payload[4] = {1, 2, 3, 4};
        std::array<std::array<uint8_t, 32>, 24> keys{};
        for (uint32_t i = 0; i < keys.size(); ++i) {
            keys[i] = make_key32(0x0C1A1100ULL + i, static_cast<uint8_t>(0xC0 + i));
            const std::size_t off = 1 + (i % 7);  // 1..7: never 8-aligned
            alignas(8) std::array<uint8_t, 40> buf{};
            REQUIRE(reinterpret_cast<std::uintptr_t>(buf.data() + off) % 8 != 0);
            std::memcpy(buf.data() + off, keys[i].data(), 32);
            const auto& probe = *reinterpret_cast<const uint8_t (*)[32]>(buf.data() + off);
            const View16 v{payload + (i % 4), 100u + i};
            if (i % 2 == 0) {
                REQUIRE(idx.try_insert(probe, v) == Idx::Insert::kInserted);
            } else {
                REQUIRE(idx.insert(probe, v));
            }
        }
        CHECK(idx.size() == keys.size());
        CHECK(idx.capacity() > cap0);  // grew: every entry was claimed again by the rehash
        for (uint32_t i = 0; i < keys.size(); ++i) {
            CAPTURE(i);
            const View16 want{payload + (i % 4), 100u + i};
            REQUIRE(idx.find(ref32(keys[i])).has_value());
            CHECK(*idx.find(ref32(keys[i])) == want);
            alignas(8) std::array<uint8_t, 40> buf{};
            std::memcpy(buf.data() + 3, keys[i].data(), 32);
            REQUIRE(idx.find_ptr(buf.data() + 3).has_value());
            CHECK(*idx.find_ptr(buf.data() + 3) == want);
            CHECK(idx.try_insert(ref32(keys[i]), View16{payload, 0xFFu}) == Idx::Insert::kExisted);
            CHECK(*idx.find(ref32(keys[i])) == want);
            // One bit off in the second, third or last word (none of which feeds the key8,
            // so the probe lands on the same home bucket) misses: the stored tail is exact.
            for (const std::size_t byte : {std::size_t{8}, std::size_t{16}, std::size_t{31}}) {
                CAPTURE(byte);
                auto flipped = keys[i];
                flipped[byte] ^= 0x01;
                CHECK_FALSE(idx.find(ref32(flipped)).has_value());
            }
        }
    }

    SECTION("64-byte key, u32 value") {
        using Idx = HashIndex<64, &storage_key8>;
        Idx idx{1};
        const uint32_t cap0 = idx.capacity();
        std::array<std::array<uint8_t, 64>, 24> keys{};
        for (uint32_t i = 0; i < keys.size(); ++i) {
            keys[i] = make_key64(0x5E7000ULL + i, 0x6E7000ULL + 3u * i, static_cast<uint8_t>(0x30 + i));
            const std::size_t off = 1 + (i % 7);
            alignas(8) std::array<uint8_t, 72> buf{};
            REQUIRE(reinterpret_cast<std::uintptr_t>(buf.data() + off) % 8 != 0);
            std::memcpy(buf.data() + off, keys[i].data(), 64);
            const auto& probe = *reinterpret_cast<const uint8_t (*)[64]>(buf.data() + off);
            if (i % 2 == 0) {
                REQUIRE(idx.try_insert(probe, 1000u + i) == Idx::Insert::kInserted);
            } else {
                REQUIRE(idx.insert(probe, 1000u + i));
            }
        }
        CHECK(idx.size() == keys.size());
        CHECK(idx.capacity() > cap0);
        for (uint32_t i = 0; i < keys.size(); ++i) {
            CAPTURE(i);
            REQUIRE(idx.find(ref64(keys[i])).has_value());
            CHECK(*idx.find(ref64(keys[i])) == 1000u + i);
            alignas(8) std::array<uint8_t, 72> buf{};
            std::memcpy(buf.data() + 5, keys[i].data(), 64);
            REQUIRE(idx.find_ptr(buf.data() + 5).has_value());
            CHECK(*idx.find_ptr(buf.data() + 5) == 1000u + i);
            // Bytes 8, 24, 40 and 63 sit in words that do not feed storage_key8 (which
            // folds bytes 0..7 and 32..39), so the flipped probe shares the home bucket.
            for (const std::size_t byte :
                 {std::size_t{8}, std::size_t{24}, std::size_t{40}, std::size_t{63}}) {
                CAPTURE(byte);
                auto flipped = keys[i];
                flipped[byte] ^= 0x01;
                CHECK_FALSE(idx.find(ref64(flipped)).has_value());
            }
        }
    }
}

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
