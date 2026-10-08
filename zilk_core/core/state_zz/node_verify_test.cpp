// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Witness trie nodes are verified by DirectState::find_node_rlp(): a node is used only when its keccak
// is the hash it was asked for. The compare is keccak256_equals() / ethash_keccak256_eq(), which on
// the guest leaves the digest in the Keccak state and compares it there. A compare that accepted a
// wrong digest would let a forged witness node into the trie, and nothing but a test with a forged
// node can show it: honest witnesses never mismatch. So these cases forge nodes, and keys, and
// require them to be rejected, and compare the equality functions with keccak + memcmp over the
// sizes around the short/long boundary (136 bytes) and all alignments of both arguments.
//
// The native build runs the host branch of both functions (the guest branch compares in the
// Keccak state through CSRs, and runs only in a guest, where a probe compares it with
// ethash_keccak256() plus memcmp).

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/keccak_prefix.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

// Around the single-block / multi-block boundary (136), the 4 and 8 byte word boundaries (1..40),
// two blocks (271..273 = 2 * 136 +- 1), the full branch (532) and a few more blocks (600).
std::vector<size_t> node_sizes() {
    std::vector<size_t> s;
    for (size_t i = 0; i <= 40; ++i) s.push_back(i);
    for (size_t i : {63u, 64u, 65u, 127u, 128u, 134u, 135u, 136u, 137u, 138u, 271u, 272u, 273u, 408u, 532u, 600u, 700u})
        s.push_back(i);
    return s;
}

std::array<uint8_t, 32> keccak_of(const uint8_t* data, size_t size) {
    const ethash::hash256 h = ethash_keccak256(data, size);
    std::array<uint8_t, 32> out;
    std::memcpy(out.data(), h.bytes, 32);
    return out;
}

Bytes random_bytes(std::mt19937_64& rng, size_t n) {
    Bytes b(n, 0);
    for (auto& x : b) x = static_cast<uint8_t>(rng());
    return b;
}

bytes32 to_b32(const std::array<uint8_t, 32>& a) {
    bytes32 b;
    std::memcpy(b.bytes, a.data(), 32);
    return b;
}

// Both equality functions agree with `keccak(data) == expected` for this input: true for the real
// hash, false for the hash with any one byte changed, at every alignment of expected.
void check_equals(const uint8_t* data, size_t size, std::mt19937_64& rng, bool every_flip) {
    const std::array<uint8_t, 32> good = keccak_of(data, size);
    // expected buffers at offset 0..3 into an aligned block.
    alignas(8) uint8_t eb[48];
    for (size_t eoff = 0; eoff < 4; ++eoff) {
        uint8_t* e = eb + eoff;
        std::memcpy(e, good.data(), 32);
        INFO("size " << size << " expected offset " << eoff);
        REQUIRE(ethash_keccak256_eq(e, data, size));
        REQUIRE(keccak256_equals(ByteView{data, size}, e));
        if (every_flip) {
            for (size_t i = 0; i < 32; ++i) {
                e[i] ^= 0x01;
                INFO("flipped byte " << i);
                REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
                REQUIRE_FALSE(keccak256_equals(ByteView{data, size}, e));
                e[i] ^= 0x01;
                // The top bit too, and the whole byte.
                e[i] ^= 0x80;
                REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
                e[i] ^= 0x80;
                e[i] = static_cast<uint8_t>(~e[i]);
                REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
                e[i] = static_cast<uint8_t>(~e[i]);
            }
        } else {
            const size_t i = rng() % 32;
            e[i] ^= 0x10;
            REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
            REQUIRE_FALSE(keccak256_equals(ByteView{data, size}, e));
            e[i] ^= 0x10;
        }
        // The digest of other data, and an all-zero and all-ones expected.
        std::memset(e, 0, 32);
        REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
        std::memset(e, 0xff, 32);
        REQUIRE_FALSE(ethash_keccak256_eq(e, data, size));
        // Equal after the 32 bytes: the bytes after expected are not read.
        std::memcpy(e, good.data(), 32);
        std::memset(e + 32, 0xa5, 16 - eoff);
        REQUIRE(ethash_keccak256_eq(e, data, size));
    }
}

// A one-entry-per-node witness store: the entry's key is `key`, its payload is `payload` (key
// == keccak(payload) for an honest entry).
struct Entry {
    bytes32 key;
    Bytes payload;
};

std::vector<uint8_t> build_node_store(const std::vector<Entry>& entries) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& e : entries) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, e.key, ByteView{e.payload.data(), e.payload.size()});
        nb.add(hash_key8(e.key), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

struct Witness {
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, {}, {});
    std::vector<uint8_t> store;
    DirectState state;
    explicit Witness(const std::vector<Entry>& entries)
        : store{build_node_store(entries)}, state{std::span<uint8_t>{prestate}, std::span<uint8_t>{store}} {}
};

// The ways a node is looked up: the plain form (ext child, init_from_root), the snapshot form with a
// bytes32 key and with the plain byte array unfold_slot passes, and the snapshot form that actually
// asks for a snapshot (a full 532-byte branch, which takes kprefix::verify_and_snap()).
enum class Form { kPlain, kSnapBytes32, kSnapArray, kSnapSlot };
constexpr Form kForms[] = {Form::kPlain, Form::kSnapBytes32, Form::kSnapArray, Form::kSnapSlot};

std::optional<ByteView> lookup(const DirectState& s, const bytes32& key, Form f) {
    constexpr auto no_snap = [] { return kprefix::SnapRequest{kprefix::kNoSlot, 0}; };
    switch (f) {
        case Form::kPlain:
            return s.find_node_rlp(key);
        case Form::kSnapBytes32:
            return s.find_node_rlp(key, no_snap);
        case Form::kSnapArray: {
            alignas(8) uint8_t k[32];
            std::memcpy(k, key.bytes, 32);
            return s.find_node_rlp(k, no_snap);
        }
        case Form::kSnapSlot:
            // Slot 6, row 5: two blocks are saved for a full branch; any other node hashes plainly.
            return s.find_node_rlp(key, [] { return kprefix::SnapRequest{6, 5}; });
    }
    return std::nullopt;
}

const char* form_name(Form f) {
    switch (f) {
        case Form::kPlain: return "plain";
        case Form::kSnapBytes32: return "snap bytes32";
        case Form::kSnapArray: return "snap array";
        case Form::kSnapSlot: return "snap slot";
    }
    return "?";
}

}  // namespace

TEST_CASE("keccak equals: the known hash of the empty input and of abc", "[keccak][nodeverify]") {
    static constexpr uint8_t kEmpty[32] = {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d,
                                           0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82,
                                           0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70};
    static constexpr uint8_t kAbc[32] = {0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b,
                                         0xa8, 0x26, 0xc8, 0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64,
                                         0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45};
    alignas(8) uint8_t e[32];
    std::memcpy(e, kEmpty, 32);
    CHECK(ethash_keccak256_eq(e, nullptr, 0));
    CHECK(keccak256_equals(ByteView{}, e));
    e[31] ^= 1;
    CHECK_FALSE(ethash_keccak256_eq(e, nullptr, 0));
    std::memcpy(e, kAbc, 32);
    CHECK(ethash_keccak256_eq(e, reinterpret_cast<const uint8_t*>("abc"), 3));
    CHECK_FALSE(ethash_keccak256_eq(e, reinterpret_cast<const uint8_t*>("abd"), 3));
    CHECK_FALSE(ethash_keccak256_eq(e, reinterpret_cast<const uint8_t*>("abc"), 2));
}

TEST_CASE("keccak equals: agrees with keccak and memcmp at every size and alignment", "[keccak][nodeverify]") {
    std::mt19937_64 rng(101);
    alignas(8) static uint8_t block[720 + 8];
    for (auto& x : block) x = static_cast<uint8_t>(rng());
    // Every size 0..700 at every data alignment; the full set of single-byte flips at each size, and
    // all four expected alignments.
    for (size_t size = 0; size <= 700; ++size) {
        for (size_t doff = 0; doff < 4; ++doff) {
            // Re-randomize so that equal-looking prefixes at different sizes are not the same input.
            for (size_t i = 0; i < size; ++i) block[doff + i] = static_cast<uint8_t>(rng());
            check_equals(block + doff, size, rng, /*every_flip=*/doff == size % 4);
        }
    }
}

TEST_CASE("keccak equals: random inputs against a random expected are rejected", "[keccak][nodeverify]") {
    std::mt19937_64 rng(102);
    alignas(8) static uint8_t block[720 + 8];
    alignas(8) uint8_t e[40];
    for (int trial = 0; trial < 20000; ++trial) {
        const size_t size = rng() % 701;
        const size_t doff = rng() % 4;
        for (size_t i = 0; i < size; ++i) block[doff + i] = static_cast<uint8_t>(rng());
        const size_t eoff = rng() % 4;
        for (size_t i = 0; i < 32; ++i) e[eoff + i] = static_cast<uint8_t>(rng());
        const bool want = std::memcmp(keccak_of(block + doff, size).data(), e + eoff, 32) == 0;
        REQUIRE(want == false);
        REQUIRE(ethash_keccak256_eq(e + eoff, block + doff, size) == want);
        REQUIRE(keccak256_equals(ByteView{block + doff, size}, e + eoff) == want);
    }
}

TEST_CASE("keccak equals: a hash that differs from the real one in one word, whichever word", "[keccak][nodeverify]") {
    // 8 words of the digest: a compare that stops early (7 words) or reads the wrong ones passes
    // every flip but one of these.
    std::mt19937_64 rng(103);
    for (const size_t size : node_sizes()) {
        const Bytes data = random_bytes(rng, size);
        const auto good = keccak_of(data.data(), size);
        alignas(8) uint8_t e[32];
        for (size_t w = 0; w < 8; ++w) {
            for (size_t b = 0; b < 4; ++b) {
                std::memcpy(e, good.data(), 32);
                e[4 * w + b] ^= 0x01;
                INFO("size " << size << " word " << w << " byte " << b);
                REQUIRE_FALSE(ethash_keccak256_eq(e, data.data(), size));
                REQUIRE_FALSE(keccak256_equals(ByteView{data.data(), size}, e));
                // Two words wrong at once.
                e[(4 * w + 20 + b) % 32] ^= 0x40;
                REQUIRE_FALSE(ethash_keccak256_eq(e, data.data(), size));
            }
        }
    }
}

TEST_CASE("find_node_rlp: honest nodes of every size are found, in every lookup form", "[state][nodeverify]") {
    std::mt19937_64 rng(104);
    std::vector<Entry> entries;
    for (const size_t size : node_sizes()) {
        Entry e;
        e.payload = random_bytes(rng, size);
        e.key = to_b32(keccak_of(e.payload.data(), size));
        entries.push_back(std::move(e));
    }
    for (const Form f : kForms) {
        INFO("form " << form_name(f));
        Witness w{entries};
        kprefix::clear_tags();
        for (int pass = 0; pass < 2; ++pass) {  // the second pass is served by the verified bit
            for (const Entry& e : entries) {
                INFO("size " << e.payload.size() << " pass " << pass);
                const auto got = lookup(w.state, e.key, f);
                REQUIRE(got.has_value());
                REQUIRE(got->size() == e.payload.size());
                REQUIRE(std::memcmp(got->data(), e.payload.data(), e.payload.size()) == 0);
            }
        }
        kprefix::clear_tags();
    }
}

TEST_CASE("find_node_rlp: a node with any one payload byte changed is rejected, and stays rejected",
          "[state][nodeverify][forged]") {
    std::mt19937_64 rng(105);
    // One entry per (size, flipped position), each under the hash of its own honest payload, so the key is
    // right and only the payload is forged.
    std::vector<Entry> forged;
    std::vector<Entry> honest;
    for (const size_t size : node_sizes()) {
        if (size == 0) continue;  // no byte to flip
        // Every position for small nodes and the block boundaries, a spread of positions beyond.
        const bool all = size <= 40 || size == 135 || size == 136 || size == 137 || size == 272 || size == 532;
        for (size_t pos = 0; pos < size; ++pos) {
            if (!all && pos % 7 != 0 && pos + 1 != size) continue;
            Entry e;
            e.payload = random_bytes(rng, size);
            e.key = to_b32(keccak_of(e.payload.data(), size));
            honest.push_back(e);
            e.payload[pos] ^= (pos & 1) ? 0x80 : 0x01;
            forged.push_back(std::move(e));
        }
    }
    REQUIRE(forged.size() > 1500);
    for (const Form f : kForms) {
        INFO("form " << form_name(f));
        Witness w{forged};
        kprefix::clear_tags();
        for (int pass = 0; pass < 2; ++pass) {  // the verified bit is never set by a failure
            for (size_t i = 0; i < forged.size(); ++i) {
                INFO("entry " << i << " size " << forged[i].payload.size() << " pass " << pass);
                REQUIRE_FALSE(lookup(w.state, forged[i].key, f).has_value());
            }
        }
        // The honest twin of each is found in a store that has it (control: the lookup is not rejecting everything).
        Witness h{honest};
        for (const Entry& e : honest) REQUIRE(lookup(h.state, e.key, f).has_value());
        kprefix::clear_tags();
    }
}

TEST_CASE("find_node_rlp: a key that is the real hash with any one byte changed is rejected",
          "[state][nodeverify][forged]") {
    std::mt19937_64 rng(106);
    // The entry is filed under (and looked up by) keccak(payload) with byte i changed: the lookup
    // finds the entry, and only the hash compare can reject it. Byte i is in word i / 4 of the 8.
    std::vector<Entry> forged;
    for (const size_t size : node_sizes()) {
        for (size_t i = 0; i < 32; ++i) {
            Entry e;
            e.payload = random_bytes(rng, size);
            auto k = keccak_of(e.payload.data(), size);
            k[i] ^= (i & 1) ? 0xff : 0x01;
            e.key = to_b32(k);
            forged.push_back(std::move(e));
        }
    }
    for (const Form f : kForms) {
        INFO("form " << form_name(f));
        Witness w{forged};
        kprefix::clear_tags();
        for (int pass = 0; pass < 2; ++pass) {
            for (size_t i = 0; i < forged.size(); ++i) {
                INFO("entry " << i << " size " << forged[i].payload.size() << " flipped byte " << i % 32 << " pass " << pass);
                REQUIRE_FALSE(lookup(w.state, forged[i].key, f).has_value());
            }
        }
        kprefix::clear_tags();
    }
}

TEST_CASE("find_node_rlp: a forged node leaves an honest one verifiable and does not poison its bit",
          "[state][nodeverify][forged]") {
    // Entries sit next to each other in the store, and the verified bit is per 8 bytes of the store: a
    // rejected node must not make its neighbours (or itself later, in an honest store) pass unchecked.
    std::mt19937_64 rng(107);
    std::vector<Entry> entries;
    for (int i = 0; i < 64; ++i) {
        const size_t size = 1 + rng() % 600;
        Entry e;
        e.payload = random_bytes(rng, size);
        e.key = to_b32(keccak_of(e.payload.data(), size));
        if (i % 2) e.payload[rng() % size] ^= 0x20;  // odd entries are forged
        entries.push_back(std::move(e));
    }
    for (const Form f : kForms) {
        Witness w{entries};
        kprefix::clear_tags();
        for (int pass = 0; pass < 3; ++pass)
            for (size_t i = 0; i < entries.size(); ++i)
                CHECK(lookup(w.state, entries[i].key, f).has_value() == (i % 2 == 0));
        kprefix::clear_tags();
    }
}
