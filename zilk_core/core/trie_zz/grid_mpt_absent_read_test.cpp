// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// GridMPT<true> regression tests: updates that read a key the trie does not have (no value to
// write; claimed as zero, 0x80, or as nothing), and lines that go away while the seek still
// climbs through them.
//
// A read of an absent key used to insert a leaf with an empty value at the point where the key
// leaves the trie, which folded away again. Folding it deleted it and every ancestor it left empty
// (cascade_delete), and the seek went on from lines it had just popped; and a branch left with a
// single child the walk had already folded could not absorb it, the new hash not being in the
// witness. A read of an absent key now inserts nothing, and a witness leaf without a value, the
// other way an empty line got into the grid, is rejected.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) { sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp}); };
    }
    for (const auto& [k, v] : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    }
    return hb.root_hash();
}

std::vector<uint8_t> build_node_store(const Bytes32Map& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : nodes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, rlp);
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

bytes32 key_from_hex(const char* s) {
    const auto b = silkworm::from_hex(s);
    REQUIRE((b && b->size() == 32));
    bytes32 k;
    std::memcpy(k.bytes, b->data(), 32);
    return k;
}

// A hashed trie key: the given nibbles, then `fill` repeated.
bytes32 key_with_nibbles(std::initializer_list<uint8_t> nibs, uint8_t fill) {
    bytes32 k{};
    size_t i = 0;
    for (uint8_t n : nibs) {
        k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? n << 4 : n);
        ++i;
    }
    for (; i < 64; ++i) k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? fill << 4 : fill);
    return k;
}

Bytes value(uint8_t v) { return Bytes{0x84, v, v, v, v}; }

// What an update claims as the value before the block for a key absent from the trie: a zero slot (0x80)
// or nothing. A claim of an empty value must not be a null view: a forged empty-valued leaf is compared
// against it.
enum class Claim { kZero, kNone };
const uint8_t kZeroRlp[1] = {0x80};

struct Update {
    bytes32 key;
    ByteView initial;
    Bytes current;  // empty: a read
};

// Runs `updates` (sorted here) against a complete witness of the trie `pre` (leaves as given, an
// empty value included) and returns the root. `valid`: the witness holds only nodes a trie can have,
// so the walk must not fail; otherwise it must.
bytes32 walk(const Bytes32Map& pre, std::vector<Update> updates, bool valid = true) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    std::ranges::sort(updates, [](const Update& a, const Update& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });
    std::vector<TrieNodeFlat> flat;  // must never reallocate: GridMPT keeps views into TrieNodeFlat::buf
    flat.reserve(updates.size());
    for (const auto& u : updates) {
        auto& node = flat.emplace_back(u.key);
        node.ext_initial = u.initial;
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(u.current.size());
        if (!u.current.empty()) std::memcpy(node.buf + 40, u.current.data(), u.current.size());
    }
    GridMPT<true> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({flat.data(), flat.size()});
    if (valid) {
        CHECK(trie.missing_count() == 0);
        CHECK_FALSE(trie.failed());
    } else {
        CHECK(trie.failed());
    }
    return got;
}

}  // namespace

// Two reads of absent keys that share 8 nibbles, after an insert: the second read split the first one's
// empty leaf into an extension over a branch of the two, all of it empty. The next update's seek folded
// both leaves, the cascade took the branch and the extension, and the seek went on to the popped
// extension's line and descended from it, into std::unreachable() in fold_line.
TEST_CASE("GridMPT<true> reads of absent keys that share a prefix", "[trie][gridmpt]") {
    const bytes32 k1 = key_from_hex("6d6c288fd01ac4893bdbcdc3b9717bba13a845056ba772398a7eaae0fffa47d9");
    const bytes32 a1 = key_from_hex("8600baa419999186f17a33e3b26008a6485f6a918223719d7d3a6f39092c4621");
    const bytes32 a2 = key_from_hex("8600baa43020cf1673e00210b7a2eccfc4fb8711dbda71bddfe0d69722b4aa79");
    const bytes32 k4 = key_from_hex("895ee3e68994cc766f08bfa57440dc818ebc401ba875058cc9e979ef89f132f1");
    for (const Claim claim : {Claim::kZero, Claim::kNone}) {
        const ByteView absent = claim == Claim::kZero ? ByteView{kZeroRlp, 1} : ByteView{};
        CAPTURE(claim == Claim::kZero);
        const bytes32 got = walk({}, {{k1, {}, value(1)}, {a1, absent, {}}, {a2, absent, {}}, {k4, {}, value(4)}});
        CHECK(got == hashbuilder_root({{k1, value(1)}, {k4, value(4)}}, nullptr));
    }
}

// A read of an absent key that leaves an extension inside its path, then a write below that extension.
// The read split the extension into a branch over its empty leaf and the extension's child; the write
// folded that child into the branch with a new hash, and only then did the empty leaf fold away, leaving
// the branch a single child to absorb whose hash the witness does not have.
TEST_CASE("GridMPT<true> read of an absent key inside an extension before a write below it", "[trie][gridmpt]") {
    // branch{2 -> ext(0,2) -> branch{0 -> K0, 1 -> ext(2) -> branch{0 -> K1, 1 -> K2}}, 7 -> R}; the absent
    // key goes 2,0,2,1 then 0, where the inner extension has 2.
    const bytes32 k0 = key_with_nibbles({2, 0, 2, 0}, 1);
    const bytes32 k1 = key_with_nibbles({2, 0, 2, 1, 2, 0}, 2);
    const bytes32 k2 = key_with_nibbles({2, 0, 2, 1, 2, 1}, 3);
    const bytes32 r = key_with_nibbles({7}, 4);
    const bytes32 absent_key = key_with_nibbles({2, 0, 2, 1, 0}, 5);
    const Bytes32Map pre{{k0, value(1)}, {k1, value(2)}, {k2, value(3)}, {r, value(4)}};
    for (const Claim claim : {Claim::kZero, Claim::kNone}) {
        const ByteView absent = claim == Claim::kZero ? ByteView{kZeroRlp, 1} : ByteView{};
        CAPTURE(claim == Claim::kZero);
        const Bytes v3 = pre.at(k2);
        const bytes32 got = walk(pre, {{absent_key, absent, {}}, {k2, ByteView{v3}, value(9)}});
        Bytes32Map post = pre;
        post[k2] = value(9);
        CHECK(got == hashbuilder_root(post, nullptr));
    }
}

// A forged witness: two leaves without a value under an extension, which the batch reads as such. As
// with the empty leaves above, the next update's seek folded them, the cascade took the branch and the
// extension too, and the seek descended from the popped extension's line, into std::unreachable(). No
// trie has a leaf without a value: decode_node() rejects it, and the walk fails.
TEST_CASE("GridMPT<true> rejects a witness leaf without a value", "[trie][gridmpt]") {
    const bytes32 k1 = key_from_hex("6d6c288fd01ac4893bdbcdc3b9717bba13a845056ba772398a7eaae0fffa47d9");
    const bytes32 a1 = key_from_hex("8600baa419999186f17a33e3b26008a6485f6a918223719d7d3a6f39092c4621");
    const bytes32 a2 = key_from_hex("8600baa43020cf1673e00210b7a2eccfc4fb8711dbda71bddfe0d69722b4aa79");
    const bytes32 k4 = key_from_hex("895ee3e68994cc766f08bfa57440dc818ebc401ba875058cc9e979ef89f132f1");
    const Bytes32Map pre{{k1, value(1)}, {a1, Bytes{}}, {a2, Bytes{}}};
    const ByteView empty{kZeroRlp, 0};
    CHECK(walk(pre, {{a1, empty, {}}, {a2, empty, {}}, {k4, {}, value(4)}}, /*valid=*/false) == bytes32{});
}
