// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// encode_branch re-emits the witness RLP a branch was unfolded from and rewrites only the dirty
// slots when no slot changed length class. Every path must equal the full re-encode byte for byte.

#include <array>
#include <cstring>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

// Branch: slots 0..12 hash refs, slot 13 an embedded 4-byte list, slots 14/15 empty, empty value.
Bytes branch_node() {
    Bytes inner;
    for (uint8_t i = 0; i < 13; ++i) {
        inner.push_back(0xa0);
        inner.append(32, static_cast<uint8_t>(0x10 + i));
    }
    inner.append({0xc3, 0x01, 0x02, 0x03});
    inner.push_back(0x80);
    inner.push_back(0x80);
    inner.push_back(0x80);  // value
    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    return node;
}

// Mirrors unfold_node_from_rlp: decode the list payload, then record the origin view.
BranchNode unfold(const Bytes& node) {
    ByteView payload{node};
    const auto hdr = silkworm::rlp::decode_header(payload);
    REQUIRE(hdr.has_value());
    BranchNode b;
    bool is_leaf{};
    std::array<uint8_t, 64> path{};
    uint8_t plen{};
    ByteView second{};
    REQUIRE(decode_node(payload, b, is_leaf, path, plen, second) == kBranch);
    b.orig = node.data();
    b.orig_size = static_cast<uint16_t>(node.size());
    b.orig_child_len = b.child_len;
    b.dirty = 0;
    return b;
}

Bytes fast_encode(const BranchNode& b) { return Bytes{encode_branch(b)}; }

Bytes slow_encode(BranchNode b) {
    b.orig = nullptr;  // forces the full re-encode
    return Bytes{encode_branch(b)};
}

}  // namespace

TEST_CASE("encode_branch patch path matches the full re-encode", "[trie][gridmpt][encode]") {
    const Bytes node = branch_node();
    const std::array<uint8_t, 32> new_hash = [] {
        std::array<uint8_t, 32> h{};
        h.fill(0xEE);
        return h;
    }();

    SECTION("unmodified branch re-emits the witness bytes") {
        BranchNode b = unfold(node);
        CHECK(b.child_len == b.orig_child_len);
        CHECK(fast_encode(b) == node);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("hash child replaced") {
        BranchNode b = unfold(node);
        b.set_child(5, ByteView{new_hash.data(), 32});
        CHECK(b.child_len == b.orig_child_len);  // patch path
        CHECK(fast_encode(b) != node);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("two hash children replaced, one with identical bytes") {
        BranchNode b = unfold(node);
        std::array<uint8_t, 32> same{};
        same.fill(0x10 + 3);
        b.set_child(3, ByteView{same.data(), 32});
        b.set_child(12, ByteView{new_hash.data(), 32});
        CHECK(b.child_len == b.orig_child_len);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("embedded child replaced by one of the same length") {
        BranchNode b = unfold(node);
        const std::array<uint8_t, 4> emb{0xc3, 0x0a, 0x0b, 0x0c};
        b.set_child(13, ByteView{emb.data(), emb.size()});
        CHECK(b.child_len == b.orig_child_len);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("empty slot filled: layout changes, full re-encode") {
        BranchNode b = unfold(node);
        b.set_child(14, ByteView{new_hash.data(), 32});
        CHECK(b.child_len != b.orig_child_len);  // fallback path
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("hash child deleted: layout changes, full re-encode") {
        BranchNode b = unfold(node);
        b.delete_child(7);
        CHECK(b.child_len != b.orig_child_len);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("embedded child replaced by a hash: layout changes, full re-encode") {
        BranchNode b = unfold(node);
        b.set_child(13, ByteView{new_hash.data(), 32});
        CHECK(b.child_len != b.orig_child_len);
        CHECK(fast_encode(b) == slow_encode(b));
    }
    SECTION("delete then re-add the same slot with a hash: lengths equal again, patch path") {
        BranchNode b = unfold(node);
        b.delete_child(2);
        b.set_child(2, ByteView{new_hash.data(), 32});
        CHECK(b.child_len == b.orig_child_len);
        CHECK(fast_encode(b) == slow_encode(b));
    }
}
