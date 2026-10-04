// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Tests for GridMPT::unfold_node_from_rlp — decoding and validation of witness
// node RLP as nodes are pulled into the grid. Add further unfold / malformed-
// node cases here.

#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

// Extension-node RLP: list( HP path {0x00,0x12} => nibbles [1,2], child string ).
Bytes ext_node(size_t child_len) {
    Bytes inner;
    inner.push_back(0x82);  // RLP string, length 2
    inner.push_back(0x00);  // HP: extension (flag 0), even
    inner.push_back(0x12);  // nibbles [1, 2]
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = child_len});
    inner.append(child_len, 0xAB);

    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    return node;
}

// Leaf-node RLP: list( HP path {0x20, 32 path bytes} => 64 nibbles, value string of value_len bytes ).
Bytes leaf_node(size_t value_len) {
    Bytes inner;
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = 33});
    inner.push_back(0x20);  // HP: leaf, even
    inner.append(32, 0x11);
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = value_len});
    inner.append(value_len, 0x5A);

    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    return node;
}

}  // namespace

// An extension child longer than 32 bytes must be rejected, not copied into the
// fixed 32-byte ExtensionNode::child. A large child makes the pre-fix overflow
// fault deterministically; catch_discover_tests isolates the crash per process.
TEST_CASE("unfold_node_from_rlp rejects an oversized extension child", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false> trie{direct, silkworm::kEmptyRoot};

    const Bytes node = ext_node(/*child_len=*/60000);
    CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
#ifndef NDEBUG
    CHECK(trie.failed());  // rejected decode must mark the trie failed (debug-only sentinel)
#endif
}

// Re-encoding writes into the fixed static_buffer, so a witness leaf whose value would not fit
// must be rejected at decode; the largest accepted one must still fit.
TEST_CASE("decode_node bounds a leaf value by the encode buffer", "[trie][gridmpt][unfold]") {
    for (const size_t value_len : {kMaxLeafValueSize, kMaxLeafValueSize + 1}) {
        const Bytes node = leaf_node(value_len);
        ByteView payload{node};
        const auto h = silkworm::rlp::decode_header(payload);
        REQUIRE(h);
        BranchNode br{};
        bool is_leaf = false;
        std::array<uint8_t, 64> path{};
        uint8_t plen = 0;
        ByteView second{};
        const Kind kind = decode_node(payload.substr(0, h->payload_length), br, is_leaf, path, plen, second);
        if (value_len > kMaxLeafValueSize) {
            CHECK(kind == kInvalid);
            continue;
        }
        REQUIRE(kind == kExtOrLeaf);
        REQUIRE(is_leaf);
        // Re-encoded one level down, as a moved leaf would be.
        const LeafNode l{nibbles64{static_cast<uint8_t>(plen - 2), path}, 0, second};
        const ByteView enc = encode_leaf(l);
        CHECK(enc.data() >= static_buffer);
        CHECK(enc.data() + enc.size() <= static_buffer + kNodeBufferSize);
    }
}

TEST_CASE("unfold_node_from_rlp rejects an oversized leaf value", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false> trie{direct, silkworm::kEmptyRoot};

    const Bytes node = leaf_node(/*value_len=*/4096);
    CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
}

// The state and storage tries have fixed-length keys, so a branch never carries a value.
TEST_CASE("unfold_node_from_rlp rejects a branch with a value", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false> trie{direct, silkworm::kEmptyRoot};

    Bytes inner;
    inner.push_back(0xC2);  // child 0: an embedded node, so the branch is not all empty
    inner.push_back(0x01);
    inner.push_back(0x02);
    inner.append(15, silkworm::rlp::kEmptyStringCode);
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = 4096});
    inner.append(4096, 0x5A);
    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
}
