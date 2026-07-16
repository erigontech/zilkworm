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
}
