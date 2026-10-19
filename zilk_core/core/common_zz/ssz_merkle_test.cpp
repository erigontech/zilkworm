// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// The roots ere-guests' stateless-validator-common asserts for its synthetic payloads and request
// containers (new_payload_request.rs, progressive_container_roots_match_reference_vectors), built here
// field by field from the same values.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/ssz_merkle.hpp>

namespace zilkworm::ssz {

namespace {

    std::string hex(const Node& n) { return silkworm::to_hex(ByteView{n.data(), n.size()}); }

    std::vector<uint8_t> filled(size_t n, uint8_t v) { return std::vector<uint8_t>(n, v); }

    Node fixed(size_t n, uint8_t v) {
        const auto b = filled(n, v);
        return root_bytes_fixed(ByteView{b.data(), b.size()});
    }

    // ExecutionPayloadV1..V4 of the reference: the fields of each are a prefix of the next's.
    std::vector<Node> payload_fields(unsigned version) {
        const auto extra = filled(7, 0xee);
        const auto tx = filled(8, 0xdd);
        const std::array<Node, 1> txs{root_progressive_bytes(ByteView{tx.data(), tx.size()})};
        std::vector<Node> f{
            fixed(32, 1), fixed(20, 2), fixed(32, 3), fixed(32, 4), fixed(256, 5), fixed(32, 6),
            root_u64(100), root_u64(30'000'000), root_u64(21'000), root_u64(1'700'000'000),
            root_byte_list(ByteView{extra.data(), extra.size()}, 32), fixed(32, 7), fixed(32, 8),
            root_progressive_list(txs),
        };
        if (version >= 2) {
            const std::array<Node, 4> w{root_u64(1), root_u64(2), fixed(20, 3), root_u64(4)};
            const std::array<Node, 1> ws{root_container(w)};
            f.push_back(root_progressive_list(ws));
        }
        if (version >= 3) {
            f.push_back(root_u64(131'072));
            f.push_back(root_u64(262'144));
        }
        if (version >= 4) {
            const auto bal = filled(33, 0xba);
            f.push_back(root_progressive_bytes(ByteView{bal.data(), bal.size()}));
            f.push_back(root_u64(42));
        }
        return f;
    }

    Node one_item_list(std::span<const Node> fields) {
        const std::array<Node, 1> items{root_container(fields)};
        return root_progressive_list(items);
    }

}  // namespace

TEST_CASE("ssz: progressive container roots match the ere-guests reference vectors", "[ssz]") {
    CHECK(hex(root_progressive_container(payload_fields(1))) ==
          "7607fcf862b0f219726ad51d8651d49a9bbbe12fb62edaacd399c25db92b8d77");
    CHECK(hex(root_progressive_container(payload_fields(2))) ==
          "2e3ce606be3d7aa667c2babf22196711f68b45bea6716c6446ec5dce4bd39449");
    CHECK(hex(root_progressive_container(payload_fields(3))) ==
          "b9ccbb429059770fb1c3796aa98dc5d5df321b6226d46ed14203cfe8df186834");
    CHECK(hex(root_progressive_container(payload_fields(4))) ==
          "fc49b59feaa0a2877a26f64bf9e6e30c3848c32c6c2ffa6ca4943a57d640f753");
}

TEST_CASE("ssz: execution request container roots match the ere-guests reference vectors", "[ssz]") {
    const std::array<Node, 5> deposit{fixed(48, 1), fixed(32, 2), root_u64(3), fixed(96, 4), root_u64(5)};
    const std::array<Node, 3> withdrawal{fixed(20, 1), fixed(48, 2), root_u64(3)};
    const std::array<Node, 3> consolidation{fixed(20, 1), fixed(48, 2), fixed(48, 3)};
    const std::array<Node, 4> builder_deposit{fixed(48, 1), fixed(32, 2), root_u64(3), fixed(96, 4)};
    const std::array<Node, 2> builder_exit{fixed(20, 1), fixed(48, 2)};

    const std::array<Node, 3> electra{one_item_list(deposit), one_item_list(withdrawal), one_item_list(consolidation)};
    CHECK(hex(root_progressive_container(electra)) ==
          "56dff976fcc8547491480bb0c68c391852c66410c1768707a851c5038047b78f");
    const std::array<Node, 5> gloas{one_item_list(deposit), one_item_list(withdrawal), one_item_list(consolidation),
                                    one_item_list(builder_deposit), one_item_list(builder_exit)};
    CHECK(hex(root_progressive_container(gloas)) ==
          "0304da3c1bcc50b26b9d6408ea98648962bde84bc81f5d50d645f2b3dcc0e9b0");
}

TEST_CASE("ssz: merkleize pads to the limit and progressive merkleization is zero-terminated", "[ssz]") {
    const Node a{1};
    const Node b{2};
    // One chunk under a 4-leaf limit: two zero levels above it.
    const std::array<Node, 1> one{a};
    Node expect = hash_nodes(hash_nodes(a, Node{}), hash_nodes(Node{}, Node{}));
    CHECK(merkleize(one, 4) == expect);
    // Two chunks progressively: the first alone in a 1-leaf subtree, the second in a 4-leaf one, then zero.
    const std::array<Node, 2> two{a, b};
    const std::array<Node, 1> rest{b};
    expect = hash_nodes(a, hash_nodes(merkleize(rest, 4), Node{}));
    CHECK(merkleize_progressive(two) == expect);
    CHECK(merkleize_progressive({}) == Node{});
    CHECK(merkleize({}, 0) == Node{});
}

}  // namespace zilkworm::ssz
