// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// The roots ere-guests' stateless-validator-common asserts for its synthetic payloads and request
// containers (new_payload_request.rs, progressive_container_roots_match_reference_vectors), built here
// field by field from the same values.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/ssz_merkle.hpp>
#include <zilk_core/core/state_zz/slib_payload.hpp>

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

TEST_CASE("ssz: versioned hashes merkleize as a list of Bytes32 limited to 4096", "[ssz]") {
    CHECK(hex(root_list({}, 4096)) == "dba9671bac9513c9482f1416a53aabd2c6ce90d5a5f865ce5a55c775325c9136");
    const std::array<Node, 1> one{fixed(32, 0x09)};
    CHECK(hex(root_list(one, 4096)) == "a1a665f66c4090bea52f9fd1abd2280d713c495267d42f84760de42c39640cfd");
    std::vector<Node> full(4096);
    for (size_t i = 0; i < full.size(); ++i) full[i] = fixed(32, static_cast<uint8_t>(i));
    CHECK(hex(root_list(full, 4096)) == "70349689f48caad8bb4ff3177aca61cece0117d64a3ec8aaae84bc821b74cce6");
}

namespace {

    ByteView view(const std::vector<uint8_t>& b) { return ByteView{b.data(), b.size()}; }

    std::vector<uint8_t> le64(uint64_t v) {
        std::vector<uint8_t> b(8);
        for (unsigned i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>(v >> (8 * i));
        return b;
    }

    std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts) {
        std::vector<uint8_t> out;
        for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
        return out;
    }

    constexpr char kGloasRequestHex[] =
    "2c000000a80200000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0ac802000001010101010101010101010101010101"
    "010101010101010101010101010101010202020202020202020202020202020202020202030303030303030303030303030303030303030303030303"
    "030303030303030304040404040404040404040404040404040404040404040404040404040404040505050505050505050505050505050505050505"
    "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505"
    "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505"
    "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505"
    "050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050506060606"
    "06060606060606060606060606060606060606060606060606060606640000000000000080c3c90100000000085200000000000000f1536500000000"
    "1c0200000707070707070707070707070707070707070707070707070707070707070707080808080808080808080808080808080808080808080808"
    "0808080808080808230200002f020000000002000000000000000400000000005b0200002a00000000000000eeeeeeeeeeeeee04000000dddddddddd"
    "dddddd0100000000000000020000000000000003030303030303030303030303030303030303030400000000000000bababababababababababababa"
    "babababababababababababababababababababa090909090909090909090909090909090909090909090909090909090909090914000000d4000000"
    "20010000940100004c020000010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101"
    "020202020202020202020202020202020202020202020202020202020202020203000000000000000404040404040404040404040404040404040404"
    "040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"
    "040404040404040404040404040404040500000000000000010101010101010101010101010101010101010102020202020202020202020202020202"
    "020202020202020202020202020202020202020202020202020202020202020203000000000000000101010101010101010101010101010101010101"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202030303030303030303030303"
    "030303030303030303030303030303030303030303030303030303030303030303030303010101010101010101010101010101010101010101010101"
    "010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203000000"
    "000000000404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404"
    "040404040404040404040404040404040404040404040404040404040404040404040404040404040101010101010101010101010101010101010101"
    "020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202";

}  // namespace

TEST_CASE("ssz: the Gloas NewPayloadRequest root matches the ere-guests reference vector", "[ssz]") {
    const auto bloom = filled(256, 0x05);
    const auto extra = filled(7, 0xee);
    const auto base_fee = filled(32, 0x07);
    const auto tx = filled(8, 0xdd);
    const auto bal = filled(33, 0xba);
    const auto hash = filled(32, 0x09);
    const auto deposit = cat({filled(48, 1), filled(32, 2), le64(3), filled(96, 4), le64(5)});
    const auto withdrawal_request = cat({filled(20, 1), filled(48, 2), le64(3)});
    const auto consolidation = cat({filled(20, 1), filled(48, 2), filled(48, 3)});
    const auto builder_deposit = cat({filled(48, 1), filled(32, 2), le64(3), filled(96, 4)});
    const auto builder_exit = cat({filled(20, 1), filled(48, 2)});

    zilkworm::SlibPayload p;
    std::memset(p.parent_hash.bytes, 0x01, 32);
    std::memset(p.fee_recipient.bytes, 0x02, 20);
    std::memset(p.state_root.bytes, 0x03, 32);
    std::memset(p.receipts_root.bytes, 0x04, 32);
    p.logs_bloom = view(bloom);
    std::memset(p.prev_randao.bytes, 0x06, 32);
    p.block_number = 100;
    p.gas_limit = 30'000'000;
    p.gas_used = 21'000;
    p.timestamp = 1'700'000'000;
    p.extra_data = view(extra);
    p.base_fee_per_gas = view(base_fee);
    std::memset(p.block_hash.bytes, 0x08, 32);
    p.transactions = {view(tx)};
    silkworm::Withdrawal w;
    w.index = 1;
    w.validator_index = 2;
    std::memset(w.address.bytes, 0x03, 20);
    w.amount = 4;
    p.withdrawals = {w};
    p.blob_gas_used = 131072;
    p.excess_blob_gas = 262144;
    p.block_access_list = view(bal);
    p.slot_number = 42;
    p.versioned_hashes = view(hash);
    std::memset(p.parent_beacon_block_root.bytes, 0x0a, 32);
    p.execution_requests = {view(deposit), view(withdrawal_request), view(consolidation), view(builder_deposit),
                            view(builder_exit)};

    CHECK(hex(zilkworm::slib_payload_root(p)) == "6a01e66b56a81b3fb0877a573151ba4a01159547dd96bc67f165e2ece858ea90");
    p.versioned_hashes = ByteView{};
    CHECK(hex(zilkworm::slib_payload_root(p)) == "b791c180eb38074085ca5c5291956bb307b40904f4c6e0a6d7fe78e40071a4a4");
}

TEST_CASE("ssz: the Gloas NewPayloadRequest decodes and hashes to the ere-guests reference vector", "[ssz]") {
    const auto bytes = silkworm::from_hex(kGloasRequestHex);
    REQUIRE(bytes.has_value());
    REQUIRE(bytes->size() == 1368);
    const auto p = zilkworm::decode_slib_payload(ByteView{*bytes});
    REQUIRE(p.has_value());
    CHECK(hex(zilkworm::slib_payload_root(*p)) == "6a01e66b56a81b3fb0877a573151ba4a01159547dd96bc67f165e2ece858ea90");
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
