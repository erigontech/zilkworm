// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Tests for GridMPT::unfold_node_from_rlp — decoding and validation of witness
// node RLP as nodes are pulled into the grid. Add further unfold / malformed-
// node cases here.

#include <cstring>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

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

// HP-encoded path of `n` nibbles (all 1): leaf flag 0x20 or extension flag 0x00, plus 0x10 | first nibble when n is odd.
Bytes hp_path(size_t n, bool leaf) {
    Bytes hp;
    const uint8_t flag = leaf ? 0x20 : 0x00;
    hp.push_back(n % 2 ? static_cast<uint8_t>(flag | 0x11) : flag);
    hp.append(n / 2, 0x11);
    return hp;
}

// Leaf or extension RLP with a path of `nibbles` nibbles: list( HP path, value string of value_len bytes ).
Bytes path_node(size_t nibbles, bool leaf, size_t value_len) {
    const Bytes hp = hp_path(nibbles, leaf);
    Bytes inner;
    if (hp.size() == 1 && hp[0] < 0x80) {
        inner.push_back(hp[0]);  // a single byte below 0x80 is its own RLP string
    } else {
        silkworm::rlp::encode_header(inner, {.list = false, .payload_length = hp.size()});
        inner.append(hp);
    }
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = value_len});
    inner.append(value_len, leaf ? 0x5A : 0xAB);

    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    return node;
}

// Unfolds `node` as the root of a fresh trie.
bool unfolds_as_root(const Bytes& node) {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false, DirectState> trie{direct, silkworm::kEmptyRoot};
    const bool ok = trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0);
    CHECK(trie.failed() == !ok);
    return ok;
}

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
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

bytes32 key_of(uint8_t fill, uint8_t last) {
    bytes32 k;
    std::memset(k.bytes, fill, 31);
    k.bytes[31] = last;
    return k;
}

// Writes k3 (absent before the block) and reads k2, keys sorted, against the witness `nodes` of `pre_root`.
struct ExtChildRun {
    bool failed;
    bytes32 root;
};
ExtChildRun write_k3_read_k2(const Bytes32Map& nodes, const bytes32& pre_root, const bytes32& k2, ByteView k2_value,
                             const bytes32& k3) {
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    std::vector<TrieNodeFlat> flat;  // must never reallocate: GridMPT keeps views into TrieNodeFlat::buf
    flat.reserve(2);
    auto& write = flat.emplace_back(k3);
    write.current_off = 40;
    write.current_len = 1;
    write.buf[40] = 0x44;
    auto& read = flat.emplace_back(k2);
    read.ext_initial = k2_value;
    read.current_off = 40;
    read.current_len = 0;
    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 root = trie.calc_root_from_updates({flat.data(), flat.size()});
    return {trie.failed(), root};
}

}  // namespace

// An extension child longer than 32 bytes must be rejected, not copied into the
// fixed 32-byte ExtensionNode::child. A large child makes the pre-fix overflow
// fault deterministically; catch_discover_tests isolates the crash per process.
TEST_CASE("unfold_node_from_rlp rejects an oversized extension child", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false, DirectState> trie{direct, silkworm::kEmptyRoot};

    const Bytes node = ext_node(/*child_len=*/60000);
    CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
    CHECK(trie.failed());  // rejected decode must mark the trie failed
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
    GridMPT<false, DirectState> trie{direct, silkworm::kEmptyRoot};

    const Bytes node = leaf_node(/*value_len=*/4096);
    CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
}

// A list header with 4 length bytes or more claims a payload no trie node has, and its length would
// not fit the 3-byte decode.
TEST_CASE("unfold_node_from_rlp rejects a node with 4 or more length bytes", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false, DirectState> trie{direct, silkworm::kEmptyRoot};

    for (const uint8_t first : {uint8_t{0xFB}, uint8_t{0xFF}}) {
        Bytes node{first};
        node.append(40, 0x00);
        CHECK_FALSE(trie.unfold_node_from_rlp(ByteView{node}, /*parent_slot=*/0, /*parent_depth=*/0));
    }
}

// The state and storage tries have fixed-length keys, so a branch never carries a value.
TEST_CASE("unfold_node_from_rlp rejects a branch with a value", "[trie][gridmpt][unfold]") {
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false, DirectState> trie{direct, silkworm::kEmptyRoot};

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

// Keys are 64 nibbles, and a witness node is bound only to the hash that referenced it, so a path whose
// length cannot fit under its position must be rejected: a leaf has to end the key, and an extension needs
// at least one nibble and leaves at least one for the branch below it. The leaf split in
// calc_root_from_updates relies on this (a shorter leaf path wrapped a length there).
TEST_CASE("unfold_node_from_rlp bounds leaf and extension path lengths", "[trie][gridmpt][unfold]") {
    for (const size_t n : {0u, 1u, 10u, 62u, 63u, 65u, 66u})
        CHECK_FALSE(unfolds_as_root(path_node(n, /*leaf=*/true, /*value_len=*/4)));
    CHECK(unfolds_as_root(path_node(64, /*leaf=*/true, /*value_len=*/4)));

    for (const size_t n : {0u, 64u, 65u})
        CHECK_FALSE(unfolds_as_root(path_node(n, /*leaf=*/false, /*value_len=*/32)));
    for (const size_t n : {1u, 2u, 31u, 63u})
        CHECK(unfolds_as_root(path_node(n, /*leaf=*/false, /*value_len=*/32)));
}

// A node under 32 bytes is embedded in its parent, never referenced by its hash. The extension child that
// calc_root_from_updates fetches must refuse such a reference, as unfold_slot does for a branch child: a batch
// that leaves the node alone would otherwise keep the reference in the root it returns, which is then not the
// root of the resulting map.
TEST_CASE("calc_root_from_updates refuses a hash reference to a short extension child", "[trie][gridmpt][unfold]") {
    // k1 and k2 share 63 nibbles; k3 is absent before the batch.
    const bytes32 k1 = key_of(0x5A, 0x50);
    const bytes32 k2 = key_of(0x5A, 0x5F);
    const bytes32 k3 = key_of(0x00, 0x01);
    const Bytes v2{0x01, 0x02, 0x03, 0x04, 0x05};

    // The branch at depth 63 over k1 -> 0x01 and k2 -> v2 is 27 bytes, so its parent embeds it.
    Bytes branch_payload{0xC2, 0x20, 0x01};                      // slot 0: k1's leaf, empty path
    branch_payload.append(14, silkworm::rlp::kEmptyStringCode);  // slots 1 to 14
    branch_payload.append({0xC7, 0x20, 0x85});                   // slot 15: k2's leaf, empty path
    branch_payload.append(v2);
    branch_payload.push_back(silkworm::rlp::kEmptyStringCode);  // no value
    Bytes branch;
    silkworm::rlp::encode_header(branch, {.list = true, .payload_length = branch_payload.size()});
    branch.append(branch_payload);
    REQUIRE(branch.size() < 32);

    SECTION("the root extension holds the short branch by its hash") {
        const bytes32 branch_hash = keccak_bytes(ByteView{branch});
        Bytes ext_payload{0xA0, 0x15};  // 63 nibbles: the odd extension flag and k1's first nibble, then 31 bytes
        ext_payload.append(31, 0xA5);
        ext_payload.push_back(0xA0);
        ext_payload.append(branch_hash.bytes, 32);
        Bytes ext;
        silkworm::rlp::encode_header(ext, {.list = true, .payload_length = ext_payload.size()});
        ext.append(ext_payload);
        const bytes32 root = keccak_bytes(ByteView{ext});
        // Not the root of {k1 -> 0x01, k2 -> v2}, whose extension embeds the branch.
        REQUIRE(root != hashbuilder_root({{k1, Bytes{0x01}}, {k2, v2}}, nullptr));
        const auto run = write_k3_read_k2({{branch_hash, branch}, {root, ext}}, root, k2, ByteView{v2}, k3);
        CHECK(run.failed);
    }
    SECTION("the control: a 32-byte branch held by its hash") {
        const Bytes32Map pre{{k1, Bytes{0x11, 0x12, 0x13, 0x14, 0x15}}, {k2, v2}};
        Bytes32Map nodes;
        const bytes32 root = hashbuilder_root(pre, &nodes);
        const auto run = write_k3_read_k2(nodes, root, k2, ByteView{v2}, k3);
        Bytes32Map post = pre;
        post[k3] = Bytes{0x44};
        CHECK_FALSE(run.failed);
        CHECK(run.root == hashbuilder_root(post, nullptr));
    }
}
