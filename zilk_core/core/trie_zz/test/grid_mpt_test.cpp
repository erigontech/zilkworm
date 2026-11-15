// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The basic GridMPT tests this file once ran (disabled in 7d0a7414a together with the
// node-store abstraction they were written against), rewritten for today's interface:
// a DirectState witness plus a sorted batch of TrieNodeFlat updates. The expected roots
// are still built by hand from leaf/branch/extension nodes and keccak-encoded, so every
// assertion of the three tests that were live at that commit is kept. The test cases
// that were already commented out before that commit stay out; they never ran.
//
// The old MockNodeStore is replaced by a plain map hash -> node RLP, and a HashBuilder
// capture supplies the complete witness when a test updates an existing trie.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

namespace silkworm::mpt {
namespace {

using Bytes = silkworm::Bytes;
using ByteView = silkworm::ByteView;
using zilkworm::BranchNode;
using zilkworm::bytes32;
using zilkworm::encode_branch;
using zilkworm::encode_ext;
using zilkworm::encode_leaf;
using zilkworm::ExtensionNode;
using zilkworm::GridMPT;
using zilkworm::is_zero_quick;
using zilkworm::keccak_bytes;
using zilkworm::LeafNode;
using zilkworm::TrieNodeFlat;

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using NodeMap = std::map<bytes32, Bytes, Bytes32Less>;

bytes32 make_key(const std::string& hex) {
    bytes32 key{};
    auto bytes = from_hex(hex);
    std::memcpy(key.bytes, bytes->data(), std::min(size_t(32), bytes->size()));
    return key;
}

Bytes make_value(const std::string& str) {
    Bytes encoded;
    rlp::encode(encoded, ByteView{reinterpret_cast<const uint8_t*>(str.data()), str.size()});
    return encoded;
}

// Helper to RLP-encode raw hex payloads
Bytes make_value_hex(const std::string& hex) {
    std::string h = hex;
    if (h.rfind("0x", 0) == 0) h = h.substr(2);
    auto raw = from_hex(h);
    if (!raw) {
        return {};
    }
    Bytes enc;
    rlp::encode(enc, ByteView{raw->data(), raw->size()});
    return enc;
}

// Builds trie nodes by hand and keeps their RLP, keyed by hash, so a parent can embed
// a short child and hash-reference a long one exactly as the encoder does.
struct TrieBuilder {
    NodeMap& store;

    explicit TrieBuilder(NodeMap& s) : store(s) {}

    uint8_t hex_to_nibble(char ch) {
        if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
        if (ch >= 'a' && ch <= 'f') return static_cast<uint8_t>(ch - 'a' + 10);
        if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
        return 0;  // invalid
    }

    // Create a single leaf and return its hash
    bytes32 make_leaf(const std::string& hex_suffix, const std::string& value) {
        LeafNode leaf{};
        for (char c : hex_suffix) {
            leaf.path[leaf.path.len++] = hex_to_nibble(c);
        }
        const Bytes value_rlp = make_value(value);
        leaf.value = ByteView{value_rlp};
        const Bytes encoded{encode_leaf(leaf)};
        const bytes32 hash = keccak_bytes(ByteView{encoded});
        store.emplace(hash, encoded);
        return hash;
    }

    // Create a single leaf and return its hash
    bytes32 make_leaf_hex(const std::string& hex_suffix, const std::string& value) {
        LeafNode leaf{};
        for (char c : hex_suffix) {
            leaf.path[leaf.path.len++] = hex_to_nibble(c);
        }
        const Bytes value_rlp = make_value_hex(value);
        leaf.value = ByteView{value_rlp};
        const Bytes encoded{encode_leaf(leaf)};
        const bytes32 hash = keccak_bytes(ByteView{encoded});
        store.emplace(hash, encoded);
        return hash;
    }

    // Create a branch with specified children and return its hash
    bytes32 make_branch(const std::vector<std::pair<uint8_t, bytes32>>& children) {
        BranchNode branch{};

        for (const auto& [idx, child_hash] : children) {
            const auto it = store.find(child_hash);
            if (it == store.end()) {
                continue;
            }
            const Bytes& rlp = it->second;
            branch.child_ptr[idx] = nullptr;  // BranchNode's constructor leaves the pointer unset
            if (rlp.size() < 32) {
                std::memcpy(branch.child[idx].bytes, rlp.data(), rlp.size());
                branch.child_len[idx] = static_cast<uint8_t>(rlp.size());
            } else {
                branch.child[idx] = child_hash;
                branch.child_len[idx] = 32;
            }
            branch.mask |= static_cast<uint16_t>(1u << idx);
        }

        const Bytes encoded{encode_branch(branch)};
        const bytes32 hash = keccak_bytes(ByteView{encoded});
        store.emplace(hash, encoded);
        return hash;
    }

    // Create an extension and return its hash
    bytes32 make_extension(const std::string& hex_path, const bytes32& child_hash) {
        ExtensionNode ext{};
        for (char c : hex_path) {
            ext.path[ext.path.len++] = hex_to_nibble(c);
        }

        const auto it = store.find(child_hash);
        if (it == store.end()) {
            return {};
        }
        const Bytes& rlp = it->second;
        if (rlp.size() < 32) {
            // Embedded node: store the full RLP
            std::memcpy(ext.child.bytes, rlp.data(), rlp.size());
            ext.child_len = static_cast<uint8_t>(rlp.size());
        } else {
            // Hash reference: store just the 32-byte hash (RLP-encoded by encode_ext)
            ext.child = child_hash;
            ext.child_len = 32;
        }

        const Bytes encoded{encode_ext(ext)};
        const bytes32 hash = keccak_bytes(ByteView{encoded});
        store.emplace(hash, encoded);
        return hash;
    }
};

// MPHF node store over {keccak(node_rlp) -> node_rlp}: what DirectState::find_node_rlp
// reads when GridMPT unfolds a witness.
std::vector<uint8_t> build_node_store(const NodeMap& nodes) {
    if (nodes.empty()) return {};
    zilkworm::MphfBuilder<32> nb{zilkworm::kMphfNodeStoreMagic, zilkworm::kMphfMapVersion};
    for (const auto& [hash, rlp] : nodes) {
        std::vector<uint8_t> body;
        zilkworm::FlatKv::encode(body, hash, ByteView{rlp});
        nb.add(zilkworm::hash_key8(hash), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

// The root GridMPT computes for `inserts` over `prev_root`, with `pre_nodes` as the
// complete witness of the previous trie (empty for an empty trie).
bytes32 run_grid(const std::vector<std::pair<bytes32, Bytes>>& inserts, bytes32 prev_root,
                 const NodeMap& pre_nodes) {
    std::vector<uint8_t> prestate{zilkworm::DirectState::build_blob_from_accounts({}, {}, {})};
    std::vector<uint8_t> nodestore{build_node_store(pre_nodes)};
    zilkworm::DirectState state{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    zilkworm::GridMPT<false, zilkworm::DirectState> grid{state, prev_root};

    std::vector<TrieNodeFlat> updates;
    updates.reserve(inserts.size());
    for (const auto& [key, value] : inserts) {
        auto& node = updates.emplace_back(key);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(value.size());
        std::memcpy(node.buf + 40, value.data(), value.size());
    }
    std::ranges::sort(updates, [](const TrieNodeFlat& a, const TrieNodeFlat& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });

    return grid.calc_root_from_updates(updates);
}

// The canonical root over leaves, capturing every node RLP into `out_nodes` (the
// independent HashBuilder, as the other GridMPT unit tests use).
bytes32 witness_from_leaves(std::vector<std::pair<bytes32, Bytes>> leaves, NodeMap& out_nodes) {
    std::ranges::sort(leaves, [](const auto& x, const auto& y) {
        return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0;
    });
    silkworm::trie::HashBuilder hb;
    hb.rlp_collector = [&](ByteView node_rlp) {
        out_nodes.emplace(keccak_bytes(node_rlp), Bytes{node_rlp});
    };
    for (const auto& [key, value] : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{key.bytes, 32}), ByteView{value});
    }
    return hb.root_hash();
}

}  // namespace

TEST_CASE("GridMPT: Insert into trie with extension", "[grid_mpt_basic]") {
    NodeMap store;
    TrieBuilder builder(store);

    // Build: Extension(ABCD) -> Branch -> 2 leaves
    bytes32 leaf1 = builder.make_leaf("11110000000000000000000000000000000000000000000000000000000", "value1");
    bytes32 leaf2 = builder.make_leaf("22220000000000000000000000000000000000000000000000000000000", "value2");

    bytes32 branch12 = builder.make_branch({{0x01, leaf1},
                                            {0x02, leaf2}});
    bytes32 ext_root = builder.make_extension("ABCD", branch12);

    const std::vector<std::pair<bytes32, Bytes>> updates1{
        {make_key("ABCD111110000000000000000000000000000000000000000000000000000000"), make_value("value1")},
        {make_key("ABCD222220000000000000000000000000000000000000000000000000000000"), make_value("value2")},
    };
    bytes32 calculated_root = run_grid(updates1, kEmptyRoot, {});
    CHECK(ext_root == calculated_root);

    bytes32 leaf3 = builder.make_leaf("0000000000000000000000000000000000000000000000000000000000000", "value3");

    bytes32 D_ext = builder.make_extension("D", branch12);
    bytes32 branch_0C = builder.make_branch({{0x00, leaf3}, {0x0C, D_ext}});
    bytes32 ext_root2 = builder.make_extension("AB", branch_0C);

    NodeMap witness;
    witness_from_leaves(
        {{make_key("ABCD111110000000000000000000000000000000000000000000000000000000"), make_value("value1")},
         {make_key("ABCD222220000000000000000000000000000000000000000000000000000000"), make_value("value2")}},
        witness);

    const std::vector<std::pair<bytes32, Bytes>> updates2{
        {make_key("AB00000000000000000000000000000000000000000000000000000000000000"), make_value("value3")},
    };

    CHECK(!is_zero_quick(branch_0C));
    CHECK(!is_zero_quick(D_ext));
    CHECK(!is_zero_quick(ext_root2));

    bytes32 new_root = run_grid(updates2, calculated_root, witness);
    CHECK(ext_root2 == new_root);
}

TEST_CASE("GridMPT: 4-level, multi-ext, multi-branch", "[grid_mpt_basic]") {
    NodeMap store2;
    TrieBuilder builder(store2);

    auto branch56 = builder.make_branch({
        {0x05, builder.make_leaf_hex("", "0x22b224a1420a802ab51d326e29fa98e34c4f24ea")},
        {0x06, builder.make_leaf_hex("", "0x67706c2076330000000000000000000000000000000000000000000000000000")},
    });
    auto ext0_4 = builder.make_extension("00000004", branch56);
    auto branch01 = builder.make_branch({{0x00, ext0_4},
                                         {0x01, builder.make_leaf_hex("234567890", "0x")}});
    auto ext_00_29 = builder.make_extension("00000000000000000000000000000", branch01);
    auto branch067e = builder.make_branch({
        {0x00, ext_00_29},
        {0x06, builder.make_leaf_hex("97c7b8c961b56f675d570498424ac8de1a918f6", "0x6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000")},
        {0x07, builder.make_leaf_hex("ef9e639e2733cb34e4dfc576d4b23f72db776b2", "0x4655474156000000000000000000000000000000000000000000000000000000")},
        {0x0e, builder.make_leaf_hex("c4f34c97e43fbb2816cfd95e388353c7181dab1", "0x4e616d6552656700000000000000000000000000000000000000000000000000")},
    });
    auto ext_00_23 = builder.make_extension("00000000000000000000000", branch067e);

    auto branch6e = builder.make_branch({
        {0x06, builder.make_leaf_hex("55474156000000000000000000000000000000000000000000000000000000", "0x7ef9e639e2733cb34e4dfc576d4b23f72db776b2")},
        {0x0e, builder.make_leaf_hex("616d6552656700000000000000000000000000000000000000000000000000", "0xec4f34c97e43fbb2816cfd95e388353c7181dab1")},
    });

    auto branch046 = builder.make_branch({
        {0x00, ext_00_23},
        {0x04, branch6e},
        {0x06, builder.make_leaf_hex("f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000", "0x697c7b8c961b56f675d570498424ac8de1a918f6")},
    });

    const std::vector<std::pair<bytes32, Bytes>> updates{
        {make_key("0000000000000000000000000000000000000000000000000000000000000045"), make_value_hex("0x22b224a1420a802ab51d326e29fa98e34c4f24ea")},
        {make_key("0000000000000000000000000000000000000000000000000000000000000046"), make_value_hex("0x67706c2076330000000000000000000000000000000000000000000000000000")},
        {make_key("0000000000000000000000000000000000000000000000000000001234567890"), make_value_hex("0x")},
        {make_key("000000000000000000000000697c7b8c961b56f675d570498424ac8de1a918f6"), make_value_hex("0x6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000")},
        {make_key("0000000000000000000000007ef9e639e2733cb34e4dfc576d4b23f72db776b2"), make_value_hex("0x4655474156000000000000000000000000000000000000000000000000000000")},
        {make_key("000000000000000000000000ec4f34c97e43fbb2816cfd95e388353c7181dab1"), make_value_hex("0x4e616d6552656700000000000000000000000000000000000000000000000000")},
        {make_key("4655474156000000000000000000000000000000000000000000000000000000"), make_value_hex("0x7ef9e639e2733cb34e4dfc576d4b23f72db776b2")},
        {make_key("4e616d6552656700000000000000000000000000000000000000000000000000"), make_value_hex("0xec4f34c97e43fbb2816cfd95e388353c7181dab1")},
        {make_key("6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000"), make_value_hex("0x697c7b8c961b56f675d570498424ac8de1a918f6")},
    };

    bytes32 calculated_root = run_grid(updates, kEmptyRoot, {});

    CHECK(branch046 == calculated_root);
    CHECK(!is_zero_quick(calculated_root));
    CHECK(!is_zero_quick(ext_00_29));
    CHECK(!is_zero_quick(branch067e));
}

TEST_CASE("HB Test 1", "[grid_mpt_basic]") {
    NodeMap store2;
    TrieBuilder builder(store2);

    auto branch12 = builder.make_branch({
        {0x01, builder.make_leaf_hex("", "0x01")},
        {0x02, builder.make_leaf_hex("", "0x02")},
    });
    auto ext0_63 = builder.make_extension("000000000000000000000000000000000000000000000000000000000000000", branch12);

    const std::vector<std::pair<bytes32, Bytes>> updates{
        {make_key("0000000000000000000000000000000000000000000000000000000000000001"), make_value_hex("0x01")},
        {make_key("0000000000000000000000000000000000000000000000000000000000000002"), make_value_hex("0x02")},
    };

    bytes32 calculated_root = run_grid(updates, kEmptyRoot, {});

    CHECK(ext0_63 == calculated_root);
    CHECK(to_hex(calculated_root.bytes) == "38d7897fa8fb512c9c9a55175fc0745865ea934d6d0c22a100caa255c80eb383");  // from silkworm::trie::HashBuilder tests
}

}  // namespace silkworm::mpt
