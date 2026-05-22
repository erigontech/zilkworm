// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdio>
#include <map>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

#include "simple_test.hpp"

namespace silkworm::mpt {

// =============================================================================
// Mock NodeStore for Testing
// =============================================================================

class MockNodeStore : public NodeStore {
  public:
    std::map<bytes32, Bytes, std::less<>> storage_;

    void clear() { storage_.clear(); }

    size_t size() const { return storage_.size(); }

    // Helper to manually insert nodes for testing
    void insert(const bytes32& hash, const Bytes& rlp) {
        storage_[hash] = rlp;
    }

    std::optional<ByteView> get_rlp(const bytes32& hash) const override {
        auto it = storage_.find(hash);
        if (it == storage_.end()) {
            return {};
        }
        return ByteView{it->second};
    }
    void put_rlp(const bytes32& hash, const Bytes& rlp) override {
        storage_[hash] = rlp;
    }
};

// =============================================================================
// Helper Functions
// =============================================================================

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

// Helper to build a simple trie manually
struct TrieBuilder {
    MockNodeStore& store;

    explicit TrieBuilder(MockNodeStore& s) : store(s) {}
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
        Bytes value_rlp = make_value(value);
        leaf.value = ByteView{value_rlp};
        Bytes encoded = encode_leaf(leaf);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }

    // Create a single leaf and return its hash
    bytes32 make_leaf_hex(const std::string& hex_suffix, const std::string& value) {
        LeafNode leaf{};
        for (char c : hex_suffix) {
            leaf.path[leaf.path.len++] = hex_to_nibble(c);
        }
        Bytes value_rlp = make_value_hex(value);
        leaf.value = ByteView{value_rlp};
        Bytes encoded = encode_leaf(leaf);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }

    // Create a branch with specified children and return its hash
    bytes32 make_branch(const std::vector<std::pair<uint8_t, bytes32>>& children) {
        BranchNode branch{};

        for (const auto& [idx, child_hash] : children) {
            auto rlp_opt = store.get_rlp(child_hash);
            if (!rlp_opt) {
                continue;
            }
            const ByteView rlp = *rlp_opt;
            if (rlp.size() < 32) {
                std::memcpy(branch.child[idx].bytes, rlp.data(), rlp.size());
                branch.child_len[idx] = rlp.size();
            } else {
                branch.child[idx] = child_hash;
                branch.child_len[idx] = 32;
            }
        }

        Bytes encoded = encode_branch(branch);
        // std::cout << "make_branch encoded branch: " << silkworm::to_hex(encoded) << std::endl;

        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }

    // Create an extension and return its hash
    bytes32 make_extension(const std::string& hex_path, const bytes32& child_hash) {
        ExtensionNode ext{};
        for (char c : hex_path) {
            ext.path[ext.path.len++] = hex_to_nibble(c);
        }

        auto rlp_opt = store.get_rlp(child_hash);
        if (!rlp_opt) {
            return {};
        }
        const ByteView rlp = *rlp_opt;
        if (rlp.size() < 32) {
            // Embedded node: store the full RLP
            std::memcpy(ext.child.bytes, rlp.data(), rlp.size());
            ext.child_len = rlp.size();
        } else {
            // Hash reference: store just the 32-byte hash (will be RLP-encoded in encode_ext)
            ext.child = child_hash;
            ext.child_len = 32;
        }

        Bytes encoded = encode_ext(ext);
        bytes32 hash = keccak_bytes(encoded);
        store.insert(hash, encoded);
        return hash;
    }
};

// =============================================================================
// Basic Tests
// =============================================================================

// TEST_CASE("nibbles64 operator[]") {
//     SECTION("basic access") {
//         nibbles64 n;
//         n.len = 5;
//         n[0] = 0x0F;
//         n[1] = 0x0A;
//         n[2] = 0x05;

//         CHECK(n[0] == 0x0F);
//         CHECK(n[1] == 0x0A);
//         CHECK(n[2] == 0x05);
//     }

//     SECTION("from_bytes32") {
//         bytes32 key{};
//         key.bytes[0] = 0xAB;
//         key.bytes[1] = 0xCD;

//         auto nibbles = nibbles64::from_bytes32(key);

//         CHECK(nibbles.len == 64);
//         CHECK(nibbles[0] == 0x0A);  // High nibble of 0xAB
//         CHECK(nibbles[1] == 0x0B);  // Low nibble of 0xAB
//         CHECK(nibbles[2] == 0x0C);  // High nibble of 0xCD
//         CHECK(nibbles[3] == 0x0D);  // Low nibble of 0xCD
//     }
// }

// TEST_CASE("RLP encoding") {
//     SECTION("encode branch node") {
//         BranchNode branch{};
//         // Empty branch (all zeros)
//         auto encoded = encode_branch(branch);
//         CHECK(!encoded.empty());

//         // Branch with one child (32-byte hash)
//         for (size_t i = 0; i < 32; ++i) {
//             branch.child[0].bytes[i] = static_cast<uint8_t>(i + 1);
//         }
//         branch.child_len[0] = 32;
//         auto encoded2 = encode_branch(branch);
//         CHECK(encoded2.size() > encoded.size());
//     }

//     SECTION("encode leaf node") {
//         LeafNode leaf{};
//         leaf.path.len = 2;
//         leaf.path[0] = 0x0A;
//         leaf.path[1] = 0x0B;
//         leaf.value = ByteView{reinterpret_cast<const uint8_t*>("test"), 4};

//         auto encoded = encode_leaf(leaf);
//         CHECK(!encoded.empty());
//     }

//     SECTION("encode extension node") {
//         ExtensionNode ext{};
//         ext.path.len = 3;
//         ext.path[0] = 0x01;
//         ext.path[1] = 0x02;
//         ext.path[2] = 0x03;
//         // Set a dummy child hash
//         ext.child.bytes[0] = 0xFF;

//         auto encoded = encode_ext(ext);
//         CHECK(!encoded.empty());
//     }
// }

// TEST_CASE("HP encoding") {
//     SECTION("encode even-length path") {
//         uint8_t path[] = {0x01, 0x02, 0x03, 0x04};
//         uint8_t buffer[10];

//         auto* end = encode_hp_path(buffer, path, 4, false);
//         size_t encoded_len = static_cast<size_t>(end - buffer);

//         CHECK(encoded_len == 3);   // 1 flag byte + 2 data bytes
//         CHECK(buffer[0] == 0x00);  // Even, not leaf
//     }

//     SECTION("encode odd-length path") {
//         uint8_t path[] = {0x01, 0x02, 0x03};
//         uint8_t buffer[10];

//         auto* end = encode_hp_path(buffer, path, 3, false);
//         size_t encoded_len = static_cast<size_t>(end - buffer);

//         CHECK(encoded_len == 2);            // 1 flag+first-nibble byte + 1 data byte
//         CHECK((buffer[0] & 0x10) == 0x10);  // Odd flag set
//     }

//     SECTION("encode leaf path") {
//         uint8_t path[] = {0x01, 0x02};
//         uint8_t buffer[10];

//         [[maybe_unused]] auto* end = encode_hp_path(buffer, path, 2, true);

//         CHECK((buffer[0] & 0x20) == 0x20);  // Leaf flag set
//     }
// }

// TEST_CASE("is_zero helper") {
//     SECTION("zero hash") {
//         bytes32 h{};
//         std::memset(h.bytes, 0, 32);
//         CHECK(is_zero_quick(h));
//     }

//     SECTION("non-zero hash") {
//         bytes32 h{};
//         std::memset(h.bytes, 0, 32);
//         h.bytes[15] = 0x01;
//         CHECK(!is_zero_quick(h));
//     }
// }

// =============================================================================
// GridMPT Trie Calculation Tests
// =============================================================================

// TEST_CASE("GridMPT: Single insertion into empty trie") {
//     MockNodeStore mock_store;
//     auto store = mock_store.make_store();

//     GridMPT grid(store, kEmptyRoot);

//     std::vector<TrieNodeFlat> updates;
//     updates.push_back({
//         make_key("1000000000000000000000000000000000000000000000000000000000000000"),
//         make_value("value1")
//     });

//     bytes32 root = grid.calc_root_from_updates(updates);

//     SECTION("root is not zero") {
//         CHECK(!is_zero_quick(root));
//     }
// }

// TEST_CASE("GridMPT: Two insertions with no common prefix") {
//     MockNodeStore mock_store;
//     auto store = mock_store.make_store();

//     GridMPT grid(store, kEmptyRoot);

//     std::vector<TrieNodeFlat> updates;
//     updates.push_back({
//         make_key("1000000000000000000000000000000000000000000000000000000000000000"),
//         make_value("value1")
//     });
//     updates.push_back({
//         make_key("2000000000000000000000000000000000000000000000000000000000000000"),
//         make_value("value2")
//     });

//     bytes32 root = grid.calc_root_from_updates(updates);

//     SECTION("root is not zero") {
//         CHECK(!is_zero_quick(root));
//     }
// }

// TEST_CASE("GridMPT: Insertions with common prefix") {
//     MockNodeStore mock_store;
//     auto store = mock_store.make_store();

//     GridMPT grid(store, kEmptyRoot);

//     std::vector<TrieNodeFlat> updates;
//     updates.push_back({
//         make_key("ABCD101234500000000000000000000000000000000000000000000000000000"),
//         make_value("value1")
//     });
//     updates.push_back({
//         make_key("ABCD201234500000000000000000000000000000000000000000000000000000"),
//         make_value("value2")
//     });

//     bytes32 root = grid.calc_root_from_updates(updates);

//     SECTION("root is not zero") {
//         CHECK(!is_zero_quick(root));
//     }
// }

// TEST_CASE("GridMPT: Update existing key in pre-populated trie") {
//     MockNodeStore mock_store;
//     auto store = mock_store.make_store();
//     TrieBuilder builder(mock_store);

//     // Build initial trie: single leaf with key ending in "10"
//     bytes32 leaf1 = builder.make_leaf("1234567890ABCDEF000000000000000000000000000000000000000000000000", "oldvalue");

//     // Use this leaf as the root
//     bytes32 initial_root = leaf1;

//     // Now update with same key but new value
//     GridMPT grid(store, initial_root);
//     std::vector<TrieNodeFlat> updates;
//     updates.push_back({
//         make_key("1234567890ABCDEF000000000000000000000000000000000000000000000000"),
//         make_value("newvalue")
//     });

//     bytes32 new_root = grid.calc_root_from_updates(updates);

//     SECTION("roots are different") {
//         CHECK(!is_zero_quick(new_root));
//         CHECK(new_root != initial_root);
//     }
// }

// TEST_CASE("GridMPT: Insert into existing trie with branch") {
//     MockNodeStore store{};
//     TrieBuilder builder(store);

//     // Build initial trie with 2 leaves under a branch
//     // Branch at root with children at index 1 and 2
//     bytes32 leaf1 = builder.make_leaf("a11000000000000000000000000000000000000000000000000000000000000", "value1");
//     bytes32 leaf2 = builder.make_leaf("b22000000000000000000000000000000000000000000000000000000000000", "value2");

//     bytes32 branch_root = builder.make_branch({{0x01, leaf1},
//                                                {0x02, leaf2}});

//     std::vector<TrieNodeFlat> updates1;
//     GridMPT grid1(store, kEmptyRoot);
//     updates1.push_back({make_key("1a11000000000000000000000000000000000000000000000000000000000000"),
//                         make_value("value1")});
//     updates1.push_back({make_key("2b22000000000000000000000000000000000000000000000000000000000000"),
//                         make_value("value2")});
//     bytes32 calculated_root = grid1.calc_root_from_updates(updates1);
//     SECTION("new root is is same without updates") {
//         CHECK(branch_root == calculated_root);
//     }

//     // // Make a 3-child branch with third's key starting in 0x03
//     bytes32 leaf3 = builder.make_leaf("c33000000000000000000000000000000000000000000000000000000000000", "value3");
//     branch_root = builder.make_branch({{0x01, leaf1},
//                                        {0x02, leaf2},
//                                        {0x03, leaf3}});

//     // Now create a grid with the existing root and push an update
//     GridMPT grid2(store, calculated_root);
//     std::vector<TrieNodeFlat> updates2;
//     updates2.push_back({make_key("3c33000000000000000000000000000000000000000000000000000000000000"),
//                         make_value("value3")});
//     calculated_root = grid2.calc_root_from_updates(updates2);

//     SECTION("new root is same as root of a branch with 3 children") {
//         CHECK(!is_zero_quick(calculated_root));
//         CHECK(branch_root == calculated_root);
//     }
// }

// ABCD -> [1, 2] -> l1, l2
// AB -> [0,c] -> 0:l3, C:D; D-> [1,2]
TEST_CASE("GridMPT: Insert into trie with extension") {
    std::cout << "\n=== Starting extension test ===" << std::endl;
    clear_static_buffer();  // Ensure clean RLP buffer state
    MockNodeStore store{};
    store.clear();  // Ensure clean state
    TrieBuilder builder(store);

    // Build: Extension(ABCD) -> Branch -> 2 leaves
    bytes32 leaf1 = builder.make_leaf("11110000000000000000000000000000000000000000000000000000000", "value1");
    bytes32 leaf2 = builder.make_leaf("22220000000000000000000000000000000000000000000000000000000", "value2");

    bytes32 branch12 = builder.make_branch({{0x01, leaf1},
                                            {0x02, leaf2}});
    bytes32 ext_root = builder.make_extension("ABCD", branch12);

    std::vector<TrieNodeFlat> updates1;
    GridMPT grid1(store, kEmptyRoot);
    updates1.push_back({make_key("ABCD111110000000000000000000000000000000000000000000000000000000"),
                        make_value("value1")});
    updates1.push_back({make_key("ABCD222220000000000000000000000000000000000000000000000000000000"),
                        make_value("value2")});
    bytes32 calculated_root = grid1.calc_root_from_updates(updates1);
    CHECK(ext_root == calculated_root);

    bytes32 leaf3 = builder.make_leaf("0000000000000000000000000000000000000000000000000000000000000", "value3");

    bytes32 D_ext = builder.make_extension("D", branch12);
    bytes32 branch_0C = builder.make_branch({{0x00, leaf3}, {0x0C, D_ext}});
    bytes32 ext_root2 = builder.make_extension("AB", branch_0C);

    GridMPT grid(store, calculated_root);
    std::vector<TrieNodeFlat> updates2;
    updates2.push_back({make_key("AB00000000000000000000000000000000000000000000000000000000000000"),
                        make_value("value3")});

    CHECK(!is_zero_quick(branch_0C));
    CHECK(!is_zero_quick(D_ext));
    CHECK(!is_zero_quick(ext_root2));

    bytes32 new_root = grid.calc_root_from_updates(updates2);
    CHECK(ext_root2 == new_root);

    clear_static_buffer();
}

TEST_CASE("GridMPT: 4-level, multi-ext, multi-branch") {
    std::cout << "\n=== Starting 4-level test ===" << std::endl;
    clear_static_buffer();  // Ensure clean RLP buffer state
    MockNodeStore store2{};
    store2.clear();  // Ensure clean state
    TrieBuilder builder(store2);

    auto branch56 = builder.make_branch({
        {0x05, builder.make_leaf_hex("", "0x22b224a1420a802ab51d326e29fa98e34c4f24ea")},
        {0x06, builder.make_leaf_hex("", "0x67706c2076330000000000000000000000000000000000000000000000000000")},
    });
    auto ext0_4 = builder.make_extension("00000004", branch56);
    auto branch01 = builder.make_branch({{0x00, ext0_4},
                                         // {0x01, builder.make_leaf_hex("234567890", "")}
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

    std::vector<TrieNodeFlat> updates;
    updates.push_back({make_key("0000000000000000000000000000000000000000000000000000000000000045"), make_value_hex("0x22b224a1420a802ab51d326e29fa98e34c4f24ea")});

    updates.push_back({make_key("0000000000000000000000000000000000000000000000000000000000000046"), make_value_hex("0x67706c2076330000000000000000000000000000000000000000000000000000")});

    // updates.push_back({make_key("0000000000000000000000000000000000000000000000000000001234567890"), Bytes{}});

    updates.push_back({make_key("0000000000000000000000000000000000000000000000000000001234567890"), make_value_hex("0x")});

    updates.push_back({make_key("000000000000000000000000697c7b8c961b56f675d570498424ac8de1a918f6"), make_value_hex("0x6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000")});

    updates.push_back({make_key("0000000000000000000000007ef9e639e2733cb34e4dfc576d4b23f72db776b2"), make_value_hex("0x4655474156000000000000000000000000000000000000000000000000000000")});

    updates.push_back({make_key("000000000000000000000000ec4f34c97e43fbb2816cfd95e388353c7181dab1"), make_value_hex("0x4e616d6552656700000000000000000000000000000000000000000000000000")});

    updates.push_back({make_key("4655474156000000000000000000000000000000000000000000000000000000"), make_value_hex("0x7ef9e639e2733cb34e4dfc576d4b23f72db776b2")});

    updates.push_back({make_key("4e616d6552656700000000000000000000000000000000000000000000000000"), make_value_hex("0xec4f34c97e43fbb2816cfd95e388353c7181dab1")});

    updates.push_back({make_key("6f6f6f6820736f2067726561742c207265616c6c6c793f000000000000000000"), make_value_hex("0x697c7b8c961b56f675d570498424ac8de1a918f6")});

    GridMPT grid(store2, kEmptyRoot);
    bytes32 calculated_root = grid.calc_root_from_updates(updates);

    std::cout << "branch046: " << to_hex(branch046.bytes) << std::endl;
    std::cout << "calculated: " << to_hex(calculated_root.bytes) << std::endl;

    CHECK(branch046 == calculated_root);
    CHECK(!is_zero_quick(calculated_root));
    CHECK(!is_zero_quick(ext_00_29));
    CHECK(!is_zero_quick(branch067e));
}

TEST_CASE("HB Test 1") {
    std::cout << "\n=== Starting HB Test 1 ===" << std::endl;
    clear_static_buffer();  // Ensure clean RLP buffer state
    MockNodeStore store2{};
    store2.clear();  // Ensure clean state
    TrieBuilder builder(store2);

    auto branch12 = builder.make_branch({
        {0x01, builder.make_leaf_hex("", "0x01")},
        {0x02, builder.make_leaf_hex("", "0x02")},
    });
    auto ext0_63 = builder.make_extension("000000000000000000000000000000000000000000000000000000000000000", branch12);

    std::vector<TrieNodeFlat> updates;
    updates.push_back({make_key("0000000000000000000000000000000000000000000000000000000000000001"), make_value_hex("0x01")});
    updates.push_back({make_key("0000000000000000000000000000000000000000000000000000000000000002"), make_value_hex("0x02")});

    GridMPT grid(store2, kEmptyRoot);
    bytes32 calculated_root = grid.calc_root_from_updates(updates);

    std::cout << "branch12: " << to_hex(branch12.bytes) << std::endl;
    std::cout << "calculated: " << to_hex(calculated_root.bytes) << std::endl;

    CHECK(ext0_63 == calculated_root);
    CHECK(to_hex(calculated_root.bytes) == "38d7897fa8fb512c9c9a55175fc0745865ea934d6d0c22a100caa255c80eb383");  // from silkworm::trie::HashBuilder tests
}

}  // namespace silkworm::mpt

// Main entry point
int main() {
    return simple_test::TestCase::run_all();
}

// namespace silkworm::trie {

// TEST_CASE("HashBuilder1") {
//     const evmc::bytes32 key1{0x0000000000000000000000000000000000000000000000000000000000000001_bytes32};
//     const evmc::bytes32 key2{0x0000000000000000000000000000000000000000000000000000000000000002_bytes32};

//     const Bytes val1{*from_hex("01")};
//     const Bytes val2{*from_hex("02")};

//     HashBuilder hb;
//     hb.add_leaf(unpack_nibbles(key1.bytes), val1);
//     hb.add_leaf(unpack_nibbles(key2.bytes), val2);

//     // even terminating
//     const Bytes encoded_empty_terminating_path{*from_hex("20")};
//     const Bytes leaf1_payload{encoded_empty_terminating_path + val1};
//     const Bytes leaf2_payload{encoded_empty_terminating_path + val2};

//     Bytes branch_payload;
//     branch_payload.push_back(rlp::kEmptyStringCode);  // nibble 0
//     rlp::encode_header(branch_payload, {.list = true, .payload_length = leaf1_payload.size()});
//     branch_payload.append(leaf1_payload);

//     rlp::encode_header(branch_payload, {.list = true, .payload_length = leaf2_payload.size()});
//     branch_payload.append(leaf2_payload);

//     std::cout<< "leaf1_payload: " << to_hex(leaf1_payload) << std::endl;
//     std::cout<< "leaf2_payload: " << to_hex(leaf2_payload) << std::endl;

//     // nibbles 3 to 15 plus nil value
//     for (size_t i = {3}; i < 17; ++i) {
//         branch_payload.push_back(rlp::kEmptyStringCode);
//     }

//     Bytes branch_rlp;
//     const rlp::Header branch_head{/*list=*/true, branch_payload.size()};
//     rlp::encode_header(branch_rlp, branch_head);
//     branch_rlp.append(branch_payload);
//     REQUIRE(branch_rlp.size() < kHashLength);

//     std::cout<< "branch_rlp: " << to_hex(branch_rlp) << std::endl;

//     // odd extension
//     const Bytes encoded_path{*from_hex("1000000000000000000000000000000000000000000000000000000000000000")};

//     Bytes extension_payload;
//     rlp::encode(extension_payload, encoded_path);
//     extension_payload.append(branch_rlp);

//     Bytes extension_rlp;
//     const rlp::Header extension_head{/*list=*/true, extension_payload.size()};
//     rlp::encode_header(extension_rlp, extension_head);
//     extension_rlp.append(extension_payload);
//     REQUIRE(extension_rlp.size() >= kHashLength);

//     std::cout<< "extension_rlp: " << to_hex(extension_rlp) << std::endl;

//     const auto hash{std::bit_cast<evmc_bytes32> (keccak256(extension_rlp))};
//     const auto root_hash{hb.root_hash()};
//     std::cout<< "HashBuilder1 computed root " << to_hex(root_hash.bytes);
//     CHECK(to_hex(root_hash.bytes) == to_hex(hash.bytes));

//     // Reset hash builder
//     hb.reset();
//     REQUIRE(hb.root_hash() == kEmptyRoot);
// }
// }  // namespace silkworm::trie
