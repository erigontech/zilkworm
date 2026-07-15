// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// GridMPT<true> regression test: a sorted update batch whose deletes empty
// the whole trie pops the last grid line, and the walker used to read
// grid_[0] on the empty vector instead of re-seeding from the next insert.
//
// The pre-state trie is built with silkworm::trie::HashBuilder, capturing
// every node RLP into a node store (a complete witness), so any root
// mismatch or missing-node report is a walker bug.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
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

// Storage-leaf value RLP for a 32-byte big-endian value (as check_root builds).
Bytes slot_value_rlp(uint64_t v) {
    bytes32 val{};
    for (int i = 0; i < 8; ++i) val.bytes[31 - i] = static_cast<uint8_t>(v >> (8 * i));
    Bytes out;
    silkworm::rlp::encode(out, silkworm::zeroless_view(ByteView{val.bytes, 32}));
    return out;
}

// Canonical root over (hashed key -> value rlp) leaves; optionally captures
// every node RLP into `sink`.
bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) {
            sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp});
        };
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

// Brute-force a hashed trie key starting with the given nibbles.
bytes32 key_with_prefix(std::initializer_list<uint8_t> nibs) {
    for (uint64_t i = 0;; ++i) {
        bytes32 raw{};
        for (int b = 0; b < 8; ++b) raw.bytes[31 - b] = static_cast<uint8_t>(i >> (8 * b));
        const bytes32 h = keccak_bytes(ByteView{raw.bytes, 32});
        bool match = true;
        size_t j = 0;
        for (uint8_t want : nibs) {
            const uint8_t got = (j % 2 == 0) ? (h.bytes[j / 2] >> 4) : (h.bytes[j / 2] & 0x0F);
            if (got != want) {
                match = false;
                break;
            }
            ++j;
        }
        if (match) return h;
    }
}

// Runs pre -> post through GridMPT<true> against a complete witness of the
// pre trie: deletes every pre leaf, inserts every post leaf (pre and post
// keys must be disjoint), and REQUIREs the canonical post root.
void check_delete_all_then_insert(const Bytes32Map& pre, const Bytes32Map& post) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    // Update batch (sorted; must never reallocate, GridMPT keeps ByteViews
    // into TrieNodeFlat::buf): deletes as check_root encodes them
    // (initial = pre value rlp, current = {0x80}), then the inserts.
    std::vector<TrieNodeFlat> updates;
    updates.reserve(pre.size() + post.size());
    for (const auto& [k, v] : pre) {
        auto& node = updates.emplace_back(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        node.buf[40] = 0x80;
        node.current_off = 40;
        node.current_len = 1;
    }
    for (const auto& [k, v] : post) {
        auto& node = updates.emplace_back(k);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf + 40, v.data(), v.size());
    }
    std::ranges::sort(updates, [](const TrieNodeFlat& a, const TrieNodeFlat& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });

    GridMPT<true> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    const bytes32 expected = hashbuilder_root(post, nullptr);

    CAPTURE(silkworm::to_hex(got), silkworm::to_hex(expected));
    CHECK(trie.missing_count() == 0);
    REQUIRE(got == expected);
}

}  // namespace

TEST_CASE("GridMPT<true> survives a batch that empties the trie", "[trie][gridmpt]") {
    // Two leaves diverging at the first nibble.
    const Bytes32Map pre{{key_with_prefix({0xa}), slot_value_rlp(1)},
                         {key_with_prefix({0xd}), slot_value_rlp(2)}};

    SECTION("deletes then insert (the grid must re-seed)") {
        check_delete_all_then_insert(pre, {{key_with_prefix({0xf}), slot_value_rlp(3)}});
    }
    SECTION("deletes only (empty post root)") {
        check_delete_all_then_insert(pre, {});
    }
}

// Deletes empty an extension's whole subtree (collapse is deferred, so the
// empty ext stays on the active path); the next insert descending through it
// used to resurrect the deleted child as a mask-set garbage ref and corrupt
// the root silently.
TEST_CASE("GridMPT<true> insert descending a delete-emptied extension", "[trie][gridmpt]") {
    // ext("8e") -> branch{1,7} -> two leaves; the insert splits the ext path.
    const Bytes32Map pre{{key_with_prefix({8, 0xe, 1}), slot_value_rlp(1)},
                         {key_with_prefix({8, 0xe, 7}), slot_value_rlp(2)}};
    check_delete_all_then_insert(pre, {{key_with_prefix({8, 0xf}), slot_value_rlp(3)}});
}

// After the eager fold of a delete-emptied line moves the seek's landing
// depth up, the cursor kept the child's consumed count and the following
// descent read a shifted key nibble (silent wrong root or a bogus
// missing-node report).
TEST_CASE("GridMPT<true> seek cursor after folding a delete-emptied line", "[trie][gridmpt]") {
    // An insert first splits ext("cf") into ext("c") -> branch; the deletes
    // then empty the inner branch and the last insert seeks across its fold.
    const Bytes32Map pre{{key_with_prefix({0xc, 0xf, 1}), slot_value_rlp(1)},
                         {key_with_prefix({0xc, 0xf, 7}), slot_value_rlp(2)}};
    check_delete_all_then_insert(pre, {{key_with_prefix({0xc, 7}), slot_value_rlp(3)},
                                       {key_with_prefix({0xc, 0xf, 0xf}), slot_value_rlp(4)}});
}
