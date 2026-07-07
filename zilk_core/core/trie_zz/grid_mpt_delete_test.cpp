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

#include <cstdint>
#include <cstring>
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

// Brute-force a key whose hashed form starts with the given nibble.
bytes32 key_with_first_nibble(uint8_t nib) {
    for (uint64_t i = 0;; ++i) {
        bytes32 raw{};
        for (int b = 0; b < 8; ++b) raw.bytes[31 - b] = static_cast<uint8_t>(i >> (8 * b));
        const bytes32 h = keccak_bytes(ByteView{raw.bytes, 32});
        if ((h.bytes[0] >> 4) == nib) return h;
    }
}

}  // namespace

TEST_CASE("GridMPT<true> survives a batch that empties the trie", "[trie][gridmpt]") {
    // Pre-state: two leaves diverging at the first nibble; complete witness.
    const Bytes32Map pre{{key_with_first_nibble(0xa), slot_value_rlp(1)},
                         {key_with_first_nibble(0xd), slot_value_rlp(2)}};
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    // Update batch (sorted; must never reallocate, GridMPT keeps ByteViews
    // into TrieNodeFlat::buf): delete both pre leaves, as check_root encodes
    // deletes (initial = pre value rlp, current = {0x80}).
    std::vector<TrieNodeFlat> updates;
    updates.reserve(3);
    for (const auto& [k, v] : pre) {
        auto& node = updates.emplace_back(k);
        node.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf, v.data(), v.size());
        node.buf[40] = 0x80;
        node.current_off = 40;
        node.current_len = 1;
    }

    Bytes32Map post;
    SECTION("deletes then insert (the grid must re-seed)") {
        post = {{key_with_first_nibble(0xf), slot_value_rlp(3)}};  // sorts after the deletes
        const auto& [k, v] = *post.begin();
        auto& node = updates.emplace_back(k);
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(node.buf + 40, v.data(), v.size());
    }
    SECTION("deletes only (empty post root)") {}

    GridMPT<true> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({updates.data(), updates.size()});
    const bytes32 expected = hashbuilder_root(post, nullptr);

    CAPTURE(silkworm::to_hex(got), silkworm::to_hex(expected));
    CHECK(trie.missing_count() == 0);
    REQUIRE(got == expected);
}
