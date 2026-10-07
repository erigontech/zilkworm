// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// GridMPT<true> regression tests: references into the walk's storage must survive it growing.
//
// The grid was a vector reserved for 66 lines, with references to its lines held across the appends of
// unfolds and insertions, and the copies of embedded nodes a vector that leaves view into. Either one
// reallocating left those references to freed memory (on the guest, whose allocator never reuses
// memory, writes through them went to the abandoned buffer and were lost). The grid now has its largest
// size, 255 lines, from the start and fails the walk past it; the copies are a deque.

#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
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

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
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

// A hashed trie key: the given nibbles, then `fill` repeated.
bytes32 key_with_nibbles(const std::vector<uint8_t>& nibs, uint8_t fill) {
    bytes32 k{};
    size_t i = 0;
    for (uint8_t n : nibs) {
        k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? n << 4 : n);
        ++i;
    }
    for (; i < 64; ++i) k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? fill << 4 : fill);
    return k;
}

// Runs the sorted `updates` (deletions as 0x80) against a complete witness of the trie `pre` and returns
// the root, with the post-state's HashBuilder root in `want`. `fits`: the walk must not fail; otherwise
// it must.
bytes32 walk(const Bytes32Map& pre, const std::map<bytes32, Bytes, Bytes32Less>& updates, bytes32& want,
             bool fits = true) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    Bytes32Map post = pre;
    std::vector<TrieNodeFlat> flat;  // must never reallocate: GridMPT keeps views into TrieNodeFlat::buf
    flat.reserve(updates.size());
    for (const auto& [k, v] : updates) {
        auto& node = flat.emplace_back(k);
        if (const auto it = pre.find(k); it != pre.end()) {
            node.self_initial_len = static_cast<uint8_t>(it->second.size());
            std::memcpy(node.buf, it->second.data(), it->second.size());
        }
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(v.size());
        if (!v.empty()) std::memcpy(node.buf + 40, v.data(), v.size());
        if (v == Bytes{0x80}) {
            post.erase(k);
        } else if (!v.empty()) {
            post[k] = v;
        }
    }
    want = hashbuilder_root(post, nullptr);
    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({flat.data(), flat.size()});
    CHECK(trie.missing_count() == 0);
    CHECK(trie.failed() == !fits);
    return got;
}

}  // namespace

// Two leaves under a branch 40 nibbles down are short enough to be embedded in it, so each unfolds from a
// copy of its bytes. Reading one, then deleting the other, takes two copies, and the second can move the
// first: the read leaf, which becomes the branch's only child and merges into the extension above it,
// was then encoded with a value viewing freed memory.
TEST_CASE("GridMPT<true> embedded leaves keep their bytes as more are unfolded", "[trie][gridmpt]") {
    const std::vector<uint8_t> prefix(40, 3);
    std::vector<uint8_t> pa = prefix, pb = prefix;
    pa.push_back(1);
    pb.push_back(2);
    const bytes32 a = key_with_nibbles(pa, 4);
    const bytes32 b = key_with_nibbles(pb, 5);
    const Bytes32Map pre{{a, Bytes{0x01}}, {b, Bytes{0x02}}, {key_with_nibbles({9}, 6), Bytes{0x84, 1, 2, 3, 4}}};
    bytes32 want;
    const bytes32 got = walk(pre, {{a, Bytes{}}, {b, Bytes{0x80}}}, want);
    CHECK(got == want);
}

// Each branch on the path of the current key keeps the lines of the children the walk unfolded under it
// until it leaves the branch. Keys that share the path's first l nibbles and differ at nibble l, for
// l = 0..D-1, give each of the path's D branches 15 such children: 16 D + 1 lines. Keys ground from slot
// numbers get there (the last 15 need a prefix of D - 1 nibbles, 16^(D-1) tries each). 66 lines were
// reserved, and past 127 the descent's bound on the line index failed the walk; the grid now holds 255.
TEST_CASE("GridMPT<true> grid of 16 lines per branch level", "[trie][gridmpt]") {
    for (const unsigned levels : {4u, 5u, 8u, 9u, 15u, 16u}) {
        CAPTURE(levels);
        Bytes32Map pre;
        std::map<bytes32, Bytes, Bytes32Less> updates;
        std::vector<uint8_t> path;
        for (unsigned l = 0; l < levels; ++l) {
            for (uint8_t v = 0; v < 15; ++v) {
                std::vector<uint8_t> p = path;
                p.push_back(v);
                pre[key_with_nibbles(p, static_cast<uint8_t>((l + v) & 15))] = Bytes{0x84, 1, 1, 1, 1};
            }
            path.push_back(15);
        }
        pre[key_with_nibbles(path, 0)] = Bytes{0x84, 1, 1, 1, 1};
        for (const auto& [k, v] : pre) updates[k] = Bytes{0x84, 2, 2, 2, 2};
        const bool fits = 16 * levels + 1 <= 255;
        bytes32 want;
        const bytes32 got = walk(pre, updates, want, fits);
        if (fits) {
            CHECK(got == want);
        } else {
            CHECK(got == bytes32{});  // the walk cannot go on, and is flagged failed
        }
    }
}
