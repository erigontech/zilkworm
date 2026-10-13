// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The keccak states of full branches saved while a witness node is verified, and the hashes resumed
// from them when the branch is folded again (kprefix, see common_zz/keccak_prefix.hpp). A resumed
// digest must equal the keccak of the branch's new encoding, and a saved state must never be used
// when any byte it covers could have changed since it was saved.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <random>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common_zz/keccak_prefix.hpp>
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

constexpr size_t kNode = kprefix::kNodeSize;

// A full branch node: 16 hash children and an empty value, 532 bytes, at the 8-aligned `at`.
void fill_full_branch(uint8_t* at, std::mt19937_64& rng) {
    at[0] = 0xf9;
    at[1] = 0x02;
    at[2] = 0x11;
    for (size_t i = 0; i < 16; ++i) {
        at[3 + 33 * i] = 0xa0;
        for (size_t k = 0; k < 32; ++k) at[4 + 33 * i + k] = static_cast<uint8_t>(rng());
    }
    at[3 + 16 * 33] = 0x80;
}

// Mirrors unfold_node_from_rlp: decode the node, then record where it came from.
BranchNode unfold(const uint8_t* node, size_t size) {
    ByteView payload{node, size};
    const auto hdr = silkworm::rlp::decode_header(payload);
    REQUIRE(hdr.has_value());
    BranchNode b;
    bool is_leaf{};
    std::array<uint8_t, 64> path{};
    uint8_t plen{};
    ByteView second{};
    REQUIRE(decode_node(payload, b, is_leaf, path, plen, second) == kBranch);
    b.orig = node;
    b.orig_size = static_cast<uint16_t>(size);
    b.orig_child_len = b.child_len;
    b.dirty = 0;
    return b;
}

// What fold_line() does with a branch, returning the digest the two ways it can get one.
struct Folded {
    unsigned blocks;  // 0: no resume
    ethash::hash256 plain;
    ethash::hash256 got;
};

Folded fold(const BranchNode& b, size_t row) {
    const ByteView encoded = encode_branch(b);
    Folded f{};
    f.plain = ethash_keccak256(encoded.data(), encoded.size());
    f.blocks = take_resumable_blocks(b, row, encoded);
    f.got = f.blocks != 0 ? ethash_keccak256_resume(kprefix::pool[row], f.blocks, encoded.data(), encoded.size())
                          : f.plain;
    return f;
}

// Saves the state of the first `blocks` blocks of `node` in `row`, as verifying it does.
void save(const uint8_t* node, size_t row, unsigned blocks) {
    const ethash::hash256 h = ethash_keccak256(node, kNode);
    REQUIRE(kprefix::verify_and_snap(node, row, blocks, h.bytes));
    REQUIRE(kprefix::tag_orig[row] == node);
    REQUIRE(kprefix::tag_sb[row] == blocks);
}

void dirty_slot(BranchNode& b, unsigned slot, std::mt19937_64& rng) {
    uint8_t h[32];
    for (auto& x : h) x = static_cast<uint8_t>(rng());
    b.set_child(slot, ByteView{h, 32});
}

}  // namespace

TEST_CASE("kprefix: a resumed hash equals the keccak of the patched node", "[trie][kprefix]") {
    std::mt19937_64 rng(1);
    alignas(256) static uint8_t node[544];
    kprefix::clear_tags();
    size_t resumed = 0;
    for (unsigned trial = 0; trial < 200; ++trial) {
        fill_full_branch(node, rng);
        const unsigned blocks = 1 + trial % 3;
        const size_t row = rng() % kprefix::kRows;
        // Every single slot, every pair of the slots that straddle or border a block, all 16, and
        // random sets.
        std::vector<uint32_t> masks;
        for (unsigned i = 0; i < 16; ++i) masks.push_back(1u << i);
        for (unsigned i : {3u, 4u, 8u, 9u, 12u, 13u, 15u})
            for (unsigned j : {0u, 3u, 8u, 12u, 15u}) masks.push_back((1u << i) | (1u << j));
        masks.push_back(0xffff);
        for (unsigned k = 0; k < 8; ++k) masks.push_back(static_cast<uint32_t>(rng() & 0xffff) | 1u);
        for (const uint32_t mask : masks) {
            save(node, row, blocks);
            BranchNode b = unfold(node, kNode);
            for (unsigned i = 0; i < 16; ++i)
                if (mask >> i & 1) dirty_slot(b, i, rng);
            const unsigned lowest = static_cast<unsigned>(std::countr_zero(mask));
            // The saved state covers the blocks before the first changed byte, the hash bytes of
            // slot i starting at 4 + 33 i: slots 8 and 12 straddle blocks 2 and 3.
            const bool allowed = 4 + 33 * lowest >= 136 * blocks;
            const Folded f = fold(b, row);
            REQUIRE((f.blocks != 0) == allowed);
            if (allowed) {
                REQUIRE(f.blocks == blocks);
                ++resumed;
                // Consumed: the state was permuted in place, so a second fold cannot take it.
                CHECK(kprefix::tag_orig[row] == nullptr);
                CHECK(take_resumable_blocks(b, row, encode_branch(b)) == 0);
            }
            REQUIRE(std::memcmp(f.got.bytes, f.plain.bytes, 32) == 0);
        }
    }
    CHECK(resumed > 1000);
}

TEST_CASE("kprefix: the guard rejects the slots that straddle a saved block", "[trie][kprefix]") {
    std::mt19937_64 rng(2);
    alignas(256) static uint8_t node[544];
    fill_full_branch(node, rng);
    const struct {
        unsigned slot, blocks;
        bool resumes;
    } cases[] = {{8, 2, false}, {12, 3, false}, {3, 1, false}, {4, 1, true}, {8, 1, true},
                 {9, 2, true},  {12, 2, true},  {13, 3, true}, {15, 3, true}, {0, 1, false}};
    for (const auto& c : cases) {
        save(node, 7, c.blocks);
        BranchNode b = unfold(node, kNode);
        dirty_slot(b, c.slot, rng);
        const Folded f = fold(b, 7);
        CHECK((f.blocks != 0) == c.resumes);
        CHECK(std::memcmp(f.got.bytes, f.plain.bytes, 32) == 0);
    }
}

TEST_CASE("kprefix: a saved state is used only for the node it was saved for", "[trie][kprefix]") {
    std::mt19937_64 rng(3);
    alignas(256) static uint8_t node[544], other[544];
    fill_full_branch(node, rng);
    std::memcpy(other, node, sizeof node);  // the same bytes at another address
    const size_t row = 9;

    SECTION("another node with the same bytes") {
        save(node, row, 2);
        BranchNode b = unfold(other, kNode);
        dirty_slot(b, 14, rng);
        CHECK(fold(b, row).blocks == 0);
    }
    SECTION("another row") {
        save(node, row, 2);
        BranchNode b = unfold(node, kNode);
        dirty_slot(b, 14, rng);
        CHECK(fold(b, row + 1).blocks == 0);
    }
    SECTION("a branch built in the grid has no origin") {
        save(node, row, 2);
        BranchNode b = unfold(node, kNode);
        dirty_slot(b, 14, rng);
        b.orig = nullptr;
        kprefix::tag_orig[row] = nullptr;  // a null tag must not match a null origin
        CHECK(fold(b, row).blocks == 0);
    }
    SECTION("nothing changed: the witness node itself") {
        save(node, row, 2);
        BranchNode b = unfold(node, kNode);
        const Folded f = fold(b, row);
        CHECK(f.blocks == 2);
        CHECK(std::memcmp(f.got.bytes, f.plain.bytes, 32) == 0);
    }
    SECTION("the layout changed") {
        save(node, row, 1);
        BranchNode b = unfold(node, kNode);
        b.delete_child(14);
        b.set_child(14, ByteView{node, 5});  // an embedded child where a hash was
        const Folded f = fold(b, row);
        CHECK(f.blocks == 0);
        CHECK(std::memcmp(f.got.bytes, f.plain.bytes, 32) == 0);
    }
    SECTION("a node that is not 8-aligned") {
        alignas(256) static uint8_t shifted[552];
        std::memcpy(shifted + 1, node, kNode);
        const ethash::hash256 h = ethash_keccak256(shifted + 1, kNode);
        // The lookup never snapshots such a node (find_node_rlp checks the alignment); a tag over it
        // would not be used either.
        kprefix::tag_orig[row] = shifted + 1;
        kprefix::tag_sb[row] = 1;
        BranchNode b = unfold(shifted + 1, kNode);
        dirty_slot(b, 14, rng);
        CHECK(fold(b, row).blocks == 0);
        (void)h;
    }
    SECTION("the bytes the state covers changed after it was saved") {
        // Not something the witness does (its bytes are fixed): this shows what a stale state is,
        // the reason the tag must go whenever its row is written or consumed.
        save(node, row, 2);
        alignas(256) static uint8_t changed[544];
        std::memcpy(changed, node, sizeof node);
        changed[50] ^= 0x01;
        BranchNode b = unfold(changed, kNode);
        dirty_slot(b, 14, rng);
        kprefix::tag_orig[row] = changed;  // forge the tag over the changed node
        const ByteView enc = encode_branch(b);
        const unsigned blocks = take_resumable_blocks(b, row, enc);
        REQUIRE(blocks == 2);
        const ethash::hash256 stale = ethash_keccak256_resume(kprefix::pool[row], blocks, enc.data(), enc.size());
        const ethash::hash256 plain = ethash_keccak256(enc.data(), enc.size());
        CHECK(std::memcmp(stale.bytes, plain.bytes, 32) != 0);
    }
}

TEST_CASE("kprefix: a failed verification leaves no tag over the overwritten row", "[trie][kprefix]") {
    std::mt19937_64 rng(4);
    alignas(256) static uint8_t good[544], bad[544];
    fill_full_branch(good, rng);
    fill_full_branch(bad, rng);
    const size_t row = 11;
    save(good, row, 3);
    const ethash::hash256 not_bad = ethash_keccak256(good, kNode);
    // `bad` hashes to something else than the hash it was looked up by: its snapshot overwrote the row.
    CHECK_FALSE(kprefix::verify_and_snap(bad, row, 2, not_bad.bytes));
    CHECK(kprefix::tag_orig[row] == nullptr);
    BranchNode b = unfold(good, kNode);
    dirty_slot(b, 15, rng);
    CHECK(fold(b, row).blocks == 0);
}

namespace {

struct Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept { return std::memcmp(a.bytes, b.bytes, 32) < 0; }
};
using Map = std::map<bytes32, Bytes, Less>;

bytes32 hb_root(const Map& leaves, Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink) hb.rlp_collector = [sink](ByteView n) { sink->emplace(keccak_bytes(n), Bytes{n}); };
    for (const auto& [k, v] : leaves) hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    return hb.root_hash();
}

std::vector<uint8_t> build_node_store(const Map& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : nodes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, rlp);
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

struct Witness {
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, {}, {});
    std::vector<uint8_t> store;
    DirectState state;
    explicit Witness(const Map& nodes)
        : store{build_node_store(nodes)}, state{std::span<uint8_t>{prestate}, std::span<uint8_t>{store}} {}
};

struct Update {
    Map expected;
    std::vector<TrieNodeFlat> updates;
    std::deque<Bytes> keep;
};

Bytes value_of(std::mt19937_64& rng, size_t n) {
    Bytes v(n, 0);
    for (auto& x : v) x = static_cast<uint8_t>(rng() | 1);
    return v;
}

// A sorted batch over the trie `pre`: each of its keys is read, rewritten, or deleted with the given
// odds (percent), and `inserts` new random keys are added.
enum class Mode { kMixed, kWritesOnly, kReadFirst };
Update make_update(const Map& pre, std::mt19937_64& rng, Mode mode, unsigned touch_pct, size_t inserts) {
    Update u;
    u.expected = pre;
    std::map<bytes32, TrieNodeFlat, Less> ups;
    for (const auto& [k, v] : pre) {
        if (rng() % 100 >= touch_pct) continue;
        TrieNodeFlat n{k};
        n.self_initial_len = static_cast<uint8_t>(v.size());
        std::memcpy(n.buf, v.data(), v.size());
        const unsigned r = static_cast<unsigned>(rng() % 100);
        if (mode == Mode::kReadFirst && ups.empty()) {
            // the first update of the trie only reads
        } else if (r < 55 || mode == Mode::kWritesOnly) {
            const Bytes w = value_of(rng, 1 + rng() % 40);
            n.current_off = 40;
            n.current_len = static_cast<uint8_t>(w.size());
            std::memcpy(n.buf + 40, w.data(), w.size());
            u.expected[k] = w;
        } else if (r < 70) {
            n.current_off = 40;
            n.current_len = 1;
            n.buf[40] = 0x80;
            u.expected.erase(k);
        }  // else: read only
        ups.emplace(k, n);
    }
    for (size_t i = 0; i < inserts; ++i) {
        bytes32 k;
        for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
        if (pre.count(k) || ups.count(k)) continue;
        TrieNodeFlat n{k};
        const Bytes w = value_of(rng, 1 + rng() % 40);
        n.current_off = 40;
        n.current_len = static_cast<uint8_t>(w.size());
        std::memcpy(n.buf + 40, w.data(), w.size());
        u.expected[k] = w;
        ups.emplace(k, n);
    }
    for (auto& [k, n] : ups) u.updates.push_back(n);
    return u;
}

Map random_trie(std::mt19937_64& rng, size_t n) {
    Map m;
    for (size_t i = 0; i < n; ++i) {
        bytes32 k;
        for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
        m.emplace(k, value_of(rng, 1 + rng() % 40));
    }
    return m;
}

}  // namespace

// Tries of a few thousand random keys have full branches in their first three levels, so most
// updates pass through nodes whose state is saved and resumed. Roots are checked against the
// canonical HashBuilder, through one GridMPT reset between tries (check_root's storage tries) and
// through a new GridMPT per trie, on a witness shared by all of them.
TEST_CASE("kprefix: GridMPT roots match HashBuilder", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(5);
    const Mode modes[] = {Mode::kMixed, Mode::kWritesOnly, Mode::kReadFirst};
    for (int round = 0; round < 6; ++round) {
        const size_t n = std::array<size_t, 6>{40, 300, 1200, 2500, 4000, 800}[static_cast<size_t>(round)];
        Map nodes;
        const Map pre = random_trie(rng, n);
        const bytes32 pre_root = hb_root(pre, &nodes);
        // Several batches over the same trie: the same witness nodes unfolded again, in tries
        // whose first update differs, with and without their state already verified.
        std::vector<Update> batches;
        for (int i = 0; i < 6; ++i)
            batches.push_back(make_update(pre, rng, modes[i % 3], i % 2 ? 4 : 30, i % 3 == 0 ? 10 : 0));
        {
            Witness w{nodes};
            GridMPT<true> reused{w.state, silkworm::kEmptyRoot};
            for (const auto& u : batches) {
                reused.reset(pre_root);
                const bytes32 got = reused.calc_root_from_updates({u.updates.data(), u.updates.size()});
                CHECK(got == hb_root(u.expected, nullptr));
            }
        }
        for (const auto& u : batches) {
            Witness w{nodes};  // unverified nodes: their states are saved
            GridMPT<true> fresh{w.state, pre_root};
            const bytes32 got = fresh.calc_root_from_updates({u.updates.data(), u.updates.size()});
            CHECK(got == hb_root(u.expected, nullptr));
        }
    }
}

TEST_CASE("kprefix: the same node folded in two storage tries", "[trie][gridmpt][kprefix]") {
    // Two tries with the same content share their witness nodes, so a node verified (and its state
    // saved) for the first is the same node, at the same address and depth, in the second. The first
    // fold consumed the state: the second must hash in full.
    std::mt19937_64 rng(6);
    Map nodes;
    const Map pre = random_trie(rng, 1500);
    const bytes32 pre_root = hb_root(pre, &nodes);
    Witness w{nodes};
    GridMPT<true> grid{w.state, silkworm::kEmptyRoot};
    for (int i = 0; i < 8; ++i) {
        const Update u = make_update(pre, rng, Mode::kWritesOnly, 10, 0);
        grid.reset(pre_root);
        CHECK(grid.calc_root_from_updates({u.updates.data(), u.updates.size()}) == hb_root(u.expected, nullptr));
    }
}

TEST_CASE("kprefix: a corrupt node at a row holding a live tag fails verification", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(7);
    alignas(256) static uint8_t good[544];
    fill_full_branch(good, rng);
    // A witness entry filed under the hash of `good` whose payload is another full branch.
    alignas(256) static uint8_t corrupt[544];
    fill_full_branch(corrupt, rng);
    const ethash::hash256 gh = ethash_keccak256(good, kNode);
    bytes32 want;
    std::memcpy(want.bytes, gh.bytes, 32);
    Map nodes;
    nodes.emplace(want, Bytes{ByteView{corrupt, kNode}});
    Witness w{nodes};
    // A live tag in the row the lookup would use.
    save(good, 5, 2);
    CHECK_FALSE(w.state.find_node_rlp(want, [] { return kprefix::SnapRequest{6, 5}; }).has_value());
    CHECK(kprefix::tag_orig[5] == nullptr);
    // The failed lookup did not mark the node verified: it fails again.
    CHECK_FALSE(w.state.find_node_rlp(want).has_value());
}

TEST_CASE("kprefix: tags do not outlive a GridMPT", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(8);
    alignas(256) static uint8_t node[544];
    fill_full_branch(node, rng);
    save(node, 3, 1);
    Witness w{Map{}};
    GridMPT<true> grid{w.state, silkworm::kEmptyRoot};
    for (size_t i = 0; i < kprefix::kRows; ++i) CHECK(kprefix::tag_orig[i] == nullptr);
}
