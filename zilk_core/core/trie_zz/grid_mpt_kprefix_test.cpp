// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// The keccak states of full branches saved while a witness node is verified.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <optional>
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
    unsigned blocks;
    ethash::hash256 plain;
    ethash::hash256 got;
};

Folded fold(const BranchNode& b, size_t row) {
    const ByteView encoded = encode_branch(b);
    Folded f{};
    f.plain = ethash_keccak256(encoded.data(), encoded.size());
    if (hashes_from_witness(b)) {
        f.blocks = take_resumable_blocks(b, row);
        f.got = b.full_branch_hash(kprefix::pool[row], f.blocks);
    } else {
        f.got = f.plain;
    }
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
            const bool allowed = 4 + 33 * lowest >= 136 * blocks;
            const Folded f = fold(b, row);
            REQUIRE((f.blocks != 0) == allowed);
            if (allowed) {
                REQUIRE(f.blocks == blocks);
                ++resumed;
                CHECK(kprefix::tag_orig[row] == nullptr);
                CHECK(take_resumable_blocks(b, row) == 0);
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
    std::memcpy(other, node, sizeof node);
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
        kprefix::tag_orig[row] = nullptr;
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
        b.set_child(14, ByteView{node, 5});
        const Folded f = fold(b, row);
        CHECK(f.blocks == 0);
        CHECK(std::memcmp(f.got.bytes, f.plain.bytes, 32) == 0);
    }
    SECTION("a node that is not 8-aligned") {
        alignas(256) static uint8_t shifted[552];
        std::memcpy(shifted + 1, node, kNode);
        const ethash::hash256 h = ethash_keccak256(shifted + 1, kNode);
        kprefix::tag_orig[row] = shifted + 1;
        kprefix::tag_sb[row] = 1;
        BranchNode b = unfold(shifted + 1, kNode);
        dirty_slot(b, 14, rng);
        CHECK(fold(b, row).blocks == 0);
        (void)h;
    }
    SECTION("the bytes the state covers changed after it was saved") {
        save(node, row, 2);
        alignas(256) static uint8_t changed[544];
        std::memcpy(changed, node, sizeof node);
        changed[50] ^= 0x01;
        BranchNode b = unfold(changed, kNode);
        dirty_slot(b, 14, rng);
        kprefix::tag_orig[row] = changed;
        REQUIRE(hashes_from_witness(b));
        const unsigned blocks = take_resumable_blocks(b, row);
        REQUIRE(blocks == 2);
        const ethash::hash256 stale = b.full_branch_hash(kprefix::pool[row], blocks);
        const ByteView enc = encode_branch(b);
        const ethash::hash256 plain = ethash_keccak256(enc.data(), enc.size());
        CHECK(std::memcmp(stale.bytes, plain.bytes, 32) != 0);
    }
}

TEST_CASE("kprefix: a block count out of range stays inside kHeadSlots", "[trie][kprefix]") {
    std::mt19937_64 rng(9);
    alignas(256) static uint8_t node[544];
    fill_full_branch(node, rng);
    const size_t row = 13;
    for (const unsigned sb : {0u, 4u, 7u, 128u, 255u}) {
        CAPTURE(sb);
        save(node, row, 1);
        kprefix::tag_sb[row] = static_cast<uint8_t>(sb);
        const BranchNode b = unfold(node, kNode);
        CHECK(take_resumable_blocks(b, row) == (sb & 3u));
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
    CHECK_FALSE(kprefix::verify_and_snap(bad, row, 2, not_bad.bytes));
    CHECK(kprefix::tag_orig[row] == nullptr);
    BranchNode b = unfold(good, kNode);
    dirty_slot(b, 15, rng);
    CHECK(fold(b, row).blocks == 0);
}

// Branches that are not full (empty slots, embedded nodes).
namespace {

enum : uint8_t { kEmptySlot, kHashSlot, kEmbeddedSlot };

// A branch with slot i of kind kinds[i] and an empty value at `at`; returns its size.
size_t fill_branch(uint8_t* at, const std::array<uint8_t, 16>& kinds, std::mt19937_64& rng) {
    uint8_t body[600];
    size_t n = 0;
    for (size_t i = 0; i < 16; ++i) {
        if (kinds[i] == kEmptySlot) {
            body[n++] = 0x80;
        } else if (kinds[i] == kHashSlot) {
            body[n++] = 0xa0;
            for (size_t k = 0; k < 32; ++k) body[n++] = static_cast<uint8_t>(rng());
        } else {
            const size_t len = 1 + rng() % 30;
            body[n++] = static_cast<uint8_t>(0xc0 + len);
            for (size_t k = 0; k < len; ++k) body[n++] = static_cast<uint8_t>(rng());
        }
    }
    body[n++] = 0x80;
    size_t h = 0;
    if (n < 256) {
        at[h++] = 0xf8;
    } else {
        at[h++] = 0xf9;
        at[h++] = static_cast<uint8_t>(n >> 8);
    }
    at[h++] = static_cast<uint8_t>(n);
    std::memcpy(at + h, body, n);
    return h + n;
}

// Rewrites slot i of b with new bytes of the same length class, as an update that keeps the node's layout does.
void dirty_same_layout(BranchNode& b, unsigned i, std::mt19937_64& rng) {
    const unsigned len = b.child_len[i];
    if (len == 0) {
        b.delete_child(i);
        return;
    }
    uint8_t x[32];
    for (auto& v : x) v = static_cast<uint8_t>(rng());
    if (len != 32) x[0] = static_cast<uint8_t>(0xc0 + len - 1);
    b.set_child(i, ByteView{x, len});
}

}  // namespace

TEST_CASE("kprefix: a branch copied and patched resumes from the blocks before its first dirty slot", "[trie][kprefix]") {
    std::mt19937_64 rng(15);
    alignas(256) static uint8_t buf[640];
    size_t resumed = 0, saved = 0;
    for (unsigned trial = 0; trial < 3000; ++trial) {
        std::array<uint8_t, 16> kinds;
        unsigned hashes = 0;
        for (auto& k : kinds) {
            const unsigned r = static_cast<unsigned>(rng() % 10);
            k = r < 6 ? kHashSlot : r < 8 ? kEmptySlot : kEmbeddedSlot;
            hashes += k == kHashSlot;
        }
        if (hashes == 16) kinds[rng() % 16] = kEmptySlot;
        uint8_t* const node = buf + 8 * (trial % 4);
        const size_t size = fill_branch(node, kinds, rng);
        if (size < kprefix::kBlock) continue;
        const ethash::hash256 h = ethash_keccak256(node, size);
        const size_t row = rng() % kprefix::kRows;
        kprefix::tag_orig[row] = nullptr;
        const unsigned j = static_cast<unsigned>(rng() % 17);
        const unsigned blocks = kprefix::blocks_before_slot(node, size, j);
        if (blocks != 0) {
            REQUIRE(kprefix::verify_and_snap(node, size, kprefix::pool[row], kprefix::tag_orig[row], kprefix::tag_sb[row],
                                             blocks, h.bytes));
            ++saved;
        }
        BranchNode b = unfold(node, size);
        REQUIRE_FALSE(hashes_from_witness(b));
        const unsigned from = rng() % 2 ? j % 16 : 0;
        for (unsigned i = from; i < 16; ++i)
            if (rng() % 4 == 0) dirty_same_layout(b, i, rng);
        REQUIRE(b.same_layout_as_orig());
        const ByteView enc = encode_branch(b);
        REQUIRE(enc.size() == size);
        REQUIRE((reinterpret_cast<uintptr_t>(enc.data()) & 7) == 0);
        const unsigned allowed = same_layout_clean_blocks(b);
        CHECK(std::memcmp(enc.data(), node, kprefix::kBlock * allowed) == 0);
        if (b.dirty != 0 && allowed < size / kprefix::kBlock) {
            size_t off = node[0] == 0xf8 ? 2 : 3;
            for (unsigned i = 0; i < lowest_set_bit(b.dirty); ++i) off += b.child_len[i] == 0 ? 1u : b.child_len[i] == 32 ? 33u : unsigned{b.child_len[i]};
            CHECK(off < kprefix::kBlock * (allowed + 1));
        }
        const ethash::hash256 plain = ethash_keccak256(enc.data(), enc.size());
        if (kprefix::tag_orig[row] == node && kprefix::tag_sb[row] <= allowed) {
            const ethash::hash256 got = ethash_keccak256_resume(kprefix::pool[row], kprefix::tag_sb[row], enc.data(), enc.size());
            kprefix::tag_orig[row] = nullptr;
            REQUIRE(std::memcmp(got.bytes, plain.bytes, 32) == 0);
            ++resumed;
        }
    }
    CHECK(saved > 1000);
    CHECK(resumed > 500);
}

TEST_CASE("kprefix: the blocks before a slot of a branch that is not full", "[trie][kprefix]") {
    std::mt19937_64 rng(16);
    alignas(256) static uint8_t node[640];
    std::array<uint8_t, 16> kinds{};
    for (unsigned i = 0; i < 16; ++i) kinds[i] = (i < 10 || i == 12 || i == 14) ? kHashSlot : kEmptySlot;
    REQUIRE(fill_branch(node, kinds, rng) == 404);
    CHECK(kprefix::blocks_before_slot(node, 404, 0) == 0);
    CHECK(kprefix::blocks_before_slot(node, 404, 4) == 0);
    CHECK(kprefix::blocks_before_slot(node, 404, 5) == 1);
    CHECK(kprefix::blocks_before_slot(node, 404, 8) == 1);
    CHECK(kprefix::blocks_before_slot(node, 404, 9) == 2);
    CHECK(kprefix::blocks_before_slot(node, 404, 12) == 2);
    CHECK(kprefix::blocks_before_slot(node, 404, 15) == 2);
    CHECK(kprefix::blocks_before_slot(node, 404, kprefix::kNoSlot) == 0);
    BranchNode b = unfold(node, 404);
    CHECK(same_layout_clean_blocks(b) == 2);
    for (const auto& [slot, blocks] : std::vector<std::pair<unsigned, unsigned>>{{0, 0}, {4, 0}, {5, 1}, {9, 2}, {13, 2}}) {
        BranchNode d = b;
        dirty_same_layout(d, slot, rng);
        CHECK(same_layout_clean_blocks(d) == blocks);
    }
    node[0] = 0xc5;
    CHECK(kprefix::blocks_before_slot(node, 404, 12) == 0);
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

// A sorted batch over the trie `pre`: each of its keys is read, rewritten, or deleted with the given odds (percent).
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
        }
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

// Tries of a few thousand random keys have full branches in their first three levels.
TEST_CASE("kprefix: GridMPT roots match HashBuilder", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(5);
    const Mode modes[] = {Mode::kMixed, Mode::kWritesOnly, Mode::kReadFirst};
    for (int round = 0; round < 6; ++round) {
        const size_t n = std::array<size_t, 6>{40, 300, 1200, 2500, 4000, 800}[static_cast<size_t>(round)];
        Map nodes;
        const Map pre = random_trie(rng, n);
        const bytes32 pre_root = hb_root(pre, &nodes);
        std::vector<Update> batches;
        for (int i = 0; i < 6; ++i)
            batches.push_back(make_update(pre, rng, modes[i % 3], i % 2 ? 4 : 30, i % 3 == 0 ? 10 : 0));
        {
            Witness w{nodes};
            GridMPT<true, DirectState> reused{w.state, silkworm::kEmptyRoot};
            for (const auto& u : batches) {
                reused.reset(pre_root);
                const bytes32 got = reused.calc_root_from_updates({u.updates.data(), u.updates.size()});
                CHECK(got == hb_root(u.expected, nullptr));
                CHECK_FALSE(reused.failed());
            }
        }
        for (const auto& u : batches) {
            Witness w{nodes};
            GridMPT<true, DirectState> fresh{w.state, pre_root};
            const bytes32 got = fresh.calc_root_from_updates({u.updates.data(), u.updates.size()});
            CHECK(got == hb_root(u.expected, nullptr));
            CHECK_FALSE(fresh.failed());
        }
    }
}

TEST_CASE("kprefix: the same node folded in two storage tries", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(6);
    Map nodes;
    const Map pre = random_trie(rng, 1500);
    const bytes32 pre_root = hb_root(pre, &nodes);
    Witness w{nodes};
    GridMPT<true, DirectState> grid{w.state, silkworm::kEmptyRoot};
    for (int i = 0; i < 8; ++i) {
        const Update u = make_update(pre, rng, Mode::kWritesOnly, 10, 0);
        grid.reset(pre_root);
        CHECK(grid.calc_root_from_updates({u.updates.data(), u.updates.size()}) == hb_root(u.expected, nullptr));
        CHECK_FALSE(grid.failed());
    }
}

namespace {

TrieNodeFlat read_of(const bytes32& k, const Bytes& v) {
    TrieNodeFlat n{k};
    n.self_initial_len = static_cast<uint8_t>(v.size());
    std::memcpy(n.buf, v.data(), v.size());
    return n;
}

TrieNodeFlat write_of(const bytes32& k, const Bytes& v, const Bytes& w) {
    TrieNodeFlat n = read_of(k, v);
    n.current_off = 40;
    n.current_len = static_cast<uint8_t>(w.size());
    std::memcpy(n.buf + 40, w.data(), w.size());
    return n;
}

// The node slot `slot` of the full branch `branch` refers to, where the node store holds it.
ByteView child_node(const DirectState& state, ByteView branch, unsigned slot) {
    REQUIRE(branch.size() == kNode);
    bytes32 h;
    std::memcpy(h.bytes, branch.data() + 4 + 33 * slot, 32);
    const auto rlp = state.find_node_rlp(h);
    REQUIRE(rlp.has_value());
    return *rlp;
}

// The pool row whose tag names `node`, or kRows.
size_t row_of(const uint8_t* node) {
    for (size_t i = 0; i < kprefix::kRows; ++i)
        if (kprefix::tag_orig[i] == node) return i;
    return kprefix::kRows;
}

// Two keys of `pre` under the same branch below the root, a full one.
struct KeyPair {
    bytes32 k1, k2;
};
std::optional<KeyPair> pair_under_full_branch(const Map& pre, unsigned lo, unsigned hi, unsigned min_top = 0) {
    std::array<uint16_t, 16> present{};
    for (const auto& [k, v] : pre) present[k.bytes[0] >> 4] |= static_cast<uint16_t>(1u << (k.bytes[0] & 0x0f));
    for (auto it = pre.begin(); it != pre.end(); ++it) {
        const unsigned top = it->first.bytes[0] >> 4;
        if (top < min_top || present[top] != 0xffff || (it->first.bytes[0] & 0x0f) != lo) continue;
        for (auto jt = std::next(it); jt != pre.end() && (jt->first.bytes[0] >> 4) == top; ++jt)
            if ((jt->first.bytes[0] & 0x0f) >= hi) return KeyPair{it->first, jt->first};
    }
    return std::nullopt;
}

// The full branch below the root that `key` goes through, once a walk verified it.
ByteView branch_below_root(const DirectState& state, const bytes32& root, const bytes32& key) {
    const auto r = state.find_node_rlp(root);
    REQUIRE(r.has_value());
    const ByteView b = child_node(state, *r, key.bytes[0] >> 4);
    REQUIRE(b.size() == kNode);
    return b;
}

}  // namespace

// Snapshots on read descents: the first key through a branch is often read only.
TEST_CASE("kprefix: a branch read first is resumed when a later update writes it", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(10);
    Map nodes;
    const Map pre = random_trie(rng, 1500);
    const bytes32 pre_root = hb_root(pre, &nodes);
    for (const unsigned lo : {4u, 9u, 13u}) {
        CAPTURE(lo);
        const auto kp = pair_under_full_branch(pre, lo, lo);
        REQUIRE(kp.has_value());
        const Bytes& v1 = pre.at(kp->k1);
        const Bytes& v2 = pre.at(kp->k2);
        const auto& [kz, vz] = *pre.rbegin();
        REQUIRE((kz.bytes[0] >> 4) != (kp->k1.bytes[0] >> 4));
        {
            Witness w{nodes};
            GridMPT<true, DirectState> grid{w.state, pre_root};
            const std::vector<TrieNodeFlat> ups{read_of(kp->k1, v1), write_of(kz, vz, vz)};
            CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == pre_root);
            CHECK_FALSE(grid.failed());
            const size_t row = row_of(branch_below_root(w.state, pre_root, kp->k1).data());
            REQUIRE(row < kprefix::kRows);
            CHECK(kprefix::tag_sb[row] == kprefix::first_blocks(lo));
        }
        {
            Witness w{nodes};
            GridMPT<true, DirectState> grid{w.state, pre_root};
            const std::vector<TrieNodeFlat> ups{read_of(kp->k1, v1), read_of(kz, vz)};
            CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == pre_root);
            CHECK_FALSE(grid.failed());
            CHECK(row_of(branch_below_root(w.state, pre_root, kp->k1).data()) == kprefix::kRows);
        }
        {
            Witness w{nodes};
            GridMPT<true, DirectState> grid{w.state, pre_root};
            const Bytes nv = value_of(rng, 33);
            const std::vector<TrieNodeFlat> ups{read_of(kp->k1, v1), write_of(kp->k2, v2, nv)};
            Map post = pre;
            post[kp->k2] = nv;
            CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
            CHECK_FALSE(grid.failed());
            CHECK(row_of(branch_below_root(w.state, pre_root, kp->k1).data()) == kprefix::kRows);
        }
    }
}

// The root is looked up when the walk starts.
TEST_CASE("kprefix: the root keeps the state of its blocks before the first slot written", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(14);
    Map nodes;
    const Map pre = random_trie(rng, 1500);
    const bytes32 pre_root = hb_root(pre, &nodes);
    std::array<bool, 16> seen{};
    for (const auto& [k, v] : pre) {
        const unsigned top = k.bytes[0] >> 4;
        if (top < 4 || seen[top]) continue;
        seen[top] = true;
        CAPTURE(top);
        std::vector<TrieNodeFlat> ups;
        for (const auto& [k0, v0] : pre) {
            if ((k0.bytes[0] >> 4) >= top) break;
            if (ups.size() < 3) ups.push_back(read_of(k0, v0));
        }
        ups.push_back(write_of(k, v, v));
        {
            Witness w{nodes};
            GridMPT<true, DirectState> grid{w.state, pre_root};
            CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == pre_root);
            CHECK_FALSE(grid.failed());
            const auto root = w.state.find_node_rlp(pre_root);
            REQUIRE(root.has_value());
            REQUIRE(root->size() == kNode);
            CHECK(kprefix::tag_orig[0] == root->data());
            CHECK(kprefix::tag_sb[0] == kprefix::first_blocks(top));
        }
        ups.back() = write_of(k, v, value_of(rng, 20));
        {
            Witness w{nodes};
            GridMPT<true, DirectState> grid{w.state, pre_root};
            Map post = pre;
            post[k] = Bytes{ups.back().current_value()};
            CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
            CHECK_FALSE(grid.failed());
            CHECK(kprefix::tag_orig[0] == nullptr);
        }
    }
    CHECK(std::count(seen.begin(), seen.end(), true) == 12);
}

TEST_CASE("kprefix: a corrupt node at a row holding a live tag fails verification", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(7);
    alignas(256) static uint8_t good[544];
    fill_full_branch(good, rng);
    alignas(256) static uint8_t corrupt[544];
    fill_full_branch(corrupt, rng);
    const ethash::hash256 gh = ethash_keccak256(good, kNode);
    bytes32 want;
    std::memcpy(want.bytes, gh.bytes, 32);
    Map nodes;
    nodes.emplace(want, Bytes{ByteView{corrupt, kNode}});
    Witness w{nodes};
    save(good, 5, 2);
    CHECK_FALSE(w.state.find_node_rlp(want, [] { return kprefix::SnapRequest{6, 5}; }).has_value());
    CHECK(kprefix::tag_orig[5] == nullptr);
    CHECK_FALSE(w.state.find_node_rlp(want).has_value());
}

TEST_CASE("kprefix: tags do not outlive a GridMPT", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(8);
    alignas(256) static uint8_t node[544];
    fill_full_branch(node, rng);
    save(node, 3, 1);
    Witness w{Map{}};
    GridMPT<true, DirectState> grid{w.state, silkworm::kEmptyRoot};
    for (size_t i = 0; i < kprefix::kRows; ++i) CHECK(kprefix::tag_orig[i] == nullptr);
}

namespace {

// A trie whose root is a full branch and whose branch under root slot 5 is not: slots 0-9.
template <class MakeKey>
struct SparseBranchTrie {
    Map pre;
    std::array<bytes32, 16> key{};
    SparseBranchTrie(std::mt19937_64& rng, MakeKey make, std::function<Bytes(std::mt19937_64&)> value) {
        for (unsigned top = 0; top < 16; ++top)
            if (top != 5) pre.emplace(make(top, static_cast<unsigned>(rng() % 16), rng), value(rng));
        for (unsigned j = 0; j < 16; ++j) {
            if (j >= 10 && j != 12 && j != 14) continue;
            key[j] = make(5, j, rng);
            pre.emplace(key[j], value(rng));
        }
    }
};

bytes32 random_key(unsigned top, unsigned second, std::mt19937_64& rng) {
    bytes32 k;
    for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
    k.bytes[0] = static_cast<uint8_t>(top << 4 | second);
    return k;
}

}  // namespace

TEST_CASE("kprefix: a branch that is not full, read first, resumes when a later update writes it", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(17);
    const SparseBranchTrie t{rng, &random_key, [](std::mt19937_64& r) { return value_of(r, 1 + r() % 40); }};
    Map nodes;
    const bytes32 pre_root = hb_root(t.pre, &nodes);
    const auto& [kz, vz] = *t.pre.rbegin();
    const auto branch_of = [&](const DirectState& state) {
        const auto r = state.find_node_rlp(pre_root);
        REQUIRE(r.has_value());
        return child_node(state, *r, 5);
    };
    {
        Witness w{nodes};
        GridMPT<true, DirectState> grid{w.state, pre_root};
        const std::vector<TrieNodeFlat> ups{read_of(t.key[12], t.pre.at(t.key[12])), write_of(kz, vz, vz)};
        CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == pre_root);
        CHECK_FALSE(grid.failed());
        const ByteView branch = branch_of(w.state);
        REQUIRE(branch.size() == 404);
        const size_t row = row_of(branch.data());
        REQUIRE(row < kprefix::kRows);
        CHECK(kprefix::tag_sb[row] == 2);
    }
    for (const unsigned written : {12u, 14u}) {
        CAPTURE(written);
        Witness w{nodes};
        GridMPT<true, DirectState> grid{w.state, pre_root};
        const Bytes nv = value_of(rng, 30);
        std::vector<TrieNodeFlat> ups;
        if (written != 12) ups.push_back(read_of(t.key[12], t.pre.at(t.key[12])));
        ups.push_back(write_of(t.key[written], t.pre.at(t.key[written]), nv));
        Map post = t.pre;
        post[t.key[written]] = nv;
        CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
        CHECK_FALSE(grid.failed());
        CHECK(row_of(branch_of(w.state).data()) == kprefix::kRows);
    }
    {
        Witness w{nodes};
        GridMPT<true, DirectState> grid{w.state, silkworm::kEmptyRoot};
        grid.reset(pre_root);
        const std::vector<TrieNodeFlat> first{read_of(t.key[12], t.pre.at(t.key[12])), write_of(kz, vz, vz)};
        CHECK(grid.calc_root_from_updates({first.data(), first.size()}) == pre_root);
        const size_t row = row_of(branch_of(w.state).data());
        REQUIRE(row < kprefix::kRows);
        grid.reset(pre_root);
        const Bytes nv = value_of(rng, 30);
        const std::vector<TrieNodeFlat> second{write_of(t.key[3], t.pre.at(t.key[3]), nv)};
        Map post = t.pre;
        post[t.key[3]] = nv;
        CHECK(grid.calc_root_from_updates({second.data(), second.size()}) == hb_root(post, nullptr));
        CHECK_FALSE(grid.failed());
        CHECK(kprefix::tag_orig[row] == branch_of(w.state).data());
        CHECK(kprefix::tag_sb[row] == 2);
    }
}

#if USE_HASH_KEY
namespace {

// A pre-state of one account whose storage trie is in the node store and none of whose slots the witness carries.
std::vector<uint8_t> blob_with_storage(const evmc::address& addr, const bytes32& root) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = 1;
    std::memcpy(info.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(info.account.storage_root, root.bytes, 32);
    return DirectState::build_blob_from_accounts({info}, {}, {});
}

struct StorageWitness {
    std::vector<uint8_t> prestate;
    std::vector<uint8_t> store;
    DirectState state;
    StorageWitness(const evmc::address& addr, const bytes32& root, const Map& nodes)
        : prestate{blob_with_storage(addr, root)},
          store{build_node_store(nodes)},
          state{std::span<uint8_t>{prestate}, std::span<uint8_t>{store}} {}
};

// The RLP of a storage value of 32 bytes, none of them zero.
Bytes slot_rlp(std::mt19937_64& rng) {
    Bytes v(33, 0xa0);
    for (size_t i = 1; i < 33; ++i) v[i] = static_cast<uint8_t>(rng() | 1);
    return v;
}

}  // namespace

// The walks of USE_HASH_KEY verify a node before check_root does.
TEST_CASE("kprefix: a branch an SLOAD walk verified is resumed when check_root writes it", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(11);
    evmc::address addr{};
    addr.bytes[19] = 0x42;
    Map slots;
    std::map<bytes32, bytes32, Less> word_of;
    for (uint32_t i = 0; i < 1500; ++i) {
        bytes32 w{};
        std::memcpy(w.bytes + 28, &i, 4);
        const bytes32 hk = keccak_bytes32(w);
        slots.emplace(hk, slot_rlp(rng));
        word_of.emplace(hk, w);
    }
    Map nodes;
    const bytes32 root = hb_root(slots, &nodes);
    unsigned roots_with_state = 0;
    for (const unsigned lo : {4u, 9u, 13u}) {
        CAPTURE(lo);
        const auto kp = pair_under_full_branch(slots, lo, lo, lo == 4 ? 0u : lo - 3);
        REQUIRE(kp.has_value());
        const bytes32 hk = kp->k1;
        StorageWitness sw{addr, root, nodes};
        const bytes32 read = sw.state.read_storage(addr, word_of.at(hk));
        CHECK(std::memcmp(read.bytes, slots.at(hk).data() + 1, 32) == 0);
        const auto root_node = sw.state.find_node_rlp(root);
        REQUIRE(root_node.has_value());
        REQUIRE(root_node->size() == kNode);
        CHECK(sw.state.walk_state_blocks(root_node->data()) == kprefix::first_blocks(hk.bytes[0] >> 4));
        const ByteView branch = branch_below_root(sw.state, root, hk);
        CHECK(sw.state.walk_state_blocks(branch.data()) == kprefix::first_blocks(lo));
        CHECK(sw.state.take_walk_state(branch.data() + 8, 3).blocks == 0);
        if (lo >= 4) {
            CHECK(sw.state.take_walk_state(branch.data(), kprefix::first_blocks(lo) - 1).blocks == 0);
            CHECK(sw.state.walk_state_blocks(branch.data()) == kprefix::first_blocks(lo));
        }
        const Bytes nv = slot_rlp(rng);
        const std::vector<TrieNodeFlat> ups{write_of(hk, slots.at(hk), nv)};
        Map post = slots;
        post[hk] = nv;
        GridMPT<true, DirectState> grid{sw.state, root};
        CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
        CHECK_FALSE(grid.failed());
        CHECK(sw.state.walk_state_blocks(branch.data()) == 0);
        CHECK(sw.state.walk_state_blocks(root_node->data()) == 0);
        roots_with_state += (hk.bytes[0] >> 4) >= 4;
    }
    CHECK(roots_with_state > 0);
}

TEST_CASE("kprefix: a write before the slot a walk saved for hashes the branch in full", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(12);
    evmc::address addr{};
    addr.bytes[19] = 0x43;
    Map slots;
    std::map<bytes32, bytes32, Less> word_of;
    for (uint32_t i = 0; i < 1500; ++i) {
        bytes32 w{};
        std::memcpy(w.bytes + 28, &i, 4);
        const bytes32 hk = keccak_bytes32(w);
        slots.emplace(hk, slot_rlp(rng));
        word_of.emplace(hk, w);
    }
    Map nodes;
    const bytes32 root = hb_root(slots, &nodes);
    const auto kp = pair_under_full_branch(slots, 4, 13);
    REQUIRE(kp.has_value());
    StorageWitness sw{addr, root, nodes};
    (void)sw.state.read_storage(addr, word_of.at(kp->k2));
    const ByteView branch = branch_below_root(sw.state, root, kp->k2);
    REQUIRE(sw.state.walk_state_blocks(branch.data()) == 3);
    const Bytes nv = slot_rlp(rng);
    const std::vector<TrieNodeFlat> ups{write_of(kp->k1, slots.at(kp->k1), nv)};
    Map post = slots;
    post[kp->k1] = nv;
    GridMPT<true, DirectState> grid{sw.state, root};
    CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
    CHECK_FALSE(grid.failed());
    CHECK(sw.state.walk_state_blocks(branch.data()) == 3);
}

TEST_CASE("kprefix: a branch that is not full, verified by an SLOAD walk, resumes when check_root writes it",
          "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(18);
    evmc::address addr{};
    addr.bytes[19] = 0x44;
    std::map<bytes32, bytes32, Less> word_of;
    uint32_t next = 0;
    const auto make = [&](unsigned top, unsigned second, std::mt19937_64&) {
        for (;; ++next) {
            bytes32 w{};
            std::memcpy(w.bytes + 28, &next, 4);
            const bytes32 hk = keccak_bytes32(w);
            if (hk.bytes[0] == (top << 4 | second) && !word_of.contains(hk)) {
                word_of.emplace(hk, w);
                return hk;
            }
        }
    };
    const SparseBranchTrie t{rng, make, &slot_rlp};
    Map nodes;
    const bytes32 root = hb_root(t.pre, &nodes);
    StorageWitness sw{addr, root, nodes};
    (void)sw.state.read_storage(addr, word_of.at(t.key[12]));
    const auto root_node = sw.state.find_node_rlp(root);
    REQUIRE(root_node.has_value());
    const ByteView branch = child_node(sw.state, *root_node, 5);
    REQUIRE(branch.size() == 404);
    CHECK(sw.state.walk_state_blocks(branch.data()) == 2);
    const Bytes nv = slot_rlp(rng);
    const std::vector<TrieNodeFlat> ups{write_of(t.key[14], t.pre.at(t.key[14]), nv)};
    Map post = t.pre;
    post[t.key[14]] = nv;
    GridMPT<true, DirectState> grid{sw.state, root};
    CHECK(grid.calc_root_from_updates({ups.data(), ups.size()}) == hb_root(post, nullptr));
    CHECK_FALSE(grid.failed());
    CHECK(sw.state.walk_state_blocks(branch.data()) == 0);
}

TEST_CASE("kprefix: a walk's corrupt node fails verification with no state saved", "[trie][kprefix]") {
    std::mt19937_64 rng(13);
    alignas(256) static uint8_t good[544], corrupt[544];
    fill_full_branch(good, rng);
    fill_full_branch(corrupt, rng);
    const ethash::hash256 gh = ethash_keccak256(good, kNode);
    bytes32 want;
    std::memcpy(want.bytes, gh.bytes, 32);
    Map nodes;
    nodes.emplace(want, Bytes{ByteView{corrupt, kNode}});
    Witness w{nodes};
    CHECK_FALSE(w.state.find_node_rlp(want, [] { return kprefix::SnapRequest{15, kprefix::kAddrRow}; }).has_value());
    CHECK_FALSE(w.state.find_node_rlp(want).has_value());
    Map good_nodes;
    good_nodes.emplace(want, Bytes{ByteView{good, kNode}});
    Witness g{good_nodes};
    const auto n = g.state.find_node_rlp(want, [] { return kprefix::SnapRequest{15, kprefix::kAddrRow}; });
    REQUIRE(n.has_value());
    CHECK(g.state.walk_state_blocks(n->data()) == 3);
}
#endif
