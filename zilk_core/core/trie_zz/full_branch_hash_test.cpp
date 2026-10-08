// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// fold_line() hashes a full branch that differs from its witness node only in hash references straight
// from that node and the new hashes (BranchNode::full_branch_hash(), ethash_keccak256_full_branch()).
// The digest must equal the keccak of encode_branch() for every set of changed slots, from the start and
// resumed from every saved state the update allows, and every other branch must take encode_branch().

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <random>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common_zz/keccak_prefix.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

constexpr size_t kNode = kprefix::kNodeSize;

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

// Mirrors unfold_node_from_rlp(): the list payload after a header of `header` bytes is decoded, then
// the origin recorded.
BranchNode unfold(const uint8_t* node, size_t size, size_t header = 3) {
    BranchNode b;
    bool is_leaf{};
    std::array<uint8_t, 64> path{};
    uint8_t plen{};
    ByteView second{};
    REQUIRE(decode_node(ByteView{node + header, size - header}, b, is_leaf, path, plen, second) == kBranch);
    b.orig = node;
    b.orig_size = static_cast<uint16_t>(size);
    b.orig_child_len = b.child_len;
    b.dirty = 0;
    return b;
}

ethash::hash256 keccak_of_encoding(const BranchNode& b) {
    const ByteView enc = encode_branch(b);
    return ethash_keccak256(enc.data(), enc.size());
}

bool same(const ethash::hash256& a, const ethash::hash256& b) { return std::memcmp(a.bytes, b.bytes, 32) == 0; }

}  // namespace

// All 2^16 sets of changed slots, on a new random node each, with the new hashes in child[] (an
// update's) or, for some changed slots, at an odd address outside the node (child_ptr, which
// encode_branch() prefers). Resumed from the state of every number of blocks before the first changed
// slot: slots 8 and 12 straddle a block boundary and count as the block they start in.
TEST_CASE("full branch hash: every set of changed slots", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(11);
    alignas(256) static uint8_t node[544];
    alignas(8) static uint8_t witness[16 * 33 + 1];  // new hashes as witness references, at odd addresses
    const size_t row = 17;
    size_t resumed = 0;
    for (int pass = 0; pass < 2; ++pass) {
        for (uint32_t mask = 0; mask < 0x10000; ++mask) {
            fill_full_branch(node, rng);
            BranchNode b = unfold(node, kNode);
            for (unsigned j = 0; j < 16; ++j) {
                if (!(mask >> j & 1)) continue;
                uint8_t h[32];
                for (auto& x : h) x = static_cast<uint8_t>(rng());
                b.set_child(j, ByteView{h, 32});
                if (pass == 1 && (rng() & 1)) {
                    uint8_t* const w = witness + 1 + 32 * (j % 16);
                    for (size_t k = 0; k < 32; ++k) w[k] = static_cast<uint8_t>(rng());
                    b.child_ptr[j] = w;
                }
            }
            REQUIRE(hashes_from_witness(b));
            const ethash::hash256 want = keccak_of_encoding(b);
            REQUIRE(same(b.full_branch_hash(nullptr, 0), want));
            for (unsigned blocks = 1; blocks <= 3 && (mask & kprefix::kHeadSlots[blocks]) == 0; ++blocks) {
                const ethash::hash256 h = ethash_keccak256(node, kNode);
                REQUIRE(kprefix::verify_and_snap(node, row, blocks, h.bytes));
                REQUIRE(take_resumable_blocks(b, row) == blocks);
                REQUIRE(same(b.full_branch_hash(kprefix::pool[row], blocks), want));
                ++resumed;
            }
        }
    }
    // Per pass, the masks with no slot changed in the first block, the first two, the first three.
    CHECK(resumed == 2 * (4096 + 128 + 8));
}

TEST_CASE("full branch hash: branches it does not take", "[trie][gridmpt][kprefix]") {
    std::mt19937_64 rng(12);
    alignas(256) static uint8_t buf[576];
    std::array<uint8_t, 32> new_hash{};
    new_hash.fill(0xee);

    SECTION("a witness node that is not 8-aligned") {
        // The node store bounds-checks its entries but does not align them; the word reads need it.
        for (size_t off = 1; off < 8; ++off) {
            fill_full_branch(buf + off, rng);
            BranchNode b = unfold(buf + off, kNode);
            b.set_child(9, ByteView{new_hash.data(), 32});
            CHECK_FALSE(hashes_from_witness(b));
        }
        fill_full_branch(buf + 8, rng);
        BranchNode b = unfold(buf + 8, kNode);
        b.set_child(9, ByteView{new_hash.data(), 32});
        CHECK(hashes_from_witness(b));
    }
    SECTION("a layout change") {
        fill_full_branch(buf, rng);
        BranchNode b = unfold(buf, kNode);
        b.delete_child(4);
        CHECK_FALSE(hashes_from_witness(b));
        b.set_child(4, ByteView{buf, 5});  // an embedded child where a hash was
        CHECK_FALSE(hashes_from_witness(b));
        b.set_child(4, ByteView{new_hash.data(), 32});  // a hash again
        CHECK(hashes_from_witness(b));
        CHECK(same(b.full_branch_hash(nullptr, 0), keccak_of_encoding(b)));
    }
    SECTION("a branch built in the grid") {
        fill_full_branch(buf, rng);
        BranchNode b = unfold(buf, kNode);
        b.orig = nullptr;
        CHECK_FALSE(hashes_from_witness(b));
    }
    SECTION("a branch that is not full") {
        // 15 hash children, an empty slot 6.
        Bytes inner;
        for (unsigned i = 0; i < 16; ++i) {
            if (i == 6) {
                inner.push_back(0x80);
                continue;
            }
            inner.push_back(0xa0);
            for (size_t k = 0; k < 32; ++k) inner.push_back(static_cast<uint8_t>(rng()));
        }
        inner.push_back(0x80);
        Bytes node;
        silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
        node.append(inner);
        std::memcpy(buf, node.data(), node.size());
        BranchNode b = unfold(buf, node.size());
        b.set_child(2, ByteView{new_hash.data(), 32});
        CHECK_FALSE(hashes_from_witness(b));
    }
    SECTION("a 532-byte branch with a 4-byte list header") {
        // fa 00 02 10: a length with a leading zero, which fast_decode_header() takes. 15 hash
        // references and an embedded node of 32 bytes (df and 31 bytes) fill 527 bytes, so the node
        // is 532 bytes with every slot of length class 32, but its slots are not at 3 + 33 i.
        uint8_t* const p = buf;
        p[0] = 0xfa;
        p[1] = 0x00;
        p[2] = 0x02;
        p[3] = 0x10;
        size_t o = 4;
        for (unsigned i = 0; i < 16; ++i) {
            if (i == 10) {
                p[o++] = 0xdf;
                for (size_t k = 0; k < 31; ++k) p[o++] = static_cast<uint8_t>(rng());
                continue;
            }
            p[o++] = 0xa0;
            for (size_t k = 0; k < 32; ++k) p[o++] = static_cast<uint8_t>(rng());
        }
        p[o++] = 0x80;
        REQUIRE(o == kNode);
        BranchNode b = unfold(p, kNode, 4);
        b.set_child(3, ByteView{new_hash.data(), 32});
        CHECK(b.same_layout_as_orig());
        CHECK_FALSE(hashes_from_witness(b));
        // encode_branch() walks the slots: slot 3's hash is at 4 + 33 * 3 + 1.
        Bytes want{ByteView{p, kNode}};
        std::memcpy(want.data() + 4 + 33 * 3 + 1, new_hash.data(), 32);
        CHECK(Bytes{encode_branch(b)} == want);
    }
}
