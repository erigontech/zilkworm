// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// HashState unit tests (zilkworm.tests target), starting with the node and code store.
// See docs/hashstate.md, "Node and code store".

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <span>
#include <optional>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <intx/intx.hpp>

#include <evmone/test/state/state_diff.hpp>        // evmone::state::StateDiff (apply_state_diff test)
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>  // silkworm::kEmptyRoot
#include <zilk_core/core/common/util.hpp>           // silkworm::keccak256(ByteView), zeroless_view
#include <zilk_core/core/common_zz/hash_index.hpp>
#include <zilk_core/core/rlp/encode.hpp>            // silkworm::rlp::encode (storage-value encode)
#include <zilk_core/core/common_zz/mphf_map.hpp>  // mix64_body (public)
#include <zilk_core/core/common_zz/ssz_read.hpp>
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/state_zz/slib_input.hpp>  // decode/parse/run_slib (the SSZ front-end)
#include <zilk_core/core/state_zz/slib_payload.hpp>  // decode_slib_payload, slib_payload_root, slib_payload_block
#include <zilk_core/core/trie_zz/mpt.hpp>        // GridMPT<DeletionEnabled, StateT>, TrieNodeFlat
#include <zilk_core/core/trie_zz/rlp_sw.hpp>     // encode_leaf/branch/ext + node types
#include <zilk_core/core/types_zz/account.hpp>   // Account (leaf-value encode/decode target)
#include <zilk_core/dev/check_root_hashstate.hpp>  // check_root_hashstate + HashStateAccountWrite

#include "slib_sample_fixture.hpp"  // a tests-zkevm v21.0.1 statelessInputBytes sample

using zilkworm::Account;
using zilkworm::BranchNode;
using zilkworm::ByteView;
using zilkworm::Bytes;
using zilkworm::ExtensionNode;
using zilkworm::HashIndex;
using zilkworm::HashState;
using zilkworm::HashStateView;
using zilkworm::hash_key8;
using zilkworm::hash_key8_at;
using zilkworm::LeafNode;
using zilkworm::nibbles64;

namespace {

// keccak256 EXACTLY as HashState computes it (direct_state.cpp:417-418 idiom): the
// binding between an entry's index key and its bytes. Tests recompute a lookup hash
// with this so it is provably the same key the store inserted.
[[nodiscard]] evmc::bytes32 keccak32(ByteView v) {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(v));
}

// A distinct 8-byte payload for counter `n`. Distinct counters -> distinct bytes ->
// distinct keccak hashes with effectively random home buckets.
[[nodiscard]] Bytes payload(uint64_t n) {
    Bytes b;
    b.resize(sizeof(n));
    std::memcpy(b.data(), &n, sizeof(n));
    return b;
}

[[nodiscard]] ByteView view_of(const Bytes& b) noexcept {
    return ByteView{b.data(), b.size()};
}

[[nodiscard]] bool eq32(const evmc::bytes32& a, const evmc::bytes32& b) noexcept {
    return std::memcmp(a.bytes, b.bytes, 32) == 0;
}

}  // namespace

// Each distinct node is retrievable by its real keccak, and add_node returns that hash.
TEST_CASE("HashState add and find nodes by real keccak", "[hash_state]") {
    HashState hs;

    std::vector<Bytes> nodes;
    for (uint64_t i = 0; i < 6; ++i) nodes.push_back(payload(0x0DE00000ULL + i));

    for (const auto& n : nodes) {
        const ByteView v = view_of(n);
        const evmc::bytes32 h = hs.add_node(v);
        CHECK(eq32(h, keccak32(v)));  // add_node returns the real keccak (identity binding)
    }
    CHECK(hs.node_count() == static_cast<std::uint32_t>(nodes.size()));

    for (const auto& n : nodes) {
        const ByteView v = view_of(n);
        auto got = hs.find_node_rlp(keccak32(v));
        REQUIRE(got.has_value());
        REQUIRE(got->size() == v.size());
        CHECK(std::memcmp(got->data(), v.data(), v.size()) == 0);
    }
}

// Adding the same node twice leaves one entry and returns the same hash both times.
TEST_CASE("HashState dedupe keeps one", "[hash_state]") {
    HashState hs;
    const Bytes n = payload(0xDED00000ULL);
    const ByteView v = view_of(n);

    const evmc::bytes32 h1 = hs.add_node(v);
    const std::uint32_t after_first = hs.node_count();
    const evmc::bytes32 h2 = hs.add_node(v);

    CHECK(eq32(h1, h2));
    CHECK(hs.node_count() == after_first);  // second add did not grow the index

    auto got = hs.find_node_rlp(h1);
    REQUIRE(got.has_value());
    REQUIRE(got->size() == v.size());
    CHECK(std::memcmp(got->data(), v.data(), v.size()) == 0);
}

// The real keccak of an input that was never added stops at the empty sentinel: miss.
TEST_CASE("HashState miss on never-added node hash", "[hash_state]") {
    HashState hs;
    const Bytes added = payload(0xADDED000ULL);
    hs.add_node(view_of(added));  // populate the table with an unrelated entry

    const Bytes never = payload(0x1234ABCDULL);
    const evmc::bytes32 h = keccak32(view_of(never));
    CHECK_FALSE(hs.find_node_rlp(h).has_value());
}

// Child refs inside node RLP are unaligned.
TEST_CASE("HashState find_node_rlp by raw pointer matches the bytes32 overload", "[hash_state]") {
    HashState hs;
    const Bytes rlp = payload(0xB17E5ULL);
    const evmc::bytes32 h = hs.add_node(view_of(rlp));
    const evmc::bytes32 never = keccak32(view_of(payload(0x0FFULL)));

    const auto by_hash = hs.find_node_rlp(h);
    REQUIRE(by_hash.has_value());

    for (const std::size_t off : {std::size_t{1}, std::size_t{3}, std::size_t{6}}) {
        CAPTURE(off);
        alignas(8) std::array<std::uint8_t, 40> buf{};
        REQUIRE(reinterpret_cast<std::uintptr_t>(buf.data() + off) % 8 != 0);

        std::memcpy(buf.data() + off, h.bytes, 32);
        const auto by_ptr = hs.find_node_rlp(buf.data() + off);
        REQUIRE(by_ptr.has_value());
        CHECK(by_ptr->data() == by_hash->data());  // the very same stored view
        CHECK(by_ptr->size() == by_hash->size());
        REQUIRE(by_ptr->size() == rlp.size());
        CHECK(std::memcmp(by_ptr->data(), rlp.data(), rlp.size()) == 0);

        std::memcpy(buf.data() + off, never.bytes, 32);
        CHECK_FALSE(hs.find_node_rlp(buf.data() + off).has_value());
    }
}

// Two distinct keccak hashes sharing a home bucket each find their own node; a third one misses.
// See docs/hashstate.md, "Node and code store".
TEST_CASE("HashState full-key gate on home-bucket collision", "[hash_state]") {
    constexpr std::uint32_t kExpectedNodes = 4;  // -> capacity 8: home-bucket collisions are frequent
    HashState hs{kExpectedNodes, 16};

    HashIndex<32, &hash_key8_at> probe{kExpectedNodes};  // identical capacity()/mask as hs.node_index_

    // Find three distinct payloads whose real keccak hashes share one home bucket.
    std::map<std::uint32_t, std::vector<std::pair<Bytes, evmc::bytes32>>> by_bucket;
    Bytes p_a, p_b, p_c;
    evmc::bytes32 h_a{}, h_b{}, h_c{};
    bool found = false;
    for (uint64_t n = 0; n < 200000 && !found; ++n) {
        Bytes p = payload(0xC011DE00000ULL + n);
        const evmc::bytes32 h = keccak32(view_of(p));
        const std::uint32_t bucket = probe.index_of(hash_key8(h.bytes));
        auto& slot = by_bucket[bucket];
        slot.emplace_back(std::move(p), h);
        if (slot.size() == 3) {
            p_a = slot[0].first; h_a = slot[0].second;
            p_b = slot[1].first; h_b = slot[1].second;
            p_c = slot[2].first; h_c = slot[2].second;
            found = true;
        }
    }
    REQUIRE(found);
    // Genuinely distinct payloads, genuinely distinct hashes, one shared home bucket.
    REQUIRE_FALSE(eq32(h_a, h_b));
    REQUIRE_FALSE(eq32(h_b, h_c));
    REQUIRE_FALSE(eq32(h_a, h_c));
    REQUIRE(probe.index_of(hash_key8(h_a.bytes)) == probe.index_of(hash_key8(h_b.bytes)));
    REQUIRE(probe.index_of(hash_key8(h_b.bytes)) == probe.index_of(hash_key8(h_c.bytes)));

    // Insert two of the three colliding nodes; leave the third out.
    CHECK(eq32(hs.add_node(view_of(p_a)), h_a));
    CHECK(eq32(hs.add_node(view_of(p_b)), h_b));
    CHECK(hs.node_count() == 2u);

    auto ga = hs.find_node_rlp(h_a);
    auto gb = hs.find_node_rlp(h_b);
    REQUIRE(ga.has_value());
    REQUIRE(gb.has_value());
    REQUIRE(ga->size() == p_a.size());
    REQUIRE(gb->size() == p_b.size());
    CHECK(std::memcmp(ga->data(), p_a.data(), p_a.size()) == 0);  // a -> a's RLP, never b's
    CHECK(std::memcmp(gb->data(), p_b.data(), p_b.size()) == 0);  // b -> b's RLP, never a's

    // The third colliding hash was never added: the probe passes both occupied buckets,
    // reaches the empty sentinel, and misses.
    CHECK_FALSE(hs.find_node_rlp(h_c).has_value());
}

// Code round-trips by code_hash; a never-added code_hash returns an EMPTY ByteView.
TEST_CASE("HashState code round-trips by code_hash", "[hash_state]") {
    HashState hs;

    std::vector<Bytes> codes;
    for (uint64_t i = 0; i < 5; ++i) codes.push_back(payload(0xC0DE0000ULL + i));

    for (const auto& c : codes) {
        const ByteView v = view_of(c);
        const evmc::bytes32 h = hs.add_code(v);
        CHECK(eq32(h, keccak32(v)));
    }
    CHECK(hs.code_count() == static_cast<std::uint32_t>(codes.size()));

    for (const auto& c : codes) {
        const ByteView v = view_of(c);
        const ByteView got = hs.find_code(keccak32(v));
        REQUIRE(got.size() == v.size());
        CHECK(std::memcmp(got.data(), v.data(), v.size()) == 0);
    }

    // A never-added code hash returns an EMPTY ByteView (miss semantics, not optional).
    const Bytes never = payload(0x0BADC0DEULL);
    const ByteView miss = hs.find_code(keccak32(view_of(never)));
    CHECK(miss.empty());
}

// reserve_stores precedes the first add: slib's path.
TEST_CASE("HashState reserve_stores then borrowed adds dedupe first-wins", "[hash_state]") {
    HashState hs{4, 4, 4, 4};  // tiny constructor hints: the reserve below does the sizing
    hs.reserve_stores(3000, 10, 100, 100);

    std::vector<Bytes> nodes;
    nodes.reserve(3000);
    for (uint64_t i = 0; i < 3000; ++i) nodes.push_back(payload(0x5E5E00000000ULL + i));
    for (const auto& n : nodes) {
        const ByteView v = view_of(n);
        CHECK(eq32(hs.add_node_borrowed(v), keccak32(v)));  // identity binding, as add_node
    }
    CHECK(hs.node_count() == 3000u);
    for (const auto& n : nodes) {
        auto got = hs.find_node_rlp(keccak32(view_of(n)));
        REQUIRE(got.has_value());
        CHECK(got->data() == n.data());  // the borrowed view itself, not a copy
        CHECK(got->size() == n.size());
    }

    const Bytes again = nodes[7];
    REQUIRE(again.data() != nodes[7].data());
    CHECK(eq32(hs.add_node_borrowed(view_of(again)), keccak32(view_of(nodes[7]))));
    CHECK(hs.node_count() == 3000u);
    REQUIRE(hs.find_node_rlp(keccak32(view_of(nodes[7]))).has_value());
    CHECK(hs.find_node_rlp(keccak32(view_of(nodes[7])))->data() == nodes[7].data());

    // The code store behaves the same.
    const Bytes code = payload(0xC0DE4E5EULL);
    const Bytes code_again = code;
    REQUIRE(code_again.data() != code.data());
    hs.add_code_borrowed(view_of(code));
    hs.add_code_borrowed(view_of(code_again));
    CHECK(hs.code_count() == 1u);
    CHECK(hs.find_code(keccak32(view_of(code))).data() == code.data());

    // reserve_stores on populated stores is a no-op.
    hs.reserve_stores(100000, 100000, 1, 1);
    CHECK(hs.node_count() == 3000u);
    CHECK(hs.code_count() == 1u);
    CHECK(hs.find_node_rlp(keccak32(view_of(nodes[0]))).has_value());
    CHECK(hs.find_node_rlp(keccak32(view_of(nodes[2999]))).has_value());
    CHECK(hs.find_code(keccak32(view_of(code))).data() == code.data());
}

// build_state_from_trie account sweep over small tries built with the shared MPT encoders.
// See docs/hashstate.md, "Trie sweep tests".

namespace {

// A trie key expressed as 64 nibbles, and the 32-byte addr_hash it packs into (the
// inverse of the packing build_state_from_trie does at a leaf).
struct Key {
    std::array<uint8_t, 64> nib{};
    evmc::bytes32 hash() const noexcept {
        evmc::bytes32 k{};
        for (std::size_t i = 0; i < 32; ++i)
            k.bytes[i] = static_cast<uint8_t>((nib[2 * i] << 4) | (nib[2 * i + 1] & 0x0F));
        return k;
    }
};

// A distinct, fully-decodable account. storage_root and code_hash are full 32-byte
// values (as real accounts always are — which is exactly why an account leaf is always
// > 32 bytes and can never be an embedded inline child).
struct TestAccount {
    Account acc{};
    evmc::bytes32 storage_root{};
    Bytes leaf_value;  // owns the account RLP the leaf points at
    void build(uint64_t seed) {
        acc.nonce = seed;
        const uint64_t bal = 0xAABBCCDD00000000ULL + seed;
        std::memcpy(acc.balance, &bal, sizeof(bal));  // native-endian, rest zero
        for (std::size_t i = 0; i < 32; ++i) {
            acc.code_hash[i] = static_cast<uint8_t>(0xC0u + i + seed);
            storage_root.bytes[i] = static_cast<uint8_t>(0x50u + i + seed);
        }
        leaf_value = acc.rlp(storage_root);  // [nonce, balance, storage_root, code_hash]
    }
};

LeafNode make_leaf(const uint8_t* nib, uint8_t len, ByteView value) {
    LeafNode l{};
    l.path.len = len;
    std::memcpy(l.path.nib.data(), nib, len);
    l.value = value;
    return l;
}

ExtensionNode make_ext(const uint8_t* nib, uint8_t len, ByteView child_ref) {
    ExtensionNode e{};
    e.path.len = len;
    std::memcpy(e.path.nib.data(), nib, len);
    e.set_child(child_ref);  // 32-byte ref -> hash child; <32 -> embedded inline child
    return e;
}

void expect_account(const Account* got, const TestAccount& want, const char* who) {
    INFO("account " << who);
    REQUIRE(got != nullptr);
    CHECK(got->nonce == want.acc.nonce);
    CHECK(std::memcmp(got->balance, want.acc.balance, 32) == 0);
    CHECK(std::memcmp(got->storage_root, want.storage_root.bytes, 32) == 0);
    CHECK(std::memcmp(got->code_hash, want.acc.code_hash, 32) == 0);
}

}  // namespace

// The block-header side of the state interface: insert_header records a header under its hash for
// read_header; get_block_hash walks the parent hashes back from the executing block's header, so it
// returns only hashes that chain to the block. read_body and total_difficulty are stubs.
namespace {

// Headers 0..n-1 chained by parent hash, and a block header numbered n on top of them.
struct HeaderChain {
    std::vector<silkworm::BlockHeader> headers;
    silkworm::BlockHeader block;
};

HeaderChain header_chain(uint64_t n) {
    HeaderChain c;
    for (uint64_t i = 0; i < n; ++i) {
        silkworm::BlockHeader h;
        h.number = i;
        h.gas_limit = 30'000'000;
        h.timestamp = 1000 + i;
        h.parent_hash = i == 0 ? evmc::bytes32{} : c.headers.back().hash();
        c.headers.push_back(h);
    }
    c.block.number = n;
    c.block.parent_hash = c.headers.back().hash();
    return c;
}

}  // namespace

TEST_CASE("HashState header store: read_header and the BLOCKHASH walk", "[hash_state]") {
    HashState hs;
    const HeaderChain c = header_chain(6);
    for (const auto& h : c.headers) hs.insert_header(h);

    for (const auto& h : c.headers) {
        auto got = hs.read_header(h.number, h.hash());
        REQUIRE(got.has_value());
        CHECK(got->number == h.number);
        CHECK(eq32(got->hash(), h.hash()));
    }
    evmc::bytes32 unknown{};
    unknown.bytes[0] = 0x99;
    CHECK_FALSE(hs.read_header(999, unknown).has_value());

    // Every ancestor the chain leads to, from the parent back to block 0.
    for (uint64_t n = 0; n < 6; ++n) CHECK(eq32(hs.get_block_hash(c.block, n), c.headers[n].hash()));
    CHECK(hs.unconfirmed_read_count() == 0u);
    CHECK_FALSE(hs.ancestor_missing());
    // The block itself and later blocks are out of range: zero, and no read to confirm.
    CHECK(eq32(hs.get_block_hash(c.block, 6), evmc::bytes32{}));
    CHECK(eq32(hs.get_block_hash(c.block, 7), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 0u);

    silkworm::BlockBody body{};
    CHECK_FALSE(hs.read_body(3, c.headers[3].hash(), body));
    CHECK_FALSE(hs.total_difficulty(3, c.headers[3].hash()).has_value());
}

// A header is only ever reached through the parent hash of its child, never by its number: a header
// chained after the parent but numbered like an ancestor is not BLOCKHASH of that number, and with
// the real ancestor omitted the read is unconfirmed.
TEST_CASE("HashState BLOCKHASH takes an ancestor's hash from its child, not from a header of its number",
          "[hash_state]") {
    const HeaderChain c = header_chain(6);
    silkworm::BlockHeader forged = c.headers[3];
    forged.parent_hash = c.headers[5].hash();  // chains after the parent, numbered 3
    REQUIRE_FALSE(eq32(forged.hash(), c.headers[3].hash()));

    HashState complete;
    for (const auto& h : c.headers) complete.insert_header(h);
    complete.insert_header(forged);
    CHECK(eq32(complete.get_block_hash(c.block, 3), c.headers[3].hash()));
    CHECK(complete.unconfirmed_read_count() == 0u);

    HashState omitted;
    for (const auto& h : c.headers) {
        if (h.number != 3) omitted.insert_header(h);
    }
    omitted.insert_header(forged);
    CHECK(eq32(omitted.get_block_hash(c.block, 3), evmc::bytes32{}));
    CHECK(omitted.ancestor_missing());
    CHECK(omitted.unconfirmed_read_count() == 1u);
    // The blocks the walk reaches before the gap still resolve.
    CHECK(eq32(omitted.get_block_hash(c.block, 4), c.headers[4].hash()));
}


// The full sweep: a root branch with two direct account leaves, one account behind an
// extension, and one embedded (<32-byte) inline non-account leaf behind a long
// extension. Every real account must land in the cache under its exact addr_hash with
// correctly-decoded fields; the embedded leaf must be reached inline (no store lookup,
// so missing_count stays 0); an addr_hash not in the trie must be absent.
TEST_CASE("HashState build_state_from_trie account sweep", "[hash_state]") {
    HashState hs;

    // --- keys, chosen so their first nibbles land in distinct root-branch slots ---
    Key kA;  // slot 0x1, then 63 trailing nibbles
    kA.nib[0] = 0x1;
    for (std::size_t i = 1; i < 64; ++i) kA.nib[i] = static_cast<uint8_t>((i * 3 + 5) & 0xF);
    Key kB;  // slot 0x4
    kB.nib[0] = 0x4;
    for (std::size_t i = 1; i < 64; ++i) kB.nib[i] = static_cast<uint8_t>((i * 5 + 2) & 0xF);
    Key kC;  // slot 0xC -> extension [0xA,0xB] -> leaf
    kC.nib[0] = 0xC; kC.nib[1] = 0xA; kC.nib[2] = 0xB;
    for (std::size_t i = 3; i < 64; ++i) kC.nib[i] = static_cast<uint8_t>((i * 7 + 1) & 0xF);
    Key kE;  // slot 0x8 -> extension (60 nibbles) -> branch -> embedded 2-nibble leaf
    kE.nib[0] = 0x8;
    for (std::size_t i = 1; i < 64; ++i) kE.nib[i] = static_cast<uint8_t>((i * 2 + 1) & 0xF);

    // --- accounts ---
    TestAccount aA, aB, aC;
    aA.build(11); aB.build(22); aC.build(33);

    // --- leaves A and B: direct hash-referenced children of the root branch ---
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
    const LeafNode leafB = make_leaf(&kB.nib[1], 63, ByteView{aB.leaf_value});
    const evmc::bytes32 hB = hs.add_node(ByteView{zilkworm::encode_leaf(leafB)});

    // --- account C behind an extension: root[0xC] -> ext[0xA,0xB] -> leaf(61 nibbles) ---
    const LeafNode leafC = make_leaf(&kC.nib[3], 61, ByteView{aC.leaf_value});
    const evmc::bytes32 hC = hs.add_node(ByteView{zilkworm::encode_leaf(leafC)});
    const ExtensionNode extC = make_ext(&kC.nib[1], 2, ByteView{hC.bytes, 32});
    const evmc::bytes32 hExtC = hs.add_node(ByteView{zilkworm::encode_ext(extC)});

    // --- embedded leaf E under a deep branch: decoded inline (no lookup), reached, not cached ---
    // See docs/hashstate.md, "Trie sweep tests".
    const uint8_t emb_value_byte = 0x2A;
    const LeafNode leafE = make_leaf(&kE.nib[62], 2, ByteView{&emb_value_byte, 1});
    const Bytes embE{zilkworm::encode_leaf(leafE)};  // own it before the next encode call
    REQUIRE(embE.size() < 32);                       // must be small enough to embed
    BranchNode branch2;
    branch2.set_child(kE.nib[61], ByteView{embE});  // < 32 bytes -> embedded inline child
    const Bytes branch2_rlp{zilkworm::encode_branch(branch2)};
    const evmc::bytes32 hBranch2 = hs.add_node(ByteView{branch2_rlp});
    const ExtensionNode extE = make_ext(&kE.nib[1], 60, ByteView{hBranch2.bytes, 32});
    const evmc::bytes32 hExtE = hs.add_node(ByteView{zilkworm::encode_ext(extE)});

    // --- root branch wiring the four children ---
    BranchNode root;
    root.set_child(0x1, ByteView{hA.bytes, 32});
    root.set_child(0x4, ByteView{hB.bytes, 32});
    root.set_child(0x8, ByteView{hExtE.bytes, 32});
    root.set_child(0xC, ByteView{hExtC.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    // --- derive ---
    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);  // embedded leaf handled inline: no bogus lookup
    CHECK(hs.leaf_count() == 4u);     // A, B, C, and the embedded E were all reached
    CHECK(hs.account_count() == 3u);  // only A, B, C decoded into cached accounts

    // Every real account is cached under its exact addr_hash with decoded fields.
    expect_account(hs.get_account(kA.hash()), aA, "A");
    expect_account(hs.get_account(kB.hash()), aB, "B");
    expect_account(hs.get_account(kC.hash()), aC, "C");

    // The embedded non-account leaf's key is not a cached account.
    CHECK(hs.get_account(kE.hash()) == nullptr);

    // An addr_hash that is not in the trie is absent.
    evmc::bytes32 absent{};
    absent.bytes[0] = 0x2F;  // root slot 0x2 was never populated
    for (int i = 1; i < 32; ++i) absent.bytes[i] = static_cast<uint8_t>(0x99 - i);
    CHECK(hs.get_account(absent) == nullptr);
}

// A referenced child hash whose node is absent is a PRUNED BOUNDARY (the EIP-8025 partial-
// witness case), NOT a missing node: the sweep stops there, missing_count stays 0 / status
// kOk, and nothing below the boundary is materialized. Completeness for the pruned part is
// enforced later — a read down it records an unconfirmed read; a write folding through it
// recomputes a non-matching root. missing_count now flags only a broken seeding root.
TEST_CASE("HashState build_state_from_trie treats a dangling child ref as a pruned boundary",
          "[hash_state]") {
    HashState hs;

    // Root branch whose one child points at a hash that was never add_node'd.
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(0x3, ByteView{dangling.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);  // pruned boundary, not a missing node
    CHECK(hs.missing_count() == 0u);               // only a broken ROOT increments this now
    CHECK(hs.account_count() == 0u);               // nothing below the boundary materialized
}

// A missing seeding root is the fail-closed case: it is surfaced, never treated as an
// empty trie.
TEST_CASE("HashState build_state_from_trie reports a missing root", "[hash_state]") {
    HashState hs;
    evmc::bytes32 never_added{};
    for (int i = 0; i < 32; ++i) never_added.bytes[i] = static_cast<uint8_t>(0x11 + i);

    const auto status = hs.build_state_from_trie(never_added);
    CHECK(status == HashState::BuildStatus::kMissingNode);
    CHECK(hs.missing_count() > 0u);
    CHECK(hs.account_count() == 0u);
}

// The empty trie derives nothing, cleanly.
TEST_CASE("HashState build_state_from_trie on the empty root derives nothing", "[hash_state]") {
    HashState hs;
    const auto status = hs.build_state_from_trie(silkworm::kEmptyRoot);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.account_count() == 0u);
    CHECK(hs.leaf_count() == 0u);
    CHECK(hs.missing_count() == 0u);
}

// ---------------------------------------------------------------------------
// build_state_from_trie — the STORAGE-trie sweep (the sibling pass over each account's
// storage_root). Fixtures are built with the same MPT encoders, and each storage leaf's
// value is encoded EXACTLY as DirectState stores it: the RLP string of the big-endian,
// zero-trimmed 32-byte word (direct_state.cpp:627 rlp::encode(zeroless_view(value))).
// ---------------------------------------------------------------------------

namespace {

// Encode a 32-byte storage word the way the storage trie stores its leaf value: the RLP
// string of the big-endian, zero-trimmed word. Mirrors direct_state.cpp:627 /
// grid_mpt_delete_test.cpp:50. zeroless_view requires an 8-byte-aligned, size-8-multiple
// buffer, so the word is staged in one before trimming.
[[nodiscard]] Bytes encode_storage_value(const evmc::bytes32& word) {
    alignas(8) uint8_t buf[32];
    std::memcpy(buf, word.bytes, 32);
    Bytes out;
    silkworm::rlp::encode(out, silkworm::zeroless_view(ByteView{buf, 32}));
    return out;
}

// An account-leaf RLP ([nonce, balance, storage_root, code_hash]) with a chosen
// storage_root — the account fixtures below need to point at a real derived storage trie
// (or at kEmptyRoot), which TestAccount::build cannot express.
[[nodiscard]] Bytes account_leaf_value(uint64_t seed, const evmc::bytes32& storage_root) {
    Account acc{};
    acc.nonce = seed;
    const uint64_t bal = 0xAABBCCDD00000000ULL + seed;
    std::memcpy(acc.balance, &bal, sizeof(bal));
    for (std::size_t i = 0; i < 32; ++i)
        acc.code_hash[i] = static_cast<uint8_t>(0xC0u + i + seed);
    return acc.rlp(storage_root);
}

// A full 64-nibble trie key whose first nibble is `first` and whose tail is a fixed,
// distinct pattern. Used for both account paths and storage-slot paths (both are 64-nibble
// keys: keccak(addr) and keccak(slot) respectively).
[[nodiscard]] Key key_with(uint8_t first, uint8_t mul, uint8_t add) {
    Key k;
    k.nib[0] = static_cast<uint8_t>(first & 0xF);
    for (std::size_t i = 1; i < 64; ++i)
        k.nib[i] = static_cast<uint8_t>((i * mul + add) & 0xF);
    return k;
}

}  // namespace

// Full storage sweep: account X carries a real 3-slot storage trie; account Y carries an
// EMPTY storage_root. After build_state_from_trie every one of X's slots is retrievable via
// get_storage under (addr_hash, slot_hash) and decodes to its exact word — including a
// value RLP-trims to a single byte and one that trims to two. An un-derived slot, a slot
// looked up under the wrong account, and every lookup against empty-storage Y all read as
// zero; no storage root here is absent, so missing_count stays 0.
TEST_CASE("HashState build_state_from_trie storage sweep", "[hash_state]") {
    HashState hs;

    // --- storage-slot values ---
    evmc::bytes32 v1{};  // full 32 bytes, no trimming
    for (std::size_t i = 0; i < 32; ++i) v1.bytes[i] = static_cast<uint8_t>(0xF1u - i);
    evmc::bytes32 v2{};  // trims to a single byte 0x2A (RLP single-byte form, no header)
    v2.bytes[31] = 0x2A;
    evmc::bytes32 v3{};  // trims to two bytes, leading byte >= 0x80 (needs a length header)
    v3.bytes[30] = 0x81;
    v3.bytes[31] = 0xFF;

    // --- X's storage trie: root branch -> three hash-referenced 63-nibble leaves ---
    const Key s1 = key_with(0x2, 3, 5);
    const Key s2 = key_with(0x7, 5, 2);
    const Key s3 = key_with(0xE, 7, 1);

    const Bytes ev1 = encode_storage_value(v1);
    const LeafNode sleaf1 = make_leaf(&s1.nib[1], 63, ByteView{ev1});
    const evmc::bytes32 hs1 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf1)});
    const Bytes ev2 = encode_storage_value(v2);
    const LeafNode sleaf2 = make_leaf(&s2.nib[1], 63, ByteView{ev2});
    const evmc::bytes32 hs2 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf2)});
    const Bytes ev3 = encode_storage_value(v3);
    const LeafNode sleaf3 = make_leaf(&s3.nib[1], 63, ByteView{ev3});
    const evmc::bytes32 hs3 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf3)});

    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hs1.bytes, 32});
    sroot.set_child(0x7, ByteView{hs2.bytes, 32});
    sroot.set_child(0xE, ByteView{hs3.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    // --- account trie: root branch -> X (storage_root above) and Y (empty storage_root) ---
    const Key kX = key_with(0x1, 3, 5);
    const Key kY = key_with(0x2, 5, 2);
    const Bytes accX = account_leaf_value(7, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[1], 63, ByteView{accX});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    const Bytes accY = account_leaf_value(9, silkworm::kEmptyRoot);
    const LeafNode leafY = make_leaf(&kY.nib[1], 63, ByteView{accY});
    const evmc::bytes32 hY = hs.add_node(ByteView{zilkworm::encode_leaf(leafY)});

    BranchNode root;
    root.set_child(0x1, ByteView{hX.bytes, 32});
    root.set_child(0x2, ByteView{hY.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    // --- derive ---
    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);        // every referenced node present
    CHECK(hs.account_count() == 2u);        // X and Y both decoded
    CHECK(hs.storage_count() == 3u);        // X's three slots cached
    CHECK(hs.storage_slot_count() == 3u);   // three storage leaves reached

    // Each slot is retrievable under (X's addr_hash, slot_hash) and decodes to its word,
    // covering full, single-byte-trimmed, and two-byte-trimmed values.
    CHECK(eq32(hs.get_storage(kX.hash(), s1.hash()), v1));
    CHECK(eq32(hs.get_storage(kX.hash(), s2.hash()), v2));
    CHECK(eq32(hs.get_storage(kX.hash(), s3.hash()), v3));

    // A slot never derived reads as zero (absent).
    const Key sMiss = key_with(0x9, 4, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), sMiss.hash()), evmc::bytes32{}));

    // The storage cache is account-scoped: X's slot is invisible under Y's addr_hash, and
    // Y (empty storage_root) has no storage at all.
    CHECK(eq32(hs.get_storage(kY.hash(), s1.hash()), evmc::bytes32{}));
    CHECK(eq32(hs.get_storage(kY.hash(), s2.hash()), evmc::bytes32{}));
}

// A hash-ref child reached WHILE walking an INCLUDED storage trie whose node is absent is a
// PRUNED BOUNDARY too (same partial-witness rule as the account trie): the account decodes
// fine, the boundary stops the storage sweep, and missing_count stays 0 / status kOk. A read
// into that pruned storage slot records the gap later (see the read-path tests below).
// (Account Z is the whole account trie — a single 64-nibble leaf as the root.)
TEST_CASE("HashState build_state_from_trie treats a dangling storage-node ref as a boundary",
          "[hash_state]") {
    HashState hs;

    // Storage trie root = a branch PRESENT in the store whose one child ref is a hash that
    // was never add_node'd.
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode sbranch;
    sbranch.set_child(0x5, ByteView{dangling.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sbranch)});

    // Account Z points at that storage trie; its leaf is the whole account trie.
    const Key kZ = key_with(0xA, 6, 4);
    const Bytes accZ = account_leaf_value(1, storage_root);
    const LeafNode leafZ = make_leaf(&kZ.nib[0], 64, ByteView{accZ});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafZ)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);  // pruned storage boundary, not a missing node
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.account_count() == 1u);      // Z itself decoded
    CHECK(hs.storage_count() == 0u);      // nothing below the boundary materialized
}

// An account whose storage_root is ABSENT from the store is skipped, NOT counted missing:
// a witness legitimately omits the storage trie of an account the block never touches.
// (This is exactly what keeps the pre-existing account-sweep fixtures — whose accounts all
// carry bogus non-present storage roots — passing unchanged.)
TEST_CASE("HashState build_state_from_trie skips an absent storage root", "[hash_state]") {
    HashState hs;

    // storage_root points at a node that was never added.
    evmc::bytes32 absent_root{};
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);

    const Key kW = key_with(0x3, 9, 7);
    const Bytes accW = account_leaf_value(5, absent_root);
    const LeafNode leafW = make_leaf(&kW.nib[0], 64, ByteView{accW});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);   // absent storage root != missing node
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.account_count() == 1u);
    CHECK(hs.storage_count() == 0u);
    CHECK(hs.storage_slot_count() == 0u);
}

namespace {

// For hand-built nodes the encoders cannot emit.
[[nodiscard]] Bytes rlp_list_of(const Bytes& payload) {
    Bytes out;
    silkworm::rlp::encode_header(out, {.list = true, .payload_length = payload.size()});
    out += payload;
    return out;
}

}  // namespace

// Long subtree first: 52 stale path nibbles.
TEST_CASE("HashState build_state_from_trie resets the path per child across sibling extensions",
          "[hash_state]") {
    HashState hs;

    const Key kA1 = key_with(0x3, 3, 5);
    Key kA2 = kA1;  // same 51-nibble prefix (root slot + 50 extension nibbles), then diverges
    kA2.nib[51] = static_cast<uint8_t>((kA1.nib[51] + 1) & 0xF);
    for (std::size_t i = 52; i < 64; ++i) kA2.nib[i] = static_cast<uint8_t>((i * 11 + 3) & 0xF);
    const Key kB = key_with(0x9, 5, 2);
    const Key kC = key_with(0xD, 7, 1);

    TestAccount aA1, aA2, aB, aC;
    aA1.build(41); aA2.build(42); aB.build(43); aC.build(44);

    // Subtree A: root[0x3]->ext(50)->branch->leaf(12)x2.
    const LeafNode leafA1 = make_leaf(&kA1.nib[52], 12, ByteView{aA1.leaf_value});
    const evmc::bytes32 hA1 = hs.add_node(ByteView{zilkworm::encode_leaf(leafA1)});
    const LeafNode leafA2 = make_leaf(&kA2.nib[52], 12, ByteView{aA2.leaf_value});
    const evmc::bytes32 hA2 = hs.add_node(ByteView{zilkworm::encode_leaf(leafA2)});
    BranchNode branchA;
    branchA.set_child(kA1.nib[51], ByteView{hA1.bytes, 32});
    branchA.set_child(kA2.nib[51], ByteView{hA2.bytes, 32});
    const evmc::bytes32 hBranchA = hs.add_node(ByteView{zilkworm::encode_branch(branchA)});
    const ExtensionNode extA = make_ext(&kA1.nib[1], 50, ByteView{hBranchA.bytes, 32});
    const evmc::bytes32 hExtA = hs.add_node(ByteView{zilkworm::encode_ext(extA)});

    // Subtree B: root[0x9]->ext(2)->leaf(61).
    const LeafNode leafB = make_leaf(&kB.nib[3], 61, ByteView{aB.leaf_value});
    const evmc::bytes32 hB = hs.add_node(ByteView{zilkworm::encode_leaf(leafB)});
    const ExtensionNode extB = make_ext(&kB.nib[1], 2, ByteView{hB.bytes, 32});
    const evmc::bytes32 hExtB = hs.add_node(ByteView{zilkworm::encode_ext(extB)});

    // Subtree C: a direct 63-nibble leaf.
    const LeafNode leafC = make_leaf(&kC.nib[1], 63, ByteView{aC.leaf_value});
    const evmc::bytes32 hC = hs.add_node(ByteView{zilkworm::encode_leaf(leafC)});

    BranchNode root;
    root.set_child(0x3, ByteView{hExtA.bytes, 32});
    root.set_child(0x9, ByteView{hExtB.bytes, 32});
    root.set_child(0xD, ByteView{hC.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 4u);
    CHECK(hs.account_count() == 4u);
    expect_account(hs.get_account(kA1.hash()), aA1, "A1");
    expect_account(hs.get_account(kA2.hash()), aA2, "A2");
    expect_account(hs.get_account(kB.hash()), aB, "B");
    expect_account(hs.get_account(kC.hash()), aC, "C");
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// 62/63-nibble paths are 0xa0 items, hash-ref shaped.
TEST_CASE("HashState build_state_from_trie sweeps a branch at depth 63 and stops past 64 nibbles",
          "[hash_state]") {
    HashState hs;

    // D: root[0x2]->ext(62)->branch->leaf(0)x3.
    const Key kD1 = key_with(0x2, 3, 5);
    Key kD2 = kD1;
    Key kD3 = kD1;
    kD2.nib[63] = static_cast<uint8_t>((kD1.nib[63] + 5) & 0xF);
    kD3.nib[63] = static_cast<uint8_t>((kD1.nib[63] + 9) & 0xF);
    const Key kE = key_with(0x6, 9, 7);  // root[0x6] -> ext(63) -> leaf(0)
    const Key kX = key_with(0x5, 5, 2);  // malformed: ext(63) -> branch at depth 64
    const Key kY = key_with(0x8, 7, 1);  // malformed: ext(60) -> leaf(10)

    TestAccount aD1, aD2, aD3, aE, aX, aY;
    aD1.build(51); aD2.build(52); aD3.build(53); aE.build(54); aX.build(55); aY.build(56);

    // Depth-63 branch with three empty-path leaves.
    const LeafNode leafD1 = make_leaf(&kD1.nib[64], 0, ByteView{aD1.leaf_value});
    const evmc::bytes32 hD1 = hs.add_node(ByteView{zilkworm::encode_leaf(leafD1)});
    const LeafNode leafD2 = make_leaf(&kD2.nib[64], 0, ByteView{aD2.leaf_value});
    const evmc::bytes32 hD2 = hs.add_node(ByteView{zilkworm::encode_leaf(leafD2)});
    const LeafNode leafD3 = make_leaf(&kD3.nib[64], 0, ByteView{aD3.leaf_value});
    const evmc::bytes32 hD3 = hs.add_node(ByteView{zilkworm::encode_leaf(leafD3)});
    BranchNode branch63;
    branch63.set_child(kD1.nib[63], ByteView{hD1.bytes, 32});
    branch63.set_child(kD2.nib[63], ByteView{hD2.bytes, 32});
    branch63.set_child(kD3.nib[63], ByteView{hD3.bytes, 32});
    const evmc::bytes32 hBranch63 = hs.add_node(ByteView{zilkworm::encode_branch(branch63)});
    const ExtensionNode extD = make_ext(&kD1.nib[1], 62, ByteView{hBranch63.bytes, 32});
    const evmc::bytes32 hExtD = hs.add_node(ByteView{zilkworm::encode_ext(extD)});

    // E: ext(63)->leaf(0), exactly 64 nibbles.
    const LeafNode leafE = make_leaf(&kE.nib[64], 0, ByteView{aE.leaf_value});
    const evmc::bytes32 hE = hs.add_node(ByteView{zilkworm::encode_leaf(leafE)});
    const ExtensionNode extE = make_ext(&kE.nib[1], 63, ByteView{hE.bytes, 32});
    const evmc::bytes32 hExtE = hs.add_node(ByteView{zilkworm::encode_ext(extE)});

    // Malformed X: a branch at depth 64.
    const LeafNode leafX = make_leaf(&kX.nib[64], 0, ByteView{aX.leaf_value});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    BranchNode branch64;
    branch64.set_child(0x0, ByteView{hX.bytes, 32});
    const evmc::bytes32 hBranch64 = hs.add_node(ByteView{zilkworm::encode_branch(branch64)});
    const ExtensionNode extX = make_ext(&kX.nib[1], 63, ByteView{hBranch64.bytes, 32});
    const evmc::bytes32 hExtX = hs.add_node(ByteView{zilkworm::encode_ext(extX)});

    // Malformed Y: 1+60+10 = 71 nibbles.
    const LeafNode leafY = make_leaf(&kY.nib[54], 10, ByteView{aY.leaf_value});
    const evmc::bytes32 hY = hs.add_node(ByteView{zilkworm::encode_leaf(leafY)});
    const ExtensionNode extY = make_ext(&kY.nib[1], 60, ByteView{hY.bytes, 32});
    const evmc::bytes32 hExtY = hs.add_node(ByteView{zilkworm::encode_ext(extY)});

    BranchNode root;
    root.set_child(0x2, ByteView{hExtD.bytes, 32});
    root.set_child(0x5, ByteView{hExtX.bytes, 32});
    root.set_child(0x6, ByteView{hExtE.bytes, 32});
    root.set_child(0x8, ByteView{hExtY.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kMalformed);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 4u);     // D1, D2, D3, E; X and Y never reach a leaf
    CHECK(hs.account_count() == 4u);
    expect_account(hs.get_account(kD1.hash()), aD1, "D1");
    expect_account(hs.get_account(kD2.hash()), aD2, "D2");
    expect_account(hs.get_account(kD3.hash()), aD3, "D3");
    expect_account(hs.get_account(kE.hash()), aE, "E");
    CHECK(hs.find_built_account(kX.hash()) == nullptr);
    CHECK(hs.find_built_account(kY.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Hand-built: the encoders cannot emit this shape.
TEST_CASE("HashState build_state_from_trie stops a branch at its first malformed child item",
          "[hash_state]") {
    HashState hs;

    const Key kA = key_with(0x0, 3, 5);
    const Key kB = key_with(0x1, 5, 2);
    const Key kC = key_with(0x5, 7, 1);
    TestAccount aA, aB, aC;
    aA.build(61); aB.build(62); aC.build(63);
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
    const LeafNode leafB = make_leaf(&kB.nib[1], 63, ByteView{aB.leaf_value});
    const evmc::bytes32 hB = hs.add_node(ByteView{zilkworm::encode_leaf(leafB)});
    const LeafNode leafC = make_leaf(&kC.nib[1], 63, ByteView{aC.leaf_value});
    const evmc::bytes32 hC = hs.add_node(ByteView{zilkworm::encode_leaf(leafC)});

    Bytes payload;
    payload.push_back(0xa0); payload.append(hA.bytes, 32);  // slot 0: hash ref -> A
    payload.push_back(0xa0); payload.append(hB.bytes, 32);  // slot 1: hash ref -> B
    payload.push_back(0x81); payload.push_back(0xff);       // slot 2: a string, not a child
    payload.push_back(0x80); payload.push_back(0x80);       // slots 3, 4: empty
    payload.push_back(0xa0); payload.append(hC.bytes, 32);  // slot 5: hash ref -> C
    for (int i = 6; i < 16; ++i) payload.push_back(0x80);   // slots 6..15: empty
    payload.push_back(0x80);                                // value: empty
    const Bytes node = rlp_list_of(payload);
    const evmc::bytes32 root_hash = hs.add_node(ByteView{node});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kMalformed);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 2u);
    CHECK(hs.account_count() == 2u);
    expect_account(hs.get_account(kA.hash()), aA, "A");
    expect_account(hs.get_account(kB.hash()), aB, "B");
    CHECK(hs.find_built_account(kC.hash()) == nullptr);  // past the malformed slot: not swept
    CHECK(hs.unconfirmed_read_count() == 0u);
}

TEST_CASE("HashState build_state_from_trie rejects every node shape decode_node rejects",
          "[hash_state]") {
    const auto build = [](const Bytes& node_rlp) {
        HashState hs;
        const evmc::bytes32 root = hs.add_node(ByteView{node_rlp});
        return hs.build_state_from_trie(root);
    };
    const auto string_of = [](const Bytes& payload) {
        Bytes out;
        silkworm::rlp::encode_header(out, {.list = false, .payload_length = payload.size()});
        out += payload;
        return out;
    };
    Bytes sixteen_empty;
    for (int i = 0; i < 16; ++i) sixteen_empty.push_back(0x80);
    Bytes leaf_path{0x20};  // even-length leaf HP path of 64 nibbles
    leaf_path.append(32, 0x33);

    SECTION("a root that is not a list") {
        CHECK(build(Bytes{0x83, 0x01, 0x02, 0x03}) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a branch with a non-empty 17th item") {
        Bytes p = sixteen_empty;
        p.push_back(0x07);
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a branch with bytes after the 17th item") {
        Bytes p = sixteen_empty;
        p.push_back(0x80);
        p.push_back(0x80);
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a branch with no 17th item") {
        CHECK(build(rlp_list_of(sixteen_empty)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a well-formed branch whose last slot is present") {
        HashState hs;
        const Key kA = key_with(0xF, 3, 5);
        TestAccount aA;
        aA.build(71);
        const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
        const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
        BranchNode b;
        b.set_child(0xF, ByteView{hA.bytes, 32});
        const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_branch(b)});
        CHECK(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
        CHECK(hs.account_count() == 1u);
    }

    // Slot 15 present: 17th-item check on pop.
    const auto with_slot15 = [](const Bytes& tail) {
        HashState hs;
        const Key kA = key_with(0xF, 3, 5);
        TestAccount aA;
        aA.build(71);
        const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
        const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
        Bytes p(15, 0x80);
        p.push_back(0xa0);
        p.append(hA.bytes, 32);
        p += tail;
        const evmc::bytes32 root = hs.add_node(ByteView{rlp_list_of(p)});
        const auto status = hs.build_state_from_trie(root);
        return std::pair{status, hs.account_count()};
    };
    SECTION("slot 15 present, the lone 0x80: the control") {
        const auto [status, accounts] = with_slot15(Bytes{0x80});
        CHECK(status == HashState::BuildStatus::kOk);
        CHECK(accounts == 1u);
    }
    SECTION("slot 15 present, a non-empty 17th item") {
        const auto [status, accounts] = with_slot15(Bytes{0x07});
        CHECK(status == HashState::BuildStatus::kMalformed);
        CHECK(accounts == 1u);
    }
    SECTION("slot 15 present, bytes after the 17th item") {
        const auto [status, accounts] = with_slot15(Bytes{0x80, 0x80});
        CHECK(status == HashState::BuildStatus::kMalformed);
        CHECK(accounts == 1u);
    }
    SECTION("slot 15 present, no 17th item") {
        const auto [status, accounts] = with_slot15(Bytes{});
        CHECK(status == HashState::BuildStatus::kMalformed);
        CHECK(accounts == 1u);
    }

    // Slots 0,1: A,B; 3: item; 5: C.
    const auto with_slot3 = [](const Bytes& item, bool rest) {
        HashState hs;
        const Key kA = key_with(0x0, 3, 5);
        const Key kB = key_with(0x1, 5, 2);
        const Key kC = key_with(0x5, 7, 1);
        TestAccount aA, aB, aC;
        aA.build(61); aB.build(62); aC.build(63);
        const auto hash_ref = [&hs](const Key& k, const TestAccount& a) {
            const LeafNode leaf = make_leaf(&k.nib[1], 63, ByteView{a.leaf_value});
            const evmc::bytes32 h = hs.add_node(ByteView{zilkworm::encode_leaf(leaf)});
            Bytes out{0xa0};
            out.append(h.bytes, 32);
            return out;
        };
        Bytes p = hash_ref(kA, aA) + hash_ref(kB, aB);
        p.push_back(0x80);
        p += item;
        if (rest) {
            p.push_back(0x80);
            p += hash_ref(kC, aC);
            p.append(11, 0x80);
        }
        const evmc::bytes32 root = hs.add_node(ByteView{rlp_list_of(p)});
        const auto status = hs.build_state_from_trie(root);
        return std::tuple{status, hs.account_count(), hs.find_built_account(kC.hash()) != nullptr};
    };
    SECTION("an embedded child over 31 payload bytes") {
        // Well-formed 32-byte leaf; only the cap rejects.
        Bytes item{0xe0, 0x20, 0x9e};
        item.append(30, 0x44);
        const auto [status, accounts, c_built] = with_slot3(item, true);
        CHECK(status == HashState::BuildStatus::kMalformed);
        CHECK(accounts == 2u);
        CHECK_FALSE(c_built);
    }
    SECTION("an embedded child of 31 payload bytes: the control") {
        Bytes item{0xdf, 0x20, 0x9d};
        item.append(29, 0x44);
        const auto [status, accounts, c_built] = with_slot3(item, true);
        CHECK(status == HashState::BuildStatus::kOk);
        CHECK(accounts == 3u);
        CHECK(c_built);
    }
    SECTION("an embedded child running past its branch") {
        const auto [status, accounts, c_built] = with_slot3(Bytes{0xc5, 0x20, 0x81}, false);
        CHECK(status == HashState::BuildStatus::kMalformed);
        CHECK(accounts == 2u);
        CHECK_FALSE(c_built);
    }
    SECTION("a leaf with an empty value") {
        Bytes p = string_of(leaf_path);
        p.push_back(0x80);
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a leaf with a value over kMaxLeafValueSize") {
        Bytes p = string_of(leaf_path);
        p += string_of(Bytes(zilkworm::kMaxLeafValueSize + 1, 0x44));
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("an extension whose child is a short string") {
        Bytes p{0x11};  // odd extension path, one nibble
        p += string_of(Bytes{0xaa, 0xbb});
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("an extension whose child is an inline list") {
        Bytes p{0x11};
        p.push_back(0xc0);
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("a path that is a list") {
        Bytes p{0xc0};
        p += string_of(Bytes(32, 0x55));
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }
    SECTION("an item running past its node") {
        Bytes p{0x85, 0x01, 0x02};
        CHECK(build(rlp_list_of(p)) == HashState::BuildStatus::kMalformed);
    }

    // tests-zkevm overlength leaves, under root slot 1.
    const auto under_slot1 = [](const Bytes& leaf_rlp) {
        HashState hs;
        const evmc::bytes32 h = hs.add_node(ByteView{leaf_rlp});
        BranchNode b;
        b.set_child(0x1, ByteView{h.bytes, 32});
        const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_branch(b)});
        return hs.build_state_from_trie(root);
    };
    TestAccount acc;
    acc.build(72);
    const auto leaf_of = [&](const Bytes& hp, const Bytes& value) {
        return rlp_list_of(string_of(hp) + string_of(value));
    };

    SECTION("tests-zkevm cumulative_path_exceeds_key_length: 64 nibbles at depth 1") {
        Bytes fixture{0xe3, 0xa1, 0x20};
        fixture.append(32, 0x00);
        fixture.push_back(0x80);
        CHECK(under_slot1(fixture) == HashState::BuildStatus::kMalformed);

        Bytes hp64{0x20};
        hp64.append(32, 0x00);
        Bytes hp63{0x30};
        hp63.append(31, 0x00);
        CHECK(build(leaf_of(hp64, acc.leaf_value)) == HashState::BuildStatus::kOk);
        CHECK(under_slot1(leaf_of(hp64, acc.leaf_value)) == HashState::BuildStatus::kMalformed);
        CHECK(under_slot1(leaf_of(hp63, acc.leaf_value)) == HashState::BuildStatus::kOk);
    }
    SECTION("tests-zkevm leaf_segment_exceeds_key_length: a 67-nibble segment") {
        Bytes fixture{0xe4, 0xa2, 0x30};
        fixture.append(33, 0x00);
        fixture.push_back(0x80);
        CHECK(under_slot1(fixture) == HashState::BuildStatus::kMalformed);
        CHECK(build(fixture) == HashState::BuildStatus::kMalformed);

        Bytes hp67{0x30};
        hp67.append(33, 0x00);
        CHECK(build(leaf_of(hp67, acc.leaf_value)) == HashState::BuildStatus::kMalformed);
        CHECK(under_slot1(leaf_of(hp67, acc.leaf_value)) == HashState::BuildStatus::kMalformed);
    }
}

// One-nibble HP paths carry no RLP header.
TEST_CASE("HashState build_state_from_trie decodes one-nibble leaf paths, hashed and embedded",
          "[hash_state]") {
    HashState hs;

    // --- X's storage trie ---
    evmc::bytes32 v1{};
    v1.bytes[31] = 0x2A;  // single-byte value: the embedded leaf is [0x3n, 0x2a] = 3 bytes
    evmc::bytes32 v2{};
    for (std::size_t i = 0; i < 32; ++i) v2.bytes[i] = static_cast<uint8_t>(0xB0u + i);
    const Key s1 = key_with(0x7, 3, 5);  // root[0x7] -> ext(61) -> branch[nib 62] -> leaf(1)
    const Key s2 = key_with(0xC, 5, 2);  // root[0xC] -> leaf(63)

    const Bytes ev1 = encode_storage_value(v1);
    const LeafNode sleaf1 = make_leaf(&s1.nib[63], 1, ByteView{ev1});
    const Bytes emb1{zilkworm::encode_leaf(sleaf1)};  // own it before the next encode call
    REQUIRE(emb1.size() == 3u);
    REQUIRE(emb1[1] < 0x80);  // the one-nibble HP path is a bare byte
    BranchNode sbranch;
    sbranch.set_child(s1.nib[62], ByteView{emb1});  // < 32 bytes -> embedded inline child
    const evmc::bytes32 hSBranch = hs.add_node(ByteView{zilkworm::encode_branch(sbranch)});
    const ExtensionNode sext = make_ext(&s1.nib[1], 61, ByteView{hSBranch.bytes, 32});
    const evmc::bytes32 hSExt = hs.add_node(ByteView{zilkworm::encode_ext(sext)});
    const Bytes ev2 = encode_storage_value(v2);
    const LeafNode sleaf2 = make_leaf(&s2.nib[1], 63, ByteView{ev2});
    const evmc::bytes32 hS2 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf2)});
    BranchNode sroot;
    sroot.set_child(0x7, ByteView{hSExt.bytes, 32});
    sroot.set_child(0xC, ByteView{hS2.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    // --- account trie: root[0x4]->ext(62)->leaf(1) ---
    const Key kX = key_with(0x4, 9, 7);
    const Bytes accX = account_leaf_value(3, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[63], 1, ByteView{accX});
    const Bytes leafX_rlp{zilkworm::encode_leaf(leafX)};
    REQUIRE(leafX_rlp.size() > 32u);  // hash-referenced
    const evmc::bytes32 hX = hs.add_node(ByteView{leafX_rlp});
    const ExtensionNode extX = make_ext(&kX.nib[1], 62, ByteView{hX.bytes, 32});
    const evmc::bytes32 hExtX = hs.add_node(ByteView{zilkworm::encode_ext(extX)});
    BranchNode root;
    root.set_child(0x4, ByteView{hExtX.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 1u);
    CHECK(hs.account_count() == 1u);
    CHECK(hs.storage_slot_count() == 2u);
    CHECK(hs.storage_count() == 2u);
    const Account* got = hs.get_account(kX.hash());
    REQUIRE(got != nullptr);
    CHECK(got->nonce == 3u);
    CHECK(std::memcmp(got->storage_root, storage_root.bytes, 32) == 0);
    CHECK(eq32(hs.get_storage(kX.hash(), s1.hash()), v1));
    CHECK(eq32(hs.get_storage(kX.hash(), s2.hash()), v2));
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Frame stack and counters reset per build.
TEST_CASE("HashState build_state_from_trie after a missing-root build derives the next root",
          "[hash_state]") {
    HashState hs;

    evmc::bytes32 v{};
    v.bytes[30] = 0x12;
    v.bytes[31] = 0x34;
    const Key s = key_with(0x3, 3, 5);
    const Bytes ev = encode_storage_value(v);
    const LeafNode sleaf = make_leaf(&s.nib[1], 63, ByteView{ev});
    const evmc::bytes32 hS = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    BranchNode sroot;
    sroot.set_child(0x3, ByteView{hS.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    const Key kX = key_with(0x1, 5, 2);
    const Bytes accX = account_leaf_value(8, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[1], 63, ByteView{accX});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    BranchNode root;
    root.set_child(0x1, ByteView{hX.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    evmc::bytes32 never_added{};
    for (int i = 0; i < 32; ++i) never_added.bytes[i] = static_cast<uint8_t>(0x31 + i);
    CHECK(hs.build_state_from_trie(never_added) == HashState::BuildStatus::kMissingNode);
    CHECK(hs.missing_count() == 1u);
    CHECK(hs.account_count() == 0u);
    CHECK(hs.storage_count() == 0u);

    CHECK(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 1u);
    CHECK(hs.account_count() == 1u);
    CHECK(hs.storage_slot_count() == 1u);
    CHECK(hs.storage_count() == 1u);
    const Account* got = hs.get_account(kX.hash());
    REQUIRE(got != nullptr);
    CHECK(got->nonce == 8u);
    CHECK(eq32(hs.get_storage(kX.hash(), s.hash()), v));
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Its arena slot must be given back.
TEST_CASE("HashState build_state_from_trie caches nothing for an undecodable hashed leaf",
          "[hash_state]") {
    HashState hs;

    const Key kN = key_with(0x2, 3, 5);
    const Key kP = key_with(0x5, 5, 2);
    const Key kQ = key_with(0x9, 7, 1);
    Bytes not_an_account;
    for (int i = 0; i < 40; ++i) not_an_account.push_back(static_cast<uint8_t>(0xE0 + i));
    TestAccount aP, aQ;
    aP.build(71); aQ.build(72);

    const LeafNode leafN = make_leaf(&kN.nib[1], 63, ByteView{not_an_account});
    const evmc::bytes32 hN = hs.add_node(ByteView{zilkworm::encode_leaf(leafN)});
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{aP.leaf_value});
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});
    const LeafNode leafQ = make_leaf(&kQ.nib[1], 63, ByteView{aQ.leaf_value});
    const evmc::bytes32 hQ = hs.add_node(ByteView{zilkworm::encode_leaf(leafQ)});
    BranchNode root;
    root.set_child(0x2, ByteView{hN.bytes, 32});
    root.set_child(0x5, ByteView{hP.bytes, 32});
    root.set_child(0x9, ByteView{hQ.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.leaf_count() == 3u);
    CHECK(hs.account_count() == 2u);
    CHECK(hs.find_built_account(kN.hash()) == nullptr);
    expect_account(hs.get_account(kP.hash()), aP, "P");
    expect_account(hs.get_account(kQ.hash()), aQ, "Q");
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Read misses: confirm_absent either proves the key empty or records an unconfirmed read.
// See docs/hashstate.md, "Partial-witness reads".

// Account: a present read hits the cache; a genuinely-absent account whose exclusion-path
// nodes are all in the store reads blank with NO unconfirmed read — proven two ways, via an
// empty root-branch slot and via a sibling leaf whose path diverges from the probe.
TEST_CASE("HashState get_account confirmed absent via present exclusion path", "[hash_state]") {
    HashState hs;

    // Root branch with two present account leaves (slots 0x1 and 0x4).
    TestAccount aP, aQ;
    aP.build(101);
    aQ.build(202);
    const Key kP = key_with(0x1, 3, 5);
    const Key kQ = key_with(0x4, 5, 2);
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{aP.leaf_value});
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});
    const LeafNode leafQ = make_leaf(&kQ.nib[1], 63, ByteView{aQ.leaf_value});
    const evmc::bytes32 hQ = hs.add_node(ByteView{zilkworm::encode_leaf(leafQ)});
    BranchNode root;
    root.set_child(0x1, ByteView{hP.bytes, 32});
    root.set_child(0x4, ByteView{hQ.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    // Present accounts read straight from the cache.
    expect_account(hs.get_account(kP.hash()), aP, "P");
    expect_account(hs.get_account(kQ.hash()), aQ, "Q");

    // Absent via an empty root-branch slot (first nibble 0x7 was never populated).
    const Key kEmptySlot = key_with(0x7, 9, 4);
    CHECK(hs.get_account(kEmptySlot.hash()) == nullptr);

    // Absent via path divergence: shares slot 0x1 with P but its tail differs from P's leaf.
    const Key kDiverge = key_with(0x1, 6, 1);
    REQUIRE_FALSE(eq32(kDiverge.hash(), kP.hash()));
    CHECK(hs.get_account(kDiverge.hash()) == nullptr);

    // Both misses were PROVEN empty: no unconfirmed read recorded.
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Account: an absent account whose confirmation walk needs a node the store does not have
// reads blank (so a value-returning caller proceeds) but records an unconfirmed read.
TEST_CASE("HashState get_account missing node leaves the read unconfirmed", "[hash_state]") {
    HashState hs;

    TestAccount aP;
    aP.build(303);
    const Key kP = key_with(0x1, 3, 5);
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{aP.leaf_value});
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});

    // Root branch slot 0x5 references a child hash that was never add_node'd.
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(0x1, ByteView{hP.bytes, 32});
    root.set_child(0x5, ByteView{dangling.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    // Slot 0x5 is a pruned boundary: the build stops there cleanly, so missing_count stays 0.
    // The witness gap on that path is enforced at READ time instead (below).
    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);  // reset by the build; no reads yet

    // The present account still reads from the cache and records nothing.
    expect_account(hs.get_account(kP.hash()), aP, "P");
    CHECK(hs.unconfirmed_read_count() == 0u);

    // A key whose path descends through the missing slot cannot be confirmed empty.
    const Key kMiss = key_with(0x5, 7, 3);
    CHECK(hs.get_account(kMiss.hash()) == nullptr);  // still blank for the caller
    CHECK(hs.unconfirmed_read_count() > 0u);         // but recorded as unconfirmed
}

// Storage: a present slot hits the cache; an absent slot whose exclusion-path nodes are all
// present reads zero with NO unconfirmed read — proven via an empty slot and via divergence.
TEST_CASE("HashState get_storage confirmed absent via present exclusion path", "[hash_state]") {
    HashState hs;

    evmc::bytes32 v1{};
    v1.bytes[31] = 0x2A;  // trims to a single byte
    evmc::bytes32 v2{};
    for (std::size_t i = 0; i < 32; ++i) v2.bytes[i] = static_cast<uint8_t>(0x10u + i);

    // X's storage trie: root branch -> two hash-referenced leaves (slots 0x2 and 0x7).
    const Key s1 = key_with(0x2, 3, 5);
    const Key s2 = key_with(0x7, 5, 2);
    const Bytes ev1 = encode_storage_value(v1);
    const LeafNode sl1 = make_leaf(&s1.nib[1], 63, ByteView{ev1});
    const evmc::bytes32 hsl1 = hs.add_node(ByteView{zilkworm::encode_leaf(sl1)});
    const Bytes ev2 = encode_storage_value(v2);
    const LeafNode sl2 = make_leaf(&s2.nib[1], 63, ByteView{ev2});
    const evmc::bytes32 hsl2 = hs.add_node(ByteView{zilkworm::encode_leaf(sl2)});
    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hsl1.bytes, 32});
    sroot.set_child(0x7, ByteView{hsl2.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    // Account X points at that storage trie; X is the whole (single-leaf) account trie.
    const Key kX = key_with(0x1, 3, 5);
    const Bytes accX = account_leaf_value(7, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[0], 64, ByteView{accX});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.storage_count() == 2u);

    // Present slots read from the cache.
    CHECK(eq32(hs.get_storage(kX.hash(), s1.hash()), v1));
    CHECK(eq32(hs.get_storage(kX.hash(), s2.hash()), v2));

    // Absent via an empty storage-branch slot (first nibble 0x9 unused).
    const Key sEmpty = key_with(0x9, 4, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), sEmpty.hash()), evmc::bytes32{}));

    // Absent via path divergence: shares slot 0x2 with s1 but its tail differs.
    const Key sDiverge = key_with(0x2, 6, 1);
    REQUIRE_FALSE(eq32(sDiverge.hash(), s1.hash()));
    CHECK(eq32(hs.get_storage(kX.hash(), sDiverge.hash()), evmc::bytes32{}));

    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Storage: a slot whose confirmation walk needs a node the store does not have reads zero
// but records an unconfirmed read (the storage trie IS included, so the build sees it too).
TEST_CASE("HashState get_storage missing node leaves the read unconfirmed", "[hash_state]") {
    HashState hs;

    // X's storage trie root branch is present: one real leaf (slot 0x2) and one dangling
    // child ref (slot 0x5) whose hash was never add_node'd.
    evmc::bytes32 vv{};
    vv.bytes[31] = 0x11;
    const Key sPresent = key_with(0x2, 3, 5);
    const Bytes evv = encode_storage_value(vv);
    const LeafNode slp = make_leaf(&sPresent.nib[1], 63, ByteView{evv});
    const evmc::bytes32 hslp = hs.add_node(ByteView{zilkworm::encode_leaf(slp)});
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hslp.bytes, 32});
    sroot.set_child(0x5, ByteView{dangling.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    const Key kX = key_with(0x1, 3, 5);
    const Bytes accX = account_leaf_value(7, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[0], 64, ByteView{accX});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});

    // The dangling storage child (slot 0x5) is a pruned boundary: the build stops there
    // cleanly (missing_count stays 0). The gap on that path is enforced at READ time (below).
    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // The present slot still reads from the cache (no confirmation, no record).
    CHECK(eq32(hs.get_storage(kX.hash(), sPresent.hash()), vv));
    CHECK(hs.unconfirmed_read_count() == 0u);

    // A slot whose path descends through the missing storage node cannot be confirmed empty.
    const Key sMiss = key_with(0x5, 7, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), sMiss.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() > 0u);
}

// Storage: the build-time-skip case is now caught on read. Account W carries a non-empty
// storage_root whose node was NEVER added; the build legitimately SKIPS that trie (an omitted
// storage trie is not a missing node), so the build reports clean. A read into it, however,
// hits the missing storage root during confirmation and is recorded — no longer a silent zero.
TEST_CASE("HashState get_storage records a read into a build-skipped storage root", "[hash_state]") {
    HashState hs;

    evmc::bytes32 absent_root{};
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);
    const Key kW = key_with(0x3, 9, 7);
    const Bytes accW = account_leaf_value(5, absent_root);
    const LeafNode leafW = make_leaf(&kW.nib[0], 64, ByteView{accW});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);  // build-time skip: NOT counted as a missing node
    REQUIRE(hs.account_count() == 1u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // A read into that storage trie hits the missing root during confirmation and is recorded.
    const Key slot = key_with(0x4, 2, 6);
    CHECK(eq32(hs.get_storage(kW.hash(), slot.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() > 0u);
}

// Storage: reads that need no confirmation at all. An account with the empty storage_root
// reads every slot as zero, and a slot read against an account absent from the cache reads
// zero too — neither attempts a confirmation walk, so neither records an unconfirmed read.
TEST_CASE("HashState get_storage on empty or absent account reads zero without confirming",
          "[hash_state]") {
    HashState hs;

    const Key kY = key_with(0x2, 5, 2);
    const Bytes accY = account_leaf_value(9, silkworm::kEmptyRoot);
    const LeafNode leafY = make_leaf(&kY.nib[0], 64, ByteView{accY});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafY)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.account_count() == 1u);

    // Empty storage_root: every slot is zero, no confirmation attempted.
    const Key slot = key_with(0x6, 3, 1);
    CHECK(eq32(hs.get_storage(kY.hash(), slot.hash()), evmc::bytes32{}));

    // Account absent from the cache: the slot is zero, no confirmation attempted.
    const Key kAbsentAddr = key_with(0xB, 7, 4);
    CHECK(eq32(hs.get_storage(kAbsentAddr.hash(), slot.hash()), evmc::bytes32{}));

    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Slots 0 and 1 classify the node.
TEST_CASE("HashState confirm_absent reads the probe's root-branch slot, first to last",
          "[hash_state]") {
    HashState hs;

    const Key k0 = key_with(0x0, 3, 5);
    const Key k1 = key_with(0x1, 5, 2);
    const Key k7 = key_with(0x7, 7, 1);
    const Key k15 = key_with(0xF, 9, 7);
    TestAccount a0, a1, a7, a15;
    a0.build(81); a1.build(82); a7.build(83); a15.build(84);
    const LeafNode leaf0 = make_leaf(&k0.nib[1], 63, ByteView{a0.leaf_value});
    const evmc::bytes32 h0 = hs.add_node(ByteView{zilkworm::encode_leaf(leaf0)});
    const LeafNode leaf1 = make_leaf(&k1.nib[1], 63, ByteView{a1.leaf_value});
    const evmc::bytes32 h1 = hs.add_node(ByteView{zilkworm::encode_leaf(leaf1)});
    const LeafNode leaf7 = make_leaf(&k7.nib[1], 63, ByteView{a7.leaf_value});
    const evmc::bytes32 h7 = hs.add_node(ByteView{zilkworm::encode_leaf(leaf7)});
    const LeafNode leaf15 = make_leaf(&k15.nib[1], 63, ByteView{a15.leaf_value});
    const evmc::bytes32 h15 = hs.add_node(ByteView{zilkworm::encode_leaf(leaf15)});
    BranchNode root;
    root.set_child(0x0, ByteView{h0.bytes, 32});
    root.set_child(0x1, ByteView{h1.bytes, 32});
    root.set_child(0x7, ByteView{h7.bytes, 32});
    root.set_child(0xF, ByteView{h15.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.account_count() == 4u);
    expect_account(hs.get_account(k0.hash()), a0, "0");
    expect_account(hs.get_account(k15.hash()), a15, "15");

    for (const Key& present : {k0, k1, k7, k15}) {
        Key probe = present;
        probe.nib[40] = static_cast<uint8_t>((present.nib[40] + 1) & 0xF);
        CHECK(hs.get_account(probe.hash()) == nullptr);
    }
    // 0x2 follows 0,1; 0xE needs 14 skips.
    CHECK(hs.get_account(key_with(0x2, 4, 3).hash()) == nullptr);
    CHECK(hs.get_account(key_with(0xE, 6, 1).hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Pruned slot 0xF: reached after 15 skips.
TEST_CASE("HashState confirm_absent skips to a pruned storage slot and records the read",
          "[hash_state]") {
    HashState hs;

    evmc::bytes32 v0{};
    v0.bytes[31] = 0x33;
    const Key s0 = key_with(0x0, 3, 5);
    const Bytes ev0 = encode_storage_value(v0);
    const LeafNode sl0 = make_leaf(&s0.nib[1], 63, ByteView{ev0});
    const evmc::bytes32 hsl0 = hs.add_node(ByteView{zilkworm::encode_leaf(sl0)});
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode sroot;
    sroot.set_child(0x0, ByteView{hsl0.bytes, 32});
    sroot.set_child(0xF, ByteView{dangling.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    const Key kX = key_with(0x1, 3, 5);
    const Bytes accX = account_leaf_value(7, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[0], 64, ByteView{accX});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.storage_count() == 1u);
    CHECK(eq32(hs.get_storage(kX.hash(), s0.hash()), v0));

    Key diverge = s0;
    diverge.nib[63] = static_cast<uint8_t>((s0.nib[63] + 1) & 0xF);
    CHECK(eq32(hs.get_storage(kX.hash(), diverge.hash()), evmc::bytes32{}));
    CHECK(eq32(hs.get_storage(kX.hash(), key_with(0x9, 4, 3).hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 0u);

    const Key pruned = key_with(0xF, 7, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), pruned.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 1u);
    CHECK(eq32(hs.get_storage(kX.hash(), pruned.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 2u);
}

// Blocks often reread cold slots.
TEST_CASE("HashState get_storage memoizes a proven-absent slot until the next build",
          "[hash_state]") {
    HashState hs;

    // X: sroot[0x2]->leaf, sroot[0x5] pruned; Y empty.
    evmc::bytes32 vv{};
    vv.bytes[31] = 0x11;
    const Key sPresent = key_with(0x2, 3, 5);
    const Bytes evv = encode_storage_value(vv);
    const LeafNode slp = make_leaf(&sPresent.nib[1], 63, ByteView{evv});
    const evmc::bytes32 hslp = hs.add_node(ByteView{zilkworm::encode_leaf(slp)});
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hslp.bytes, 32});
    sroot.set_child(0x5, ByteView{dangling.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    const Key kX = key_with(0x1, 3, 5);
    const Bytes accX = account_leaf_value(7, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[1], 63, ByteView{accX});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    const Key kY = key_with(0x2, 5, 2);
    const Bytes accY = account_leaf_value(9, silkworm::kEmptyRoot);
    const LeafNode leafY = make_leaf(&kY.nib[1], 63, ByteView{accY});
    const evmc::bytes32 hY = hs.add_node(ByteView{zilkworm::encode_leaf(leafY)});
    BranchNode root;
    root.set_child(0x1, ByteView{hX.bytes, 32});
    root.set_child(0x2, ByteView{hY.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.account_count() == 2u);
    REQUIRE(hs.absent_slot_count() == 0u);

    // Second read: memo hit, no walk.
    const Key sEmpty = key_with(0x9, 4, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), sEmpty.hash()), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 1u);
    CHECK(eq32(hs.get_storage(kX.hash(), sEmpty.hash()), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 1u);
    CHECK(hs.unconfirmed_read_count() == 0u);

    // A cache hit enters nothing.
    Key sDiverge = sPresent;
    sDiverge.nib[63] = static_cast<uint8_t>((sPresent.nib[63] + 1) & 0xF);
    CHECK(eq32(hs.get_storage(kX.hash(), sDiverge.hash()), evmc::bytes32{}));
    CHECK(eq32(hs.get_storage(kX.hash(), sPresent.hash()), vv));
    CHECK(hs.absent_slot_count() == 2u);

    // The pruned slot: unprovable, so never memoized.
    const Key sMiss = key_with(0x5, 7, 3);
    CHECK(eq32(hs.get_storage(kX.hash(), sMiss.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 1u);
    CHECK(eq32(hs.get_storage(kX.hash(), sMiss.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 2u);
    CHECK(hs.absent_slot_count() == 2u);

    // Y (empty storage), uncached account: answered pre-memo.
    CHECK(eq32(hs.get_storage(kY.hash(), sEmpty.hash()), evmc::bytes32{}));
    CHECK(eq32(hs.get_storage(key_with(0xB, 7, 4).hash(), sEmpty.hash()), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 2u);
    CHECK(hs.unconfirmed_read_count() == 2u);

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    CHECK(hs.absent_slot_count() == 0u);
    CHECK(hs.unconfirmed_read_count() == 0u);
    CHECK(eq32(hs.get_storage(kX.hash(), sEmpty.hash()), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 1u);
}

// root[0x8]->ext(60)->branch->embedded-leaf(2); its value is no account.
TEST_CASE("HashState confirm_absent follows an embedded child in place", "[hash_state]") {
    HashState hs;

    Key kE;
    kE.nib[0] = 0x8;
    for (std::size_t i = 1; i < 64; ++i) kE.nib[i] = static_cast<uint8_t>((i * 2 + 1) & 0xF);
    const uint8_t emb_value_byte = 0x2A;
    const LeafNode leafE = make_leaf(&kE.nib[62], 2, ByteView{&emb_value_byte, 1});
    const Bytes embE{zilkworm::encode_leaf(leafE)};  // own it before the next encode call
    REQUIRE(embE.size() < 32);
    BranchNode branch2;
    branch2.set_child(kE.nib[61], ByteView{embE});  // < 32 bytes -> embedded inline child
    const Bytes branch2_rlp{zilkworm::encode_branch(branch2)};
    const evmc::bytes32 hBranch2 = hs.add_node(ByteView{branch2_rlp});
    const ExtensionNode extE = make_ext(&kE.nib[1], 60, ByteView{hBranch2.bytes, 32});
    const evmc::bytes32 hExtE = hs.add_node(ByteView{zilkworm::encode_ext(extE)});
    BranchNode root;
    root.set_child(0x8, ByteView{hExtE.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.leaf_count() == 1u);
    REQUIRE(hs.account_count() == 0u);

    Key in_ext = kE;  // diverges at nibble 30, inside the extension's 60
    in_ext.nib[30] = static_cast<uint8_t>((kE.nib[30] + 1) & 0xF);
    CHECK(hs.get_account(in_ext.hash()) == nullptr);
    Key empty_slot = kE;  // the deep branch's other slots are empty
    empty_slot.nib[61] = static_cast<uint8_t>((kE.nib[61] + 1) & 0xF);
    CHECK(hs.get_account(empty_slot.hash()) == nullptr);
    Key first = kE;  // reaches the embedded leaf, diverges on its first nibble
    first.nib[62] = static_cast<uint8_t>((kE.nib[62] + 1) & 0xF);
    CHECK(hs.get_account(first.hash()) == nullptr);
    Key second = kE;  // ... and on its second
    second.nib[63] = static_cast<uint8_t>((kE.nib[63] + 1) & 0xF);
    CHECK(hs.get_account(second.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 0u);

    // Own key: in the trie, uncached, refuted.
    CHECK(hs.get_account(kE.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 1u);
}

// D: root[0x2]->ext(62)->branch->leaf(0)x2; X, Y, Z malformed.
TEST_CASE("HashState confirm_absent at a branch at depth 63 and past 64 nibbles",
          "[hash_state]") {
    HashState hs;

    const Key kD1 = key_with(0x2, 3, 5);
    Key kD2 = kD1;
    kD2.nib[63] = static_cast<uint8_t>((kD1.nib[63] + 5) & 0xF);
    const Key kX = key_with(0x5, 5, 2);
    const Key kY = key_with(0x8, 7, 1);
    TestAccount aD1, aD2, aX, aY;
    aD1.build(91); aD2.build(92); aX.build(93); aY.build(94);

    const LeafNode leafD1 = make_leaf(&kD1.nib[64], 0, ByteView{aD1.leaf_value});
    const evmc::bytes32 hD1 = hs.add_node(ByteView{zilkworm::encode_leaf(leafD1)});
    const LeafNode leafD2 = make_leaf(&kD2.nib[64], 0, ByteView{aD2.leaf_value});
    const evmc::bytes32 hD2 = hs.add_node(ByteView{zilkworm::encode_leaf(leafD2)});
    BranchNode branch63;
    branch63.set_child(kD1.nib[63], ByteView{hD1.bytes, 32});
    branch63.set_child(kD2.nib[63], ByteView{hD2.bytes, 32});
    const evmc::bytes32 hBranch63 = hs.add_node(ByteView{zilkworm::encode_branch(branch63)});
    const ExtensionNode extD = make_ext(&kD1.nib[1], 62, ByteView{hBranch63.bytes, 32});
    const evmc::bytes32 hExtD = hs.add_node(ByteView{zilkworm::encode_ext(extD)});

    // X: a branch at depth 64.
    const LeafNode leafX = make_leaf(&kX.nib[64], 0, ByteView{aX.leaf_value});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    BranchNode branch64;
    branch64.set_child(0x0, ByteView{hX.bytes, 32});
    const evmc::bytes32 hBranch64 = hs.add_node(ByteView{zilkworm::encode_branch(branch64)});
    const ExtensionNode extX = make_ext(&kX.nib[1], 63, ByteView{hBranch64.bytes, 32});
    const evmc::bytes32 hExtX = hs.add_node(ByteView{zilkworm::encode_ext(extX)});

    // Y: 1+60+10 = 71 nibbles.
    std::array<uint8_t, 10> ypath{};
    for (std::size_t i = 0; i < 3; ++i) ypath[i] = kY.nib[61 + i];
    for (std::size_t i = 3; i < 10; ++i) ypath[i] = static_cast<uint8_t>(i);
    const LeafNode leafY = make_leaf(ypath.data(), 10, ByteView{aY.leaf_value});
    const evmc::bytes32 hY = hs.add_node(ByteView{zilkworm::encode_leaf(leafY)});
    const ExtensionNode extY = make_ext(&kY.nib[1], 60, ByteView{hY.bytes, 32});
    const evmc::bytes32 hExtY = hs.add_node(ByteView{zilkworm::encode_ext(extY)});

    // Z: hand-built leaf, 66-nibble HP path.
    Bytes zpath;
    zpath.push_back(0x20);
    for (int i = 0; i < 33; ++i) zpath.push_back(static_cast<uint8_t>(0x11 * (i % 15 + 1)));
    Bytes zpayload;
    silkworm::rlp::encode(zpayload, ByteView{zpath});          // item 0: the 34-byte path
    silkworm::rlp::encode(zpayload, ByteView{aY.leaf_value});  // item 1: a value
    const Bytes zleaf = rlp_list_of(zpayload);
    const evmc::bytes32 hZ = hs.add_node(ByteView{zleaf});

    BranchNode root;
    root.set_child(0x2, ByteView{hExtD.bytes, 32});
    root.set_child(0x5, ByteView{hExtX.bytes, 32});
    root.set_child(0x8, ByteView{hExtY.bytes, 32});
    root.set_child(0x9, ByteView{hZ.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kMalformed);
    REQUIRE(hs.account_count() == 2u);  // D1, D2; X, Y and Z stop before a leaf is keyed
    expect_account(hs.get_account(kD1.hash()), aD1, "D1");
    expect_account(hs.get_account(kD2.hash()), aD2, "D2");

    Key d_empty = kD1;  // an empty slot of the depth-63 branch
    d_empty.nib[63] = static_cast<uint8_t>((kD1.nib[63] + 1) & 0xF);
    CHECK(hs.get_account(d_empty.hash()) == nullptr);
    Key d_ext = kD1;  // diverges inside the 62-nibble extension
    d_ext.nib[33] = static_cast<uint8_t>((kD1.nib[33] + 1) & 0xF);
    CHECK(hs.get_account(d_ext.hash()) == nullptr);
    CHECK(hs.get_account(kY.hash()) == nullptr);  // the leaf's path outlasts the key
    CHECK(hs.unconfirmed_read_count() == 0u);

    CHECK(hs.get_account(kX.hash()) == nullptr);  // a branch at depth 64
    CHECK(hs.unconfirmed_read_count() == 1u);
    CHECK(hs.get_account(key_with(0x9, 2, 6).hash()) == nullptr);  // a 66-nibble HP path
    CHECK(hs.unconfirmed_read_count() == 2u);
}

// X: root[0x4]->ext(62)->leaf(1); slot: root[0x7]->ext(61)->branch->embedded-leaf(1).
TEST_CASE("HashState confirm_absent compares one-nibble and even HP paths", "[hash_state]") {
    HashState hs;

    evmc::bytes32 v1{};
    v1.bytes[31] = 0x2A;
    const Key s1 = key_with(0x7, 3, 5);
    const Bytes ev1 = encode_storage_value(v1);
    const LeafNode sleaf1 = make_leaf(&s1.nib[63], 1, ByteView{ev1});
    const Bytes emb1{zilkworm::encode_leaf(sleaf1)};  // own it before the next encode call
    REQUIRE(emb1.size() == 3u);
    BranchNode sbranch;
    sbranch.set_child(s1.nib[62], ByteView{emb1});
    const evmc::bytes32 hSBranch = hs.add_node(ByteView{zilkworm::encode_branch(sbranch)});
    const ExtensionNode sext = make_ext(&s1.nib[1], 61, ByteView{hSBranch.bytes, 32});
    const evmc::bytes32 hSExt = hs.add_node(ByteView{zilkworm::encode_ext(sext)});
    BranchNode sroot;
    sroot.set_child(0x7, ByteView{hSExt.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    const Key kX = key_with(0x4, 9, 7);
    const Bytes accX = account_leaf_value(3, storage_root);
    const LeafNode leafX = make_leaf(&kX.nib[63], 1, ByteView{accX});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    const ExtensionNode extX = make_ext(&kX.nib[1], 62, ByteView{hX.bytes, 32});
    const evmc::bytes32 hExtX = hs.add_node(ByteView{zilkworm::encode_ext(extX)});
    BranchNode root;
    root.set_child(0x4, ByteView{hExtX.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.account_count() == 1u);
    REQUIRE(hs.storage_count() == 1u);
    CHECK(eq32(hs.get_storage(kX.hash(), s1.hash()), v1));

    Key a_last = kX;  // diverges on the hashed leaf's single nibble
    a_last.nib[63] = static_cast<uint8_t>((kX.nib[63] + 1) & 0xF);
    CHECK(hs.get_account(a_last.hash()) == nullptr);
    Key a_ext = kX;  // diverges on the last nibble of the even 62-nibble extension
    a_ext.nib[62] = static_cast<uint8_t>((kX.nib[62] + 1) & 0xF);
    CHECK(hs.get_account(a_ext.hash()) == nullptr);
    Key s_last = s1;  // diverges on the embedded leaf's single nibble
    s_last.nib[63] = static_cast<uint8_t>((s1.nib[63] + 1) & 0xF);
    CHECK(eq32(hs.get_storage(kX.hash(), s_last.hash()), evmc::bytes32{}));
    Key s_slot = s1;  // an empty slot of the deep storage branch
    s_slot.nib[62] = static_cast<uint8_t>((s1.nib[62] + 1) & 0xF);
    CHECK(eq32(hs.get_storage(kX.hash(), s_slot.hash()), evmc::bytes32{}));
    Key s_ext = s1;  // diverges on the first nibble of the odd 61-nibble extension
    s_ext.nib[1] = static_cast<uint8_t>((s1.nib[1] + 1) & 0xF);
    CHECK(eq32(hs.get_storage(kX.hash(), s_ext.hash()), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 0u);
}

TEST_CASE("HashState confirm_absent refutes a leaf at the key the build did not cache",
          "[hash_state]") {
    HashState hs;

    const Key kG = key_with(0x6, 3, 5);
    const Bytes garbage{0x01};
    const LeafNode leafG = make_leaf(&kG.nib[1], 63, ByteView{garbage});
    const evmc::bytes32 hG = hs.add_node(ByteView{zilkworm::encode_leaf(leafG)});
    BranchNode root;
    root.set_child(0x6, ByteView{hG.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.leaf_count() == 1u);
    REQUIRE(hs.account_count() == 0u);

    CHECK(hs.get_account(kG.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 1u);
    CHECK(hs.get_account(kG.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 2u);
    Key near = kG;
    near.nib[63] = static_cast<uint8_t>((kG.nib[63] + 1) & 0xF);
    CHECK(hs.get_account(near.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 2u);
}

// Hand-built: the encoders cannot emit this shape.
TEST_CASE("HashState confirm_absent stops at a malformed sibling before the probe's slot",
          "[hash_state]") {
    HashState hs;

    const Key kA = key_with(0x0, 3, 5);
    const Key kB = key_with(0x1, 5, 2);
    const Key kC = key_with(0x5, 7, 1);
    TestAccount aA, aB, aC;
    aA.build(64); aB.build(65); aC.build(66);
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
    const LeafNode leafB = make_leaf(&kB.nib[1], 63, ByteView{aB.leaf_value});
    const evmc::bytes32 hB = hs.add_node(ByteView{zilkworm::encode_leaf(leafB)});
    const LeafNode leafC = make_leaf(&kC.nib[1], 63, ByteView{aC.leaf_value});
    const evmc::bytes32 hC = hs.add_node(ByteView{zilkworm::encode_leaf(leafC)});

    Bytes payload;
    payload.push_back(0xa0); payload.append(hA.bytes, 32);  // slot 0: hash ref -> A
    payload.push_back(0xa0); payload.append(hB.bytes, 32);  // slot 1: hash ref -> B
    payload.push_back(0x81); payload.push_back(0xff);       // slot 2: a string, not a child
    payload.push_back(0x80); payload.push_back(0x80);       // slots 3, 4: empty
    payload.push_back(0xa0); payload.append(hC.bytes, 32);  // slot 5: hash ref -> C
    for (int i = 6; i < 16; ++i) payload.push_back(0x80);   // slots 6..15: empty
    payload.push_back(0x80);                                // value: empty
    const Bytes node = rlp_list_of(payload);
    const evmc::bytes32 root_hash = hs.add_node(ByteView{node});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kMalformed);
    REQUIRE(hs.account_count() == 2u);

    // Before the malformed item: proven.
    Key a_div = kA;
    a_div.nib[20] = static_cast<uint8_t>((kA.nib[20] + 1) & 0xF);
    CHECK(hs.get_account(a_div.hash()) == nullptr);
    Key b_div = kB;
    b_div.nib[20] = static_cast<uint8_t>((kB.nib[20] + 1) & 0xF);
    CHECK(hs.get_account(b_div.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 0u);

    // At and past it: never proven.
    CHECK(hs.get_account(key_with(0x2, 4, 3).hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 1u);
    CHECK(hs.get_account(key_with(0x3, 4, 3).hash()) == nullptr);  // the 0x80 right after it
    CHECK(hs.unconfirmed_read_count() == 2u);
    CHECK(hs.get_account(kC.hash()) == nullptr);  // C itself: not swept, not confirmable
    CHECK(hs.unconfirmed_read_count() == 3u);
    Key c_div = kC;
    c_div.nib[20] = static_cast<uint8_t>((kC.nib[20] + 1) & 0xF);
    CHECK(hs.get_account(c_div.hash()) == nullptr);
    CHECK(hs.unconfirmed_read_count() == 4u);
}

namespace {

// Deterministic, so failures reproduce.
struct Xorshift64 {
    uint64_t s;
    uint64_t next() noexcept {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
};

}  // namespace

// Garbage values and dangling children: nothing cached.
TEST_CASE("HashState confirm_absent HP compare matches hp_decode on random paths",
          "[hash_state]") {
    HashState hs;
    Xorshift64 rng{0x9E3779B97F4A7C15ULL};
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    const Bytes garbage{0x01};

    for (int trial = 0; trial < 1000; ++trial) {
        const unsigned plen = static_cast<unsigned>(rng.next() % 65u);
        const bool is_leaf = (rng.next() & 1u) != 0;
        std::array<uint8_t, 64> path{};
        for (unsigned i = 0; i < plen; ++i) path[i] = static_cast<uint8_t>(rng.next() & 0xF);
        const unsigned shared = static_cast<unsigned>(rng.next() % (plen + 1u));
        Key probe;
        for (unsigned i = 0; i < 64; ++i) probe.nib[i] = static_cast<uint8_t>(rng.next() & 0xF);
        for (unsigned i = 0; i < shared; ++i) probe.nib[i] = path[i];
        if (shared < plen)
            probe.nib[shared] = static_cast<uint8_t>((path[shared] + 1 + rng.next() % 15) & 0xF);

        const uint8_t plen8 = static_cast<uint8_t>(plen);
        const Bytes node = is_leaf
            ? Bytes{zilkworm::encode_leaf(make_leaf(path.data(), plen8, ByteView{garbage}))}
            : Bytes{zilkworm::encode_ext(make_ext(path.data(), plen8, ByteView{dangling.bytes, 32}))};

        // The oracle: hp_decode on the node itself.
        ByteView items{node};
        auto oh = silkworm::rlp::decode_header(items);
        REQUIRE(oh);
        REQUIRE(oh->list);
        auto h0 = silkworm::rlp::decode_header(items);
        REQUIRE(h0);
        std::array<uint8_t, 64> nibs{};
        uint8_t nlen = 0;
        bool leaf_flag = false;
        REQUIRE(zilkworm::hp_decode(items.substr(0, h0->payload_length), leaf_flag, nibs, nlen));
        REQUIRE(leaf_flag == is_leaf);
        REQUIRE(nlen == plen);
        const nibbles64 target = nibbles64::from_bytes32(probe.hash());
        unsigned matched = 0;
        while (matched < plen && nibs[matched] == target.nib[matched]) ++matched;
        bool expected;
        if (matched < plen) expected = true;       // diverges inside the overlap
        else if (is_leaf) expected = plen != 64;   // the exact key refutes absence
        else expected = false;                     // the extension's child is missing

        const evmc::bytes32 root_hash = hs.add_node(ByteView{node});
        REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
        REQUIRE(hs.unconfirmed_read_count() == 0u);
        INFO("trial " << trial << " plen " << plen << " leaf " << is_leaf << " shared " << shared);
        CHECK(hs.get_account(probe.hash()) == nullptr);
        CHECK((hs.unconfirmed_read_count() == 0u) == expected);
    }
}

// GridMPT<true, HashState> fold over the witness node store, checked against a hand-built root.
// See docs/hashstate.md, "GridMPT fold over HashState".

// Change an existing account's value and fold: the recomputed root must equal the
// independently hand-computed root of the post-write trie.
TEST_CASE("GridMPT fold over HashState recomputes the post-write account root",
          "[hash_state][fold]") {
    HashState hs;

    // --- pre-state: root branch -> two hash-referenced account leaves (A @ slot 0x1, B @ 0x4).
    TestAccount aA, aB;
    aA.build(11);
    aB.build(22);
    const Key kA = key_with(0x1, 3, 5);
    const Key kB = key_with(0x4, 5, 2);
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
    const LeafNode leafB = make_leaf(&kB.nib[1], 63, ByteView{aB.leaf_value});
    const evmc::bytes32 hB = hs.add_node(ByteView{zilkworm::encode_leaf(leafB)});
    BranchNode root;
    root.set_child(0x1, ByteView{hA.bytes, 32});
    root.set_child(0x4, ByteView{hB.bytes, 32});
    const Bytes root_rlp{zilkworm::encode_branch(root)};
    const evmc::bytes32 prev_root = hs.add_node(ByteView{root_rlp});

    // Mirror the real accept flow: derive the pre-state before folding. A/B carry bogus
    // (absent) storage roots, which build legitimately skips -> kOk, missing 0.
    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    expect_account(hs.get_account(kA.hash()), aA, "A");
    expect_account(hs.get_account(kB.hash()), aB, "B");

    // --- the write: account A -> A2 (distinct seed => distinct leaf value). ---
    TestAccount aA2;
    aA2.build(101);
    REQUIRE(aA2.leaf_value != aA.leaf_value);

    // --- gather the sorted TrieNodeFlat update set the way check_root does
    // (state_transition.cpp:591-607): key = addr_hash, current_value = new account leaf
    // RLP staged in buf. HashState update set carries NO initial_value / NO read-only entry
    // (the pre-value check is compiled out for this instantiation). ---
    std::vector<zilkworm::TrieNodeFlat> updates;
    {
        auto& node = updates.emplace_back(kA.hash());
        REQUIRE(aA2.leaf_value.size() <= sizeof(node.buf));
        node.current_off = 0;
        node.current_len = static_cast<uint8_t>(aA2.leaf_value.size());
        std::memcpy(node.buf, aA2.leaf_value.data(), aA2.leaf_value.size());
    }
    // Single entry -> already in memcmp(key) order (mpt.hpp:202); no sort needed.

    // --- fold over HashState's node store ---
    zilkworm::GridMPT<true, HashState> acc_trie(hs, prev_root);
    const evmc::bytes32 new_root =
        acc_trie.calc_root_from_updates({updates.data(), updates.size()});
    CHECK(acc_trie.missing_count() == 0u);

    // --- oracle: the post-write trie root, hand-computed with the fold's own encoders. ---
    const LeafNode leafA2 = make_leaf(&kA.nib[1], 63, ByteView{aA2.leaf_value});
    const Bytes leafA2_rlp{zilkworm::encode_leaf(leafA2)};  // own before the next encode call
    const evmc::bytes32 hA2 = keccak32(ByteView{leafA2_rlp});
    BranchNode post_root;
    post_root.set_child(0x1, ByteView{hA2.bytes, 32});  // A's leaf hash changed
    post_root.set_child(0x4, ByteView{hB.bytes, 32});   // B unchanged
    const Bytes post_root_rlp{zilkworm::encode_branch(post_root)};
    const evmc::bytes32 expected_root = keccak32(ByteView{post_root_rlp});

    CHECK(eq32(new_root, expected_root));      // HashState fold == hand-computed post-root
    CHECK_FALSE(eq32(new_root, prev_root));    // the write actually moved the root
}

// A write whose key descends through a hash ref absent from the node store must make the
// fold reject: calc_root_from_updates returns {} (zero root) and records the missing node.
TEST_CASE("GridMPT fold over HashState rejects a missing fold node", "[hash_state][fold]") {
    HashState hs;

    // Root branch: a present account leaf at slot 0x1, and slot 0x5 referencing a child
    // hash that was never add_node'd.
    TestAccount aA;
    aA.build(7);
    const Key kA = key_with(0x1, 3, 5);
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{aA.leaf_value});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});

    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(0x1, ByteView{hA.bytes, 32});
    root.set_child(0x5, ByteView{dangling.bytes, 32});
    const Bytes root_rlp{zilkworm::encode_branch(root)};
    const evmc::bytes32 prev_root = hs.add_node(ByteView{root_rlp});

    // A write at a key whose first nibble is 0x5 forces the fold to unfold the dangling
    // child -> find_node_rlp miss -> kMissing -> reject.
    TestAccount aMiss;
    aMiss.build(9);
    const Key kMiss = key_with(0x5, 7, 3);
    std::vector<zilkworm::TrieNodeFlat> updates;
    {
        auto& node = updates.emplace_back(kMiss.hash());
        REQUIRE(aMiss.leaf_value.size() <= sizeof(node.buf));
        node.current_off = 0;
        node.current_len = static_cast<uint8_t>(aMiss.leaf_value.size());
        std::memcpy(node.buf, aMiss.leaf_value.data(), aMiss.leaf_value.size());
    }

    zilkworm::GridMPT<true, HashState> acc_trie(hs, prev_root);
    const evmc::bytes32 new_root =
        acc_trie.calc_root_from_updates({updates.data(), updates.size()});

    CHECK(acc_trie.missing_count() > 0u);         // the missing node was observed
    CHECK(eq32(new_root, evmc::bytes32{}));        // reject -> zero root (never equals a header)
}

// check_root_hashstate accepts iff the root matches and the missing/unconfirmed counts are zero.
// See docs/hashstate.md, "Accept check tests".

namespace {

using zilkworm::HashStateAccountWrite;

// Build an Account POD with distinct, fully-decodable fields from `seed` and a chosen
// storage_root — the object check_root_hashstate re-encodes the account leaf from via
// rlp_into(buf, root). Field pattern matches account_leaf_value so leaves agree byte-for-byte.
Account make_test_account(uint64_t seed, const evmc::bytes32& storage_root) {
    Account a{};
    a.nonce = seed;
    const uint64_t bal = 0xAABBCCDD00000000ULL + seed;
    std::memcpy(a.balance, &bal, sizeof(bal));
    for (std::size_t i = 0; i < 32; ++i)
        a.code_hash[i] = static_cast<uint8_t>(0xC0u + i + seed);
    std::memcpy(a.storage_root, storage_root.bytes, 32);
    return a;
}

}  // namespace

// ACCEPT: two touched accounts — A changes an account FIELD (nonce), X changes a STORAGE
// SLOT (so the per-account storage fold runs). check_root_hashstate must recompute exactly
// the independently hand-computed post-state root and accept it.
TEST_CASE("check_root_hashstate accepts writes that recompute the header root",
          "[hash_state][accept]") {
    HashState hs;

    // --- X's pre-state storage trie: root branch -> three hash-referenced 63-nibble leaves.
    evmc::bytes32 v1{};  // full 32 bytes
    for (std::size_t i = 0; i < 32; ++i) v1.bytes[i] = static_cast<uint8_t>(0xF1u - i);
    evmc::bytes32 v2{};  v2.bytes[31] = 0x2A;                 // trims to one byte
    evmc::bytes32 v3{};  v3.bytes[30] = 0x81; v3.bytes[31] = 0xFF;  // trims to two bytes

    const Key s1 = key_with(0x2, 3, 5);
    const Key s2 = key_with(0x7, 5, 2);
    const Key s3 = key_with(0xE, 7, 1);
    const Bytes ev1 = encode_storage_value(v1);
    const LeafNode sleaf1 = make_leaf(&s1.nib[1], 63, ByteView{ev1});
    const evmc::bytes32 hs1 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf1)});
    const Bytes ev2 = encode_storage_value(v2);
    const LeafNode sleaf2 = make_leaf(&s2.nib[1], 63, ByteView{ev2});
    const evmc::bytes32 hs2 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf2)});
    const Bytes ev3 = encode_storage_value(v3);
    const LeafNode sleaf3 = make_leaf(&s3.nib[1], 63, ByteView{ev3});
    const evmc::bytes32 hs3 = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf3)});
    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hs1.bytes, 32});
    sroot.set_child(0x7, ByteView{hs2.bytes, 32});
    sroot.set_child(0xE, ByteView{hs3.bytes, 32});
    const evmc::bytes32 sroot_X = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});

    // --- account trie: root branch -> A (@0x1, absent/skipped storage) and X (@0x2, sroot_X).
    evmc::bytes32 absent_root{};  // never add_node'd; build legitimately skips A's storage
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);

    const Key kA = key_with(0x1, 3, 5);
    const Key kX = key_with(0x2, 5, 2);
    const Account accA = make_test_account(11, absent_root);
    const Account accX = make_test_account(7, sroot_X);
    const Bytes leafA_val = accA.rlp(absent_root);
    const Bytes leafX_val = accX.rlp(sroot_X);
    const LeafNode leafA = make_leaf(&kA.nib[1], 63, ByteView{leafA_val});
    const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
    const LeafNode leafX = make_leaf(&kX.nib[1], 63, ByteView{leafX_val});
    const evmc::bytes32 hX = hs.add_node(ByteView{zilkworm::encode_leaf(leafX)});
    BranchNode root;
    root.set_child(0x1, ByteView{hA.bytes, 32});
    root.set_child(0x2, ByteView{hX.bytes, 32});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    // Mirror the real accept flow: derive the pre-state before folding. missing/unconfirmed 0.
    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // --- writes: A's nonce -> 101 (field change); X's slot s1 -> v1_new (storage change). ---
    evmc::bytes32 v1_new{};
    for (std::size_t i = 0; i < 32; ++i) v1_new.bytes[i] = static_cast<uint8_t>(0x20u + i);
    REQUIRE_FALSE(eq32(v1_new, v1));

    const Account accA2 = make_test_account(101, absent_root);  // A's storage unchanged

    std::vector<zilkworm::TrieNodeFlat> x_storage;  // sorted (single entry); must outlive the call
    {
        const Bytes ev = encode_storage_value(v1_new);
        auto& n = x_storage.emplace_back(s1.hash());
        n.current_off = 0;
        n.current_len = static_cast<uint8_t>(ev.size());
        std::memcpy(n.buf, ev.data(), ev.size());
    }

    std::vector<HashStateAccountWrite> writes;                  // sorted by addr_hash: A (0x18..) < X (0x27..)
    writes.push_back({kA.hash(), absent_root, {}, &accA2});
    writes.push_back({kX.hash(), sroot_X,
                      std::span<const zilkworm::TrieNodeFlat>{x_storage}, &accX});

    // --- oracle: post-write root, hand-computed with the fold's own encoders. ---
    // A' leaf (new nonce, storage unchanged).
    const Bytes leafA2_val = accA2.rlp(absent_root);
    const LeafNode leafA2 = make_leaf(&kA.nib[1], 63, ByteView{leafA2_val});
    const evmc::bytes32 hA2 = keccak32(ByteView{zilkworm::encode_leaf(leafA2)});
    // X's new storage root: s1 leaf value changed, s2/s3 unchanged.
    const Bytes ev1_new = encode_storage_value(v1_new);
    const LeafNode sleaf1_new = make_leaf(&s1.nib[1], 63, ByteView{ev1_new});
    const evmc::bytes32 hs1_new = keccak32(ByteView{zilkworm::encode_leaf(sleaf1_new)});
    BranchNode sroot_new;
    sroot_new.set_child(0x2, ByteView{hs1_new.bytes, 32});
    sroot_new.set_child(0x7, ByteView{hs2.bytes, 32});
    sroot_new.set_child(0xE, ByteView{hs3.bytes, 32});
    const Bytes sroot_new_rlp{zilkworm::encode_branch(sroot_new)};
    const evmc::bytes32 sroot_X_new = keccak32(ByteView{sroot_new_rlp});
    REQUIRE_FALSE(eq32(sroot_X_new, sroot_X));  // the storage write moved X's storage root
    // X' account leaf re-encoded with the new storage root (X's fields unchanged).
    const Bytes leafX2_val = accX.rlp(sroot_X_new);
    const LeafNode leafX2 = make_leaf(&kX.nib[1], 63, ByteView{leafX2_val});
    const evmc::bytes32 hX2 = keccak32(ByteView{zilkworm::encode_leaf(leafX2)});
    // post-state account root.
    BranchNode post_root;
    post_root.set_child(0x1, ByteView{hA2.bytes, 32});
    post_root.set_child(0x2, ByteView{hX2.bytes, 32});
    const Bytes post_root_rlp{zilkworm::encode_branch(post_root)};
    const evmc::bytes32 expected_root = keccak32(ByteView{post_root_rlp});
    REQUIRE_FALSE(eq32(expected_root, prev_root));  // the writes moved the account root

    // ACCEPT: recomputed root == header root, both counts zero.
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, writes, expected_root));

    // REJECT on a tampered header root: same writes, one flipped byte.
    evmc::bytes32 bad_root = expected_root;
    bad_root.bytes[0] = static_cast<uint8_t>(bad_root.bytes[0] ^ 0xFF);
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, writes, bad_root));
}

// REJECT on unconfirmed read: a build-skipped storage root is read after the build, leaving
// unconfirmed_read_count() > 0 while missing_count() stays 0. The SAME writes + correct root
// accept BEFORE the read and reject AFTER it — the count is the only thing that changed, so
// the accept gate rejects even though the root matches.
TEST_CASE("check_root_hashstate rejects when a read was left unconfirmed",
          "[hash_state][accept]") {
    HashState hs;

    evmc::bytes32 absent_root{};  // W's storage_root; its node is never add_node'd
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);

    // Whole account trie is a single 64-nibble leaf (account W).
    const Key kW = key_with(0x3, 9, 7);
    const Account accW = make_test_account(5, absent_root);
    const Bytes leafW_val = accW.rlp(absent_root);
    const LeafNode leafW = make_leaf(&kW.nib[0], 64, ByteView{leafW_val});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);              // build-time skip: NOT a missing node
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // Write: W's nonce -> 55 (storage unchanged; absent_root carried through).
    const Account accW2 = make_test_account(55, absent_root);
    std::vector<HashStateAccountWrite> writes;
    writes.push_back({kW.hash(), absent_root, {}, &accW2});

    // Oracle: single-leaf trie root == keccak(encode_leaf(new leaf)).
    const Bytes leafW2_val = accW2.rlp(absent_root);
    const LeafNode leafW2 = make_leaf(&kW.nib[0], 64, ByteView{leafW2_val});
    const evmc::bytes32 expected_root = keccak32(ByteView{zilkworm::encode_leaf(leafW2)});

    // Baseline: with both counts still zero and the correct root, it ACCEPTS.
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, writes, expected_root));

    // Read into W's build-skipped storage trie: confirmation hits the absent root -> unconfirmed.
    const Key slot = key_with(0x4, 2, 6);
    (void)hs.get_storage(kW.hash(), slot.hash());
    REQUIRE(hs.unconfirmed_read_count() > 0u);
    REQUIRE(hs.missing_count() == 0u);

    // Same writes, same (correct) root -> now REJECTS purely on the unconfirmed read.
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, writes, expected_root));
}

// Regression: BLOCKHASH of an omitted in-range ancestor must reject even when the root matches.
// See docs/hashstate.md, "Omitted BLOCKHASH ancestor".
TEST_CASE("check_root_hashstate rejects a BLOCKHASH read of an omitted in-range ancestor",
          "[hash_state][accept][blockhash]") {
    HashState hs;

    // Pre-state: a single-leaf account trie holding account W (empty storage).
    const Key kW = key_with(0x3, 9, 7);
    const Account accW = make_test_account(5, silkworm::kEmptyRoot);
    const Bytes leafW_val = accW.rlp(silkworm::kEmptyRoot);
    const LeafNode leafW = make_leaf(&kW.nib[0], 64, ByteView{leafW_val});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // Witness ancestor headers: the chain up to the parent with the in-range ancestor number 3
    // deliberately omitted (the missing-oldest-ancestor shape).
    const HeaderChain c = header_chain(6);
    for (const auto& h : c.headers) {
        if (h.number != 3) hs.insert_header(h);
    }

    // The block's write set: bump W's nonce (a real, root-changing write). The block ALSO runs
    // SSTORE(slot, BLOCKHASH(3)); with header 3 omitted BLOCKHASH yields 0, and a zero write to
    // a never-present slot folds to nothing, so it never appears in the write set. The attacker
    // sets header.state_root to exactly this forged execution's root.
    const Account accW2 = make_test_account(55, silkworm::kEmptyRoot);
    std::vector<HashStateAccountWrite> writes;
    writes.push_back({kW.hash(), silkworm::kEmptyRoot, {}, &accW2});
    const Bytes leafW2_val = accW2.rlp(silkworm::kEmptyRoot);
    const LeafNode leafW2 = make_leaf(&kW.nib[0], 64, ByteView{leafW2_val});
    const evmc::bytes32 forged_root = keccak32(ByteView{zilkworm::encode_leaf(leafW2)});

    // Baseline: both counters zero and the forged root matches the fold -> ACCEPT. This is the
    // exploit's "root matches" precondition (identical pre- and post-fix).
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, writes, forged_root));

    // SAFETY: a PRESENT ancestor read costs nothing — a legitimate BLOCKHASH of a shipped
    // ancestor (number 5) hits, the counter stays zero, and acceptance still holds.
    (void)hs.get_block_hash(c.block, 5);
    CHECK(hs.unconfirmed_read_count() == 0u);
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, writes, forged_root));

    // EXPLOIT: the block reads BLOCKHASH(3) — an in-range ancestor whose header was omitted.
    (void)hs.get_block_hash(c.block, 3);

    // POST-FIX the omitted-ancestor read is recorded, so the SAME forged root is now REJECTED.
    // PRE-FIX both assertions FAIL: the counter stayed zero and acceptance still returned true.
    CHECK(hs.unconfirmed_read_count() > 0u);
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, writes, forged_root));
}

// A PRUNED BOUNDARY in the pre-state is legitimate now (not a missing node), so a write that
// avoids it ACCEPTS. But a write whose fold MUST descend into the boundary is still caught:
// GridMPT cannot unfold the absent node, records a missing node, and recomputes a degenerate
// (zero) root, so new_root == header_state_root fails with NO fourth accept condition. This
// is the B3 degenerate-root reject, preserved on top of the partial-witness change; it also
// confirms GridMPT does NOT silently mis-fold over a boundary.
TEST_CASE("check_root_hashstate accepts an off-boundary write but rejects a fold through a "
          "pruned boundary", "[hash_state][accept]") {
    HashState hs;

    // Root branch: present account P @ slot 0x1, PRUNED boundary (bare hash ref, node absent)
    // @ slot 0x5.
    const Key kP = key_with(0x1, 3, 5);
    const Account accP = make_test_account(303, silkworm::kEmptyRoot);  // empty storage
    const Bytes leafP_val = accP.rlp(silkworm::kEmptyRoot);
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{leafP_val});
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});
    evmc::bytes32 pruned{};
    for (int i = 0; i < 32; ++i) pruned.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(0x1, ByteView{hP.bytes, 32});
    root.set_child(0x5, ByteView{pruned.bytes, 32});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    // The pruned boundary is NOT a missing node: the build reports clean.
    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // --- (1) off-boundary write ACCEPTS. P's nonce -> 3030 (path slot 0x1, avoids slot 0x5).
    const Account accP2 = make_test_account(3030, silkworm::kEmptyRoot);
    std::vector<HashStateAccountWrite> ok_writes;
    ok_writes.push_back({kP.hash(), silkworm::kEmptyRoot, {}, &accP2});

    // Oracle: fold the same single update with a raw GridMPT; it never touches slot 0x5, so
    // it recomputes a real root cleanly.
    std::vector<zilkworm::TrieNodeFlat> acc_updates;
    {
        const Bytes v = accP2.rlp(silkworm::kEmptyRoot);
        auto& n = acc_updates.emplace_back(kP.hash());
        n.current_off = 0;
        n.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(n.buf, v.data(), v.size());
    }
    zilkworm::GridMPT<true, HashState> probe(hs, prev_root);
    const evmc::bytes32 folded =
        probe.calc_root_from_updates({acc_updates.data(), acc_updates.size()});
    REQUIRE(probe.missing_count() == 0u);          // the off-boundary fold hit no missing node
    REQUIRE_FALSE(eq32(folded, evmc::bytes32{}));   // a real root

    // A valid partial witness + a correct off-boundary write + the matching root ACCEPTS
    // (the pruned boundary no longer blocks acceptance).
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, ok_writes, folded));

    // --- (2) a write whose fold MUST descend into the pruned boundary is REJECTED.
    const Account accMiss = make_test_account(9, silkworm::kEmptyRoot);
    const Key kMiss = key_with(0x5, 7, 3);  // first nibble 0x5 -> straight through the boundary
    std::vector<HashStateAccountWrite> bad_writes;
    bad_writes.push_back({kMiss.hash(), silkworm::kEmptyRoot, {}, &accMiss});

    // Sanity: the fold over the boundary degenerates to the zero root — GridMPT records the
    // missing node and returns {}, it does NOT silently mis-fold.
    std::vector<zilkworm::TrieNodeFlat> bad_updates;
    {
        const Bytes v = accMiss.rlp(silkworm::kEmptyRoot);
        auto& n = bad_updates.emplace_back(kMiss.hash());
        n.current_off = 0;
        n.current_len = static_cast<uint8_t>(v.size());
        std::memcpy(n.buf, v.data(), v.size());
    }
    zilkworm::GridMPT<true, HashState> bad_probe(hs, prev_root);
    const evmc::bytes32 bad_folded =
        bad_probe.calc_root_from_updates({bad_updates.data(), bad_updates.size()});
    REQUIRE(bad_probe.missing_count() > 0u);        // the boundary was observed by the fold
    REQUIRE(eq32(bad_folded, evmc::bytes32{}));      // degenerate zero root, not a real state

    // Even feeding a real header, the accept fails: the fold recomputes {} != header.
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, bad_writes, folded));
}

// slib front end: decode StatelessInputBytes into a HashState; real, synthetic and malformed blobs.
// See docs/hashstate.md, "Stateless input front end".

namespace {

using zilkworm::Bytes;

[[nodiscard]] Bytes hex_to_bytes(const char* h) {
    auto v = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    Bytes out;
    for (std::size_t i = 0; h[i] && h[i + 1]; i += 2)
        out.push_back(static_cast<std::uint8_t>((v(h[i]) << 4) | v(h[i + 1])));
    return out;
}

// --- minimal SSZ encoders mirroring slib_input.cpp's decoders (test-only) ---
void put_u32(Bytes& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
void put_u64(Bytes& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
void put_u32_at(Bytes& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8u * i));
}

// [N u32 LE offset table][concatenated elements], offsets relative to this blob.
[[nodiscard]] Bytes encode_bytelist_list(const std::vector<Bytes>& els) {
    Bytes out;
    const std::uint32_t table = static_cast<std::uint32_t>(els.size()) * 4u;
    std::uint32_t off = table;
    for (const auto& e : els) {
        put_u32(out, off);
        off += static_cast<std::uint32_t>(e.size());
    }
    for (const auto& e : els) out.insert(out.end(), e.begin(), e.end());
    return out;
}

// StatelessInput around pre-encoded list blobs; headers empty.
[[nodiscard]] Bytes encode_stateless_input_lists(const Bytes& state_blob, const Bytes& codes_blob,
                                                 std::uint64_t chain_id) {
    // SszExecutionWitness: [off_state=12][off_codes][off_headers] + state++codes++headers.
    Bytes wit;
    const std::uint32_t off_state = 12u;
    const std::uint32_t off_codes = off_state + static_cast<std::uint32_t>(state_blob.size());
    const std::uint32_t off_headers = off_codes + static_cast<std::uint32_t>(codes_blob.size());
    put_u32(wit, off_state);
    put_u32(wit, off_codes);
    put_u32(wit, off_headers);  // headers empty -> off_headers == wit end
    wit.insert(wit.end(), state_blob.begin(), state_blob.end());
    wit.insert(wit.end(), codes_blob.begin(), codes_blob.end());
    // StatelessInput: [off_npr=16][off_wit=16][chain_id u64] + wit (npr empty).
    Bytes body;
    const std::uint32_t off_npr = 16u;
    const std::uint32_t off_wit = 16u;
    put_u32(body, off_npr);
    put_u32(body, off_wit);
    put_u64(body, chain_id);
    body.insert(body.end(), wit.begin(), wit.end());
    Bytes blob;
    blob.push_back(0x15);
    blob.push_back(0x01);
    blob.insert(blob.end(), body.begin(), body.end());
    return blob;
}

// schema_id||SSZ StatelessInput with empty new_payload_request/headers.
[[nodiscard]] Bytes encode_stateless_input(const std::vector<Bytes>& state,
                                           const std::vector<Bytes>& codes,
                                           std::uint64_t chain_id) {
    return encode_stateless_input_lists(encode_bytelist_list(state), encode_bytelist_list(codes),
                                        chain_id);
}

}  // namespace

// The cross-check on real wire bytes: a tests-zkevm v21.0.1 statelessInputBytes decodes, its
// NewPayloadRequest hashes to the root the fixture's statelessOutputBytes commits to, the block it
// describes hashes to the payload's block_hash, and the witness builds against the parent's state root.
TEST_CASE("slib decodes the real StatelessInputBytes sample: request root, block hash, pre-state",
          "[hash_state][slib]") {
    const Bytes blob = hex_to_bytes(slib_sample::kBlobHex);
    REQUIRE(blob.size() == slib_sample::kBlobBytes);
    const Bytes expected_output = hex_to_bytes(slib_sample::kExpectedOutputHex);
    REQUIRE(expected_output.size() == 43);

    const auto dec = zilkworm::decode_stateless_input(ByteView{blob});
    REQUIRE(dec.has_value());
    CHECK(dec->chain_id == slib_sample::kChainId);
    CHECK(dec->state.size() == slib_sample::kExpectedNodes);
    CHECK(dec->codes.size() == slib_sample::kExpectedCodes);
    REQUIRE(dec->headers.size() == slib_sample::kExpectedHeaders);

    const auto payload = zilkworm::decode_slib_payload(dec->new_payload_request);
    REQUIRE(payload.has_value());
    CHECK(payload->block_number == slib_sample::kBlockNumber);
    CHECK(payload->transactions.size() == slib_sample::kTransactions);
    CHECK(payload->withdrawals.size() == slib_sample::kWithdrawals);
    CHECK(eq32(payload->block_hash, to_bytes32(ByteView{hex_to_bytes(slib_sample::kBlockHashHex)})));

    // statelessOutputBytes: root, successful_validation (1: a valid block), chain_id, schema_id.
    const auto root = zilkworm::slib_payload_root(*payload);
    CHECK(std::memcmp(root.data(), expected_output.data(), 32) == 0);
    CHECK(expected_output[32] == 1);
    uint64_t chain_id = 0;
    std::memcpy(&chain_id, expected_output.data() + 33, 8);
    CHECK(chain_id == slib_sample::kChainId);
    CHECK(expected_output[41] == (zilkworm::kSlibSchemaId & 0xff));
    CHECK(expected_output[42] == (zilkworm::kSlibSchemaId >> 8));

    const auto block = zilkworm::slib_payload_block(*payload);
    REQUIRE(block.has_value());
    CHECK(eq32(block->header.hash(), payload->block_hash));

    // The parent header, last of the witness headers, carries the root the witness is anchored to.
    silkworm::BlockHeader parent;
    ByteView hv{dec->headers.back()};
    REQUIRE(silkworm::rlp::decode(hv, parent));
    CHECK(eq32(parent.hash(), block->header.parent_hash));

    HashState hs;
    const auto res = zilkworm::run_slib(ByteView{blob}, hs, parent.state_root);
    REQUIRE(res.has_value());
    CHECK(res->status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.node_count() == slib_sample::kExpectedNodes);
    CHECK(hs.code_count() == slib_sample::kExpectedCodes);
    CHECK(hs.account_count() > 0u);
}


// A COMPLETE synthetic witness encoded into the exact wire format: the clean
// missing_count()==0 path, with an account carrying a real storage trie so get_storage
// can be cross-checked. Parses through the SAME parse_stateless_input the real sample uses.
TEST_CASE("slib parses a synthetic complete witness and rebuilds accounts + storage",
          "[hash_state][slib]") {
    // --- X's storage trie: root branch -> two hash-referenced 63-nibble leaves. ---
    evmc::bytes32 v1{};
    v1.bytes[31] = 0x2A;  // trims to a single byte
    evmc::bytes32 v2{};
    for (std::size_t i = 0; i < 32; ++i) v2.bytes[i] = static_cast<std::uint8_t>(0x10u + i);
    const Key s1 = key_with(0x2, 3, 5);
    const Key s2 = key_with(0x7, 5, 2);
    const Bytes ev1 = encode_storage_value(v1);
    const Bytes sl1_rlp{zilkworm::encode_leaf(make_leaf(&s1.nib[1], 63, ByteView{ev1}))};
    const evmc::bytes32 hsl1 = keccak32(ByteView{sl1_rlp});
    const Bytes ev2 = encode_storage_value(v2);
    const Bytes sl2_rlp{zilkworm::encode_leaf(make_leaf(&s2.nib[1], 63, ByteView{ev2}))};
    const evmc::bytes32 hsl2 = keccak32(ByteView{sl2_rlp});
    BranchNode sroot;
    sroot.set_child(0x2, ByteView{hsl1.bytes, 32});
    sroot.set_child(0x7, ByteView{hsl2.bytes, 32});
    const Bytes sroot_rlp{zilkworm::encode_branch(sroot)};
    const evmc::bytes32 storage_root = keccak32(ByteView{sroot_rlp});

    // --- account trie: root branch -> A (empty storage) and X (the storage trie above). ---
    const Key kA = key_with(0x1, 3, 5);
    const Key kX = key_with(0x2, 5, 2);
    const Bytes accA = account_leaf_value(11, silkworm::kEmptyRoot);
    const Bytes leafA_rlp{zilkworm::encode_leaf(make_leaf(&kA.nib[1], 63, ByteView{accA}))};
    const evmc::bytes32 hA = keccak32(ByteView{leafA_rlp});
    const Bytes accX = account_leaf_value(7, storage_root);
    const Bytes leafX_rlp{zilkworm::encode_leaf(make_leaf(&kX.nib[1], 63, ByteView{accX}))};
    const evmc::bytes32 hX = keccak32(ByteView{leafX_rlp});
    BranchNode root;
    root.set_child(0x1, ByteView{hA.bytes, 32});
    root.set_child(0x2, ByteView{hX.bytes, 32});
    const Bytes root_rlp{zilkworm::encode_branch(root)};
    const evmc::bytes32 root_hash = keccak32(ByteView{root_rlp});

    // --- encode all six nodes into a StatelessInput blob and parse it. ---
    const std::vector<Bytes> state{root_rlp, leafA_rlp, leafX_rlp, sroot_rlp, sl1_rlp, sl2_rlp};
    const Bytes blob = encode_stateless_input(state, /*codes=*/{}, /*chain_id=*/1);

    HashState hs;
    auto view = zilkworm::parse_stateless_input(ByteView{blob}, hs);
    REQUIRE(view.has_value());
    CHECK(view->chain_id == 1u);
    CHECK(view->node_count == 6u);
    CHECK(view->code_count == 0u);
    CHECK(hs.node_count() == 6u);

    const auto status = hs.build_state_from_trie(root_hash);
    CHECK(status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);   // complete witness: every referenced node present
    CHECK(hs.account_count() == 2u);
    CHECK(hs.storage_count() == 2u);

    const Account* pa = hs.get_account(kA.hash());
    REQUIRE(pa != nullptr);
    CHECK(pa->nonce == 11u);
    const Account* px = hs.get_account(kX.hash());
    REQUIRE(px != nullptr);
    CHECK(px->nonce == 7u);

    // Storage slots reconstruct to their exact words.
    CHECK(eq32(hs.get_storage(kX.hash(), s1.hash()), v1));
    CHECK(eq32(hs.get_storage(kX.hash(), s2.hash()), v2));
    // A's storage is empty; a slot read returns zero.
    CHECK(eq32(hs.get_storage(kA.hash(), s1.hash()), evmc::bytes32{}));
}

// Malformed blobs must fail cleanly (std::nullopt) with no crash / out-of-bounds read.
TEST_CASE("slib rejects malformed StatelessInputBytes blobs", "[hash_state][slib]") {
    // A known-good synthetic blob to mutate. Two state nodes so the state-list offset table
    // has a second offset to corrupt (decode does not validate trie structure, only SSZ).
    const Key kA = key_with(0x1, 3, 5);
    const Key kB = key_with(0x4, 5, 2);
    const Bytes accA = account_leaf_value(11, silkworm::kEmptyRoot);
    const Bytes accB = account_leaf_value(22, silkworm::kEmptyRoot);
    const Bytes leafA_rlp{zilkworm::encode_leaf(make_leaf(&kA.nib[0], 64, ByteView{accA}))};
    const Bytes leafB_rlp{zilkworm::encode_leaf(make_leaf(&kB.nib[0], 64, ByteView{accB}))};
    const Bytes good = encode_stateless_input({leafA_rlp, leafB_rlp}, /*codes=*/{}, /*chain_id=*/1);
    {  // sanity: the good blob parses
        HashState hs;
        CHECK(zilkworm::decode_stateless_input(ByteView{good}).has_value());
        CHECK(zilkworm::parse_stateless_input(ByteView{good}, hs).has_value());
    }

    SECTION("empty / too short for the marker") {
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{}).has_value());
        Bytes one{good.substr(0, 1)};
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{one}).has_value());
    }
    SECTION("bad big-endian marker") {
        Bytes b = good;
        b[1] ^= 0xFF;  // 0x1501 -> not the schema id
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("truncated below the 16-byte top-level fixed region") {
        Bytes b{good.substr(0, 2 + 10)};  // marker + 10 body bytes
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("first offset != fixed-region size") {
        Bytes b = good;
        put_u32_at(b, 2 + 0, 17u);  // off(new_payload_request) must be 16
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("out-of-order top-level offset") {
        Bytes b = good;
        put_u32_at(b, 2 + 4, 0u);  // off(witness) = 0 < off(new_payload_request) = 16
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("offset past end of blob") {
        Bytes b = good;
        put_u32_at(b, 2 + 4, 0xFFFFFFFFu);  // off(witness) beyond the body
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("witness first offset != 12") {
        Bytes b = good;
        put_u32_at(b, 2 + 16, 13u);  // witness off(state) must be 12
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("out-of-order state-list offset") {
        Bytes b = good;
        // state list begins at body(16) + witness fixed(12) = blob offset 2+16+12 = 30;
        // its second u32 offset lives at +4. Force it below the first offset (non-monotone).
        put_u32_at(b, 2 + 16 + 12 + 4, 0u);
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
}

// A failed parse leaves HashState partly fed.
TEST_CASE("slib stops the streamed feed at a non-monotone state-list offset",
          "[hash_state][slib]") {
    const Key kA = key_with(0x1, 3, 5);
    const Key kB = key_with(0x4, 5, 2);
    const Key kC = key_with(0x9, 2, 7);
    const Bytes accA = account_leaf_value(11, silkworm::kEmptyRoot);
    const Bytes accB = account_leaf_value(22, silkworm::kEmptyRoot);
    const Bytes accC = account_leaf_value(33, silkworm::kEmptyRoot);
    const Bytes leafA_rlp{zilkworm::encode_leaf(make_leaf(&kA.nib[0], 64, ByteView{accA}))};
    const Bytes leafB_rlp{zilkworm::encode_leaf(make_leaf(&kB.nib[0], 64, ByteView{accB}))};
    const Bytes leafC_rlp{zilkworm::encode_leaf(make_leaf(&kC.nib[0], 64, ByteView{accC}))};
    const Bytes good =
        encode_stateless_input({leafA_rlp, leafB_rlp, leafC_rlp}, /*codes=*/{}, /*chain_id=*/1);
    {  // sanity: the good blob feeds all three
        HashState hs;
        auto v = zilkworm::parse_stateless_input(ByteView{good}, hs);
        REQUIRE(v.has_value());
        CHECK(v->node_count == 3u);
        CHECK(hs.node_count() == 3u);
    }

    // marker(2)+top-fixed(16)+witness-fixed(12); entry i at +4i.
    Bytes b = good;
    const std::size_t state_at = 2 + 16 + 12;
    const std::uint32_t off1 = 3u * 4u + static_cast<std::uint32_t>(leafA_rlp.size());
    put_u32_at(b, state_at + 8, off1 - 1u);

    HashState hs;
    CHECK_FALSE(zilkworm::parse_stateless_input(ByteView{b}, hs).has_value());
    CHECK(hs.node_count() == 1u);  // element 0 was fed; element 1 failed on its end offset
    CHECK(hs.find_node_rlp(keccak32(ByteView{leafA_rlp})).has_value());
    CHECK_FALSE(hs.find_node_rlp(keccak32(ByteView{leafB_rlp})).has_value());
    CHECK_FALSE(hs.find_node_rlp(keccak32(ByteView{leafC_rlp})).has_value());
    // The materialising decoder rejects the same blob.
    CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
}

// (cap+1)*4-byte table: count check rejects, not bounds.
TEST_CASE("slib rejects a state list announcing more than the node count cap",
          "[hash_state][slib]") {
    const std::uint32_t n = zilkworm::kMaxWitnessStateNodes + 1u;
    Bytes state(static_cast<std::size_t>(n) * 4u, 0);
    for (std::uint32_t i = 0; i < n; ++i)
        put_u32_at(state, static_cast<std::size_t>(i) * 4u, n * 4u);
    const Bytes blob = encode_stateless_input_lists(state, /*codes_blob=*/{}, /*chain_id=*/1);

    HashState hs;
    CHECK_FALSE(zilkworm::parse_stateless_input(ByteView{blob}, hs).has_value());
    CHECK(hs.node_count() == 0u);  // rejected at the count: nothing was fed
    CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{blob}).has_value());

    // Control: the same shape at count 3.
    Bytes small(3u * 4u, 0);
    for (std::uint32_t i = 0; i < 3u; ++i) put_u32_at(small, i * 4u, 12u);
    const Bytes small_blob = encode_stateless_input_lists(small, /*codes_blob=*/{}, /*chain_id=*/1);
    HashState hs_small;
    auto v = zilkworm::parse_stateless_input(ByteView{small_blob}, hs_small);
    REQUIRE(v.has_value());
    CHECK(v->node_count == 3u);
    CHECK(hs_small.node_count() == 1u);
}

// Counts over kMaxReserve size like kMaxReserve.
TEST_CASE("slib clamps the store hints of a count past kMaxReserve", "[hash_state][slib]") {
    using Index = HashIndex<32, &hash_key8_at>;
    // Second count catches an unclamped account hint.
    for (const std::uint32_t n : {HashState::kMaxReserve + 1u, 2u * HashState::kMaxReserve}) {
        CAPTURE(n);
        REQUIRE(Index::capacity_for(n) != Index::capacity_for(HashState::kMaxReserve));
        Bytes table(static_cast<std::size_t>(n) * 4u, 0);
        for (std::uint32_t i = 0; i < n; ++i)
            put_u32_at(table, static_cast<std::size_t>(i) * 4u, n * 4u);
        const Bytes blob = encode_stateless_input_lists(table, table, /*chain_id=*/1);

        HashState hs{4, 4, 4, 4};
        auto v = zilkworm::parse_stateless_input(ByteView{blob}, hs);
        REQUIRE(v.has_value());
        CHECK(v->node_count == n);
        CHECK(v->code_count == n);
        CHECK(hs.node_count() == 1u);
        CHECK(hs.code_count() == 1u);
        const auto caps = hs.index_capacities();
        CHECK(caps[0] == Index::capacity_for(HashState::kMaxReserve));
        CHECK(caps[1] == Index::capacity_for(HashState::kMaxReserve));
        CHECK(caps[2] == Index::capacity_for(HashState::kMaxReserve / 8u));
        CHECK(caps[3] == Index::capacity_for(4096u));
    }
    REQUIRE(Index::capacity_for(2u * HashState::kMaxReserve / 8u) !=
            Index::capacity_for(HashState::kMaxReserve / 8u));
}

TEST_CASE("HashState reserve_stores caps every hint at kMaxReserve", "[hash_state]") {
    using Index = HashIndex<32, &hash_key8_at>;
    const std::uint32_t cap = Index::capacity_for(HashState::kMaxReserve);

    HashState below{4, 4, 4, 4};
    below.reserve_stores(3000, 10, 100, HashState::kMaxReserve);
    const auto b = below.index_capacities();
    CHECK(b[0] == Index::capacity_for(3000));
    CHECK(b[1] == Index::capacity_for(10));
    CHECK(b[2] == Index::capacity_for(100));
    CHECK(b[3] == cap);

    HashState above{4, 4, 4, 4};
    above.reserve_stores(HashState::kMaxReserve + 1u, 1u << 20, 1u << 18, 1u << 17);
    for (const std::uint32_t c : above.index_capacities()) CHECK(c == cap);
}

TEST_CASE("ssz for_each_byte_list rejects bad tables and stops on the sink",
          "[hash_state][slib]") {
    const auto list_of = [](const std::vector<std::uint32_t>& offsets, std::size_t size) {
        Bytes b(size, 0xEE);
        for (std::size_t i = 0; i < offsets.size(); ++i) put_u32_at(b, i * 4u, offsets[i]);
        return b;
    };
    std::vector<Bytes> got;
    const auto walk = [&got](const Bytes& blob, std::uint32_t elem_cap, std::uint32_t count_cap,
                             std::size_t stop_at = SIZE_MAX) {
        got.clear();
        return zilkworm::ssz::for_each_byte_list(ByteView{blob}, elem_cap, count_cap,
                                                 [&](ByteView e) {
                                                     got.emplace_back(e);
                                                     return got.size() - 1 != stop_at;
                                                 });
    };
    std::vector<ByteView> out;

    SECTION("a well-formed list delivers every element") {
        const Bytes b = encode_bytelist_list({Bytes{0x01}, Bytes{}, Bytes{0x02, 0x03}});
        CHECK(zilkworm::ssz::byte_list_count(ByteView{b}, 3) == 3u);
        REQUIRE(walk(b, 2, 3));
        REQUIRE(got.size() == 3u);
        CHECK(got[0] == Bytes{0x01});
        CHECK(got[1].empty());
        CHECK(got[2] == (Bytes{0x02, 0x03}));
    }
    SECTION("an empty blob is the empty list") {
        CHECK(zilkworm::ssz::byte_list_count(ByteView{}, 3) == 0u);
        CHECK(walk(Bytes{}, 2, 3));
        CHECK(got.empty());
    }
    SECTION("a blob shorter than one offset") {
        const Bytes b{0x04, 0x00, 0x00};
        CHECK_FALSE(zilkworm::ssz::byte_list_count(ByteView{b}, 3).has_value());
        CHECK_FALSE(walk(b, 2, 3));
    }
    SECTION("a first offset that is not a multiple of 4") {
        const Bytes b = list_of({6, 6}, 8);
        CHECK_FALSE(zilkworm::ssz::byte_list_count(ByteView{b}, 3).has_value());
        CHECK_FALSE(walk(b, 2, 3));
        CHECK(got.empty());
    }
    SECTION("a first offset below 4 or past the blob") {
        CHECK_FALSE(walk(list_of({0}, 4), 2, 3));
        CHECK_FALSE(walk(list_of({12}, 8), 2, 3));
        CHECK(got.empty());
    }
    SECTION("more elements than count_cap") {
        const Bytes b = encode_bytelist_list({Bytes{0x01}, Bytes{0x02}, Bytes{0x03}});
        CHECK_FALSE(zilkworm::ssz::byte_list_count(ByteView{b}, 2).has_value());
        CHECK_FALSE(walk(b, 2, 2));
        CHECK(got.empty());
        CHECK_FALSE(zilkworm::ssz::decode_byte_lists(ByteView{b}, 2, 2, out));
    }
    SECTION("an offset past the blob") {
        CHECK_FALSE(walk(list_of({12, 13, 99}, 14), 2, 3));
        REQUIRE(got.size() == 1u);
        CHECK(got[0].size() == 1u);
    }
    SECTION("an offset below the one before it") {
        CHECK_FALSE(walk(list_of({12, 14, 13}, 15), 2, 3));
        REQUIRE(got.size() == 1u);
        CHECK(got[0].size() == 2u);
        CHECK_FALSE(zilkworm::ssz::decode_byte_lists(ByteView{list_of({12, 14, 13}, 15)}, 2, 3, out));
    }
    SECTION("an element over elem_cap") {
        const Bytes b = encode_bytelist_list({Bytes{0x01}, Bytes(5, 0x02), Bytes{0x03}});
        CHECK_FALSE(walk(b, 4, 3));
        REQUIRE(got.size() == 1u);
        CHECK(got[0] == Bytes{0x01});
        CHECK(walk(b, 5, 3));
    }
    SECTION("a sink that returns false stops the walk") {
        const Bytes b = encode_bytelist_list({Bytes{0x01}, Bytes{0x02}, Bytes{0x03}});
        CHECK_FALSE(walk(b, 2, 3, /*stop_at=*/1));
        REQUIRE(got.size() == 2u);
        CHECK(got[0] == Bytes{0x01});
        CHECK(got[1] == Bytes{0x02});
    }
}

// Write overlay, mutators and address-keyed readers, plus the two DirectState divergences.
// See docs/hashstate.md, "Write overlay and mutators".

namespace {

// A real 20-byte address with a distinct byte pattern seeded from `tag`.
[[nodiscard]] evmc::address s2_addr(std::uint8_t tag) {
    evmc::address a{};
    for (int i = 0; i < 20; ++i) a.bytes[i] = static_cast<std::uint8_t>(tag + 7 * i + 1);
    return a;
}

// The trie path an address / slot key hashes to (== keccak256 of its bytes).
[[nodiscard]] evmc::bytes32 keccak_addr(const evmc::address& a) { return keccak32(ByteView{a.bytes, 20}); }
[[nodiscard]] evmc::bytes32 keccak_slot(const evmc::bytes32& k) { return keccak32(ByteView{k.bytes, 32}); }

// The full 64-nibble trie path of a 32-byte hash.
[[nodiscard]] std::array<std::uint8_t, 64> nibbles_of(const evmc::bytes32& h) {
    std::array<std::uint8_t, 64> n{};
    for (std::size_t i = 0; i < 32; ++i) {
        n[2 * i] = static_cast<std::uint8_t>(h.bytes[i] >> 4);
        n[2 * i + 1] = static_cast<std::uint8_t>(h.bytes[i] & 0xF);
    }
    return n;
}

// Add a single-leaf account trie at keccak256(addr) with `leaf_val`; return the root hash
// (caller runs build_state_from_trie). Makes the account reachable through the built cache by
// the address-keyed readers, which hash the address internally.
[[nodiscard]] evmc::bytes32 add_single_account(HashState& hs, const evmc::address& addr,
                                               const Bytes& leaf_val) {
    const auto path = nibbles_of(keccak_addr(addr));
    const LeafNode leaf = make_leaf(path.data(), 64, ByteView{leaf_val});
    return hs.add_node(ByteView{zilkworm::encode_leaf(leaf)});
}

}  // namespace

// Balance and nonce set + overwrite on a brand-new overlay account (empty pre-state).
TEST_CASE("HashState set/overwrite balance and nonce on a new overlay account", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x10);

    hs.set_balance(addr, intx::uint256{100});
    CHECK(hs.get_balance(addr) == intx::uint256{100});
    hs.set_balance(addr, intx::uint256{250});  // overwrite
    CHECK(hs.get_balance(addr) == intx::uint256{250});

    hs.set_nonce(addr, 7);
    CHECK(hs.get_nonce(addr) == 7u);
    hs.set_nonce(addr, 9);  // overwrite
    CHECK(hs.get_nonce(addr) == 9u);

    // The write left an overlay record the read sees (not the absent built cache).
    CHECK(hs.read_account(addr) != nullptr);
    CHECK(hs.created_accounts().find(addr) != hs.created_accounts().end());
    // Confirmed-absent creation on the empty trie records no unconfirmed read.
    CHECK(hs.unconfirmed_read_count() == 0u);
}

// Balance is stored native-endian (the DirectState memcpy layout, direct_state.cpp:203-212).
TEST_CASE("HashState stores balance native-endian", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x20);

    intx::uint256 big = intx::uint256{0x1122334455667788ULL};
    big = (big << 128) | intx::uint256{0x99AABBCCDDEEFF00ULL};
    hs.set_balance(addr, big);
    CHECK(hs.get_balance(addr) == big);  // round-trips through the overlay

    const auto& ca = hs.created_accounts();
    auto it = ca.find(addr);
    REQUIRE(it != ca.end());
    std::uint8_t expect[32];
    std::memcpy(expect, &big, 32);  // native-endian byte image of the intx value
    CHECK(std::memcmp(it->second.balance, expect, 32) == 0);
}

// A write to a BUILT account copies it into the overlay and the read sees the write shadow
// the pre-state value.
TEST_CASE("HashState write to a built account shadows the pre-state value", "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0x30);
    const Bytes leaf_val = account_leaf_value(5, silkworm::kEmptyRoot);  // nonce 5, bal ..+5
    const evmc::bytes32 root = add_single_account(hs, addr, leaf_val);
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    const std::uint64_t built_bal = 0xAABBCCDD00000000ULL + 5;
    CHECK(hs.get_nonce(addr) == 5u);
    CHECK(hs.get_balance(addr) == intx::uint256{built_bal});
    CHECK(hs.unconfirmed_read_count() == 0u);  // present built account -> hit, no record

    hs.set_balance(addr, intx::uint256{9999});
    hs.set_nonce(addr, 42);
    CHECK(hs.get_balance(addr) == intx::uint256{9999});  // overlay shadows built
    CHECK(hs.get_nonce(addr) == 42u);
    CHECK(hs.created_accounts().find(addr) != hs.created_accounts().end());
}

// Storage: a nonzero write reads back; a ZERO write is RETAINED in the overlay (divergence a)
// — DirectState would erase it — so it stays available as a pending 0x80 delete for the fold.
TEST_CASE("HashState storage write read-back and zero-write retention (divergence a)",
          "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x40);
    hs.set_balance(addr, intx::uint256{1});  // bring the account alive in the overlay
    Account* pa = hs.find_or_create_account(addr);

    evmc::bytes32 key1{};
    key1.bytes[31] = 0x01;
    evmc::bytes32 val1{};
    for (int i = 0; i < 32; ++i) val1.bytes[i] = static_cast<std::uint8_t>(0x30 + i);
    hs.set_storage_slot(addr, *pa, key1, val1);
    CHECK(eq32(hs.read_storage(addr, key1), val1));  // nonzero read-back

    evmc::bytes32 key0{};
    key0.bytes[31] = 0x02;
    hs.set_storage_slot(addr, *pa, key0, evmc::bytes32{});  // write zero
    CHECK(eq32(hs.read_storage(addr, key0), evmc::bytes32{}));

    const auto* slots = hs.overflow_slots_for(addr);
    REQUIRE(slots != nullptr);
    auto z = slots->find(key0);
    REQUIRE(z != slots->end());  // RETAINED, not erased (the divergence)
    CHECK(eq32(z->second, evmc::bytes32{}));
    CHECK(slots->find(key1) != slots->end());
}

// destruct removes an account; revive-after-destruct in the same block restores it fresh.
TEST_CASE("HashState destruct removes an account; revive-after-destruct restores it",
          "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x50);

    hs.set_balance(addr, intx::uint256{1000});
    hs.set_nonce(addr, 3);
    CHECK(hs.get_balance(addr) == intx::uint256{1000});

    hs.destruct(addr);
    CHECK(hs.read_account(addr) == nullptr);          // gone
    CHECK(hs.get_balance(addr) == intx::uint256{0});  // gone -> zero
    CHECK(hs.is_deleted(addr));

    hs.set_balance(addr, intx::uint256{2000});  // revive in the same block
    CHECK(hs.read_account(addr) != nullptr);
    CHECK(hs.get_balance(addr) == intx::uint256{2000});
    CHECK(hs.get_nonce(addr) == 0u);  // nonce reset by revive
    CHECK_FALSE(hs.is_deleted(addr));
}

// EIP-158: a touched account left empty (0 nonce / 0 balance / empty code) is cleared by
// destruct_dead_among over the touched set.
TEST_CASE("HashState EIP-158 destruct_dead_among clears a touched empty account", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x60);

    hs.add_to_balance(addr, intx::uint256{0});  // touch, leaving a 0/0/empty account
    CHECK(hs.read_account(addr) != nullptr);     // present but empty
    CHECK(hs.is_empty_account(addr));
    CHECK(hs.is_dead(addr));

    hs.destruct_dead_among(hs.touched());
    CHECK(hs.read_account(addr) == nullptr);  // EIP-158 cleared it
    CHECK(hs.is_deleted(addr));
    CHECK(hs.unconfirmed_read_count() == 0u);  // empty-trie confirms the creation absent
}

// read_code FAIL-CLOSED: a derived account carries a non-empty code_hash whose bytes the
// witness omitted (find_code misses) -> read blank AND bump unconfirmed_read_count_.
TEST_CASE("HashState read_code fail-closed when the witness omitted the code", "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0x70);
    // make_test_account's code_hash is 0xC0+i+seed (non-empty); the code is never add_code'd.
    const Account acc = make_test_account(3, silkworm::kEmptyRoot);
    const Bytes leaf_val = acc.rlp(silkworm::kEmptyRoot);
    const evmc::bytes32 root = add_single_account(hs, addr, leaf_val);
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    const ByteView code = hs.read_code(addr);
    CHECK(code.empty());
    CHECK(hs.unconfirmed_read_count() > 0u);  // omitted code recorded (no silent empty-code)
}

// set_code stashes in-block created code; read_code resolves it, no fail-closed bump.
TEST_CASE("HashState set_code then read_code resolves in-block created code", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x80);
    const Bytes code = {0x60, 0x01, 0x60, 0x02, 0x01};
    hs.set_code(addr, ByteView{code.data(), code.size()});
    const ByteView got = hs.read_code(addr);
    REQUIRE(got.size() == code.size());
    CHECK(std::memcmp(got.data(), code.data(), code.size()) == 0);
    CHECK(hs.unconfirmed_read_count() == 0u);  // created code resolves cleanly
}

// find_or_create_account on a CONFIRMED-ABSENT key (empty trie): a fresh, usable record and
// NO unconfirmed read.
TEST_CASE("HashState find_or_create_account on a confirmed-absent key is fresh, no unconfirmed",
          "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x90);

    Account* pa = hs.find_or_create_account(addr);
    REQUIRE(pa != nullptr);  // never null
    CHECK(pa->deleted);      // materialized fresh (a subsequent write revives it)
    CHECK(hs.unconfirmed_read_count() == 0u);  // the empty trie proves absence
}

// find_or_create_account on a PRUNED-BOUNDARY key: a usable record is still returned, but the
// unprovable miss bumps unconfirmed_read_count_ so the accept gate rejects.
TEST_CASE("HashState find_or_create_account on a pruned-boundary key is usable but unconfirmed",
          "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0xA0);
    const evmc::bytes32 ah = keccak_addr(addr);
    const std::uint8_t first = static_cast<std::uint8_t>(ah.bytes[0] >> 4);
    const std::uint8_t other = static_cast<std::uint8_t>((first + 1) & 0xF);

    // A present leaf at another root-branch slot so the root itself exists in the store.
    const Key kP = key_with(other, 3, 5);
    const Bytes accP = account_leaf_value(1, silkworm::kEmptyRoot);
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{accP});
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});

    // A dangling (pruned) child ref at the slot the address's path descends into.
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<std::uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(first, ByteView{dangling.bytes, 32});
    root.set_child(other, ByteView{hP.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);           // pruned boundary, not a missing node
    REQUIRE(hs.unconfirmed_read_count() == 0u);  // reset by the build

    Account* pa = hs.find_or_create_account(addr);
    REQUIRE(pa != nullptr);                   // never null, even at a pruned boundary
    CHECK(hs.unconfirmed_read_count() > 0u);  // confirm_absent could not prove absence
}

// apply_code_diff contract creation WIPES pre-state storage via the storage_wiped_ flag
// (divergence b): the pre-state slot reads zero afterwards and has_storage goes false.
TEST_CASE("HashState apply_code_diff wipes storage on contract creation (divergence b)",
          "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0xB0);

    // Pre-state: a real account carrying a 1-slot storage trie.
    evmc::bytes32 slot_key{};
    slot_key.bytes[31] = 0xAB;
    evmc::bytes32 slot_val{};
    slot_val.bytes[31] = 0x77;
    const Bytes ev = encode_storage_value(slot_val);
    const auto spath = nibbles_of(keccak_slot(slot_key));
    const LeafNode sleaf = make_leaf(spath.data(), 64, ByteView{ev});
    const evmc::bytes32 sroot = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    const Bytes accv = account_leaf_value(5, sroot);
    const auto apath = nibbles_of(keccak_addr(addr));
    const LeafNode aleaf = make_leaf(apath.data(), 64, ByteView{accv});
    const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_leaf(aleaf)});
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    CHECK(eq32(hs.read_storage(addr, slot_key), slot_val));  // pre-state slot via built cache
    CHECK(hs.has_storage(addr));

    Account* pa = hs.find_or_create_account(addr);
    const Bytes code = {0x60, 0x01};  // plain bytecode, not an EIP-7702 delegation
    hs.apply_code_diff(addr, *pa, evmc::bytes(code.data(), code.size()));

    CHECK(hs.storage_wiped(addr));                                  // divergence-b flag set
    CHECK(eq32(hs.read_storage(addr, slot_key), evmc::bytes32{}));  // pre-state slot now zero
    CHECK_FALSE(hs.has_storage(addr));
}

// Wiped accounts return before the built cache.
TEST_CASE("HashState read_storage of a wiped account never reaches the absent-slot memo",
          "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0xB4);

    // p: present, p+1: pruned, p+2, p+3: empty.
    evmc::bytes32 present_key{};
    present_key.bytes[31] = 0xAB;
    const auto ppath = nibbles_of(keccak_slot(present_key));
    const uint8_t p = ppath[0];
    const auto key_at = [](uint8_t first) {
        evmc::bytes32 k{};
        for (unsigned b = 1; b < 0x10000; ++b) {
            k.bytes[30] = static_cast<uint8_t>(b >> 8);
            k.bytes[31] = static_cast<uint8_t>(b & 0xFF);
            if (nibbles_of(keccak_slot(k))[0] == first) return k;
        }
        FAIL("no slot key hashes to that nibble");
        return k;
    };
    const uint8_t p1 = static_cast<uint8_t>((p + 1) & 0xF);
    const evmc::bytes32 pruned_key = key_at(p1);
    const evmc::bytes32 cold_key = key_at(static_cast<uint8_t>((p + 2) & 0xF));
    const evmc::bytes32 cold_key2 = key_at(static_cast<uint8_t>((p + 3) & 0xF));

    evmc::bytes32 slot_val{};
    slot_val.bytes[31] = 0x77;
    const Bytes ev = encode_storage_value(slot_val);
    const LeafNode sleaf = make_leaf(ppath.data() + 1, 63, ByteView{ev});
    const evmc::bytes32 hsl = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode sroot;
    sroot.set_child(p, ByteView{hsl.bytes, 32});
    sroot.set_child(p1, ByteView{dangling.bytes, 32});
    const evmc::bytes32 storage_root = hs.add_node(ByteView{zilkworm::encode_branch(sroot)});
    const Bytes accv = account_leaf_value(5, storage_root);
    const evmc::bytes32 root = add_single_account(hs, addr, accv);
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    // Before the wipe: cold entered, pruned recorded.
    CHECK(eq32(hs.read_storage(addr, present_key), slot_val));
    CHECK(eq32(hs.read_storage(addr, cold_key), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 1u);
    CHECK(hs.unconfirmed_read_count() == 0u);
    CHECK(eq32(hs.read_storage(addr, pruned_key), evmc::bytes32{}));
    CHECK(hs.unconfirmed_read_count() == 1u);

    Account* pa = hs.find_or_create_account(addr);
    const Bytes code = {0x60, 0x01};  // plain bytecode, not an EIP-7702 delegation
    hs.apply_code_diff(addr, *pa, evmc::bytes(code.data(), code.size()));
    REQUIRE(hs.storage_wiped(addr));

    // After: nothing reaches the memo or walk.
    CHECK(eq32(hs.read_storage(addr, present_key), evmc::bytes32{}));
    CHECK(eq32(hs.read_storage(addr, cold_key), evmc::bytes32{}));
    CHECK(eq32(hs.read_storage(addr, pruned_key), evmc::bytes32{}));
    CHECK(eq32(hs.read_storage(addr, cold_key2), evmc::bytes32{}));
    CHECK(hs.absent_slot_count() == 1u);
    CHECK(hs.unconfirmed_read_count() == 1u);
}

// apply_code_diff on an EIP-7702 delegation is EXEMPT from the storage wipe (mirrors
// direct_state.cpp:409-415): the flag stays clear and pre-state storage is preserved.
TEST_CASE("HashState apply_code_diff exempts an EIP-7702 delegation from the storage wipe",
          "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0xC0);

    evmc::bytes32 slot_key{};
    slot_key.bytes[31] = 0xCD;
    evmc::bytes32 slot_val{};
    slot_val.bytes[31] = 0x55;
    const Bytes ev = encode_storage_value(slot_val);
    const auto spath = nibbles_of(keccak_slot(slot_key));
    const LeafNode sleaf = make_leaf(spath.data(), 64, ByteView{ev});
    const evmc::bytes32 sroot = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    const Bytes accv = account_leaf_value(6, sroot);
    const auto apath = nibbles_of(keccak_addr(addr));
    const LeafNode aleaf = make_leaf(apath.data(), 64, ByteView{accv});
    const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_leaf(aleaf)});
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);

    Bytes deleg = {0xef, 0x01, 0x00};  // EIP-7702 delegation prefix
    for (int i = 0; i < 20; ++i) deleg.push_back(0x11);
    Account* pa = hs.find_or_create_account(addr);
    hs.apply_code_diff(addr, *pa, evmc::bytes(deleg.data(), deleg.size()));

    CHECK_FALSE(hs.storage_wiped(addr));                     // delegation exempt from wipe
    CHECK(eq32(hs.read_storage(addr, slot_key), slot_val));  // storage preserved
}

// Clearing an EIP-7702 delegation sets empty code; the authority's storage survives it, as
// DirectState::apply_code_diff keeps it. The wipe belongs to contract creation alone.
TEST_CASE("HashState apply_code_diff keeps the storage of a cleared EIP-7702 delegation",
          "[hash_state]") {
    HashState hs;
    const evmc::address addr = s2_addr(0xC1);

    evmc::bytes32 slot_key{};
    slot_key.bytes[31] = 0x01;
    evmc::bytes32 slot_val{};
    slot_val.bytes[31] = 0x2a;
    const Bytes ev = encode_storage_value(slot_val);
    const auto spath = nibbles_of(keccak_slot(slot_key));
    const LeafNode sleaf = make_leaf(spath.data(), 64, ByteView{ev});
    const evmc::bytes32 sroot = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    const Bytes accv = account_leaf_value(1, sroot);
    const auto apath = nibbles_of(keccak_addr(addr));
    const LeafNode aleaf = make_leaf(apath.data(), 64, ByteView{accv});
    const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_leaf(aleaf)});
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);

    Account* pa = hs.find_or_create_account(addr);
    hs.apply_code_diff(addr, *pa, evmc::bytes{});

    CHECK(std::memcmp(pa->code_hash, silkworm::kEmptyHash.bytes, 32) == 0);
    CHECK(pa->code_store_len == 0);
    CHECK_FALSE(hs.storage_wiped(addr));
    CHECK(hs.has_storage(addr));
    CHECK(eq32(hs.read_storage(addr, slot_key), slot_val));
}

// A secured trie path is the 64-nibble hashed key: a leaf whose path runs past it makes the
// witness malformed, and tests-zkevm v21.0.6 rejects the block (test_witness_state_rejects_overlength_
// secured_trie_path). The sweep used to skip such a node silently.
TEST_CASE("HashState build_state_from_trie rejects a trie path longer than the key", "[hash_state]") {
    HashState hs;
    std::array<uint8_t, 66> nib{};
    nib.fill(0x3);
    const Bytes accv = account_leaf_value(1, silkworm::kEmptyRoot);
    const LeafNode leaf = make_leaf(nib.data(), 65, ByteView{accv});
    const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_leaf(leaf)});
    CHECK(hs.build_state_from_trie(root) == HashState::BuildStatus::kMalformed);
}

// apply_state_diff drives the whole mutation surface: modified account (nonce/balance/storage)
// then a deleted account.
TEST_CASE("HashState apply_state_diff applies modified and deleted accounts", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0xD0);

    evmc::bytes32 skey{};
    skey.bytes[31] = 0x09;
    evmc::bytes32 sval{};
    sval.bytes[31] = 0x42;

    evmone::state::StateDiff diff;
    evmone::state::StateDiff::Entry e{};
    e.addr = addr;
    e.nonce = 4;
    e.balance = intx::uint256{777};
    e.modified_storage = {{skey, sval}};
    diff.modified_accounts.push_back(std::move(e));
    hs.apply_state_diff(diff);

    CHECK(hs.get_nonce(addr) == 4u);
    CHECK(hs.get_balance(addr) == intx::uint256{777});
    CHECK(eq32(hs.read_storage(addr, skey), sval));

    evmone::state::StateDiff del;
    del.deleted_accounts.push_back(addr);
    hs.apply_state_diff(del);
    CHECK(hs.read_account(addr) == nullptr);  // destructed
}

// subtract_from_balance / add_to_balance arithmetic over the overlay.
TEST_CASE("HashState subtract_from_balance and add_to_balance", "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0xE0);
    hs.set_balance(addr, intx::uint256{1000});
    hs.subtract_from_balance(addr, intx::uint256{250});
    CHECK(hs.get_balance(addr) == intx::uint256{750});
    hs.add_to_balance(addr, intx::uint256{50});
    CHECK(hs.get_balance(addr) == intx::uint256{800});
}

// HashStateView forwards each StateView call faithfully to the address-keyed readers.
// See docs/hashstate.md, "Per-transaction read view".

namespace {

// Build a single-slot storage trie keyed by keccak256(slot_key) (the trie path the
// address-keyed read_storage hashes to): a branch root -> one hash-referenced 63-nibble leaf
// hanging under the slot-hash's first nibble, mirroring the storage-sweep fixture above.
// Returns the storage root so an account leaf can point at it.
[[nodiscard]] evmc::bytes32 add_single_storage_slot(HashState& hs, const evmc::bytes32& slot_key,
                                                    const evmc::bytes32& word) {
    const auto snib = nibbles_of(keccak_slot(slot_key));
    const Bytes ev = encode_storage_value(word);
    const LeafNode sleaf = make_leaf(&snib[1], 63, ByteView{ev});
    const evmc::bytes32 hleaf = hs.add_node(ByteView{zilkworm::encode_leaf(sleaf)});
    BranchNode sroot;
    sroot.set_child(snib[0], ByteView{hleaf.bytes, 32});
    return hs.add_node(ByteView{zilkworm::encode_branch(sroot)});
}

// An account-leaf RLP ([nonce, balance, storage_root, code_hash]) with FULLY chosen fields —
// account_leaf_value hard-codes a synthetic (non-empty) code_hash, but the view's code and
// empty-account cases need a real code_hash (keccak of the added code) or the empty hash.
[[nodiscard]] Bytes account_leaf_full(uint64_t nonce, uint64_t balance_lo,
                                       const evmc::bytes32& storage_root,
                                       const evmc::bytes32& code_hash) {
    Account acc{};
    acc.nonce = nonce;
    std::memcpy(acc.balance, &balance_lo, sizeof(balance_lo));  // native-endian, rest zero
    std::memcpy(acc.code_hash, code_hash.bytes, 32);
    return acc.rlp(storage_root);
}

}  // namespace

// A read of code the witness omits is served when the block derives the same bytes: the
// authorizations' EIP-7702 markers are kept by hash before their transaction runs (processor.cpp),
// as evmone sets them inside it and a same-marker read there never reaches the state diff.
TEST_CASE("HashState note_created_code serves an omitted code by its hash", "[hash_state]") {
    Bytes marker = {0xef, 0x01, 0x00};
    for (int i = 0; i < 20; ++i) marker.push_back(0x42);
    const auto code_hash = std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{marker}));
    const evmc::address addr = s2_addr(0xC2);
    const auto build = [&](HashState& hs) {
        const Bytes accv = account_leaf_full(1, 0, silkworm::kEmptyRoot, code_hash);
        const auto apath = nibbles_of(keccak_addr(addr));
        const LeafNode aleaf = make_leaf(apath.data(), 64, ByteView{accv});
        const evmc::bytes32 root = hs.add_node(ByteView{zilkworm::encode_leaf(aleaf)});
        REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    };

    HashState omitted;
    build(omitted);
    CHECK(omitted.read_code(addr).empty());  // the witness has no such code: a gap
    CHECK(omitted.unconfirmed_read_count() == 1);

    HashState derived;
    derived.note_created_code(ByteView{marker});
    build(derived);
    CHECK(derived.read_code(addr) == ByteView{marker});
    CHECK(derived.unconfirmed_read_count() == 0);
}

// A present account reachable through the built cache: the view surfaces its nonce / balance /
// code_hash / has_storage, forwards get_account_code to the real witness code, forwards
// get_storage to the derived slot, and reads an untouched slot as zero — all with no
// unconfirmed read (every key is present in the witness).
TEST_CASE("HashStateView forwards a present account, storage, and code", "[hash_state][view]") {
    HashState hs;
    const evmc::address addr = s2_addr(0x40);

    // Real code -> its keccak is the account's code_hash, so read_code resolves via find_code.
    const Bytes code = {0x60, 0x00, 0x60, 0x00, 0xF3};  // PUSH1 0 PUSH1 0 RETURN
    const evmc::bytes32 chash = hs.add_code(ByteView{code});

    // One storage slot in the account's own storage trie.
    evmc::bytes32 slot_key{};
    for (std::size_t i = 0; i < 32; ++i) slot_key.bytes[i] = static_cast<uint8_t>(0x10u + i);
    evmc::bytes32 word{};
    for (std::size_t i = 0; i < 32; ++i) word.bytes[i] = static_cast<uint8_t>(0xA0u + i);
    const evmc::bytes32 storage_root = add_single_storage_slot(hs, slot_key, word);

    const uint64_t balance_lo = 0x0102030405060708ULL;
    const Bytes leaf_val = account_leaf_full(11, balance_lo, storage_root, chash);
    const evmc::bytes32 root = add_single_account(hs, addr, leaf_val);
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    HashStateView view{hs};

    const auto acc = view.get_account(addr);
    REQUIRE(acc.has_value());
    CHECK(acc->nonce == 11u);
    CHECK(acc->balance == intx::uint256{balance_lo});
    CHECK(eq32(acc->code_hash, chash));
    CHECK(acc->has_storage);  // non-empty storage_root

    const auto code_out = view.get_account_code(addr);
    REQUIRE(code_out.size() == code.size());
    CHECK(std::memcmp(code_out.data(), code.data(), code.size()) == 0);

    CHECK(eq32(view.get_storage(addr, slot_key), word));  // derived slot forwarded

    evmc::bytes32 absent_slot{};
    for (std::size_t i = 0; i < 32; ++i) absent_slot.bytes[i] = static_cast<uint8_t>(0xDDu - i);
    CHECK(eq32(view.get_storage(addr, absent_slot), evmc::bytes32{}));  // untouched slot -> zero

    CHECK(hs.unconfirmed_read_count() == 0u);  // every read hit or was confirmed empty
}

// A live account with the empty storage_root and the empty code hash: the view reports it
// present, has_storage=false, empty code, and every slot zero — none of which is a fault.
TEST_CASE("HashStateView reports a live empty account", "[hash_state][view]") {
    HashState hs;
    const evmc::address addr = s2_addr(0x50);

    const Bytes leaf_val = account_leaf_full(3, 500, silkworm::kEmptyRoot, silkworm::kEmptyHash);
    const evmc::bytes32 root = add_single_account(hs, addr, leaf_val);
    REQUIRE(hs.build_state_from_trie(root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    HashStateView view{hs};

    const auto acc = view.get_account(addr);
    REQUIRE(acc.has_value());
    CHECK(acc->nonce == 3u);
    CHECK(acc->balance == intx::uint256{500});
    CHECK(eq32(acc->code_hash, silkworm::kEmptyHash));
    CHECK_FALSE(acc->has_storage);  // empty storage_root, no overlay slot

    CHECK(view.get_account_code(addr).empty());  // empty code_hash -> empty, no fail-closed bump

    evmc::bytes32 any_slot{};
    any_slot.bytes[31] = 0x07;
    CHECK(eq32(view.get_storage(addr, any_slot), evmc::bytes32{}));

    CHECK(hs.unconfirmed_read_count() == 0u);  // empty storage_root needs no confirmation walk
}

// An address absent from a complete witness: get_account materializes a deleted record, so the
// view returns nullopt, and the empty-trie confirmation proves absence (no unconfirmed read).
TEST_CASE("HashStateView returns nullopt for a confirmed-absent account", "[hash_state][view]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);

    HashStateView view{hs};
    const evmc::address absent = s2_addr(0x60);

    CHECK_FALSE(view.get_account(absent).has_value());  // materialized deleted -> nullopt
    CHECK(view.get_account_code(absent).empty());
    evmc::bytes32 any_slot{};
    any_slot.bytes[31] = 0x01;
    CHECK(eq32(view.get_storage(absent, any_slot), evmc::bytes32{}));

    CHECK(hs.unconfirmed_read_count() == 0u);  // empty trie proves every key absent
}

// Gather overload of check_root_hashstate: the overlay-derived write set decides like the span.
// See docs/hashstate.md, "Accept check tests".

// The full gather path: a built account's FIELD change, a storage slot SET, a storage slot
// CLEARED-TO-ZERO, and a freshly CREATED account, all through the mutators. The gather overload
// must recompute a hand-built post-state root (canonical encoders, no GridMPT) and accept it,
// reject a tampered root, and decide identically to the hand-built span on the same writes.
TEST_CASE("check_root_hashstate gather overload reconstructs the overlay write set",
          "[hash_state][accept]") {
    HashState hs;

    // --- pre-state: ONE built account B carrying a ONE-slot storage trie (slot s_clear). ---
    const evmc::address aB = s2_addr(0x11);
    const uint64_t seedB = 21;

    evmc::bytes32 s_clear{};
    s_clear.bytes[31] = 0xC1;
    evmc::bytes32 v_clear_old{};
    for (int i = 0; i < 32; ++i) v_clear_old.bytes[i] = static_cast<uint8_t>(0x40 + i);
    const Bytes ev_clear = encode_storage_value(v_clear_old);
    const auto sclear_path = nibbles_of(keccak_slot(s_clear));
    const LeafNode sclear_leaf = make_leaf(sclear_path.data(), 64, ByteView{ev_clear});
    const evmc::bytes32 sr_B_pre = hs.add_node(ByteView{zilkworm::encode_leaf(sclear_leaf)});

    const Account accB = make_test_account(seedB, sr_B_pre);
    const Bytes leafB_pre_val = accB.rlp(sr_B_pre);
    const auto aB_path = nibbles_of(keccak_addr(aB));
    const LeafNode leafB_pre = make_leaf(aB_path.data(), 64, ByteView{leafB_pre_val});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leafB_pre)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.unconfirmed_read_count() == 0u);
    CHECK(eq32(hs.read_storage(aB, s_clear), v_clear_old));  // pre-state slot via built cache
    CHECK(hs.get_nonce(aB) == seedB);

    // --- pick a created account C whose addr_hash starts on a DIFFERENT root-branch nibble than
    // B, so the post-state account trie is a clean two-leaf branch (hand-computable). ---
    const uint8_t nibB0 = static_cast<uint8_t>(keccak_addr(aB).bytes[0] >> 4);
    evmc::address aC{};
    bool found_c = false;
    for (int t = 1; t < 256 && !found_c; ++t) {
        const evmc::address cand = s2_addr(static_cast<uint8_t>(t));
        if (cand == aB) continue;
        if (static_cast<uint8_t>(keccak_addr(cand).bytes[0] >> 4) != nibB0) {
            aC = cand;
            found_c = true;
        }
    }
    REQUIRE(found_c);
    const uint8_t nibC0 = static_cast<uint8_t>(keccak_addr(aC).bytes[0] >> 4);

    // --- writes through the S2 mutators. ---
    const uint64_t newNonceB = 210;
    hs.set_nonce(aB, newNonceB);  // (1) built-account FIELD change

    evmc::bytes32 s_new{};
    s_new.bytes[31] = 0x2E;
    evmc::bytes32 v_new{};
    for (int i = 0; i < 32; ++i) v_new.bytes[i] = static_cast<uint8_t>(0x90 + i);
    Account* paB = hs.find_or_create_account(aB);
    hs.set_storage_slot(aB, *paB, s_new, v_new);             // (2) storage slot SET (non-zero)
    hs.set_storage_slot(aB, *paB, s_clear, evmc::bytes32{});  // (3) storage slot CLEARED to zero

    const intx::uint256 balC{123456};
    const uint64_t nonceC = 9;
    hs.set_balance(aC, balC);  // (4) CREATED account
    hs.set_nonce(aC, nonceC);

    // The overlay now reflects every write; no read poisoned the fail-closed counters.
    CHECK(hs.get_nonce(aB) == newNonceB);
    CHECK(hs.get_balance(aB) == intx::uint256{0xAABBCCDD00000000ULL + seedB});
    CHECK(eq32(hs.read_storage(aB, s_new), v_new));
    CHECK(eq32(hs.read_storage(aB, s_clear), evmc::bytes32{}));  // cleared reads zero
    CHECK(hs.get_balance(aC) == balC);
    CHECK(hs.get_nonce(aC) == nonceC);
    REQUIRE(hs.created_accounts().size() == 2u);  // exactly B and C entered the overlay
    REQUIRE(hs.overflow_slots_for(aB) != nullptr);
    CHECK(hs.overflow_slots_for(aB)->size() == 2u);  // s_new + s_clear (zero RETAINED)
    REQUIRE(hs.unconfirmed_read_count() == 0u);
    REQUIRE(hs.missing_count() == 0u);

    // --- INDEPENDENT oracle: hand-compute the post-state root with the canonical encoders. ---
    // B's new storage trie: s_clear deleted, s_new inserted -> single leaf s_new.
    const Bytes ev_new = encode_storage_value(v_new);
    const auto snew_path = nibbles_of(keccak_slot(s_new));
    const LeafNode snew_leaf = make_leaf(snew_path.data(), 64, ByteView{ev_new});
    const evmc::bytes32 sr_B_new = keccak32(ByteView{zilkworm::encode_leaf(snew_leaf)});
    REQUIRE_FALSE(eq32(sr_B_new, sr_B_pre));  // the storage writes moved B's storage root

    // B' account leaf (nonce changed, storage root folded).
    Account accB_new = make_test_account(seedB, sr_B_pre);
    accB_new.nonce = newNonceB;
    const Bytes leafB_new_val = accB_new.rlp(sr_B_new);
    const LeafNode leafB_new = make_leaf(&aB_path[1], 63, ByteView{leafB_new_val});
    const evmc::bytes32 hB_new = keccak32(ByteView{zilkworm::encode_leaf(leafB_new)});

    // C account leaf (created: nonce/balance set, EMPTY code + EMPTY storage root — the case
    // the gather must seed as kEmptyRoot, not zero).
    Account accC{};
    accC.nonce = nonceC;
    std::memcpy(accC.balance, &balC, 32);  // native-endian, mirroring store_be_u256 (memcpy)
    std::memcpy(accC.code_hash, silkworm::kEmptyHash.bytes, 32);
    const Bytes leafC_val = accC.rlp(silkworm::kEmptyRoot);
    const auto aC_path = nibbles_of(keccak_addr(aC));
    const LeafNode leafC = make_leaf(&aC_path[1], 63, ByteView{leafC_val});
    const evmc::bytes32 hC = keccak32(ByteView{zilkworm::encode_leaf(leafC)});

    // post-state account root: a two-child branch (B and C differ on the first nibble).
    BranchNode post;
    post.set_child(nibB0, ByteView{hB_new.bytes, 32});
    post.set_child(nibC0, ByteView{hC.bytes, 32});
    const Bytes post_rlp{zilkworm::encode_branch(post)};
    const evmc::bytes32 expected_root = keccak32(ByteView{post_rlp});
    REQUIRE_FALSE(eq32(expected_root, prev_root));

    // --- (A) the GATHER overload accepts the hand-built root and rejects a tampered one. ---
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, expected_root));
    evmc::bytes32 bad_root = expected_root;
    bad_root.bytes[0] = static_cast<uint8_t>(bad_root.bytes[0] ^ 0xFF);
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, bad_root));

    // --- (B) the hand-built span-based version, on the SAME writes, must DECIDE IDENTICALLY. ---
    std::vector<zilkworm::TrieNodeFlat> b_storage;  // sorted by slot_hash; outlives the calls
    {
        auto& n1 = b_storage.emplace_back(keccak_slot(s_new));
        n1.current_off = 40;
        n1.current_len = static_cast<uint8_t>(ev_new.size());
        std::memcpy(n1.buf + 40, ev_new.data(), ev_new.size());
        auto& n0 = b_storage.emplace_back(keccak_slot(s_clear));
        n0.current_off = 40;
        n0.buf[40] = 0x80;  // zero value -> 0x80 delete
        n0.current_len = 1;
        std::sort(b_storage.begin(), b_storage.end());
    }
    std::vector<HashStateAccountWrite> manual;
    manual.push_back({keccak_addr(aB), sr_B_pre,
                      std::span<const zilkworm::TrieNodeFlat>{b_storage}, hs.read_account(aB)});
    manual.push_back({keccak_addr(aC), silkworm::kEmptyRoot, {}, hs.read_account(aC)});
    std::sort(manual.begin(), manual.end(),
              [](const HashStateAccountWrite& a, const HashStateAccountWrite& b) {
                  return std::memcmp(a.addr_hash.bytes, b.addr_hash.bytes, 32) < 0;
              });
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, manual, expected_root));   // == gather accept
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, manual, bad_root));  // == gather reject
}

// A run that leaves unconfirmed_read_count() > 0 must REJECT through the gather overload too:
// the accept gate is (root match && missing==0 && unconfirmed==0), and the gather delegates to
// the same gate. Mirror of the span-based unconfirmed case (above), driven end-to-end through a
// mutator + the gather: the SAME writes + correct root accept BEFORE a build-skipped read and
// reject AFTER it, with the gather and hand-built span agreeing at both points.
TEST_CASE("check_root_hashstate gather overload rejects when a read was left unconfirmed",
          "[hash_state][accept]") {
    HashState hs;

    evmc::bytes32 absent_root{};  // W's storage_root; its node is never add_node'd
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);

    const evmc::address aW = s2_addr(0x33);
    const uint64_t seedW = 5;
    const Account accW = make_test_account(seedW, absent_root);
    const Bytes leafW_val = accW.rlp(absent_root);
    const auto aW_path = nibbles_of(keccak_addr(aW));
    const LeafNode leafW = make_leaf(aW_path.data(), 64, ByteView{leafW_val});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);              // build-time skip of an absent storage root
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // Write W's nonce (storage untouched; absent_root carried through as the frozen seed).
    const uint64_t newNonceW = 55;
    hs.set_nonce(aW, newNonceW);

    // Oracle: single-leaf account trie -> root == keccak(encode_leaf(new W leaf)).
    Account accW_new = make_test_account(seedW, absent_root);
    accW_new.nonce = newNonceW;
    const Bytes leafW2_val = accW_new.rlp(absent_root);
    const LeafNode leafW2 = make_leaf(aW_path.data(), 64, ByteView{leafW2_val});
    const evmc::bytes32 expected_root = keccak32(ByteView{zilkworm::encode_leaf(leafW2)});

    // Hand-built span on the same single write (no storage updates -> seed carried as the leaf's
    // storage_root), for the before/after agreement cross-check.
    std::vector<HashStateAccountWrite> manual;
    manual.push_back({keccak_addr(aW), absent_root, {}, hs.read_account(aW)});

    // BEFORE the read: both counters zero, correct root -> gather AND span both ACCEPT.
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, expected_root));            // gather
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, manual, expected_root));    // span (agrees)

    // Read into W's build-skipped storage trie: confirmation hits the absent root -> unconfirmed.
    evmc::bytes32 probe_slot{};
    probe_slot.bytes[31] = 0x77;
    (void)hs.get_storage(keccak_addr(aW), keccak_slot(probe_slot));
    REQUIRE(hs.unconfirmed_read_count() > 0u);
    REQUIRE(hs.missing_count() == 0u);

    // AFTER the read: same writes, same (correct) root -> gather AND span both REJECT.
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, expected_root));          // gather
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, manual, expected_root));  // span (agrees)
}

// Reads enter the overlay unmodified (copy-on-write).
TEST_CASE("check_root_hashstate gather overload skips a built account the block only read",
          "[hash_state][accept]") {
    HashState hs;

    // Pre-state: a single-leaf trie holding R.
    const evmc::address aR = s2_addr(0x71);
    const uint64_t seedR = 71;
    const Account accR = make_test_account(seedR, silkworm::kEmptyRoot);
    const Bytes leafR_val = accR.rlp(silkworm::kEmptyRoot);
    const auto aR_path = nibbles_of(keccak_addr(aR));
    const LeafNode leafR = make_leaf(aR_path.data(), 64, ByteView{leafR_val});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leafR)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);
    REQUIRE(hs.created_accounts().empty());  // nothing loaded yet

    HashStateView view{hs};
    const auto seen = view.get_account(aR);
    REQUIRE(seen.has_value());
    CHECK(seen->nonce == seedR);
    REQUIRE(hs.created_accounts().size() == 1u);
    {
        const auto it = hs.created_accounts().find(aR);
        REQUIRE(it != hs.created_accounts().end());
        CHECK_FALSE(it->second.modified);
        CHECK_FALSE(it->second.deleted);
        // Skip premise: no wipe, no slot writes.
        CHECK_FALSE(hs.storage_wiped(aR));
        CHECK((hs.overflow_slots_for(aR) == nullptr || hs.overflow_slots_for(aR)->empty()));
    }
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // (a) Read only: nothing folded.
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
    evmc::bytes32 bad_root = prev_root;
    bad_root.bytes[0] = static_cast<uint8_t>(bad_root.bytes[0] ^ 0xFF);
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, bad_root));
    CHECK(hs.unconfirmed_read_count() == 0u);

    // (b) Mutated: the record is folded.
    const uint64_t newNonceR = 710;
    hs.set_nonce(aR, newNonceR);
    CHECK(hs.created_accounts().find(aR)->second.modified);
    Account accR_new = make_test_account(seedR, silkworm::kEmptyRoot);
    accR_new.nonce = newNonceR;
    const Bytes leafR2_val = accR_new.rlp(silkworm::kEmptyRoot);
    const LeafNode leafR2 = make_leaf(aR_path.data(), 64, ByteView{leafR2_val});
    const evmc::bytes32 expected_root = keccak32(ByteView{zilkworm::encode_leaf(leafR2)});
    REQUIRE_FALSE(eq32(expected_root, prev_root));
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, expected_root));
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
}

// The gather's skip rests on these flags.
TEST_CASE("every HashState mutator that changes a built account sets modified or deleted",
          "[hash_state][accept]") {
    const evmc::address addr = s2_addr(0x7A);
    const Account acc = make_test_account(7, silkworm::kEmptyRoot);
    const Bytes val = acc.rlp(silkworm::kEmptyRoot);
    const auto path = nibbles_of(keccak_addr(addr));
    const LeafNode leaf = make_leaf(path.data(), 64, ByteView{val});

    evmc::bytes32 skey{};
    skey.bytes[31] = 0x05;
    evmc::bytes32 sval{};
    sval.bytes[31] = 0x06;
    const Bytes code{0x60, 0x00, 0x60, 0x00, 0xfd};
    intx::uint256 acc_balance;
    std::memcpy(&acc_balance, acc.balance, 32);

    const auto changed_by = [&](const char* name, auto&& mutate) {
        CAPTURE(name);
        HashState hs;
        const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_leaf(leaf)});
        REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
        HashStateView view{hs};
        REQUIRE(view.get_account(addr).has_value());
        const auto& rec = hs.created_accounts().find(addr)->second;
        REQUIRE_FALSE(rec.modified);
        REQUIRE_FALSE(rec.deleted);
        mutate(hs);
        CHECK((rec.modified || rec.deleted));
    };

    changed_by("set_balance", [&](HashState& hs) { hs.set_balance(addr, intx::uint256{12345}); });
    changed_by("add_to_balance", [&](HashState& hs) { hs.add_to_balance(addr, intx::uint256{1}); });
    changed_by("subtract_from_balance",
               [&](HashState& hs) { hs.subtract_from_balance(addr, intx::uint256{1}); });
    changed_by("set_nonce", [&](HashState& hs) { hs.set_nonce(addr, 99); });
    changed_by("set_code", [&](HashState& hs) { hs.set_code(addr, ByteView{code}); });
    changed_by("destruct", [&](HashState& hs) { hs.destruct(addr); });
    changed_by("apply_state_diff nonce", [&](HashState& hs) {
        evmone::state::StateDiff diff;
        evmone::state::StateDiff::Entry e{};
        e.addr = addr;
        e.nonce = 8;
        e.balance = acc_balance;
        diff.modified_accounts.push_back(std::move(e));
        hs.apply_state_diff(diff);
    });
    changed_by("apply_state_diff storage only", [&](HashState& hs) {
        evmone::state::StateDiff diff;
        evmone::state::StateDiff::Entry e{};
        e.addr = addr;
        e.nonce = acc.nonce;
        e.balance = acc_balance;
        e.modified_storage = {{skey, sval}};
        diff.modified_accounts.push_back(std::move(e));
        hs.apply_state_diff(diff);
    });
    changed_by("apply_state_diff code", [&](HashState& hs) {
        evmone::state::StateDiff diff;
        evmone::state::StateDiff::Entry e{};
        e.addr = addr;
        e.nonce = acc.nonce;
        e.balance = acc_balance;
        e.code = evmc::bytes{code.data(), code.size()};
        diff.modified_accounts.push_back(std::move(e));
        hs.apply_state_diff(diff);
    });
    changed_by("apply_state_diff cleared delegation", [&](HashState& hs) {
        evmone::state::StateDiff diff;
        evmone::state::StateDiff::Entry e{};
        e.addr = addr;
        e.nonce = acc.nonce;
        e.balance = acc_balance;
        e.code = evmc::bytes{};
        diff.modified_accounts.push_back(std::move(e));
        hs.apply_state_diff(diff);
    });
    changed_by("apply_state_diff deletion", [&](HashState& hs) {
        evmone::state::StateDiff diff;
        diff.deleted_accounts.push_back(addr);
        hs.apply_state_diff(diff);
    });
}

// The delete branch precedes the read-only skip.
TEST_CASE("check_root_hashstate gather overload deletes a built account read then destructed",
          "[hash_state][accept]") {
    HashState hs;

    // Pre-state: R, D under different root slots.
    const evmc::address aR = s2_addr(0x72);
    const uint8_t nibR0 = static_cast<uint8_t>(keccak_addr(aR).bytes[0] >> 4);
    evmc::address aD{};
    bool found_d = false;
    for (int t = 1; t < 256 && !found_d; ++t) {
        const evmc::address cand = s2_addr(static_cast<uint8_t>(t));
        if (cand == aR) continue;
        if (static_cast<uint8_t>(keccak_addr(cand).bytes[0] >> 4) != nibR0) {
            aD = cand;
            found_d = true;
        }
    }
    REQUIRE(found_d);
    const uint8_t nibD0 = static_cast<uint8_t>(keccak_addr(aD).bytes[0] >> 4);

    const Account accR = make_test_account(72, silkworm::kEmptyRoot);
    const Bytes leafR_val = accR.rlp(silkworm::kEmptyRoot);
    const auto aR_path = nibbles_of(keccak_addr(aR));
    const LeafNode leafR = make_leaf(&aR_path[1], 63, ByteView{leafR_val});
    const evmc::bytes32 hR = hs.add_node(ByteView{zilkworm::encode_leaf(leafR)});
    const Account accD = make_test_account(73, silkworm::kEmptyRoot);
    const Bytes leafD_val = accD.rlp(silkworm::kEmptyRoot);
    const auto aD_path = nibbles_of(keccak_addr(aD));
    const LeafNode leafD = make_leaf(&aD_path[1], 63, ByteView{leafD_val});
    const evmc::bytes32 hD = hs.add_node(ByteView{zilkworm::encode_leaf(leafD)});
    BranchNode root;
    root.set_child(nibR0, ByteView{hR.bytes, 32});
    root.set_child(nibD0, ByteView{hD.bytes, 32});
    const evmc::bytes32 prev_root = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    REQUIRE(hs.build_state_from_trie(prev_root) == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    HashStateView view{hs};
    REQUIRE(view.get_account(aR).has_value());
    REQUIRE(view.get_account(aD).has_value());
    hs.destruct(aD);
    REQUIRE(hs.created_accounts().size() == 2u);
    CHECK_FALSE(hs.created_accounts().find(aR)->second.modified);  // skipped by the gather
    CHECK(hs.created_accounts().find(aD)->second.deleted);         // folded as a delete
    CHECK(hs.read_account(aD) == nullptr);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // Oracle: the branch collapses to R alone.
    const LeafNode leafR_post = make_leaf(aR_path.data(), 64, ByteView{leafR_val});
    const evmc::bytes32 expected_root = keccak32(ByteView{zilkworm::encode_leaf(leafR_post)});
    REQUIRE_FALSE(eq32(expected_root, prev_root));
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, expected_root));
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, prev_root));  // the delete is not lost
}


// Skipping real read-only records keeps the root.
TEST_CASE("slib real sample: folding the accounts the block only read leaves the root unchanged",
          "[hash_state][slib][accept]") {
    const Bytes blob = hex_to_bytes(slib_sample::kBlobHex);
    const auto dec = zilkworm::decode_stateless_input(ByteView{blob});
    REQUIRE(dec.has_value());
    REQUIRE_FALSE(dec->headers.empty());
    const auto payload = zilkworm::decode_slib_payload(dec->new_payload_request);
    REQUIRE(payload.has_value());
    const auto block = zilkworm::slib_payload_block(*payload);
    REQUIRE(block.has_value());
    silkworm::BlockHeader parent;
    ByteView hv{dec->headers.back()};
    REQUIRE(silkworm::rlp::decode(hv, parent));
    const evmc::bytes32 prev_root = parent.state_root;

    HashState hs;
    const auto res = zilkworm::run_slib(ByteView{blob}, hs, prev_root);
    REQUIRE(res.has_value());
    REQUIRE(res->status == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    // Every account the payload names, BAL included.
    std::vector<evmc::address> candidates{block->header.beneficiary};
    for (const auto& tx : block->transactions) {
        if (const auto sender = tx.sender()) candidates.push_back(*sender);
        if (tx.to) candidates.push_back(*tx.to);
    }
    for (const auto& w : payload->withdrawals) candidates.push_back(w.address);
    ByteView bal = payload->block_access_list;
    const auto bal_list = silkworm::rlp::decode_header(bal);
    REQUIRE((bal_list && bal_list->list && bal_list->payload_length == bal.size()));
    while (!bal.empty()) {
        const auto entry = silkworm::rlp::decode_header(bal);
        REQUIRE((entry && entry->list && entry->payload_length <= bal.size()));
        ByteView fields = bal.substr(0, entry->payload_length);
        bal.remove_prefix(entry->payload_length);
        const auto addr = silkworm::rlp::decode_header(fields);
        REQUIRE((addr && !addr->list && addr->payload_length == 20u));
        evmc::address a;
        std::memcpy(a.bytes, fields.data(), 20);
        candidates.push_back(a);
    }
    // Absent ones would leave an unconfirmed read.
    std::vector<evmc::address> addrs;
    for (const auto& a : candidates) {
        if (hs.find_built_account(keccak_addr(a)) == nullptr) continue;
        if (std::find(addrs.begin(), addrs.end(), a) == addrs.end()) addrs.push_back(a);
    }
    REQUIRE(addrs.size() >= 2u);

    HashStateView view{hs};
    for (const auto& a : addrs) REQUIRE(view.get_account(a).has_value());
    REQUIRE(hs.unconfirmed_read_count() == 0u);
    REQUIRE(hs.created_accounts().size() == addrs.size());
    for (const auto& [addr, acc] : hs.created_accounts()) {
        CHECK_FALSE(acc.modified);
        CHECK_FALSE(acc.deleted);
    }

    const auto gather_updates = [&hs](bool modified_only) {
        std::vector<zilkworm::TrieNodeFlat> updates;
        for (const auto& [addr, acc] : hs.created_accounts()) {
            if (modified_only && !acc.modified) continue;
            auto& node = updates.emplace_back(keccak_addr(addr));
            evmc::bytes32 storage_root{};
            std::memcpy(storage_root.bytes, acc.storage_root, 32);
            node.current_off = 0;
            node.current_len = acc.rlp_into(node.buf, storage_root);
        }
        std::sort(updates.begin(), updates.end());
        return updates;
    };
    const auto fold = [&hs, &prev_root](const std::vector<zilkworm::TrieNodeFlat>& updates) {
        zilkworm::GridMPT<true, HashState> acc_trie(hs, prev_root);
        const evmc::bytes32 root = acc_trie.calc_root_from_updates({updates.data(), updates.size()});
        CHECK(acc_trie.missing_count() == 0u);
        return root;
    };

    {
        const auto all = gather_updates(false);
        REQUIRE(all.size() == addrs.size());
        REQUIRE(gather_updates(true).empty());
        CHECK(eq32(fold(all), prev_root));
        CHECK(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
        evmc::bytes32 bad_root = prev_root;
        bad_root.bytes[0] = static_cast<std::uint8_t>(bad_root.bytes[0] ^ 0x01);
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, bad_root));
    }

    const auto* first = hs.read_account(addrs[0]);
    REQUIRE(first != nullptr);
    hs.set_nonce(addrs[0], first->nonce + 1);
    {
        const auto all = gather_updates(false);
        const auto modified = gather_updates(true);
        REQUIRE(all.size() == addrs.size());
        REQUIRE(modified.size() == 1u);
        const evmc::bytes32 root_mod = fold(modified);
        CHECK(eq32(fold(all), root_mod));
        CHECK_FALSE(eq32(root_mod, prev_root));
        CHECK(zilkworm::check_root_hashstate(hs, prev_root, root_mod));
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
    }
    CHECK(hs.unconfirmed_read_count() == 0u);
}
