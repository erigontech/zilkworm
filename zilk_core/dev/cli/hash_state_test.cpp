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
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/state_zz/slib_input.hpp>  // decode/parse/run_slib (the SSZ front-end)
#include <zilk_core/core/trie_zz/mpt.hpp>        // GridMPT<DeletionEnabled, StateT>, TrieNodeFlat
#include <zilk_core/core/trie_zz/rlp_sw.hpp>     // encode_leaf/branch/ext + node types
#include <zilk_core/core/types_zz/account.hpp>   // Account (leaf-value encode/decode target)
#include <zilk_core/dev/check_root_hashstate.hpp>  // check_root_hashstate + HashStateAccountWrite

#include "slib_sample_fixture.hpp"  // real tests-zkevm@v0.8.0 statelessInputBytes sample

using zilkworm::Account;
using zilkworm::BranchNode;
using zilkworm::ByteView;
using zilkworm::Bytes;
using zilkworm::ExtensionNode;
using zilkworm::HashIndex;
using zilkworm::HashState;
using zilkworm::HashStateView;
using zilkworm::hash_key8;
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

// The raw-pointer find_node_rlp (the form the trie sweep and the confirmation walk use on a
// child hash ref inside node RLP) is the same probe as the bytes32 form: the same view on a
// hit and a miss on a never-added hash, from an unaligned pointer.
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

    HashIndex<32, &hash_key8> probe{kExpectedNodes};  // identical capacity()/mask as hs.node_index_

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

    // The full-key compare gate routes each colliding lookup to its OWN payload.
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

// reserve_stores sizes the stores for the counts the input announces before the first add
// (the slib parser's path), and the borrowed adds that follow dedupe by content with the
// FIRST view kept: one probe inserts or finds the hash present, and a repeat is the same
// bytes under the same hash.
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

    // A repeat from a different buffer with the same content is deduped, and the view added
    // first stays indexed.
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

    // A later reserve_stores on stores that already hold entries changes nothing.
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

// S1: HashState provides the block-header side of the state interface (the silkworm::
// BlockState base) mirroring DirectState. insert_header records a header under its keccak
// hash (read_header) and in a block-number-sorted table (get_block_hash / BLOCKHASH);
// read_body and total_difficulty are the DirectState stubs. Headers are inserted out of
// order to exercise insert_header's sorted-insertion into created_block_hashes_, and one
// header is the genesis (number 0).
TEST_CASE("HashState header store: read_header / get_block_hash round-trip", "[hash_state]") {
    HashState hs;

    auto make_header = [](uint64_t number, uint8_t tag) {
        silkworm::BlockHeader h;
        h.number = number;
        h.gas_limit = 30'000'000;
        h.parent_hash.bytes[0] = tag;  // perturb content so each header's RLP hash is unique
        return h;
    };

    const silkworm::BlockHeader genesis = make_header(0, 0x00);  // genesis insert
    const silkworm::BlockHeader h10 = make_header(10, 0xAA);
    const silkworm::BlockHeader h3 = make_header(3, 0xBB);
    const silkworm::BlockHeader h7 = make_header(7, 0xCC);

    // Out-of-order insertion; created_block_hashes_ must stay sorted internally.
    hs.insert_header(h10);
    hs.insert_header(genesis);
    hs.insert_header(h7);
    hs.insert_header(h3);

    // read_header: keyed by the header's keccak hash; the passed block_num is ignored (as in
    // DirectState), so it resolves purely from the hash.
    for (const auto* h : {&genesis, &h3, &h7, &h10}) {
        auto got = hs.read_header(h->number, h->hash());
        REQUIRE(got.has_value());
        CHECK(got->number == h->number);
        CHECK(eq32(got->hash(), h->hash()));
    }

    // read_header on a hash that was never inserted misses (keccak never yields 0x99||0..0).
    evmc::bytes32 unknown{};
    unknown.bytes[0] = 0x99;
    CHECK_FALSE(hs.read_header(999, unknown).has_value());

    // get_block_hash: the BLOCKHASH lookup returns each inserted header's hash by number.
    CHECK(eq32(hs.get_block_hash(0), genesis.hash()));
    CHECK(eq32(hs.get_block_hash(3), h3.hash()));
    CHECK(eq32(hs.get_block_hash(7), h7.hash()));
    CHECK(eq32(hs.get_block_hash(10), h10.hash()));

    // Numbers that were never inserted return the all-zero sentinel (below, between, above).
    CHECK(eq32(hs.get_block_hash(5), evmc::bytes32{}));
    CHECK(eq32(hs.get_block_hash(11), evmc::bytes32{}));

    // read_body and total_difficulty are the DirectState stubs (unused by the slib path).
    silkworm::BlockBody body{};
    CHECK_FALSE(hs.read_body(3, h3.hash(), body));
    CHECK_FALSE(hs.total_difficulty(3, h3.hash()).has_value());
}

// insert_header on an existing block number overwrites the BLOCKHASH entry in place (last
// write wins) while read_header retains BOTH headers under their distinct hashes — the
// DirectState in-place-update branch (direct_state.cpp:714-715).
TEST_CASE("HashState header store: same-number reinsert updates blockhash in place",
          "[hash_state]") {
    HashState hs;

    silkworm::BlockHeader a;
    a.number = 5;
    a.parent_hash.bytes[0] = 0x11;
    silkworm::BlockHeader b;
    b.number = 5;  // same number, different content -> different hash
    b.parent_hash.bytes[0] = 0x22;
    REQUIRE_FALSE(eq32(a.hash(), b.hash()));

    hs.insert_header(a);
    CHECK(eq32(hs.get_block_hash(5), a.hash()));

    hs.insert_header(b);
    CHECK(eq32(hs.get_block_hash(5), b.hash()));  // in-place overwrite, no duplicate entry

    // headers_ is keyed by hash, so BOTH headers remain resolvable via read_header.
    CHECK(hs.read_header(5, a.hash()).has_value());
    CHECK(hs.read_header(5, b.hash()).has_value());
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

    // Witness ancestor headers: genesis (0) and one older ancestor (number 5) are shipped, but
    // the in-range ancestor number 3 is DELIBERATELY OMITTED (the missing-oldest-ancestor shape).
    auto make_header = [](uint64_t number, uint8_t tag) {
        silkworm::BlockHeader h;
        h.number = number;
        h.gas_limit = 30'000'000;
        h.parent_hash.bytes[0] = tag;  // unique content -> unique keccak hash
        return h;
    };
    hs.insert_header(make_header(0, 0x00));
    hs.insert_header(make_header(5, 0x55));

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
    (void)hs.get_block_hash(5);
    CHECK(hs.unconfirmed_read_count() == 0u);
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, writes, forged_root));

    // EXPLOIT: the block reads BLOCKHASH(3) — an in-range ancestor whose header was omitted.
    (void)hs.get_block_hash(3);

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

[[nodiscard]] evmc::bytes32 to_bytes32(const std::uint8_t (&b)[32]) noexcept {
    evmc::bytes32 out{};
    std::memcpy(out.bytes, b, 32);
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

// schema_id||SSZ StatelessInput around already-encoded state and codes list blobs, with
// empty new_payload_request/headers/public_keys.
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
    // SszStatelessInput: [off_npr=20][off_wit=20][chain_id u64][off_pk] + wit (npr/pk empty).
    Bytes body;
    const std::uint32_t off_npr = 20u;
    const std::uint32_t off_wit = 20u;
    const std::uint32_t off_pk = off_wit + static_cast<std::uint32_t>(wit.size());
    put_u32(body, off_npr);
    put_u32(body, off_wit);
    put_u64(body, chain_id);
    put_u32(body, off_pk);
    body.insert(body.end(), wit.begin(), wit.end());
    Bytes blob;
    blob.push_back(0x15);
    blob.push_back(0x01);
    blob.insert(blob.end(), body.begin(), body.end());
    return blob;
}

// schema_id||SSZ StatelessInput with empty new_payload_request/headers/public_keys.
[[nodiscard]] Bytes encode_stateless_input(const std::vector<Bytes>& state,
                                           const std::vector<Bytes>& codes,
                                           std::uint64_t chain_id) {
    return encode_stateless_input_lists(encode_bytelist_list(state), encode_bytelist_list(codes),
                                        chain_id);
}

}  // namespace

// The load-bearing cross-check: parse the REAL statelessInputBytes blob, then build the
// pre-state from its genesis-anchored witness trie and confirm every account the witness
// carries reconstructs exactly (nonce/balance/code_hash), its code is retrievable, and the
// intentionally-pruned untouched accounts read absent. This exercises the whole default
// front-end path on real wire bytes.
TEST_CASE("slib parses the real StatelessInputBytes sample and rebuilds pre-state",
          "[hash_state][slib]") {
    const Bytes blob = hex_to_bytes(slib_sample::kBlobHex);
    REQUIRE(blob.size() == slib_sample::kBlobBytes);

    HashState hs;
    // run_slib = parse_stateless_input + build_state_from_trie against the anchoring root.
    const evmc::bytes32 prev_root = to_bytes32(slib_sample::kGenesisRoot);
    auto res = zilkworm::run_slib(ByteView{blob}, hs, prev_root);
    REQUIRE(res.has_value());

    // Decoder output matches the confirmed wire contents exactly.
    CHECK(res->input.chain_id == slib_sample::kChainId);
    CHECK(res->input.node_count == slib_sample::kExpectedNodes);
    CHECK(res->input.code_count == slib_sample::kExpectedCodes);
    CHECK(res->input.headers.size() == slib_sample::kExpectedHeaders);
    CHECK(res->input.public_keys.size() == slib_sample::kExpectedPublicKeys);
    for (const ByteView pk : res->input.public_keys) CHECK(pk.size() == 65u);
    CHECK(hs.node_count() == slib_sample::kExpectedNodes);
    CHECK(hs.code_count() == slib_sample::kExpectedCodes);

    // This is an EIP-8025 "optional proofs" partial witness: 2 untouched system accounts are
    // pruned to bare hash refs. Those pruned children are legitimate BOUNDARIES, not missing
    // nodes, so the build is CLEAN — missing_count() now flags only a broken seeding root,
    // and this witness's genesis root is present. The 9 touched accounts still materialize.
    CHECK(res->status == HashState::BuildStatus::kOk);
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.account_count() == slib_sample::kPresentCount);

    // Every account the witness DOES carry reconstructs exactly, and its code is present.
    // Each hits the account cache, so none of these reads is left unconfirmed.
    for (std::size_t i = 0; i < slib_sample::kPresentCount; ++i) {
        const auto& want = slib_sample::kPresent[i];
        INFO("present account index " << i);
        const auto addr_hash = keccak32(ByteView{want.addr, 20});
        const Account* got = hs.get_account(addr_hash);
        REQUIRE(got != nullptr);
        CHECK(got->nonce == want.nonce);
        CHECK(std::memcmp(got->balance, want.balance_le, 32) == 0);
        CHECK(std::memcmp(got->code_hash, want.code_hash, 32) == 0);
        // The witness `codes` list must carry this account's bytecode (empty for the EOA).
        const ByteView code = hs.find_code(to_bytes32(want.code_hash));
        CHECK(code.size() == want.code_len);
    }
    CHECK(hs.unconfirmed_read_count() == 0u);  // every touched-account read hit the cache

    // The pruned untouched accounts read absent (blank) for the caller — but each read must
    // descend into a pruned boundary, which confirm_absent cannot prove empty, so each is
    // recorded as an unconfirmed read. Completeness for the pruned parts is enforced HERE,
    // at read time (the accept gate would reject on a non-zero unconfirmed count), not at
    // build time.
    for (std::size_t i = 0; i < slib_sample::kPrunedCount; ++i) {
        const auto addr_hash = keccak32(ByteView{slib_sample::kPrunedAddrs[i], 20});
        CHECK(hs.get_account(addr_hash) == nullptr);
    }
    CHECK(hs.unconfirmed_read_count() > 0u);  // a read into a pruned boundary is unconfirmed
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
    SECTION("truncated below the 20-byte top-level fixed region") {
        Bytes b{good.substr(0, 2 + 10)};  // marker + 10 body bytes
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("first offset != fixed-region size") {
        Bytes b = good;
        put_u32_at(b, 2 + 0, 21u);  // off(new_payload_request) must be 20
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("out-of-order top-level offset") {
        Bytes b = good;
        put_u32_at(b, 2 + 16, 0u);  // off(public_keys) = 0 < off(witness) = 20
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("offset past end of blob") {
        Bytes b = good;
        put_u32_at(b, 2 + 16, 0xFFFFFFFFu);  // off(public_keys) beyond the body
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("witness first offset != 12") {
        Bytes b = good;
        put_u32_at(b, 2 + 20, 13u);  // witness off(state) must be 12
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("out-of-order state-list offset") {
        Bytes b = good;
        // state list begins at body(20) + witness fixed(12) = blob offset 2+20+12 = 34;
        // its second u32 offset lives at +4. Force it below the first offset (non-monotone).
        put_u32_at(b, 2 + 20 + 12 + 4, 0u);
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
    SECTION("public_keys not a multiple of the 65-byte stride") {
        Bytes b = good;
        b.push_back(0x00);  // one stray trailing byte -> pk region size % 65 != 0
        CHECK_FALSE(zilkworm::decode_stateless_input(ByteView{b}).has_value());
    }
}

// The state and code lists are streamed into the stores as they are validated, so a
// malformed element part-way through stops the feed there: parse returns std::nullopt, the
// elements before the violation have been fed (the caller discards the HashState), and
// nothing at or past it was. Element 2's offset is forced below element 1's, which the
// monotonicity check catches while validating element 1 (its end offset).
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

    // The state list begins at blob offset 2 (marker) + 20 (top-level fixed) + 12 (witness
    // fixed); its 3-entry offset table holds element i's start at +4*i. Element 1 starts
    // right after element 0; element 2's entry is forced one byte before that.
    Bytes b = good;
    const std::size_t state_at = 2 + 20 + 12;
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

// A state list whose first offset announces more elements than kMaxWitnessStateNodes is
// rejected by the count check before any store is sized or fed. For that check, and not the
// bounds check on the first offset, to be the one that rejects it, the offset table has to
// really be (cap + 1) * 4 bytes long: the blob carries a 4 MB table whose every entry is the
// table end, i.e. cap + 1 empty elements, well-formed in every other respect.
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

    // The same shape at a small count is well-formed, so the rejection above was the count:
    // three empty elements parse, are counted as fed, and dedupe to one stored entry.
    Bytes small(3u * 4u, 0);
    for (std::uint32_t i = 0; i < 3u; ++i) put_u32_at(small, i * 4u, 12u);
    const Bytes small_blob = encode_stateless_input_lists(small, /*codes_blob=*/{}, /*chain_id=*/1);
    HashState hs_small;
    auto v = zilkworm::parse_stateless_input(ByteView{small_blob}, hs_small);
    REQUIRE(v.has_value());
    CHECK(v->node_count == 3u);
    CHECK(hs_small.node_count() == 1u);
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

// find_or_create_account on an address the empty trie does not have: a fresh, usable record
// and NO unconfirmed read (the miss is not walked at read time).
TEST_CASE("HashState find_or_create_account on a confirmed-absent key is fresh, no unconfirmed",
          "[hash_state]") {
    HashState hs;
    REQUIRE(hs.build_state_from_trie(silkworm::kEmptyRoot) == HashState::BuildStatus::kOk);
    const evmc::address addr = s2_addr(0x90);

    Account* pa = hs.find_or_create_account(addr);
    REQUIRE(pa != nullptr);  // never null
    CHECK(pa->deleted);      // materialized fresh (a subsequent write revives it)
    CHECK(hs.unconfirmed_read_count() == 0u);  // no walk at read time
}

// find_or_create_account on an address the pre-state trie does not have: a usable (deleted)
// record and NO walk at read time (unconfirmed_read_count stays 0). The record's account-trie
// update claims the key absent, and the accept check walks the claim: proven where the key
// leaves the trie (accepted, the root unchanged), unprovable at a pruned boundary (the walk
// fails, rejected), refuted by a leaf at the key the build did not decode (rejected).
TEST_CASE("HashState find_or_create_account claims the address absent at accept time",
          "[hash_state][accept]") {
    const evmc::address addr = s2_addr(0xA0);
    const evmc::bytes32 ah = keccak_addr(addr);
    const auto ah_path = nibbles_of(ah);
    const std::uint8_t first = static_cast<std::uint8_t>(ah.bytes[0] >> 4);
    const std::uint8_t other = static_cast<std::uint8_t>((first + 1) & 0xF);
    const std::uint8_t third = static_cast<std::uint8_t>((first + 2) & 0xF);

    // Present leaves at two other root-branch slots, so the root exists in the store.
    const Key kP = key_with(other, 3, 5);
    const Bytes accP = account_leaf_value(1, silkworm::kEmptyRoot);
    const LeafNode leafP = make_leaf(&kP.nib[1], 63, ByteView{accP});
    const Key kQ = key_with(third, 5, 2);
    const Bytes accQ = account_leaf_value(2, silkworm::kEmptyRoot);
    const LeafNode leafQ = make_leaf(&kQ.nib[1], 63, ByteView{accQ});

    HashState hs;
    const evmc::bytes32 hP = hs.add_node(ByteView{zilkworm::encode_leaf(leafP)});
    const evmc::bytes32 hQ = hs.add_node(ByteView{zilkworm::encode_leaf(leafQ)});
    BranchNode root;
    root.set_child(other, ByteView{hP.bytes, 32});
    root.set_child(third, ByteView{hQ.bytes, 32});

    SECTION("proven: the address's root-branch slot is empty") {
        const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});
        REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);

        Account* pa = hs.find_or_create_account(addr);
        REQUIRE(pa != nullptr);
        CHECK(pa->deleted);                        // materialized fresh, never written
        CHECK(hs.unconfirmed_read_count() == 0u);  // no walk at read time
        REQUIRE(hs.created_accounts().size() == 1u);

        // The read-only claim inserts nothing: the root is the pre-state's.
        CHECK(zilkworm::check_root_hashstate(hs, root_hash, root_hash));
        CHECK(hs.unconfirmed_read_count() == 0u);
    }

    SECTION("unprovable: a pruned boundary at the address's slot") {
        evmc::bytes32 dangling{};
        for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<std::uint8_t>(0xDE - i);
        root.set_child(first, ByteView{dangling.bytes, 32});
        const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});
        REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
        REQUIRE(hs.missing_count() == 0u);  // pruned boundary, not a missing node

        Account* pa = hs.find_or_create_account(addr);
        REQUIRE(pa != nullptr);                    // never null, even at a pruned boundary
        CHECK(hs.unconfirmed_read_count() == 0u);  // nothing is walked at read time

        // The claim's walk needs the pruned node: it fails, and the block is rejected.
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, root_hash, root_hash));
    }

    SECTION("refuted: a leaf at the address the build did not decode") {
        // A leaf at the address's full path whose value is no account RLP: the build skips it,
        // so the address is a total miss, while the trie has the key.
        const Bytes garbage{0x01};
        const LeafNode leafA = make_leaf(&ah_path[1], 63, ByteView{garbage});
        const evmc::bytes32 hA = hs.add_node(ByteView{zilkworm::encode_leaf(leafA)});
        root.set_child(first, ByteView{hA.bytes, 32});
        const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});
        REQUIRE(hs.build_state_from_trie(root_hash) == HashState::BuildStatus::kOk);
        REQUIRE(hs.find_built_account(ah) == nullptr);

        Account* pa = hs.find_or_create_account(addr);
        REQUIRE(pa != nullptr);
        CHECK(hs.unconfirmed_read_count() == 0u);

        // Read as absent and left deleted: the claim meets the leaf, and the walk fails.
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, root_hash, root_hash));

        // Created: the same claim with the account's new leaf, refuted the same way.
        hs.set_nonce(addr, 7);
        REQUIRE(hs.read_account(addr) != nullptr);
        CHECK_FALSE(hs.read_account(addr)->deleted);
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, root_hash, root_hash));
    }
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
    // C is created: its write claims the key absent, as the gather marks it.
    manual.push_back({keccak_addr(aC), silkworm::kEmptyRoot, {}, hs.read_account(aC), /*absent=*/true});
    std::sort(manual.begin(), manual.end(),
              [](const HashStateAccountWrite& a, const HashStateAccountWrite& b) {
                  return std::memcmp(a.addr_hash.bytes, b.addr_hash.bytes, 32) < 0;
              });
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, manual, expected_root));   // == gather accept
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, manual, bad_root));  // == gather reject

    // --- (C) a claim of absence for B, whose leaf the pre-state trie has, is refuted: the walk
    // meets B's leaf and fails, whatever the header root. ---
    std::vector<HashStateAccountWrite> claimed = manual;
    for (auto& w : claimed)
        if (eq32(w.addr_hash, keccak_addr(aB))) w.absent = true;
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, claimed, expected_root));
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

// Gather overload skip of the built accounts the block only READ. A built account enters the
// overlay on its first read (HashStateView::get_account -> find_or_create_account's copy-on-write)
// with modified == false, a verbatim copy of its pre-state leaf: the gather does not fold it, and
// the recomputed root is the one a run without the read gives. Once mutated (set_nonce) it is
// folded, so only the new root is accepted. The read-only !built case (a claim of absence) is
// "find_or_create_account claims the address absent at accept time" above.
TEST_CASE("check_root_hashstate gather overload skips a built account the block only read",
          "[hash_state][accept]") {
    HashState hs;

    // --- pre-state: ONE built account R with empty storage, a single-leaf account trie. ---
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

    // The block reads R through the evmone view: R enters the overlay unmodified, not deleted.
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
    }
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // (a) Read only: nothing is folded, the root is the pre-state's; a tampered root rejects.
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
    evmc::bytes32 bad_root = prev_root;
    bad_root.bytes[0] = static_cast<uint8_t>(bad_root.bytes[0] ^ 0xFF);
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, bad_root));
    CHECK(hs.unconfirmed_read_count() == 0u);

    // (b) Then mutated: the record is folded, so the new root and only the new root is accepted.
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

// A built account the block read and then destructed still emits its 0x80 leaf delete: the
// deleted branch of the gather runs ahead of the read-only skip. A second built account read
// alongside it is skipped, and the recomputed root is the trie with only that leaf left.
TEST_CASE("check_root_hashstate gather overload deletes a built account read then destructed",
          "[hash_state][accept]") {
    HashState hs;

    // --- pre-state: a root branch over two built accounts on different first nibbles: R (read
    // only) and D (read, then destructed). ---
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

    // Both read through the view, then D destructed.
    HashStateView view{hs};
    REQUIRE(view.get_account(aR).has_value());
    REQUIRE(view.get_account(aD).has_value());
    hs.destruct(aD);
    REQUIRE(hs.created_accounts().size() == 2u);
    CHECK_FALSE(hs.created_accounts().find(aR)->second.modified);  // skipped by the gather
    CHECK(hs.created_accounts().find(aD)->second.deleted);         // folded as a delete
    CHECK(hs.read_account(aD) == nullptr);
    REQUIRE(hs.unconfirmed_read_count() == 0u);

    // Oracle: D's leaf deleted, the branch collapses to R alone, a single full-path leaf.
    const LeafNode leafR_post = make_leaf(aR_path.data(), 64, ByteView{leafR_val});
    const evmc::bytes32 expected_root = keccak32(ByteView{zilkworm::encode_leaf(leafR_post)});
    REQUIRE_FALSE(eq32(expected_root, prev_root));
    CHECK(zilkworm::check_root_hashstate(hs, prev_root, expected_root));
    CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, prev_root));  // the delete is not lost
}

// Over the real witness sample: every present account read through the view enters the overlay
// unmodified, and the fold recomputes an IDENTICAL root whether those records are folded (the
// update set of every loaded account) or left out (the modified ones only, which is what the
// gather folds), both before and after a write. The gather accepts that root. This mirrors the
// host harness's byte-identical recomputed roots over the mainnet blocks.
TEST_CASE("slib real sample: folding the accounts the block only read leaves the root unchanged",
          "[hash_state][slib][accept]") {
    const Bytes blob = hex_to_bytes(slib_sample::kBlobHex);
    HashState hs;
    const evmc::bytes32 prev_root = to_bytes32(slib_sample::kGenesisRoot);
    auto res = zilkworm::run_slib(ByteView{blob}, hs, prev_root);
    REQUIRE(res.has_value());
    REQUIRE(res->status == HashState::BuildStatus::kOk);
    REQUIRE(hs.missing_count() == 0u);

    // The block loads every present account through the evmone view (what build_diff reports).
    HashStateView view{hs};
    std::vector<evmc::address> addrs;
    for (std::size_t i = 0; i < slib_sample::kPresentCount; ++i) {
        INFO("present account index " << i);
        evmc::address a{};
        std::memcpy(a.bytes, slib_sample::kPresent[i].addr, 20);
        const auto acc = view.get_account(a);
        REQUIRE(acc.has_value());
        CHECK(acc->nonce == slib_sample::kPresent[i].nonce);
        addrs.push_back(a);
    }
    REQUIRE(hs.unconfirmed_read_count() == 0u);
    REQUIRE(hs.created_accounts().size() == slib_sample::kPresentCount);
    for (const auto& [addr, acc] : hs.created_accounts()) {
        CHECK_FALSE(acc.modified);
        CHECK_FALSE(acc.deleted);
        CHECK(hs.find_built_account(keccak_addr(addr)) != nullptr);
    }

    // The account-trie update set of the overlay's live records, encoded as the span overload
    // encodes a write (rlp_into over the frozen storage_root): every record, or the modified only.
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
        REQUIRE_FALSE(acc_trie.failed());
        REQUIRE(acc_trie.missing_count() == 0u);
        return root;
    };

    // Before any write: the full set folds to the pre-state root, exactly as the empty set does.
    {
        const auto all = gather_updates(false);
        const auto modified = gather_updates(true);
        REQUIRE(all.size() == slib_sample::kPresentCount);
        REQUIRE(modified.empty());
        CHECK(eq32(fold(all), prev_root));
        CHECK(eq32(fold(modified), prev_root));
        CHECK(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
    }

    // After a write to one of them: the other eight stay unmodified, and folding them or not
    // gives the same (moved) root, which the gather accepts; the pre-state root is rejected.
    hs.set_nonce(addrs[0], slib_sample::kPresent[0].nonce + 1);
    {
        const auto all = gather_updates(false);
        const auto modified = gather_updates(true);
        REQUIRE(all.size() == slib_sample::kPresentCount);
        REQUIRE(modified.size() == 1u);
        const evmc::bytes32 root_all = fold(all);
        const evmc::bytes32 root_mod = fold(modified);
        CHECK(eq32(root_all, root_mod));
        CHECK_FALSE(eq32(root_mod, prev_root));
        CHECK(zilkworm::check_root_hashstate(hs, prev_root, root_mod));
        CHECK_FALSE(zilkworm::check_root_hashstate(hs, prev_root, prev_root));
    }
    CHECK(hs.unconfirmed_read_count() == 0u);
}
