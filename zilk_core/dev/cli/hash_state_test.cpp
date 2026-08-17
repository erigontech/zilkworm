// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// HashState substrate unit tests (zilkworm.tests target).
//
// HashState is the SSZ-input-path node/code store, parallel to DirectState's
// serialized MphfMap stores. add_node/add_code key their input by its REAL keccak256
// and record the arena offset in an open-addressed HashIndex<32,&hash_key8>;
// find_node_rlp / find_code recover the bytes. These tests cover round-trip, dedupe,
// definitive miss, and — the load-bearing case — the full-key memcmp gate under a
// home-bucket collision. A literal 8-byte key8 collision is infeasible to construct
// under real keccak, so instead we drive two DISTINCT real keccak hashes into the SAME
// index home bucket and confirm each still resolves to its own payload while a third
// colliding-but-never-added hash misses.

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>  // silkworm::kEmptyRoot
#include <zilk_core/core/common/util.hpp>           // silkworm::keccak256(ByteView), zeroless_view
#include <zilk_core/core/common_zz/hash_index.hpp>
#include <zilk_core/core/rlp/encode.hpp>            // silkworm::rlp::encode (storage-value encode)
#include <zilk_core/core/common_zz/mphf_map.hpp>  // mix64_body (public)
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>     // encode_leaf/branch/ext + node types
#include <zilk_core/core/types_zz/account.hpp>   // Account (leaf-value encode/decode target)

using zilkworm::Account;
using zilkworm::BranchNode;
using zilkworm::ByteView;
using zilkworm::Bytes;
using zilkworm::ExtensionNode;
using zilkworm::HashIndex;
using zilkworm::HashState;
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

// The safety gate: two DISTINCT real keccak hashes forced into the same index home
// bucket must each resolve to their OWN payload (open-address probe + full-key memcmp),
// and a third colliding-but-never-added hash must still miss.
//
// A literal key8 collision under real keccak is infeasible to construct, so a home-
// bucket collision (mix64_body(hash_key8(h)) & (capacity-1)) is used instead. mix64_body
// is public in mphf_map.hpp, but the exact home bucket also depends on the table's
// capacity/mask; a sibling HashIndex sized with the SAME expected count reproduces both,
// so its public index_of() gives the authoritative home bucket the real node index uses.
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

    // The full-key memcmp gate routes each colliding lookup to its OWN payload.
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

// ---------------------------------------------------------------------------
// derive_state — the standalone account-trie sweep.
//
// These tests hand-build small account tries out of the project's own MPT node
// encoders (encode_leaf/encode_branch/encode_ext, rlp_sw.hpp), add the referenced
// nodes to the store under their real keccak, then run derive_state(root) and check
// the emitted account cache. Using the shared encoders (rather than raw RLP bytes)
// keeps the fixtures canonical and readable — the same bytes decode_node reads back.
// ---------------------------------------------------------------------------

namespace {

// A trie key expressed as 64 nibbles, and the 32-byte addr_hash it packs into (the
// inverse of the packing derive_state does at a leaf).
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

// The full sweep: a root branch with two direct account leaves, one account behind an
// extension, and one embedded (<32-byte) inline non-account leaf behind a long
// extension. Every real account must land in the cache under its exact addr_hash with
// correctly-decoded fields; the embedded leaf must be reached inline (no store lookup,
// so missing_count stays 0); an addr_hash not in the trie must be absent.
TEST_CASE("HashState derive_state account sweep", "[hash_state]") {
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
    Key kE;  // slot 0x8 -> extension (62 nibbles) -> embedded 1-nibble leaf
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

    // --- embedded inline leaf E under a deep branch: root[0x8] -> ext(60 nibbles) ->
    // branch2 -> EMBEDDED leaf(2 nibbles, tiny 1-byte value). Embedded inline children
    // only ever hang off a BRANCH (an extension's child is always a 32-byte hash ref, so
    // decode_node rejects an inline-list ext child). The 60-nibble extension pushes the
    // branch deep enough that the leaf's 2-nibble remainder + 1-byte value fit in
    // < 32 bytes, so the leaf is inlined into branch2's RLP rather than hash-referenced.
    // The leaf is NOT added to the store; derive_state must decode it inline (no lookup,
    // so missing_count stays 0). Its 1-byte value is not a decodable account (a real
    // account leaf is always > 32 bytes — two 32-byte hashes — hence never embeddable),
    // so it is counted as a reached leaf but never cached. ---
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
    const auto status = hs.derive_state(root_hash);
    CHECK(status == HashState::DeriveStatus::kOk);
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

// A referenced child hash that is absent from the store must be surfaced as a missing
// node (missing_count > 0, status kMissingNode) — never a silent skip.
TEST_CASE("HashState derive_state reports a dangling child ref", "[hash_state]") {
    HashState hs;

    // Root branch whose one child points at a hash that was never add_node'd.
    evmc::bytes32 dangling{};
    for (int i = 0; i < 32; ++i) dangling.bytes[i] = static_cast<uint8_t>(0xDE - i);
    BranchNode root;
    root.set_child(0x3, ByteView{dangling.bytes, 32});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_branch(root)});

    const auto status = hs.derive_state(root_hash);
    CHECK(status == HashState::DeriveStatus::kMissingNode);
    CHECK(hs.missing_count() > 0u);   // observable, not skipped
    CHECK(hs.account_count() == 0u);  // nothing decodable was reachable
}

// A missing seeding root is the fail-closed case: it is surfaced, never treated as an
// empty trie.
TEST_CASE("HashState derive_state reports a missing root", "[hash_state]") {
    HashState hs;
    evmc::bytes32 never_added{};
    for (int i = 0; i < 32; ++i) never_added.bytes[i] = static_cast<uint8_t>(0x11 + i);

    const auto status = hs.derive_state(never_added);
    CHECK(status == HashState::DeriveStatus::kMissingNode);
    CHECK(hs.missing_count() > 0u);
    CHECK(hs.account_count() == 0u);
}

// The empty trie derives nothing, cleanly.
TEST_CASE("HashState derive_state on the empty root derives nothing", "[hash_state]") {
    HashState hs;
    const auto status = hs.derive_state(silkworm::kEmptyRoot);
    CHECK(status == HashState::DeriveStatus::kOk);
    CHECK(hs.account_count() == 0u);
    CHECK(hs.leaf_count() == 0u);
    CHECK(hs.missing_count() == 0u);
}

// ---------------------------------------------------------------------------
// derive_state — the STORAGE-trie sweep (the sibling pass over each account's
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
// EMPTY storage_root. After derive_state every one of X's slots is retrievable via
// get_storage under (addr_hash, slot_hash) and decodes to its exact word — including a
// value RLP-trims to a single byte and one that trims to two. An un-derived slot, a slot
// looked up under the wrong account, and every lookup against empty-storage Y all read as
// zero; no storage root here is absent, so missing_count stays 0.
TEST_CASE("HashState derive_state storage sweep", "[hash_state]") {
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
    const auto status = hs.derive_state(root_hash);
    CHECK(status == HashState::DeriveStatus::kOk);
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

// A dangling ref reached WHILE walking an included storage trie is fail-closed: the account
// decodes fine, but the missing storage node surfaces as missing_count > 0 / kMissingNode.
// (Account Z is the whole account trie — a single 64-nibble leaf as the root.)
TEST_CASE("HashState derive_state reports a dangling storage-node ref", "[hash_state]") {
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

    const auto status = hs.derive_state(root_hash);
    CHECK(status == HashState::DeriveStatus::kMissingNode);
    CHECK(hs.missing_count() > 0u);       // the dangling storage child is surfaced
    CHECK(hs.account_count() == 1u);      // Z itself decoded; the gap is inside its storage
    CHECK(hs.storage_count() == 0u);      // the dangling child yielded no slot
}

// An account whose storage_root is ABSENT from the store is skipped, NOT counted missing:
// a witness legitimately omits the storage trie of an account the block never touches.
// (This is exactly what keeps the pre-existing account-sweep fixtures — whose accounts all
// carry bogus non-present storage roots — passing unchanged.)
TEST_CASE("HashState derive_state skips an absent storage root", "[hash_state]") {
    HashState hs;

    // storage_root points at a node that was never added.
    evmc::bytes32 absent_root{};
    for (int i = 0; i < 32; ++i) absent_root.bytes[i] = static_cast<uint8_t>(0x50 + i);

    const Key kW = key_with(0x3, 9, 7);
    const Bytes accW = account_leaf_value(5, absent_root);
    const LeafNode leafW = make_leaf(&kW.nib[0], 64, ByteView{accW});
    const evmc::bytes32 root_hash = hs.add_node(ByteView{zilkworm::encode_leaf(leafW)});

    const auto status = hs.derive_state(root_hash);
    CHECK(status == HashState::DeriveStatus::kOk);   // absent storage root != missing node
    CHECK(hs.missing_count() == 0u);
    CHECK(hs.account_count() == 1u);
    CHECK(hs.storage_count() == 0u);
    CHECK(hs.storage_slot_count() == 0u);
}
