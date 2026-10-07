// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for a witness-validation soundness gap (PR #90 review):
//
//   A read-only account (or storage slot) that EXISTS under prev_root can be
//   OMITTED from the flat witness. The EVM read path then returns it as
//   empty/non-existent, and check_root used to fold only the accounts and
//   slots the witness carries: the omitted one's subtree hash flowed through
//   unchanged, the root came out as prev_root, and the witness was accepted.
//
// check_root now walks every such read as a claim that the key is absent: the
// record DirectState makes for an address the witness does not carry, and each
// slot it reads as zero for want of a witness slot (AbsentRead).
// The walk shows the key absent along the witness's nodes, or reaches the leaf
// the witness left out, or a node it left out, and rejects. With USE_HASH_KEY
// the read path recovers the account or slot from the node store instead, and
// the EVM sees it.
//
// Setup mirrors a real trie: account W is witnessed, account A's leaf is in
// the node store but its preimage is missing from the keys (the USE_HASH_KEY
// witness bug); the storage twin hides slot S2 behind C's storage_root.
// MissingAccountNode_* keeps the original hiding (leaf_A absent). The honest
// twins read an account or slot the trie does not have, whose proof of absence
// runs through the hidden one's leaf.
//
// Standalone test (no gtest); exit code = failure count, like mphf_map_test.cpp.

#include <algorithm>
#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <print>
#include <source_location>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

#if USE_HASH_KEY
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "../state_transition.hpp"

using namespace zilkworm;
using silkworm::ByteView;
using silkworm::Bytes;

namespace {

int g_failures = 0;

void expect_true(bool cond, const char* msg,
                 std::source_location loc = std::source_location::current()) {
    if (!cond) {
        std::println(stderr, "[FAIL] {}:{}  {}", loc.file_name(), loc.line(), msg);
        ++g_failures;
    } else {
        std::println("[ ok ] {}", msg);
    }
}

evmc::address make_addr(uint8_t b0, uint8_t b19) {
    evmc::address a{};
    a.bytes[0] = b0;
    a.bytes[19] = b19;
    return a;
}

bytes32 make_word(uint8_t b31) {
    bytes32 w{};
    w.bytes[31] = b31;
    return w;
}

bytes32 keccak_addr32(const evmc::address& a) {
    return keccak_bytes(ByteView{a.bytes, 20});
}

unsigned first_nibble(const bytes32& hashed_key) { return hashed_key.bytes[0] >> 4; }

// The first address from make_addr(b0, 0) on whose hashed key's first nibble `pred` accepts.
template <class Pred>
evmc::address find_addr(uint8_t b0, Pred pred) {
    for (unsigned b = 0; b < 256; ++b) {
        const evmc::address a = make_addr(b0, static_cast<uint8_t>(b));
        if (pred(first_nibble(keccak_addr32(a)))) return a;
    }
    return make_addr(b0, 0);
}

// The first slot from make_word(from) on whose hashed key's first nibble `pred` accepts.
template <class Pred>
bytes32 find_word(uint8_t from, Pred pred) {
    for (unsigned b = from; b < 256; ++b) {
        const bytes32 w = make_word(static_cast<uint8_t>(b));
        if (pred(first_nibble(keccak_bytes32(w)))) return w;
    }
    return make_word(from);
}

// Build the canonical account RLP via the SAME encoder the flat state uses,
// so the trie-leaf value is byte-identical to what check_root compares against.
Bytes account_rlp(const evmc::address& addr, uint64_t nonce, uint64_t balance,
                  const bytes32& storage_root = silkworm::kEmptyRoot,
                  const bytes32& code_hash = silkworm::kEmptyHash) {
    Account acc{};
    std::memcpy(acc.addr, addr.bytes, 20);
    acc.nonce = nonce;
    intx::uint256 bal{balance};
    std::memcpy(acc.balance, &bal, 32);
    std::memcpy(acc.code_hash, code_hash.bytes, 32);
    std::memcpy(acc.storage_root, storage_root.bytes, 32);
    acc.code_store_len = 0;
    acc.slot_count = 0;
    const uint8_t len = acc.rlp_into_cache(storage_root);
    return Bytes{acc.acc_rlp_buf, acc.acc_rlp_buf + len};
}

DirectState::AccountInfo make_info(const evmc::address& addr, uint64_t nonce, uint64_t balance) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = nonce;
    intx::uint256 bal{balance};
    std::memcpy(info.account.balance, &bal, 32);
    std::memcpy(info.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(info.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    info.account.code_store_len = 0;
    info.account.slot_count = 0;
    return info;
}

// Encode a leaf node (path = hashed-key nibbles after the branch, value = acct RLP).
Bytes make_leaf_rlp(const bytes32& hashed_key, ByteView value) {
    nibbles64 full = nibbles64::from_bytes32(hashed_key);
    LeafNode leaf{};
    leaf.parent_slot = full.nib[0];
    leaf.path.len = 63;
    std::memcpy(leaf.path.nib.data(), full.nib.data() + 1, 63);
    leaf.value = value;
    return Bytes{encode_leaf(leaf)};  // copy out of the shared static buffer
}

// RLP scalar encoding of a storage value — the storage-trie leaf value bytes.
Bytes scalar_rlp(const bytes32& v) {
    Bytes out;
    silkworm::rlp::encode(out, silkworm::zeroless_view(ByteView{v.bytes, 32}));
    return out;
}

void add_node(MphfBuilder<32>& nb, const bytes32& hash, const Bytes& node_rlp) {
    std::vector<uint8_t> body;
    FlatKv::encode(body, hash, node_rlp);
    nb.add(hash_key8(hash), ByteView{body.data(), body.size()});
}

// Independent oracle: canonical state-trie root over the given (hashed_key, rlp)
// leaves, via silkworm::trie::HashBuilder (a different trie implementation than
// GridMPT). Leaves must be supplied sorted by hashed key.
bytes32 hashbuilder_root(std::vector<std::pair<bytes32, Bytes>> leaves) {
    std::sort(leaves.begin(), leaves.end(), [](const auto& x, const auto& y) {
        return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0;
    });
    silkworm::trie::HashBuilder hb;
    for (const auto& [k, v] : leaves)
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    return hb.root_hash();
}

// A trie of two leaves whose hashed keys differ in the first nibble: a branch root over both.
struct TwoLeafTrie {
    Bytes leaf1;
    Bytes leaf2;
    Bytes root_rlp;
    bytes32 root;
};

TwoLeafTrie two_leaf_trie(const bytes32& k1, ByteView v1, const bytes32& k2, ByteView v2) {
    TwoLeafTrie t{make_leaf_rlp(k1, v1), make_leaf_rlp(k2, v2), {}, {}};
    BranchNode br{};
    br.set_child(first_nibble(k1), ByteView{keccak_bytes(t.leaf1).bytes, 32});
    br.set_child(first_nibble(k2), ByteView{keccak_bytes(t.leaf2).bytes, 32});
    t.root_rlp = Bytes{encode_branch(br)};
    t.root = keccak_bytes(t.root_rlp);
    return t;
}

// Runs the real check_root on the block after `parent`, whose header commits to `post_root`.
bool check_root_accepts(DirectState& direct, const BlockHeader& parent, const bytes32& post_root) {
    BlockHeader head{};
    head.number = parent.number + 1;
    head.parent_hash = parent.hash();
    head.state_root = post_root;
    silkworm::cmd::state_transition::StateTransition st{std::span<uint8_t>{}};
    return st.check_root(direct, head, EVMC_CANCUN);
}

#if USE_HASH_KEY
// Mirrors check_root's per-account storage recompute: flat slots (initial +
// current-if-changed), overflow slots (current only) and recovered slots
// (initial + current-if-changed).
bytes32 recompute_storage_root(DirectState& direct, const evmc::address& addr,
                               const bytes32& anchor) {
    std::vector<TrieNodeFlat> upds;
    std::span<const Slot> existing_slots;
    if (const auto* pa = direct.find_pre_account_unchecked(addr);
        pa != nullptr && !pa->deleted && pa->slot_count > 0) {
        existing_slots = direct.slots_for(*pa).first(pa->slot_count);
    }
    for (const auto& slot : existing_slots) {
        auto& n = upds.emplace_back(keccak_bytes32(std::bit_cast<bytes32>(slot.key)));
        n.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
            n.buf + 0, silkworm::zeroless_view(ByteView{slot.initial, 32})));
        if (!eq_hash32(slot.initial, slot.current)) {
            n.current_off = 40;
            n.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                n.buf + 40, silkworm::zeroless_view(ByteView{slot.current, 32})));
        }
    }
    if (const auto* created = direct.overflow_slots_for(addr)) {
        for (const auto& [k, v] : *created) {
            auto& n = upds.emplace_back(keccak_bytes32(k));
            n.current_off = 40;
            n.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                n.buf + 40, silkworm::zeroless_view(ByteView{v.bytes, 32})));
        }
    }
    if (const auto* rec = direct.recovered_slots_for(addr)) {
        for (const auto& [k, rs] : *rec) {
            if (!rs.found) continue;
            auto& n = upds.emplace_back(keccak_bytes32(k));
            n.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
                n.buf + 0, silkworm::zeroless_view(ByteView{rs.initial.bytes, 32})));
            if (!eq_hash32(rs.initial.bytes, rs.current.bytes)) {
                n.current_off = 40;
                n.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                    n.buf + 40, silkworm::zeroless_view(ByteView{rs.current.bytes, 32})));
            }
        }
    }
    std::sort(upds.begin(), upds.end());
    GridMPT<true, DirectState> st{direct, anchor};
    return st.calc_root_from_updates({upds.data(), upds.size()});
}
#endif

// prev_root R commits to accounts W and A (first nibbles distinct; leaf1 is leaf_W, leaf2 leaf_A); the
// witness carries W alone, and the node store holds R, leaf_W and leaf_A.
struct HiddenAccount {
    evmc::address W;
    evmc::address A;
    uint64_t a_balance{5000};
    TwoLeafTrie trie;
    std::vector<uint8_t> prestate;
    std::vector<uint8_t> nodestore;
    BlockHeader parent;
};

HiddenAccount hidden_account() {
    HiddenAccount h;
    h.W = make_addr(0x11, 0x00);
    const unsigned w_nib = first_nibble(keccak_addr32(h.W));
    h.A = find_addr(0x22, [&](unsigned n) { return n != w_nib; });
    const bytes32 kW = keccak_addr32(h.W);
    const bytes32 kA = keccak_addr32(h.A);
    const Bytes wRlp = account_rlp(h.W, /*nonce=*/0, 1000);
    const Bytes aRlp = account_rlp(h.A, /*nonce=*/0, h.a_balance);
    h.trie = two_leaf_trie(kW, wRlp, kA, aRlp);
    h.prestate = DirectState::build_blob_from_accounts({make_info(h.W, 0, 1000)}, /*block_hashes=*/{},
                                                       /*code_store=*/{});
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, h.trie.root, h.trie.root_rlp);
    add_node(nb, keccak_bytes(h.trie.leaf1), h.trie.leaf1);
    add_node(nb, keccak_bytes(h.trie.leaf2), h.trie.leaf2);
    h.nodestore = std::move(nb).finalize();
    h.parent.number = 1;
    h.parent.state_root = h.trie.root;
    return h;
}

void HiddenReadOnlyAccount_RejectedByCheckRoot() {
    HiddenAccount h = hidden_account();
    expect_true(first_nibble(keccak_addr32(h.W)) != first_nibble(keccak_addr32(h.A)),
                "S1: W and A hashed keys differ in first nibble (single-branch root)");
    expect_true(h.trie.root == hashbuilder_root({{keccak_addr32(h.W), account_rlp(h.W, 0, 1000)},
                                                 {keccak_addr32(h.A), account_rlp(h.A, 0, h.a_balance)}}),
                "S2: hand-built root node hashes to canonical prev_root R");
    expect_true(h.trie.root != hashbuilder_root({{keccak_addr32(h.W), account_rlp(h.W, 0, 1000)}}),
                "S3: prev_root R provably commits to A (R != root without A)");

    DirectState direct{std::span<uint8_t>{h.prestate}, std::span<uint8_t>{h.nodestore}};
    expect_true(direct.sanitize(), "S4: sanitize() ACCEPTS the witness (all present identities hash-bind)");
    expect_true(direct.find_node_rlp(keccak_bytes(h.trie.leaf2)).has_value(),
                "S5: leaf_A present in node store (preimage hidden from keys)");
    direct.insert_header(h.parent);

    // The EVM reads A as BALANCE does, through DirectStateView::get_account.
    const auto seen = DirectStateView{direct}.get_account(h.A);
    std::println("    [observed] get_account(A) = {}", seen ? "present" : "absent");
#if USE_HASH_KEY
    expect_true(seen && seen->balance == intx::uint256{h.a_balance},
                "G1[SECURITY]: account A (committed by prev_root) is recovered and visible to the EVM");
    expect_true(direct.read_storage(h.A, make_word(0x01)) == bytes32{},
                "S6: slot read on (recovered) empty-storage account returns 0");
    expect_true(check_root_accepts(direct, h.parent, h.trie.root),
                "G1b: check_root accepts the block that read the recovered A");
#else
    expect_true(!seen, "S6: account A, its preimage left out of the keys, reads as absent");
    expect_true(!check_root_accepts(direct, h.parent, h.trie.root),
                "G1[SECURITY]: check_root rejects the block that read A, committed by prev_root, as absent");
#endif
}

// Honest twin: the witness carries W; B, which the trie does not have, shares its first nibble with A,
// so the proof of its absence is leaf_A, which only that walk unfolds.
void HonestAbsentAccount_AcceptedByCheckRoot() {
    HiddenAccount h = hidden_account();
    const unsigned a_nib = first_nibble(keccak_addr32(h.A));
    const evmc::address B = find_addr(0x55, [&](unsigned n) { return n == a_nib; });
    expect_true(first_nibble(keccak_addr32(B)) == a_nib && B != h.A,
                "H1: B's hashed key leaves the trie inside leaf_A");

    DirectState direct{std::span<uint8_t>{h.prestate}, std::span<uint8_t>{h.nodestore}};
    expect_true(direct.sanitize(), "H2: sanitize() ACCEPTS the witness");
    direct.insert_header(h.parent);
    expect_true(!DirectStateView{direct}.get_account(B).has_value(), "H3: account B reads as absent");
    expect_true(check_root_accepts(direct, h.parent, h.trie.root),
                "H4: check_root accepts the block that read B, absent from prev_root, as absent");
}

// Account C (first nibble distinct from anchor account E) holds slots S1 and S2, whose hashed keys
// differ in the first nibble (leaf1 and leaf2 of `storage`); the witness carries C with S1 alone, and the
// node store holds both tries.
struct HiddenSlot {
    evmc::address C;
    evmc::address E;
    bytes32 S1;
    bytes32 S2;
    bytes32 V1{make_word(0xAA)};
    bytes32 V2{make_word(0xBB)};  // the 'hidden' value committed by storage_root
    TwoLeafTrie storage;
    TwoLeafTrie accounts;
    std::vector<uint8_t> prestate;
    std::vector<uint8_t> nodestore;
    BlockHeader parent;
};

HiddenSlot hidden_slot() {
    HiddenSlot h;
    h.C = make_addr(0x33, 0x00);
    const unsigned c_nib = first_nibble(keccak_addr32(h.C));
    h.E = find_addr(0x55, [&](unsigned n) { return n != c_nib; });
    h.S1 = make_word(0x01);
    const unsigned s1_nib = first_nibble(keccak_bytes32(h.S1));
    h.S2 = find_word(0x02, [&](unsigned n) { return n != s1_nib; });
    h.storage = two_leaf_trie(keccak_bytes32(h.S1), scalar_rlp(h.V1), keccak_bytes32(h.S2), scalar_rlp(h.V2));
    h.accounts = two_leaf_trie(keccak_addr32(h.C), account_rlp(h.C, 1, 777, h.storage.root),
                               keccak_addr32(h.E), account_rlp(h.E, 0, 42));

    DirectState::AccountInfo info = make_info(h.C, 1, 777);
    std::memcpy(info.account.storage_root, h.storage.root.bytes, 32);
    info.storage.push_back({h.S1, h.V1});
    h.prestate = DirectState::build_blob_from_accounts({info, make_info(h.E, 0, 42)}, /*block_hashes=*/{},
                                                       /*code_store=*/{});
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const TwoLeafTrie* t : {&h.storage, &h.accounts}) {
        add_node(nb, t->root, t->root_rlp);
        add_node(nb, keccak_bytes(t->leaf1), t->leaf1);
        add_node(nb, keccak_bytes(t->leaf2), t->leaf2);
    }
    h.nodestore = std::move(nb).finalize();
    h.parent.number = 1;
    h.parent.state_root = h.accounts.root;
    return h;
}

void HiddenStorageSlot_RejectedByCheckRoot() {
    HiddenSlot h = hidden_slot();
    expect_true(first_nibble(keccak_bytes32(h.S1)) != first_nibble(keccak_bytes32(h.S2)),
                "T1: S1 and S2 hashed slot keys differ in first nibble");
    expect_true(h.storage.root == hashbuilder_root({{keccak_bytes32(h.S1), scalar_rlp(h.V1)},
                                                    {keccak_bytes32(h.S2), scalar_rlp(h.V2)}}),
                "T2: hand-built storage root node hashes to canonical SR");

    DirectState direct{std::span<uint8_t>{h.prestate}, std::span<uint8_t>{h.nodestore}};
    expect_true(direct.sanitize(), "T3: sanitize() ACCEPTS the witness");
    direct.insert_header(h.parent);
    expect_true(direct.read_storage(h.C, h.S1) == h.V1, "T4: witnessed slot S1 reads back");

    const bytes32 readS2 = direct.read_storage(h.C, h.S2);
    std::println("    [observed] read_storage(C, S2) = 0x..{:02x}", readS2.bytes[31]);
#if USE_HASH_KEY
    expect_true(readS2 == h.V2,
                "G2[SECURITY]: slot S2 (committed by storage_root) is recovered and visible to the EVM");
    expect_true(recompute_storage_root(direct, h.C, h.storage.root) == h.storage.root,
                "T5: read-only storage recompute reproduces SR");
    expect_true(check_root_accepts(direct, h.parent, h.accounts.root),
                "G2b: check_root accepts the block that read the recovered S2");

    // Write both the witnessed and the recovered slot.
    Account* paC = direct.read_account(h.C);
    expect_true(paC != nullptr, "T6: account C readable");
    const bytes32 V1n = make_word(0xA1);
    const bytes32 V2n = make_word(0xB1);
    direct.set_storage_slot(h.C, *paC, h.S1, V1n);
    direct.set_storage_slot(h.C, *paC, h.S2, V2n);
    expect_true(direct.read_storage(h.C, h.S2) == V2n, "T7: written slot S2 reads back the new value");
    const bytes32 post1 = hashbuilder_root({{keccak_bytes32(h.S1), scalar_rlp(V1n)},
                                            {keccak_bytes32(h.S2), scalar_rlp(V2n)}});
    expect_true(recompute_storage_root(direct, h.C, h.storage.root) == post1,
                "G3: storage recompute matches oracle after writing recovered slot");

    // A zero write deletes the recovered slot's leaf.
    direct.set_storage_slot(h.C, *paC, h.S2, bytes32{});
    expect_true(direct.read_storage(h.C, h.S2) == bytes32{}, "T8: zeroed slot S2 reads back 0");
    const bytes32 post2 = hashbuilder_root({{keccak_bytes32(h.S1), scalar_rlp(V1n)}});
    expect_true(recompute_storage_root(direct, h.C, h.storage.root) == post2,
                "G4: storage recompute matches oracle after zero-write delete");
#else
    expect_true(readS2 == bytes32{}, "T5: slot S2, left out of the witness, reads as 0");
    expect_true(!check_root_accepts(direct, h.parent, h.accounts.root),
                "G2[SECURITY]: check_root rejects the block that read S2, committed by storage_root, as 0");
#endif
}

// Honest twin: S3, which C's storage trie does not have, shares its first nibble with S2, so the proof of
// its absence is leaf_S2, which only that walk unfolds.
void HonestAbsentSlot_AcceptedByCheckRoot() {
    HiddenSlot h = hidden_slot();
    const unsigned s2_nib = first_nibble(keccak_bytes32(h.S2));
    const bytes32 S3 = find_word(static_cast<uint8_t>(h.S2.bytes[31] + 1), [&](unsigned n) { return n == s2_nib; });
    expect_true(first_nibble(keccak_bytes32(S3)) == s2_nib && S3 != h.S2,
                "H5: S3's hashed key leaves the storage trie inside leaf_S2");

    DirectState direct{std::span<uint8_t>{h.prestate}, std::span<uint8_t>{h.nodestore}};
    expect_true(direct.sanitize(), "H6: sanitize() ACCEPTS the witness");
    direct.insert_header(h.parent);
    expect_true(direct.read_storage(h.C, S3) == bytes32{}, "H7: slot S3 reads as 0");
    expect_true(check_root_accepts(direct, h.parent, h.accounts.root),
                "H8: check_root accepts the block that read S3, absent from storage_root, as 0");
}

#if USE_HASH_KEY
// Blocker regression: account whose ONLY slots are recovered ones, driven
// through the REAL StateTransition::check_root.
void RecoveredSlotsOnlyAccount_RealCheckRoot() {
    const evmc::address D = make_addr(0x44, 0x00);
    const bytes32 S1 = make_word(0x01);
    bytes32 S2 = make_word(0x02);
    const bytes32 kS1 = keccak_bytes32(S1);
    bytes32 kS2 = keccak_bytes32(S2);
    for (uint8_t b = 3; (kS1.bytes[0] >> 4) == (kS2.bytes[0] >> 4) && b != 0; ++b) {
        S2 = make_word(b);
        kS2 = keccak_bytes32(S2);
    }
    const bytes32 V1 = make_word(0xAA);
    const bytes32 V2 = make_word(0xBB);

    const bytes32 SR = hashbuilder_root({{kS1, scalar_rlp(V1)}, {kS2, scalar_rlp(V2)}});
    const Bytes leafS1_rlp = make_leaf_rlp(kS1, scalar_rlp(V1));
    const Bytes leafS2_rlp = make_leaf_rlp(kS2, scalar_rlp(V2));
    const bytes32 hashS1 = keccak_bytes(leafS1_rlp);
    const bytes32 hashS2 = keccak_bytes(leafS2_rlp);
    BranchNode br{};
    br.set_child(kS1.bytes[0] >> 4, ByteView{hashS1.bytes, 32});
    br.set_child(kS2.bytes[0] >> 4, ByteView{hashS2.bytes, 32});
    const Bytes sroot_rlp{encode_branch(br)};

    // D carries ZERO flat slots; storage_root still commits S1+S2.
    DirectState::AccountInfo info = make_info(D, 1, 777);
    std::memcpy(info.account.storage_root, SR.bytes, 32);

    // Anchor account E: first-nibble-distinct so prev_root is a branch.
    const bytes32 kD = keccak_addr32(D);
    evmc::address E = make_addr(0x55, 0x00);
    bytes32 kE = keccak_addr32(E);
    for (uint8_t b = 1; (kD.bytes[0] >> 4) == (kE.bytes[0] >> 4) && b != 0; ++b) {
        E = make_addr(0x55, b);
        kE = keccak_addr32(E);
    }
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts(
        {info, make_info(E, 0, 42)}, /*block_hashes=*/{}, /*code_store=*/{});
    expect_true(!prestate.empty(), "U1: prestate blob built");

    const Bytes dRlp_pre = account_rlp(D, 1, 777, SR);
    const Bytes eRlp = account_rlp(E, 0, 42);
    const bytes32 R = hashbuilder_root({{kD, dRlp_pre}, {kE, eRlp}});
    const Bytes leafD_rlp = make_leaf_rlp(kD, dRlp_pre);
    const Bytes leafE_rlp = make_leaf_rlp(kE, eRlp);
    BranchNode abr{};
    abr.set_child(kD.bytes[0] >> 4, ByteView{keccak_bytes(leafD_rlp).bytes, 32});
    abr.set_child(kE.bytes[0] >> 4, ByteView{keccak_bytes(leafE_rlp).bytes, 32});
    const Bytes aroot_rlp{encode_branch(abr)};
    expect_true(keccak_bytes(aroot_rlp) == R, "U2: hand-built account root matches R");

    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, SR, sroot_rlp);
    add_node(nb, hashS1, leafS1_rlp);
    add_node(nb, hashS2, leafS2_rlp);
    add_node(nb, R, aroot_rlp);
    add_node(nb, keccak_bytes(leafD_rlp), leafD_rlp);
    add_node(nb, keccak_bytes(leafE_rlp), leafE_rlp);
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!nodestore.empty(), "U2b: node store blob built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(), "U3: sanitize() ACCEPTS the witness");

    BlockHeader parent{};
    parent.number = 1;
    parent.state_root = R;
    direct.insert_header(parent);

    // 'Execution': the only touched slot is the recovered S2.
    expect_true(direct.read_storage(D, S2) == V2, "U4: hidden slot S2 recovered");
    Account* paD = direct.read_account(D);
    expect_true(paD != nullptr, "U5: account D readable");
    const bytes32 V2n = make_word(0xB2);
    direct.set_storage_slot(D, *paD, S2, V2n);

    const bytes32 postSR = hashbuilder_root({{kS1, scalar_rlp(V1)}, {kS2, scalar_rlp(V2n)}});
    const bytes32 R_post =
        hashbuilder_root({{kD, account_rlp(D, 1, 777, postSR)}, {kE, eRlp}});

    expect_true(check_root_accepts(direct, parent, R_post),
                "G5: real check_root keeps recovered-only storage recompute");
    // Flat/overflow empty, so the merge root is the recovered slot alone.
    expect_true(direct.account_storage_root(D) == hashbuilder_root({{kS2, scalar_rlp(V2n)}}),
                "G6: account_storage_root merges written recovered slot");
}

std::vector<uint8_t> make_code_store(const bytes32& code_hash, const Bytes& code) {
    MphfBuilder<32> cb{kMphfCodeStoreMagic, kMphfMapVersion};
    std::vector<uint8_t> body;
    FlatKv::encode(body, code_hash, ByteView{code.data(), code.size()});
    cb.add(hash_key8(code_hash), ByteView{body.data(), body.size()});
    return std::move(cb).finalize();
}

// R4 regression: a recovered contract must bind its code from the code store,
// not execute as empty code.
void HiddenContractAccount_CodeBoundFromCodeStore() {
    const evmc::address W = make_addr(0x66, 0x00);
    evmc::address K = make_addr(0x77, 0x00);
    const bytes32 kW = keccak_addr32(W);
    bytes32 kK = keccak_addr32(K);
    for (uint8_t b = 1; (kW.bytes[0] >> 4) == (kK.bytes[0] >> 4) && b != 0; ++b) {
        K = make_addr(0x77, b);
        kK = keccak_addr32(K);
    }
    const Bytes code{0x60, 0x01, 0x60, 0x00, 0x55, 0x00};  // PUSH1 1 PUSH1 0 SSTORE STOP
    const bytes32 code_hash = keccak_bytes(code);

    const Bytes wRlp = account_rlp(W, 0, 1000);
    const Bytes kRlp = account_rlp(K, 1, 0, silkworm::kEmptyRoot, code_hash);
    const bytes32 R = hashbuilder_root({{kW, wRlp}, {kK, kRlp}});
    const Bytes leafW_rlp = make_leaf_rlp(kW, wRlp);
    const Bytes leafK_rlp = make_leaf_rlp(kK, kRlp);
    BranchNode br{};
    br.set_child(kW.bytes[0] >> 4, ByteView{keccak_bytes(leafW_rlp).bytes, 32});
    br.set_child(kK.bytes[0] >> 4, ByteView{keccak_bytes(leafK_rlp).bytes, 32});
    const Bytes root_rlp{encode_branch(br)};
    expect_true(keccak_bytes(root_rlp) == R, "V1: hand-built account root matches R");

    // Flat state = {W}; K's preimage is hidden but its code IS in the code store.
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts(
        {make_info(W, 0, 1000)}, /*block_hashes=*/{}, make_code_store(code_hash, code));
    expect_true(!prestate.empty(), "V2: prestate blob built");

    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, R, root_rlp);
    add_node(nb, keccak_bytes(leafW_rlp), leafW_rlp);
    add_node(nb, keccak_bytes(leafK_rlp), leafK_rlp);
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!nodestore.empty(), "V3: node store blob built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(), "V4: sanitize() ACCEPTS the witness");

    BlockHeader parent{};
    parent.number = 1;
    parent.state_root = R;
    direct.insert_header(parent);

    const Account* paK = direct.read_account(K);
    expect_true(paK != nullptr && std::memcmp(paK->code_hash, code_hash.bytes, 32) == 0,
                "V5: hidden contract K recovered with its code_hash");
    expect_true(paK != nullptr && paK->code_store_len == code.size(),
                "G7: recovered account bound to its code-store entry");
    const ByteView got = direct.read_code(K);
    expect_true(got.size() == code.size() &&
                    std::memcmp(got.data(), code.data(), code.size()) == 0,
                "G8[SECURITY]: read_code on recovered contract returns its bytecode");
}
#endif

// R6 regression: leaf_A absent, not just preimage.
void MissingAccountNode_RejectedByValidator() {
    HiddenAccount h = hidden_account();
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, h.trie.root, h.trie.root_rlp);
    add_node(nb, keccak_bytes(h.trie.leaf1), h.trie.leaf1);  // leaf_W; leaf_A omitted
    std::vector<uint8_t> nodestore = std::move(nb).finalize();

    DirectState direct{std::span<uint8_t>{h.prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(), "M1: sanitize() ACCEPTS the witness");
    expect_true(!direct.find_node_rlp(keccak_bytes(h.trie.leaf2)).has_value(), "M2: leaf_A ABSENT from node store");
    direct.insert_header(h.parent);

#if USE_HASH_KEY
    // fatal() exits; observe from a child.
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        (void)direct.read_account(h.A);
        _exit(0);  // only if fatal() did not fire
    }
    int status = 0;
    const bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;
    expect_true(reaped && WIFEXITED(status) && WEXITSTATUS(status) == 1,
                "G9[SECURITY]: recovery walk halts (exit 1) on missing account leaf");
#else
    expect_true(!DirectStateView{direct}.get_account(h.A).has_value(), "M3: account A reads as absent");
    expect_true(!check_root_accepts(direct, h.parent, h.trie.root),
                "G9[SECURITY]: check_root rejects the claim that A is absent, its leaf missing from the witness");
#endif
}

}  // namespace

int main() {
    HiddenReadOnlyAccount_RejectedByCheckRoot();
    HonestAbsentAccount_AcceptedByCheckRoot();
    HiddenStorageSlot_RejectedByCheckRoot();
    HonestAbsentSlot_AcceptedByCheckRoot();
    MissingAccountNode_RejectedByValidator();
#if USE_HASH_KEY
    RecoveredSlotsOnlyAccount_RealCheckRoot();
    HiddenContractAccount_CodeBoundFromCodeStore();
#endif
    std::println("\n{} failure(s)", g_failures);
    return g_failures == 0 ? 0 : 1;
}
