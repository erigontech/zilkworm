// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for a witness-validation soundness gap (PR #90 review):
//
//   A read-only account (or storage slot) that EXISTS under prev_root can be
//   OMITTED from the flat witness. The EVM read path then returns it as
//   empty/non-existent, and check_root (GridMPT::calc_root_from_updates
//   anchored at prev_root) still reconstructs prev_root exactly — i.e. the
//   witness is accepted.
//
// The two subsystems never reconcile:
//   * sanitize() only binds the identities that ARE present to their hashes.
//   * check_root only folds the accounts that ARE present (addr_hashes +
//     created); an omitted account's subtree hash flows through unchanged.
//   * the EVM read path (find_pre_account_unchecked) returns nullptr on a miss.
//
// Setup mirrors a real trie: account W is witnessed, account A's leaf is in
// the node store but its preimage is missing from the keys (the USE_HASH_KEY
// witness bug); the storage twin hides slot S2 behind C's storage_root.
// MissingAccountNode_* keeps the original hiding (leaf_A absent): flag-on halts.
//
// Flag-on every case passes; flag-off the G-cases FAIL (the documented
// soundness hole). Deliberately not registered with ctest.
//
// Standalone test (no gtest); exit code = failure count, like mphf_map_test.cpp.

#include <array>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

#include "../state_transition.hpp"
#endif

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

// Mirrors check_root's per-account storage recompute: flat slots (initial +
// current-if-changed), overflow slots (current only), and — flag-on —
// recovered slots (initial + current-if-changed).
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
#if USE_HASH_KEY
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
#endif
    std::sort(upds.begin(), upds.end());
    GridMPT<true, DirectState> st{direct, anchor};
    return st.calc_root_from_updates({upds.data(), upds.size()});
}

void HiddenReadOnlyAccount_AcceptedByValidator() {
    // --- Two accounts with first-nibble-distinct hashed keys -----------------
    const evmc::address W = make_addr(0x11, 0x00);
    evmc::address A = make_addr(0x22, 0x00);
    const bytes32 kW = keccak_addr32(W);
    bytes32 kA = keccak_addr32(A);
    for (uint8_t b = 1; (kW.bytes[0] >> 4) == (kA.bytes[0] >> 4) && b != 0; ++b) {
        A = make_addr(0x22, b);
        kA = keccak_addr32(A);
    }
    expect_true((kW.bytes[0] >> 4) != (kA.bytes[0] >> 4),
                "S1: W and A hashed keys differ in first nibble (single-branch root)");

    const uint64_t W_BAL = 1000;
    const uint64_t A_BAL = 5000;  // the 'hidden' funds that exist under prev_root
    const Bytes wRlp = account_rlp(W, /*nonce=*/0, W_BAL);
    const Bytes aRlp = account_rlp(A, /*nonce=*/0, A_BAL);

    // --- prev_root R: canonical root committing to BOTH W and A --------------
    const bytes32 R = hashbuilder_root({{kW, wRlp}, {kA, aRlp}});
    const bytes32 R_without_A = hashbuilder_root({{kW, wRlp}});
    expect_true(R != R_without_A,
                "S2: prev_root R provably commits to A (R != root without A)");

    // --- Hand-build the trie nodes; confirm they reproduce canonical R -------
    const Bytes leafW_rlp = make_leaf_rlp(kW, wRlp);
    const Bytes leafA_rlp = make_leaf_rlp(kA, aRlp);
    const bytes32 hashW = keccak_bytes(leafW_rlp);
    const bytes32 hashA = keccak_bytes(leafA_rlp);

    BranchNode br{};
    br.set_child(kW.bytes[0] >> 4, ByteView{hashW.bytes, 32});
    br.set_child(kA.bytes[0] >> 4, ByteView{hashA.bytes, 32});
    const Bytes root_rlp{encode_branch(br)};
    expect_true(keccak_bytes(root_rlp) == R,
                "S3: hand-built root node hashes to canonical prev_root R");

    // --- Build the WITNESS: flat state = {W} only (A omitted) ----------------
    std::vector<DirectState::AccountInfo> accts{make_info(W, 0, W_BAL)};
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts(accts, /*block_hashes=*/{}, /*code_store=*/{});
    expect_true(!prestate.empty(), "S4: prestate blob built");

    // --- Node store: {R, leaf_W, leaf_A} — A's leaf IS committed and present,
    //     but its address preimage is missing from the flat keys.
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, R, root_rlp);
    add_node(nb, hashW, leafW_rlp);
    add_node(nb, hashA, leafA_rlp);
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!nodestore.empty(), "S5: node store blob built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(),
                "S6: sanitize() ACCEPTS the witness (all present identities hash-bind)");

    // Node store models the bug: A's leaf present, its preimage absent from keys.
    expect_true(direct.find_node_rlp(R).has_value(), "S7a: root node present in witness");
    expect_true(direct.find_node_rlp(hashW).has_value(), "S7b: leaf_W present in witness");
    expect_true(direct.find_node_rlp(hashA).has_value(),
                "S7c: leaf_A present in node store (preimage hidden from keys)");

    // sanity: W is readable with the right balance.
    const Account* paW = direct.read_account(W);
    expect_true(paW != nullptr && direct.get_balance(W) == intx::uint256{W_BAL},
                "S8: witness account W reads back correctly");

    // Parent header supplies the pre-state root the account walker starts from.
    BlockHeader parent{};
    parent.number = 1;
    parent.state_root = R;
    direct.insert_header(parent);

    // ====================== THE EXPLOIT ======================================
    // (1) EVM read path: A exists under R but — without recovery — reads as
    //     empty/non-existent.
    const Account* paA = direct.read_account(A);
    const intx::uint256 balA = direct.get_balance(A);
    std::println("    [observed] read_account(A) = {}, get_balance(A) = {}",
                 paA == nullptr ? "nullptr" : "non-null",
                 static_cast<uint64_t>(balA[0]));

    // (2) Validator core: anchored at the TRUE prev_root R, given only W as a
    //     read-only update (exactly what check_root builds from this flat
    //     state), reconstruct the root. A is never unfolded → its child hash
    //     flows through unchanged → result is exactly R. Witness ACCEPTED.
    TrieNodeFlat updW{kW};
    updW.ext_initial = ByteView{wRlp.data(), wRlp.size()};  // initial == pre-value
    updW.self_initial_len = 0;
    updW.current_off = 0;
    updW.current_len = 0;  // read-only: no SSTORE/no balance change
    GridMPT<true, DirectState> acc_trie{direct, R};
    const bytes32 reconstructed = acc_trie.calc_root_from_updates({&updW, 1});
    expect_true(acc_trie.missing_count() == 0,
                "P1: validator reported NO missing node (witness looks complete)");
#ifndef NDEBUG
    expect_true(!acc_trie.failed(),
                "P1: validator reported NO failure (witness looks complete)");
#endif
    expect_true(reconstructed == R,
                "P2: check_root ACCEPTS — reconstructs true prev_root R without A");

    // ====================== REGRESSION GUARD =================================
    // Sound behaviour: a witness whose flat keys omit an account committed by
    // prev_root must NOT let the EVM observe it as empty. USE_HASH_KEY
    // node-store recovery makes this pass; flag-off it FAILS → proves the hole.
    expect_true(paA != nullptr && balA == intx::uint256{A_BAL},
                "G1[SECURITY]: account A (committed by prev_root) must be visible "
                "to the EVM, not read as empty");

    // Recovered accounts have empty storage; a slot read must be a clean miss.
    expect_true(direct.read_storage(A, make_word(0x01)) == bytes32{},
                "S9: slot read on (recovered) empty-storage account returns 0");
}

void HiddenStorageSlot_RecoveredFromNodeStore() {
    // --- Account C with two slots whose hashed keys split at the first nibble
    const evmc::address C = make_addr(0x33, 0x00);
    const bytes32 S1 = make_word(0x01);
    bytes32 S2 = make_word(0x02);
    const bytes32 kS1 = keccak_bytes32(S1);
    bytes32 kS2 = keccak_bytes32(S2);
    for (uint8_t b = 3; (kS1.bytes[0] >> 4) == (kS2.bytes[0] >> 4) && b != 0; ++b) {
        S2 = make_word(b);
        kS2 = keccak_bytes32(S2);
    }
    expect_true((kS1.bytes[0] >> 4) != (kS2.bytes[0] >> 4),
                "T1: S1 and S2 hashed slot keys differ in first nibble");

    const bytes32 V1 = make_word(0xAA);
    const bytes32 V2 = make_word(0xBB);  // the 'hidden' value committed by storage_root
    const Bytes v1_rlp = scalar_rlp(V1);
    const Bytes v2_rlp = scalar_rlp(V2);

    // --- Canonical pre storage root SR over BOTH slots ------------------------
    const bytes32 SR = hashbuilder_root({{kS1, v1_rlp}, {kS2, v2_rlp}});

    // --- Hand-build the storage trie nodes; confirm they reproduce SR --------
    const Bytes leafS1_rlp = make_leaf_rlp(kS1, v1_rlp);
    const Bytes leafS2_rlp = make_leaf_rlp(kS2, v2_rlp);
    const bytes32 hashS1 = keccak_bytes(leafS1_rlp);
    const bytes32 hashS2 = keccak_bytes(leafS2_rlp);
    BranchNode br{};
    br.set_child(kS1.bytes[0] >> 4, ByteView{hashS1.bytes, 32});
    br.set_child(kS2.bytes[0] >> 4, ByteView{hashS2.bytes, 32});
    const Bytes sroot_rlp{encode_branch(br)};
    expect_true(keccak_bytes(sroot_rlp) == SR,
                "T2: hand-built storage root node hashes to canonical SR");

    // --- Flat witness: C carries ONLY S1; storage_root still commits to S2 ---
    DirectState::AccountInfo info = make_info(C, 1, 777);
    std::memcpy(info.account.storage_root, SR.bytes, 32);
    info.storage.push_back({S1, V1});
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({info}, /*block_hashes=*/{}, /*code_store=*/{});
    expect_true(!prestate.empty(), "T3: prestate blob built");

    // --- Node store: complete storage trie {SR, leaf_S1, leaf_S2} ------------
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, SR, sroot_rlp);
    add_node(nb, hashS1, leafS1_rlp);
    add_node(nb, hashS2, leafS2_rlp);
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!nodestore.empty(), "T4: node store blob built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(), "T5: sanitize() ACCEPTS the witness");

    expect_true(direct.read_storage(C, S1) == V1, "T6: witnessed slot S1 reads back");

    // --- Case 1: hidden-slot read ---------------------------------------------
    const bytes32 readS2 = direct.read_storage(C, S2);
    std::println("    [observed] read_storage(C, S2) = 0x..{:02x}", readS2.bytes[31]);
    expect_true(readS2 == V2,
                "G2[SECURITY]: slot S2 (committed by storage_root) must be visible "
                "to the EVM, not read as 0");

    // Read-only recompute: anchors alone must reproduce SR.
    expect_true(recompute_storage_root(direct, C, SR) == SR,
                "T7: read-only storage recompute reproduces SR");

    // --- Case 2: write both the witnessed and the recovered slot -------------
    Account* paC = direct.read_account(C);
    expect_true(paC != nullptr, "T8: account C readable");
    const bytes32 V1n = make_word(0xA1);
    const bytes32 V2n = make_word(0xB1);
    direct.set_storage_slot(C, *paC, S1, V1n);
    direct.set_storage_slot(C, *paC, S2, V2n);
    expect_true(direct.read_storage(C, S2) == V2n,
                "T9: written slot S2 reads back the new value");
    const bytes32 post1 = hashbuilder_root({{kS1, scalar_rlp(V1n)}, {kS2, scalar_rlp(V2n)}});
    expect_true(recompute_storage_root(direct, C, SR) == post1,
                "G3: storage recompute matches oracle after writing recovered slot");

    // --- Case 3: zero-write deletes the recovered slot's leaf ----------------
    direct.set_storage_slot(C, *paC, S2, bytes32{});
    expect_true(direct.read_storage(C, S2) == bytes32{},
                "T10: zeroed slot S2 reads back 0");
    const bytes32 post2 = hashbuilder_root({{kS1, scalar_rlp(V1n)}});
    expect_true(recompute_storage_root(direct, C, SR) == post2,
                "G4: storage recompute matches oracle after zero-write delete");
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

    BlockHeader head{};
    head.number = 2;
    head.parent_hash = parent.hash();
    head.state_root = R_post;
    silkworm::cmd::state_transition::StateTransition st{std::span<uint8_t>{}};
    expect_true(st.check_root(direct, head, EVMC_CANCUN),
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
    const evmc::address W = make_addr(0x11, 0x00);
    evmc::address A = make_addr(0x22, 0x00);
    const bytes32 kW = keccak_addr32(W);
    bytes32 kA = keccak_addr32(A);
    for (uint8_t b = 1; (kW.bytes[0] >> 4) == (kA.bytes[0] >> 4) && b != 0; ++b) {
        A = make_addr(0x22, b);
        kA = keccak_addr32(A);
    }
    const uint64_t W_BAL = 1000;
    const Bytes wRlp = account_rlp(W, 0, W_BAL);
    const Bytes aRlp = account_rlp(A, 0, 5000);
    const bytes32 R = hashbuilder_root({{kW, wRlp}, {kA, aRlp}});
    const Bytes leafW_rlp = make_leaf_rlp(kW, wRlp);
    const bytes32 hashW = keccak_bytes(leafW_rlp);
    const bytes32 hashA = keccak_bytes(make_leaf_rlp(kA, aRlp));
    BranchNode br{};
    br.set_child(kW.bytes[0] >> 4, ByteView{hashW.bytes, 32});
    br.set_child(kA.bytes[0] >> 4, ByteView{hashA.bytes, 32});
    const Bytes root_rlp{encode_branch(br)};
    expect_true(keccak_bytes(root_rlp) == R, "M1: hand-built account root matches R");

    // Node store omits leaf_A entirely.
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts(
        {make_info(W, 0, W_BAL)}, /*block_hashes=*/{}, /*code_store=*/{});
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    add_node(nb, R, root_rlp);
    add_node(nb, hashW, leafW_rlp);
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!prestate.empty() && !nodestore.empty(), "M2: witness blobs built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(), "M3: sanitize() ACCEPTS the witness");
    expect_true(!direct.find_node_rlp(hashA).has_value(), "M4: leaf_A ABSENT from node store");

    BlockHeader parent{};
    parent.number = 1;
    parent.state_root = R;
    direct.insert_header(parent);

    // A never unfolded: its hash flows through.
    TrieNodeFlat updW{kW};
    updW.ext_initial = ByteView{wRlp.data(), wRlp.size()};
    GridMPT<true, DirectState> acc_trie{direct, R};
    const bytes32 reconstructed = acc_trie.calc_root_from_updates({&updW, 1});
    expect_true(reconstructed == R && acc_trie.missing_count() == 0,
                "M5: validator core ACCEPTS — never unfolds the missing leaf");

#if USE_HASH_KEY
    // fatal() exits; observe from a child.
    std::fflush(stdout);
    const pid_t pid = fork();
    if (pid == 0) {
        (void)direct.read_account(A);
        _exit(0);  // only if fatal() did not fire
    }
    int status = 0;
    const bool reaped = pid > 0 && waitpid(pid, &status, 0) == pid;
    expect_true(reaped && WIFEXITED(status) && WEXITSTATUS(status) == 1,
                "G9[SECURITY]: recovery walk halts (exit 1) on missing account leaf");
#else
    expect_true(direct.read_account(A) != nullptr,
                "G9[SECURITY]: account A (committed by prev_root) must be visible "
                "to the EVM, not read as empty");
#endif
}

}  // namespace

int main() {
    HiddenReadOnlyAccount_AcceptedByValidator();
    HiddenStorageSlot_RecoveredFromNodeStore();
    MissingAccountNode_RejectedByValidator();
#if USE_HASH_KEY
    RecoveredSlotsOnlyAccount_RealCheckRoot();
    HiddenContractAccount_CodeBoundFromCodeStore();
#endif
    std::println("\n{} failure(s)", g_failures);
    return g_failures == 0 ? 0 : 1;
}
