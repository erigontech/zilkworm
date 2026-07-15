// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for a witness-validation soundness gap (PR #90 review):
//
//   A read-only account that EXISTS under prev_root can be OMITTED from the
//   flat witness. The EVM read path then returns it as empty/non-existent,
//   and check_root (GridMPT::calc_root_from_updates anchored at prev_root)
//   still reconstructs prev_root exactly — i.e. the witness is accepted.
//
// The two subsystems never reconcile:
//   * sanitize() only binds the identities that ARE present to their hashes.
//   * check_root only folds the accounts that ARE present (addr_hashes +
//     created); an omitted account's subtree hash flows through unchanged.
//   * the EVM read path (find_pre_account_unchecked) returns nullptr on a miss.
//
// Setup mirrors a real account trie: two accounts W and A whose keccak(addr)
// differ in the first nibble, so prev_root R is a single branch with two leaf
// children. The "witness" we build contains ONLY W in the flat state and ONLY
// {root, leaf_W} in the node store — A is committed by R (as the branch child
// hash child[nibble_A]) but is otherwise invisible.
//
// Standalone test (no gtest); exit code = failure count, like mphf_map_test.cpp.

#include <array>
#include <cstdint>
#include <cstring>
#include <print>
#include <source_location>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

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

bytes32 keccak_addr32(const evmc::address& a) {
    return keccak_bytes(ByteView{a.bytes, 20});
}

// Build the canonical account RLP via the SAME encoder the flat state uses,
// so the trie-leaf value is byte-identical to what check_root compares against.
Bytes account_rlp(const evmc::address& /*addr*/, uint64_t nonce, uint64_t balance) {
    Account acc{};
    acc.nonce = nonce;
    intx::uint256 bal{balance};
    std::memcpy(acc.balance, &bal, 32);
    std::memcpy(acc.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(acc.storage_root, silkworm::kEmptyRoot.bytes, 32);
    acc.code_store_len = 0;
    acc.slot_count = 0;
    const uint8_t len = acc.rlp_into_cache(silkworm::kEmptyRoot);
    return Bytes{acc.acc_rlp_buf, acc.acc_rlp_buf + len};
}

DirectState::AccountInfo make_info(const evmc::address& addr, uint64_t nonce, uint64_t balance) {
    DirectState::AccountInfo info{};
    info.addr = addr;
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

// Independent oracle: canonical state-trie root over the given (hashed_key, rlp)
// leaves, via silkworm::trie::HashBuilder (a different trie implementation than
// GridMPT). Leaves must be supplied sorted by hashed key.
bytes32 hashbuilder_root(std::vector<std::pair<bytes32, ByteView>> leaves) {
    std::sort(leaves.begin(), leaves.end(), [](const auto& x, const auto& y) {
        return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0;
    });
    silkworm::trie::HashBuilder hb;
    for (const auto& [k, v] : leaves)
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    return hb.root_hash();
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

    // --- Build the node store: {R -> root_rlp, hashW -> leafW_rlp} -----------
    //     leaf_A is deliberately NOT included: A is hidden.
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    {
        std::vector<uint8_t> body;
        FlatKv::encode(body, R, root_rlp);
        nb.add(hash_key8(R), ByteView{body.data(), body.size()});
        std::vector<uint8_t> body2;
        FlatKv::encode(body2, hashW, leafW_rlp);
        nb.add(hash_key8(hashW), ByteView{body2.data(), body2.size()});
    }
    std::vector<uint8_t> nodestore = std::move(nb).finalize();
    expect_true(!nodestore.empty(), "S5: node store blob built");

    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    expect_true(direct.sanitize(),
                "S6: sanitize() ACCEPTS the witness (all present identities hash-bind)");

    // node store models the hiding: A's leaf is absent, W's and root present.
    expect_true(direct.find_node_rlp(R).has_value(), "S7a: root node present in witness");
    expect_true(direct.find_node_rlp(hashW).has_value(), "S7b: leaf_W present in witness");
    expect_true(!direct.find_node_rlp(hashA).has_value(), "S7c: leaf_A HIDDEN (absent from witness)");

    // sanity: W is readable with the right balance.
    const Account* paW = direct.read_account(W);
    expect_true(paW != nullptr && direct.get_balance(W) == intx::uint256{W_BAL},
                "S8: witness account W reads back correctly");

    // ====================== THE EXPLOIT ======================================
    // (1) EVM read path: A exists under R but reads as empty/non-existent.
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
    GridMPT<true> acc_trie{direct, R};
    const bytes32 reconstructed = acc_trie.calc_root_from_updates({&updW, 1});
    expect_true(acc_trie.missing_count() == 0,
                "P1: validator reported NO missing node (witness looks complete)");
    expect_true(reconstructed == R,
                "P2: check_root ACCEPTS — reconstructs true prev_root R without A");

    // ====================== REGRESSION GUARD =================================
    // Sound behaviour: a witness that omits an account committed by prev_root
    // must NOT let the EVM observe that account as empty. Mirrors the (disabled)
    // USE_HASH_KEY node-store recovery intent. FAILS today → proves the hole;
    // flips green once read-path recovery / witness-completeness is enforced.
    expect_true(paA != nullptr,
                "G1[SECURITY]: account A (committed by prev_root) must be visible "
                "to the EVM, not read as empty");
}

// Regression test for the missing-preimage soundness gap (block 25538620):
//
//   An account leaf reachable in the node store whose 20-byte address
//   preimage is NOT known to the witness producer (e.g. a counterfactual
//   CREATE2 address) used to be silently dropped from the flat pre-state,
//   so the EVM read of e.g. BALANCE returned 0 for an account with funds.
//
// Fixed by keying the flat pre-state with the trie key keccak256(address)
// (always derivable from the leaf path) and hashing the queried address at
// lookup time. This test builds the pre-state exactly the way the producer
// now does for a preimage-less leaf — AccountInfo carries only addr_hash
// (raw addr zeroed) and pre-hashed storage keys — and checks execution-side
// reads observe the account and its storage.
void PreimagelessAccount_VisibleToExecution() {
    const evmc::address W = make_addr(0x33, 0x01);   // preimage known
    const evmc::address C = make_addr(0x44, 0x02);   // preimage withheld
    const bytes32 kC = keccak_addr32(C);

    const evmc::bytes32 raw_slot{intx::be::store<evmc::bytes32>(intx::uint256{7})};
    const bytes32 hashed_slot = keccak_bytes(ByteView{raw_slot.bytes, 32});
    const evmc::bytes32 slot_value{intx::be::store<evmc::bytes32>(intx::uint256{0xBEEF})};

    std::vector<DirectState::AccountInfo> accts;
    accts.push_back(make_info(W, /*nonce=*/1, /*balance=*/1000));

    // Producer view of a preimage-less leaf: trie keys only.
    DirectState::AccountInfo hidden{};
    hidden.addr_hash = std::bit_cast<evmc::bytes32>(kC);
    hidden.storage_keys_hashed = true;
    hidden.account.nonce = 0;
    intx::uint256 bal{5000};
    std::memcpy(hidden.account.balance, &bal, 32);
    std::memcpy(hidden.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(hidden.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    hidden.storage.emplace_back(std::bit_cast<evmc::bytes32>(hashed_slot), slot_value);
    accts.push_back(std::move(hidden));

    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts(std::move(accts),
                                              /*block_hashes=*/{}, /*code_store=*/{});
    expect_true(!prestate.empty(), "P1: prestate blob built without any address preimage for C");

    DirectState direct{std::span<uint8_t>{prestate}};
    expect_true(direct.sanitize(),
                "P2: sanitize() accepts hashed-key records (no preimage required)");

    // Execution-side reads hash the queried address/slot themselves.
    const Account* paC = direct.read_account(C);
    expect_true(paC != nullptr,
                "P3: preimage-less account C is visible to the EVM read path");
    expect_true(direct.get_balance(C) == intx::uint256{5000},
                "P4: BALANCE(C) reads the trie-committed value, not 0");
    expect_true(direct.read_storage(C, raw_slot) == slot_value,
                "P5: SLOAD(C, slot) resolves via keccak256(slot) trie key");
    expect_true(direct.read_account(W) != nullptr &&
                    direct.get_balance(W) == intx::uint256{1000},
                "P6: raw-address producer path (W) still resolves");

    // Root recomputation needs no preimage either.
    const auto root = direct.state_root_hash();
    expect_true(root.has_value(), "P7: state_root_hash computable without preimages");
    if (root.has_value()) {
        const Bytes wRlp = account_rlp(W, 1, 1000);
        Account acc_c{};
        acc_c.nonce = 0;
        std::memcpy(acc_c.balance, &bal, 32);
        std::memcpy(acc_c.code_hash, silkworm::kEmptyHash.bytes, 32);
        Bytes value_rlp;
        silkworm::rlp::encode(value_rlp, silkworm::zeroless_view(ByteView{slot_value.bytes, 32}));
        silkworm::trie::HashBuilder shb;
        shb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{hashed_slot.bytes, 32}), value_rlp);
        const bytes32 c_storage_root = shb.root_hash();
        const uint8_t len = acc_c.rlp_into_cache(std::bit_cast<evmc::bytes32>(c_storage_root));
        const Bytes cRlp{acc_c.acc_rlp_buf, acc_c.acc_rlp_buf + len};
        const bytes32 expected =
            hashbuilder_root({{keccak_addr32(W), wRlp}, {kC, cRlp}});
        expect_true(*root == expected,
                    "P8: recomputed state root matches canonical trie root");
    }
}

}  // namespace

int main() {
    HiddenReadOnlyAccount_AcceptedByValidator();
    PreimagelessAccount_VisibleToExecution();
    std::println("\n{} failure(s)", g_failures);
    return g_failures == 0 ? 0 : 1;
}
