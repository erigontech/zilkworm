// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Unit test: a GENUINE account present in addr_hashes with a valid body + hash, but
// unreachable via the MPHF read path (find()) — an ORPHANED slot — lets a full stateless
// validation accept an invalid state transition. End-to-end soundness proof driven through
// the PUBLIC guest entry point (StateTransition::run over real MFBD envelopes).
//
// Scenario: accounts S (sender EOA), D (contract whose code does SSTORE(0, BALANCE(C)+1)),
// and C (EOA, balance 5000), all committed by prev_root. Zeroing C's MPHF slot leaves C's
// addr_hashes entry, body and leaf intact, but makes find(C) miss. An EVM run of "S calls D"
// then reads C as empty, so D stores 1 instead of 5001 — a different post-state.
// The account-trie GridMPT builds its updates from addr_hashes (which still lists C) and
// unfolds from the node store; it never consults find(), so it reconstructs the orphaned
// post-root cleanly and would accept it against a header carrying that root.
// sanitize()'s per-entry routing check rejects the bundle.

// The orphaned bundle is well-formed: same layout as the genuine one except two things that
// get forged in the serialized bytes:
// - C's MPHF slot is zeroed (so in the EVM read path C is empty)
// - C's Account cache is filled with the genuine RLP (saniitize won't fill it if the slot is zeroed)
// The forged bundle passes all other checks (prestate layout, MPHF integrity, etc.) and is accepted
// by StateTransition::run() if the routing check is disabled.
// It is authored entirely at rest (forge_orphan touches only serialized-layout fields an
// untrusted producer could control); nothing is mutated on a live parsed object mid-run.

// The pre-state root (R) is computed from the genuine leaf, so it is the same for both bundles.
// The divergence happens at the post-state root: check_root rebuilds it from addr_hashes and node
// store, where C is genuine and unchanged. The forged block commits state root as forged_root;
// check_root reproduces exactly that (C read as the genuine 5000 via addr_hashes, unchanged) and
// accepts, even though forged_root is an incoherent state: D was computed as if C's balance was 0,
// yet C's balance still is 5000.
// That contradiction (EVM sees C via find, check_root sees C via addr_hashes) is the whole bug a
// forged MFBD bundle may exploit. The routing check is what forces the two views to agree.


#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <zilk_core/core/common_zz/data_byte_count.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/crypto/ecdsa.h>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/execution/processor.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie/vector_root.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/bloom.hpp>
#include <zilk_core/core/types/receipt.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

#include <zilk_core/dev/state_transition.hpp>

using namespace zilkworm;
using silkworm::ByteView;
using silkworm::Bytes;
namespace protocol = silkworm::protocol;
using silkworm::cmd::state_transition::StateTransition;

namespace {

evmc::address make_addr(uint8_t b0, uint8_t b19) {
    evmc::address a{};
    a.bytes[0] = b0;
    a.bytes[19] = b19;
    return a;
}
bytes32 keccak_addr32(const evmc::address& a) { return keccak_bytes(ByteView{a.bytes, 20}); }

// PUSH20 <C>; BALANCE; PUSH1 1; ADD; PUSH1 0; SSTORE; STOP -> storage[0] = balance(C)+1.
Bytes balance_probe_code(const evmc::address& c) {
    Bytes code;
    code.push_back(0x73);
    code.insert(code.end(), c.bytes, c.bytes + 20);
    code.push_back(0x31);
    code.push_back(0x60);
    code.push_back(0x01);
    code.push_back(0x01);
    code.push_back(0x60);
    code.push_back(0x00);
    code.push_back(0x55);
    code.push_back(0x00);
    return code;
}

Bytes account_rlp(const evmc::address& addr, uint64_t nonce, const intx::uint256& balance,
                  const bytes32& code_hash, const bytes32& storage_root) {
    Account acc{};
    std::memcpy(acc.addr, addr.bytes, 20);
    acc.nonce = nonce;
    std::memcpy(acc.balance, &balance, 32);
    std::memcpy(acc.code_hash, code_hash.bytes, 32);
    std::memcpy(acc.storage_root, storage_root.bytes, 32);
    const uint8_t len = acc.rlp_into_cache(storage_root);
    return Bytes{acc.acc_rlp_buf, acc.acc_rlp_buf + len};
}

DirectState::AccountInfo make_eoa(const evmc::address& addr, uint64_t nonce, const intx::uint256& balance) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = nonce;
    std::memcpy(info.account.balance, &balance, 32);
    std::memcpy(info.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(info.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    return info;
}

DirectState::AccountInfo make_contract(const evmc::address& addr, uint64_t nonce,
                                       const bytes32& code_hash, uint32_t code_len) {
    DirectState::AccountInfo info{};
    info.addr = addr;
    std::memcpy(info.account.addr, addr.bytes, 20);
    info.account.nonce = nonce;
    std::memcpy(info.account.code_hash, code_hash.bytes, 32);
    std::memcpy(info.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    info.account.code_store_len = code_len;
    return info;
}

std::vector<uint8_t> build_code_store(const bytes32& code_hash, ByteView code) {
    MphfBuilder<32> cb{kMphfCodeStoreMagic, kMphfMapVersion};
    std::vector<uint8_t> body;
    FlatKv::encode(body, code_hash, code);
    body.insert(body.end(), FlatKv::kCodePadding, 0);  // Execute-in-place padding.
    cb.add(hash_key8(code_hash), ByteView{body.data(), body.size()});
    return std::move(cb).finalize();
}

// Account-trie node store via HashBuilder rlp_collector; returns the pre-state root.
bytes32 build_account_node_store(std::vector<std::pair<bytes32, Bytes>> leaves,
                                 std::vector<uint8_t>& node_store_out) {
    std::sort(leaves.begin(), leaves.end(),
              [](const auto& x, const auto& y) { return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0; });
    std::vector<std::pair<bytes32, Bytes>> captured;
    silkworm::trie::HashBuilder hb;
    hb.rlp_collector = [&](ByteView node_rlp) {
        captured.emplace_back(keccak_bytes(node_rlp), Bytes{node_rlp.begin(), node_rlp.end()});
    };
    for (const auto& [k, v] : leaves)
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), ByteView{v.data(), v.size()});
    const bytes32 root = hb.root_hash();
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : captured) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, ByteView{rlp.data(), rlp.size()});
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    node_store_out = std::move(nb).finalize();
    return root;
}

// Byte-level authoring of the malicious bundle, applied at rest (no live parse):
//   (1) seal C's genuine RLP into its Account POD cache (part of the serialized bytes);
//   (2) set C's MPHF slot to 0 so find(C) misses.
void forge_orphan(std::vector<uint8_t>& blob, const evmc::address& victim) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    auto* slots = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mh) + mh->slot_offsets_offset);
    uint8_t* data = reinterpret_cast<uint8_t*>(mh) + mh->data_offset;
    auto* ahe = reinterpret_cast<AddrHashEntry*>(blob.data() + meta->addr_hashes_offset);
    for (uint32_t i = 0; i < meta->n_accounts; ++i) {
        if (std::memcmp(ahe[i].addr, victim.bytes, 20) == 0) {
            auto* pa = reinterpret_cast<Account*>(data + ahe[i].entry_offset + 8u);
            pa->rlp_into_cache(std::bit_cast<evmc::bytes32>(pa->storage_root));
            break;
        }
    }
    slots[mh->index_lookup(addr_key8(victim))] = 0;
}

// The tx the block carries: <recovered sender> -> D, gas price 0. A fixed valid
// secp256k1 signature is attached (values from a real signed tx, so r is a valid
// curve x-coordinate) — the sender is whatever the signature recovers to. run()
// RLP-decodes the block, so the sender MUST come from the signature, not set_sender
// (which does not survive encode/decode); we build the pre-state around the recovered
// address instead of signing a chosen one.
silkworm::Transaction make_txn(const evmc::address& D) {
    silkworm::Transaction tx{};
    tx.type = silkworm::TransactionType::kLegacy;
    tx.chain_id = 1;
    tx.nonce = 0;
    tx.max_fee_per_gas = 0;
    tx.max_priority_fee_per_gas = 0;
    tx.gas_limit = 1'000'000;
    tx.to = D;
    tx.value = 0;
    tx.r = intx::from_string<intx::uint256>(
        "0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276");
    tx.s = intx::from_string<intx::uint256>(
        "0x67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
    tx.odd_y_parity = false;
    return tx;
}

// Sender the attached signature recovers to (same computation as Transaction::sender).
evmc::address recover_sender(const silkworm::Transaction& tx) {
    Bytes rlp;
    tx.encode_for_signing(rlp);
    const auto hash = silkworm::keccak256(rlp);
    uint8_t sig[64];
    intx::be::unsafe::store(sig, tx.r);
    intx::be::unsafe::store(sig + 32, tx.s);
    evmc::address out{};
    const bool ok = silkworm_recover_address(out.bytes, hash.bytes, sig, tx.odd_y_parity);
    return ok ? out : evmc::address{};
}

// Account-trie root over the post-execution state, computed as check_root does:
// read-only C from addr_hashes (genuine leaf), modified S/D re-encoded live, GridMPT
// anchored at prev_root. missing == 0 means the node store unfolds cleanly.
bytes32 post_root(DirectState& ds, const bytes32& prev_root,
                  const evmc::address& S, const bytes32& kS, const Bytes& rlpS,
                  const evmc::address& D, const bytes32& kD, const Bytes& rlpD,
                  const bytes32& kC, const Bytes& rlpC, unsigned& missing) {
    std::vector<TrieNodeFlat> ups;
    auto add_modified = [&](const bytes32& k, const Bytes& pre, const evmc::address& addr) {
        TrieNodeFlat u{k};
        u.ext_initial = ByteView{pre.data(), pre.size()};
        u.self_initial_len = 0;
        const Account* pa = ds.read_account(addr);
        u.current_off = 0;
        u.current_len = pa->rlp_into(u.buf + 0, ds.account_storage_root(addr));
        ups.push_back(u);
    };
    add_modified(kS, rlpS, S);
    add_modified(kD, rlpD, D);
    {
        TrieNodeFlat u{kC};
        u.ext_initial = ByteView{rlpC.data(), rlpC.size()};
        u.self_initial_len = 0;
        u.current_off = 0;
        u.current_len = 0;
        ups.push_back(u);
    }
    std::sort(ups.begin(), ups.end(), [](const TrieNodeFlat& x, const TrieNodeFlat& y) {
        return std::memcmp(x.key.bytes, y.key.bytes, 32) < 0;
    });
    GridMPT<true> acc_trie{ds, prev_root};
    const bytes32 root = acc_trie.calc_root_from_updates({ups.data(), ups.size()});
    missing = acc_trie.missing_count();
    return root;
}

// Attacker-side simulation of the orphaned execution to learn the header fields the
// forged block must carry (gas, receipt/tx roots, bloom, state_root). Runs on a COPY
// so the bundle handed to the guest stays exactly as authored.
struct ShadowResult {
    uint64_t gas_used{};
    evmc::bytes32 receipts_root{};
    silkworm::Bloom logs_bloom{};
    bytes32 state_root{};
    evmc::bytes32 storage{};
};

ShadowResult shadow_execute(std::vector<uint8_t> blob, std::span<uint8_t> nodestore,
                            const bytes32& prev_root, const silkworm::BlockHeader& provisional,
                            const silkworm::Transaction& tx,
                            const evmc::address& S, const bytes32& kS, const Bytes& rlpS,
                            const evmc::address& D, const bytes32& kD, const Bytes& rlpD,
                            const bytes32& kC, const Bytes& rlpC,
                            void (*forge)(std::vector<uint8_t>&, const evmc::address&) = nullptr,
                            const evmc::address& victim = {}) {
    DirectState ds{std::span<uint8_t>{blob}, nodestore};
    ds.sanitize();  // genuine bundle: resolves D's code + fills caches in the MPHF sweep
    if (forge) forge(blob, victim);  // author the orphan at rest AFTER code is resolved

    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);

    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
    // Bypasses pre-validation, so publish what it would have computed.
    const auto& t0 = block.transactions[0];
    t0.set_data_non_zero_bytes(zilkworm::count_nonzero_bytes(t0.data));
    proc.execute_transaction(t0, receipt);

    ShadowResult r{};
    r.gas_used = receipt.cumulative_gas_used;
    static constexpr auto kEncoder = [](Bytes& to, const silkworm::Receipt& rc) { silkworm::rlp::encode(to, rc); };
    std::vector<silkworm::Receipt> receipts{receipt};
    r.receipts_root = silkworm::trie::root_hash(receipts, kEncoder);
    r.logs_bloom = silkworm::Bloom{};
    silkworm::join(r.logs_bloom, receipt.bloom);
    r.storage = ds.read_storage(D, evmc::bytes32{});
    unsigned missing = 1;
    r.state_root = post_root(ds, prev_root, S, kS, rlpS, D, kD, rlpD, kC, rlpC, missing);
    return r;
}

std::vector<uint8_t> wrap_mfbd(const std::vector<uint8_t>& flat_bundle) {
    std::vector<uint8_t> env(kInputHeaderSizeMFBD, 0);
    uint32_t magic = kInputMagicMFBD, version = kInputVersionMFBD;
    uint64_t n = 1;
    std::memcpy(env.data() + 0, &magic, 4);
    std::memcpy(env.data() + 4, &version, 4);
    std::memcpy(env.data() + 8, &n, 8);
    env.insert(env.end(), flat_bundle.begin(), flat_bundle.end());
    return env;
}

}  // namespace

TEST_CASE("StateTransition::run accepts the genuine MFBD but must reject the orphaned one",
          "[mphf][state_transition][exec]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address C = make_addr(0x33, 0x03);

    // Sender is derived from the tx signature (see make_txn/recover_sender): the block
    // is RLP-decoded by run(), so the pre-state must be built around the recovered S.
    const silkworm::Transaction tx = make_txn(D);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != C);
    const bytes32 kS = keccak_addr32(S), kD = keccak_addr32(D), kC = keccak_addr32(C);

    const Bytes code = balance_probe_code(C);
    const bytes32 code_hash = keccak_bytes(ByteView{code.data(), code.size()});

    const uint64_t C_BAL = 5000;
    const intx::uint256 S_BAL{intx::uint256{1} << 64};
    const Bytes rlpS = account_rlp(S, 0, S_BAL, silkworm::kEmptyHash, silkworm::kEmptyRoot);
    const Bytes rlpD = account_rlp(D, 1, 0, code_hash, silkworm::kEmptyRoot);
    const Bytes rlpC = account_rlp(C, 0, intx::uint256{C_BAL}, silkworm::kEmptyHash, silkworm::kEmptyRoot);

    std::vector<uint8_t> nodestore;
    const bytes32 R = build_account_node_store({{kS, rlpS}, {kD, rlpD}, {kC, rlpC}}, nodestore);
    REQUIRE_FALSE(nodestore.empty());

    const std::vector<uint8_t> code_store = build_code_store(code_hash, ByteView{code.data(), code.size()});

    auto build_prestate = [&]() {
        std::vector<DirectState::AccountInfo> accts{
            make_eoa(S, 0, S_BAL),
            make_contract(D, 1, code_hash, static_cast<uint32_t>(code.size())),
            make_eoa(C, 0, intx::uint256{C_BAL})};
        return DirectState::build_blob_from_accounts(accts, {}, code_store);
    };

    // Two pre-state bundles over the SAME accounts: one genuine, one with C orphaned
    // from the MPHF read path (well-formed layout; find(C) misses, addr_hashes[C] intact).
    std::vector<uint8_t> genuine_blob = build_prestate();
    std::vector<uint8_t> forged_blob = build_prestate();
    forge_orphan(forged_blob, C);

    // ---- Genesis (parent, block 0) anchors prev_root = R for both bundles ----
    silkworm::Block genesis{};
    genesis.header.number = 0;
    genesis.header.state_root = R;
    genesis.header.gas_limit = 30'000'000;
    genesis.header.gas_used = 0;
    genesis.header.timestamp = 1000;
    genesis.header.ommers_hash = silkworm::kEmptyListHash;
    genesis.header.transactions_root = silkworm::kEmptyRoot;
    genesis.header.receipts_root = silkworm::kEmptyRoot;
    genesis.header.base_fee_per_gas = intx::uint256{0};
    genesis.header.withdrawals_root = silkworm::kEmptyRoot;
    genesis.withdrawals = std::vector<silkworm::Withdrawal>{};
    Bytes genesis_rlp;
    silkworm::rlp::encode(genesis_rlp, genesis);

    // ---- Shared valid Shanghai block carrying the S->D tx (roots/gas filled per-variant) ----
    silkworm::Block base{};
    base.header.parent_hash = genesis.header.hash();
    base.header.number = 1;
    base.header.beneficiary = S;
    base.header.gas_limit = 30'000'000;
    base.header.timestamp = 1001;
    base.header.ommers_hash = silkworm::kEmptyListHash;
    base.header.difficulty = 0;
    base.header.base_fee_per_gas = protocol::expected_base_fee_per_gas(genesis.header);
    base.transactions.push_back(tx);
    base.withdrawals = std::vector<silkworm::Withdrawal>{};
    base.header.withdrawals_root = protocol::compute_withdrawals_root(base);
    base.header.transactions_root = protocol::compute_transaction_root(base);

    // Prover-side block production (the EL that builds the block, not the guest): run each
    // pre-state once to obtain the header commitments the block must carry. The bad variant
    // sanitizes the genuine bundle (to resolve D's code) and forges the orphan afterwards,
    // since the routing check now aborts sanitize() on the already-forged bundle.
    const ShadowResult sr_valid = shadow_execute(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                                 base.header, tx, S, kS, rlpS, D, kD, rlpD, kC, rlpC);
    const ShadowResult sr_bad = shadow_execute(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                               base.header, tx, S, kS, rlpS, D, kD, rlpD, kC, rlpC,
                                               forge_orphan, C);

    // Same block, two pre-states: gas/receipts/bloom identical, only the post-root differs.
    // The divergence at the root of it: the EVM saw BALANCE(C)=5000 (stored 5001) on the
    // genuine pre-state, 0 (stored 1) when C is orphaned from find().
    evmc::bytes32 expect_g{}, expect_o{};
    intx::be::store(expect_g.bytes, intx::uint256{C_BAL + 1});
    intx::be::store(expect_o.bytes, intx::uint256{1});
    CHECK(sr_valid.storage == expect_g);
    CHECK(sr_bad.storage == expect_o);
    CHECK(sr_valid.gas_used == sr_bad.gas_used);
    CHECK(sr_valid.state_root != sr_bad.state_root);

    auto make_envelope = [&](const std::vector<uint8_t>& blob, const ShadowResult& sr) {
        silkworm::Block b = base;
        b.header.gas_used = sr.gas_used;
        b.header.receipts_root = sr.receipts_root;
        b.header.logs_bloom = sr.logs_bloom;
        b.header.state_root = sr.state_root;
        Bytes brlp;
        silkworm::rlp::encode(brlp, b);
        const std::array<ByteView, 1> brlps{ByteView{brlp.data(), brlp.size()}};
        std::vector<uint8_t> flat = build_flat_bundle(
            ByteView{genesis_rlp.data(), genesis_rlp.size()},
            std::span<const ByteView>{brlps},
            /*ancestors_rlp=*/ByteView{},
            blob, nodestore, "Shanghai");
        REQUIRE_FALSE(flat.empty());
        return wrap_mfbd(flat);
    };

    // ---- Run 1: genuine bundle + true post-root -> guest ACCEPTS ----
    std::vector<uint8_t> env_valid = make_envelope(genuine_blob, sr_valid);
    StateTransition st_valid{std::span<uint8_t>{env_valid}};
    const uint64_t gas_valid = st_valid.run().gas_used;
    CHECK_FALSE(st_valid.failed());
    CHECK(gas_valid == sr_valid.gas_used);

    // ---- Run 2: orphaned bundle + its post-root -> guest must REJECT ----
    // Same block as Run 1 except it commits to the orphaned post-root (sr_bad.state_root,
    // which necessarily differs from sr_valid.state_root); only the pre-state bundle is
    // malformed (C orphaned). WITH the routing check sanitize() rejects, so run() fails.
    // Strip the check and it flips (run() returns sr_bad.gas_used, failed()==false): the
    // guest ACCEPTS an invalid transition — the true post-root is sr_valid.state_root.
    std::vector<uint8_t> env_bad = make_envelope(forged_blob, sr_bad);
    StateTransition st_bad{std::span<uint8_t>{env_bad}};
    const uint64_t gas_bad = st_bad.run().gas_used;
    CHECK(st_bad.failed());
    CHECK(gas_bad == StateTransition::kRunFailure);
}

// ============================================================================
// Collision-sidecar orphan: the same soundness break as above, but the victim
// is unreachable via find() WITHOUT zeroing its slot, so the RLP cache is
// re-filled by the account walk (find and for_each both traverse slot_offsets,
// but only for_each traverses the collision sidecar unconditionally — find
// consults it via a key-matching fallback). A collision entry whose key does
// not match addr_key8(victim) keeps the body walked (cache genuine, modified
// toggled to readonly) yet makes find(victim) miss. The parity check in the
// current sanitize() is satisfied and check_root's pre-value comparison passes,
// so the guest accepts an incoherent transition (EVM reads victim as empty,
// check_root validates it as unchanged-genuine). Only the per-entry routing
// check (find(addr) == account_at_offset(entry_offset)) rejects it.
namespace {

// Sibling sharing addr_key8 (bytes[0..6] + byte[19]) with make_addr(b0,b19),
// differing only in byte[7] (cleared by addr_key8) -> forced MPHF collision.
evmc::address make_addr_colliding(uint8_t b0, uint8_t b19, uint8_t mid) {
    evmc::address a{};
    a.bytes[0] = b0;
    a.bytes[7] = mid;
    a.bytes[19] = b19;
    return a;
}

// Corrupt the collision entry whose body address == victim so find(victim) misses,
// keeping the sidecar sorted by key. Authored at rest, like forge_orphan.
void forge_collision(std::vector<uint8_t>& blob, const evmc::address& victim) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    auto* base = reinterpret_cast<uint8_t*>(mh);
    auto* coll = reinterpret_cast<MphfCollisionEntry*>(base + mh->collisions_offset);
    const uint32_t n = mh->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
    uint8_t* data = base + mh->data_offset;
    for (uint32_t i = 0; i < n; ++i) {
        if (std::memcmp(data + coll[i].offset + 8u, victim.bytes, 20) == 0) {
            coll[i].key |= (1ull << 63);  // != addr_key8(victim); find() fallback misses
            break;
        }
    }
    std::sort(coll, coll + n,
              [](const MphfCollisionEntry& a, const MphfCollisionEntry& b) { return a.key < b.key; });
}

// check_root mirror for S,D modified + C,C2 read-only-unchanged (see post_root).
bytes32 post_root_ro(DirectState& ds, const bytes32& prev_root,
                     const evmc::address& S, const bytes32& kS, const Bytes& rlpS,
                     const evmc::address& D, const bytes32& kD, const Bytes& rlpD,
                     const bytes32& kC, const Bytes& rlpC,
                     const bytes32& kC2, const Bytes& rlpC2, unsigned& missing) {
    std::vector<TrieNodeFlat> ups;
    auto add_modified = [&](const bytes32& k, const Bytes& pre, const evmc::address& addr) {
        TrieNodeFlat u{k};
        u.ext_initial = ByteView{pre.data(), pre.size()};
        u.self_initial_len = 0;
        const Account* pa = ds.read_account(addr);
        u.current_off = 0;
        u.current_len = pa->rlp_into(u.buf + 0, ds.account_storage_root(addr));
        ups.push_back(u);
    };
    auto add_readonly = [&](const bytes32& k, const Bytes& pre) {
        TrieNodeFlat u{k};
        u.ext_initial = ByteView{pre.data(), pre.size()};
        u.self_initial_len = 0;
        u.current_off = 0;
        u.current_len = 0;
        ups.push_back(u);
    };
    add_modified(kS, rlpS, S);
    add_modified(kD, rlpD, D);
    add_readonly(kC, rlpC);
    add_readonly(kC2, rlpC2);
    std::sort(ups.begin(), ups.end(), [](const TrieNodeFlat& x, const TrieNodeFlat& y) {
        return std::memcmp(x.key.bytes, y.key.bytes, 32) < 0;
    });
    GridMPT<true> acc_trie{ds, prev_root};
    const bytes32 root = acc_trie.calc_root_from_updates({ups.data(), ups.size()});
    missing = acc_trie.missing_count();
    return root;
}

ShadowResult shadow_execute_ro(std::vector<uint8_t> blob, std::span<uint8_t> nodestore,
                               const bytes32& prev_root, const silkworm::BlockHeader& provisional,
                               const silkworm::Transaction& tx,
                               const evmc::address& S, const bytes32& kS, const Bytes& rlpS,
                               const evmc::address& D, const bytes32& kD, const Bytes& rlpD,
                               const bytes32& kC, const Bytes& rlpC,
                               const bytes32& kC2, const Bytes& rlpC2,
                               const evmc::address& victim, unsigned& missing) {
    DirectState ds{std::span<uint8_t>{blob}, nodestore};
    ds.sanitize();  // genuine bundle: resolves D's code + caches in the MPHF sweep
    forge_collision(blob, victim);  // orphan victim from find() AFTER code is resolved
    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);
    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
    // Bypasses pre-validation, so publish what it would have computed.
    const auto& t0 = block.transactions[0];
    t0.set_data_non_zero_bytes(zilkworm::count_nonzero_bytes(t0.data));
    proc.execute_transaction(t0, receipt);
    ShadowResult r{};
    r.gas_used = receipt.cumulative_gas_used;
    static constexpr auto kEncoder = [](Bytes& to, const silkworm::Receipt& rc) { silkworm::rlp::encode(to, rc); };
    std::vector<silkworm::Receipt> receipts{receipt};
    r.receipts_root = silkworm::trie::root_hash(receipts, kEncoder);
    r.logs_bloom = silkworm::Bloom{};
    silkworm::join(r.logs_bloom, receipt.bloom);
    r.storage = ds.read_storage(D, evmc::bytes32{});
    r.state_root = post_root_ro(ds, prev_root, S, kS, rlpS, D, kD, rlpD, kC, rlpC, kC2, rlpC2, missing);
    return r;
}

}  // namespace

TEST_CASE("StateTransition::run must reject a collision-orphaned MFBD bundle",
          "[mphf][state_transition][exec]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address C = make_addr(0x33, 0x03);                  // victim (probed by D)
    const evmc::address C2 = make_addr_colliding(0x33, 0x03, 0x77); // shares addr_key8 with C
    REQUIRE(addr_key8(C) == addr_key8(C2));

    const silkworm::Transaction tx = make_txn(D);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != C);
    REQUIRE(S != C2);
    REQUIRE(addr_key8(S) != addr_key8(C));  // S keeps its own slot; only C/C2 collide

    const bytes32 kS = keccak_addr32(S), kD = keccak_addr32(D), kC = keccak_addr32(C), kC2 = keccak_addr32(C2);
    const Bytes code = balance_probe_code(C);
    const bytes32 code_hash = keccak_bytes(ByteView{code.data(), code.size()});

    const uint64_t C_BAL = 5000;
    const intx::uint256 S_BAL{intx::uint256{1} << 64};
    const Bytes rlpS = account_rlp(S, 0, S_BAL, silkworm::kEmptyHash, silkworm::kEmptyRoot);
    const Bytes rlpD = account_rlp(D, 1, 0, code_hash, silkworm::kEmptyRoot);
    const Bytes rlpC = account_rlp(C, 0, intx::uint256{C_BAL}, silkworm::kEmptyHash, silkworm::kEmptyRoot);
    const Bytes rlpC2 = account_rlp(C2, 7, intx::uint256{1234}, silkworm::kEmptyHash, silkworm::kEmptyRoot);

    std::vector<uint8_t> nodestore;
    const bytes32 R = build_account_node_store({{kS, rlpS}, {kD, rlpD}, {kC, rlpC}, {kC2, rlpC2}}, nodestore);
    REQUIRE_FALSE(nodestore.empty());
    const std::vector<uint8_t> code_store = build_code_store(code_hash, ByteView{code.data(), code.size()});

    std::vector<DirectState::AccountInfo> accts{
        make_eoa(S, 0, S_BAL),
        make_contract(D, 1, code_hash, static_cast<uint32_t>(code.size())),
        make_eoa(C, 0, intx::uint256{C_BAL}),
        make_eoa(C2, 7, intx::uint256{1234})};
    std::vector<uint8_t> genuine_blob = DirectState::build_blob_from_accounts(accts, {}, code_store);
    REQUIRE_FALSE(genuine_blob.empty());
    // Bundle handed to the guest: C orphaned from find() at rest, body still walked via sidecar.
    std::vector<uint8_t> forged_blob = genuine_blob;
    forge_collision(forged_blob, C);

    // ---- Genesis (parent, block 0) anchors prev_root = R ----
    silkworm::Block genesis{};
    genesis.header.number = 0;
    genesis.header.state_root = R;
    genesis.header.gas_limit = 30'000'000;
    genesis.header.gas_used = 0;
    genesis.header.timestamp = 1000;
    genesis.header.ommers_hash = silkworm::kEmptyListHash;
    genesis.header.transactions_root = silkworm::kEmptyRoot;
    genesis.header.receipts_root = silkworm::kEmptyRoot;
    genesis.header.base_fee_per_gas = intx::uint256{0};
    genesis.header.withdrawals_root = silkworm::kEmptyRoot;
    genesis.withdrawals = std::vector<silkworm::Withdrawal>{};
    Bytes genesis_rlp;
    silkworm::rlp::encode(genesis_rlp, genesis);

    silkworm::Block base{};
    base.header.parent_hash = genesis.header.hash();
    base.header.number = 1;
    base.header.beneficiary = S;
    base.header.gas_limit = 30'000'000;
    base.header.timestamp = 1001;
    base.header.ommers_hash = silkworm::kEmptyListHash;
    base.header.difficulty = 0;
    base.header.base_fee_per_gas = protocol::expected_base_fee_per_gas(genesis.header);
    base.transactions.push_back(tx);
    base.withdrawals = std::vector<silkworm::Withdrawal>{};
    base.header.withdrawals_root = protocol::compute_withdrawals_root(base);
    base.header.transactions_root = protocol::compute_transaction_root(base);

    // Attacker-side block production: sanitize the genuine bundle (to resolve D's code),
    // then orphan C and execute, since the routing check now aborts sanitize() on the
    // already-forged bundle.
    unsigned missing = 1;
    const ShadowResult sr = shadow_execute_ro(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                              base.header, tx, S, kS, rlpS, D, kD, rlpD,
                                              kC, rlpC, kC2, rlpC2, C, missing);
    // EVM read BALANCE(C)=0 (find missed) -> D stored 1; check_root unfolds cleanly.
    evmc::bytes32 expect_o{};
    intx::be::store(expect_o.bytes, intx::uint256{1});
    CHECK(sr.storage == expect_o);
    CHECK(missing == 0);

    silkworm::Block b = base;
    b.header.gas_used = sr.gas_used;
    b.header.receipts_root = sr.receipts_root;
    b.header.logs_bloom = sr.logs_bloom;
    b.header.state_root = sr.state_root;
    Bytes brlp;
    silkworm::rlp::encode(brlp, b);
    const std::array<ByteView, 1> brlps{ByteView{brlp.data(), brlp.size()}};
    std::vector<uint8_t> flat = build_flat_bundle(
        ByteView{genesis_rlp.data(), genesis_rlp.size()},
        std::span<const ByteView>{brlps},
        /*ancestors_rlp=*/ByteView{},
        forged_blob, nodestore, "Shanghai");
    REQUIRE_FALSE(flat.empty());
    std::vector<uint8_t> env = wrap_mfbd(flat);

    // The forged bundle carries a coherent-looking post-root, so GridMPT accepts it;
    // only sanitize()'s per-entry routing check forces find() and addr_hashes to agree.
    StateTransition st{std::span<uint8_t>{env}};
    const uint64_t gas = st.run().gas_used;
    CHECK(st.failed());
    CHECK(gas == StateTransition::kRunFailure);
}

// ============================================================================
// Slot-swap orphan: transpose two accounts' MPHF slot offsets. find(C) then routes
// to C2's body (addr mismatch -> miss) and find(C2) to C's body (miss), yet BOTH
// bodies stay walked by for_each (they still occupy slots, just swapped). Caches are
// re-filled genuine, the parity check balances, GridMPT sees genuine pre-values, no
// collision sidecar is involved, and n_keys == n_accounts is preserved. This defeats
// every targeted guard (parity + GridMPT + collision sweep + n_keys==n_accounts);
// only the per-entry routing check (find(addr) == account_at_offset(entry_offset))
// catches it. C and C2 have distinct addr_key8 so each owns a slot to swap.
namespace {

void forge_slot_swap(std::vector<uint8_t>& blob, const evmc::address& a, const evmc::address& b) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    auto* slots = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mh) + mh->slot_offsets_offset);
    std::swap(slots[mh->index_lookup(addr_key8(a))], slots[mh->index_lookup(addr_key8(b))]);
}

ShadowResult shadow_execute_swap(std::vector<uint8_t> blob, std::span<uint8_t> nodestore,
                                 const bytes32& prev_root, const silkworm::BlockHeader& provisional,
                                 const silkworm::Transaction& tx,
                                 const evmc::address& S, const bytes32& kS, const Bytes& rlpS,
                                 const evmc::address& D, const bytes32& kD, const Bytes& rlpD,
                                 const bytes32& kC, const Bytes& rlpC,
                                 const bytes32& kC2, const Bytes& rlpC2,
                                 const evmc::address& va, const evmc::address& vb, unsigned& missing) {
    DirectState ds{std::span<uint8_t>{blob}, nodestore};
    ds.sanitize();  // genuine bundle: resolves D's code + caches
    forge_slot_swap(blob, va, vb);  // transpose slots AFTER code is resolved
    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);
    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
    // Bypasses pre-validation, so publish what it would have computed.
    const auto& t0 = block.transactions[0];
    t0.set_data_non_zero_bytes(zilkworm::count_nonzero_bytes(t0.data));
    proc.execute_transaction(t0, receipt);
    ShadowResult r{};
    r.gas_used = receipt.cumulative_gas_used;
    static constexpr auto kEncoder = [](Bytes& to, const silkworm::Receipt& rc) { silkworm::rlp::encode(to, rc); };
    std::vector<silkworm::Receipt> receipts{receipt};
    r.receipts_root = silkworm::trie::root_hash(receipts, kEncoder);
    r.logs_bloom = silkworm::Bloom{};
    silkworm::join(r.logs_bloom, receipt.bloom);
    r.storage = ds.read_storage(D, evmc::bytes32{});
    r.state_root = post_root_ro(ds, prev_root, S, kS, rlpS, D, kD, rlpD, kC, rlpC, kC2, rlpC2, missing);
    return r;
}

}  // namespace

TEST_CASE("StateTransition::run must reject a slot-swapped MFBD bundle",
          "[mphf][state_transition][exec]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address C = make_addr(0x33, 0x03);   // victim (probed by D)
    const evmc::address C2 = make_addr(0x44, 0x04);  // swap partner (distinct addr_key8)
    REQUIRE(addr_key8(C) != addr_key8(C2));

    const silkworm::Transaction tx = make_txn(D);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != C);
    REQUIRE(S != C2);

    const bytes32 kS = keccak_addr32(S), kD = keccak_addr32(D), kC = keccak_addr32(C), kC2 = keccak_addr32(C2);
    const Bytes code = balance_probe_code(C);
    const bytes32 code_hash = keccak_bytes(ByteView{code.data(), code.size()});

    const uint64_t C_BAL = 5000;
    const intx::uint256 S_BAL{intx::uint256{1} << 64};
    const Bytes rlpS = account_rlp(S, 0, S_BAL, silkworm::kEmptyHash, silkworm::kEmptyRoot);
    const Bytes rlpD = account_rlp(D, 1, 0, code_hash, silkworm::kEmptyRoot);
    const Bytes rlpC = account_rlp(C, 0, intx::uint256{C_BAL}, silkworm::kEmptyHash, silkworm::kEmptyRoot);
    const Bytes rlpC2 = account_rlp(C2, 7, intx::uint256{1234}, silkworm::kEmptyHash, silkworm::kEmptyRoot);

    std::vector<uint8_t> nodestore;
    const bytes32 R = build_account_node_store({{kS, rlpS}, {kD, rlpD}, {kC, rlpC}, {kC2, rlpC2}}, nodestore);
    REQUIRE_FALSE(nodestore.empty());
    const std::vector<uint8_t> code_store = build_code_store(code_hash, ByteView{code.data(), code.size()});

    std::vector<DirectState::AccountInfo> accts{
        make_eoa(S, 0, S_BAL),
        make_contract(D, 1, code_hash, static_cast<uint32_t>(code.size())),
        make_eoa(C, 0, intx::uint256{C_BAL}),
        make_eoa(C2, 7, intx::uint256{1234})};
    std::vector<uint8_t> genuine_blob = DirectState::build_blob_from_accounts(accts, {}, code_store);
    REQUIRE_FALSE(genuine_blob.empty());
    {
        DirectState ds{std::span<uint8_t>{genuine_blob}};
        REQUIRE(ds.mphf()->collisions_size == 0);  // C and C2 are slot-resident (no CHD spill)
    }
    std::vector<uint8_t> forged_blob = genuine_blob;
    forge_slot_swap(forged_blob, C, C2);  // guest bundle: C and C2 slots transposed at rest

    silkworm::Block genesis{};
    genesis.header.number = 0;
    genesis.header.state_root = R;
    genesis.header.gas_limit = 30'000'000;
    genesis.header.gas_used = 0;
    genesis.header.timestamp = 1000;
    genesis.header.ommers_hash = silkworm::kEmptyListHash;
    genesis.header.transactions_root = silkworm::kEmptyRoot;
    genesis.header.receipts_root = silkworm::kEmptyRoot;
    genesis.header.base_fee_per_gas = intx::uint256{0};
    genesis.header.withdrawals_root = silkworm::kEmptyRoot;
    genesis.withdrawals = std::vector<silkworm::Withdrawal>{};
    Bytes genesis_rlp;
    silkworm::rlp::encode(genesis_rlp, genesis);

    silkworm::Block base{};
    base.header.parent_hash = genesis.header.hash();
    base.header.number = 1;
    base.header.beneficiary = S;
    base.header.gas_limit = 30'000'000;
    base.header.timestamp = 1001;
    base.header.ommers_hash = silkworm::kEmptyListHash;
    base.header.difficulty = 0;
    base.header.base_fee_per_gas = protocol::expected_base_fee_per_gas(genesis.header);
    base.transactions.push_back(tx);
    base.withdrawals = std::vector<silkworm::Withdrawal>{};
    base.header.withdrawals_root = protocol::compute_withdrawals_root(base);
    base.header.transactions_root = protocol::compute_transaction_root(base);

    unsigned missing = 1;
    const ShadowResult sr = shadow_execute_swap(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                                base.header, tx, S, kS, rlpS, D, kD, rlpD,
                                                kC, rlpC, kC2, rlpC2, C, C2, missing);
    evmc::bytes32 expect_o{};
    intx::be::store(expect_o.bytes, intx::uint256{1});
    CHECK(sr.storage == expect_o);   // EVM read BALANCE(C)=0 (find missed) -> D stored 1
    CHECK(missing == 0);

    silkworm::Block b = base;
    b.header.gas_used = sr.gas_used;
    b.header.receipts_root = sr.receipts_root;
    b.header.logs_bloom = sr.logs_bloom;
    b.header.state_root = sr.state_root;
    Bytes brlp;
    silkworm::rlp::encode(brlp, b);
    const std::array<ByteView, 1> brlps{ByteView{brlp.data(), brlp.size()}};
    std::vector<uint8_t> flat = build_flat_bundle(
        ByteView{genesis_rlp.data(), genesis_rlp.size()},
        std::span<const ByteView>{brlps},
        /*ancestors_rlp=*/ByteView{},
        forged_blob, nodestore, "Shanghai");
    REQUIRE_FALSE(flat.empty());
    std::vector<uint8_t> env = wrap_mfbd(flat);

    StateTransition st{std::span<uint8_t>{env}};
    const uint64_t gas = st.run().gas_used;
    CHECK(st.failed());
    CHECK(gas == StateTransition::kRunFailure);
}
