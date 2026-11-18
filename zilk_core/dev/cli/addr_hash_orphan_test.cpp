// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// Unit test: a GENUINE account present in addr_hashes with a valid body + hash.

// The orphaned bundle is well-formed.

// The pre-state root (R) is computed from the genuine leaf, so it is the same for both bundles.


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

// Byte-level authoring of the malicious bundle, applied at rest (no live parse).
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

// The tx the block carries: <recovered sender> -> D, gas price 0.
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

// Account-trie root over the post-execution state, computed as check_root does: read-only C from addr_hashes.
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
    GridMPT<true, DirectState> acc_trie{ds, prev_root};
    const bytes32 root = acc_trie.calc_root_from_updates({ups.data(), ups.size()});
    missing = acc_trie.missing_count();
    return root;
}

// Attacker-side simulation of the orphaned execution to learn the header fields the forged block must carry.
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
    ds.sanitize();
    if (forge) forge(blob, victim);

    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);

    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
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

    std::vector<uint8_t> genuine_blob = build_prestate();
    std::vector<uint8_t> forged_blob = build_prestate();
    forge_orphan(forged_blob, C);

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

    const ShadowResult sr_valid = shadow_execute(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                                 base.header, tx, S, kS, rlpS, D, kD, rlpD, kC, rlpC);
    const ShadowResult sr_bad = shadow_execute(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                               base.header, tx, S, kS, rlpS, D, kD, rlpD, kC, rlpC,
                                               forge_orphan, C);

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

    std::vector<uint8_t> env_valid = make_envelope(genuine_blob, sr_valid);
    StateTransition st_valid{std::span<uint8_t>{env_valid}};
    const uint64_t gas_valid = st_valid.run().gas_used;
    CHECK_FALSE(st_valid.failed());
    CHECK(gas_valid == sr_valid.gas_used);

    std::vector<uint8_t> env_bad = make_envelope(forged_blob, sr_bad);
    StateTransition st_bad{std::span<uint8_t>{env_bad}};
    const uint64_t gas_bad = st_bad.run().gas_used;
    CHECK(st_bad.failed());
    CHECK(gas_bad == StateTransition::kRunFailure);
}

// Collision-sidecar orphan: the same soundness break as above.
namespace {

// Sibling sharing addr_key8 (bytes[0..6] + byte[19]) with make_addr(b0,b19), differing only in byte[7].
evmc::address make_addr_colliding(uint8_t b0, uint8_t b19, uint8_t mid) {
    evmc::address a{};
    a.bytes[0] = b0;
    a.bytes[7] = mid;
    a.bytes[19] = b19;
    return a;
}

// Corrupt the collision entry whose body address == victim so find(victim) misses, keeping the sidecar sorted by key.
void forge_collision(std::vector<uint8_t>& blob, const evmc::address& victim) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    auto* base = reinterpret_cast<uint8_t*>(mh);
    auto* coll = reinterpret_cast<MphfCollisionEntry*>(base + mh->collisions_offset);
    const uint32_t n = mh->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
    uint8_t* data = base + mh->data_offset;
    for (uint32_t i = 0; i < n; ++i) {
        if (std::memcmp(data + coll[i].offset + 8u, victim.bytes, 20) == 0) {
            coll[i].key |= (1ull << 63);
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
    GridMPT<true, DirectState> acc_trie{ds, prev_root};
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
    ds.sanitize();
    forge_collision(blob, victim);
    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);
    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
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
    const evmc::address C = make_addr(0x33, 0x03);
    const evmc::address C2 = make_addr_colliding(0x33, 0x03, 0x77);
    REQUIRE(addr_key8(C) == addr_key8(C2));

    const silkworm::Transaction tx = make_txn(D);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != C);
    REQUIRE(S != C2);
    REQUIRE(addr_key8(S) != addr_key8(C));

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
    std::vector<uint8_t> forged_blob = genuine_blob;
    forge_collision(forged_blob, C);

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
    const ShadowResult sr = shadow_execute_ro(genuine_blob, std::span<uint8_t>{nodestore}, R,
                                              base.header, tx, S, kS, rlpS, D, kD, rlpD,
                                              kC, rlpC, kC2, rlpC2, C, missing);
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

    StateTransition st{std::span<uint8_t>{env}};
    const uint64_t gas = st.run().gas_used;
    CHECK(st.failed());
    CHECK(gas == StateTransition::kRunFailure);
}

// Slot-swap orphan: transpose two accounts' MPHF slot offsets.
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
    ds.sanitize();
    forge_slot_swap(blob, va, vb);
    silkworm::Block block{};
    block.header = provisional;
    block.transactions.push_back(tx);
    const auto& cfg = silkworm::test::kShanghaiConfig;
    auto rs = protocol::rule_set_factory(cfg);
    silkworm::ExecutionProcessor proc{block, *rs, ds, cfg};
    silkworm::Receipt receipt{};
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
    const evmc::address C = make_addr(0x33, 0x03);
    const evmc::address C2 = make_addr(0x44, 0x04);
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
        REQUIRE(ds.mphf()->collisions_size == 0);
    }
    std::vector<uint8_t> forged_blob = genuine_blob;
    forge_slot_swap(forged_blob, C, C2);

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

    StateTransition st{std::span<uint8_t>{env}};
    const uint64_t gas = st.run().gas_used;
    CHECK(st.failed());
    CHECK(gas == StateTransition::kRunFailure);
}
