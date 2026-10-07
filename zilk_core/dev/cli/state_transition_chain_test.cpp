// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The Airbender guest commits only the hash of the last block a run validates. A bundle is one
// chain: its first block is anchored at the parent header its parent hash names, and each later
// block runs on the state the one before it left, so StateTransition requires each block to
// extend the one validated before it in the bundle. Bundles are independent chains (the EEST
// conversions pack one test per bundle). These cases drive the public entry point over MFBD
// envelopes built from one honest two-block chain (genesis -> A -> B, a value transfer each,
// complete witnesses):
//
//   1. a single-block run returns A's hash, the genesis state root and A's state root;
//   2. A then B, in one bundle or in two, is accepted and returns B's hash;
//   3. in one bundle, B's execution re-parented onto genesis after A is rejected (it was accepted
//      before the check: its root still matches), while two independent bundles are accepted in
//      either order and return the hash of the last one's block.

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/state_zz/account_read_test_util.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::ByteView;
using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

const evmc::address kRecipient = make_addr(0xee, 0x01);
constexpr uint64_t kBalance = 1'000'000;
constexpr uint64_t kTransferGas = 21'000;

/// The four header fields a producer learns only by executing the block.
silkworm::Block seal(silkworm::Block b, const ShadowRun& sr) {
    b.header.gas_used = sr.gas_used;
    b.header.receipts_root = sr.receipts_root;
    b.header.logs_bloom = sr.logs_bloom;
    b.header.state_root = sr.post.root;
    return b;
}

Bytes encode(const silkworm::Block& b) {
    Bytes out;
    silkworm::rlp::encode(out, b);
    return out;
}

struct Chain {
    Prestate pre_a;  // witness before A (the genesis state)
    Prestate pre_b;  // witness before B (the state after A)
    silkworm::Block genesis, a, b;
    silkworm::Block b_off;  // B's execution, re-parented onto genesis as block 1
    Bytes genesis_rlp, a_rlp, b_rlp, b_off_rlp;
};

Chain make_chain_ab() {
    const auto tx_a = make_legacy_txn(kRecipient, 50'000, /*value=*/1);
    const auto tx_b = make_legacy_txn(kRecipient, 50'000, /*value=*/2);
    const evmc::address s_a = recover_sender(tx_a);
    const evmc::address s_b = recover_sender(tx_b);
    REQUIRE(s_a != evmc::address{});
    REQUIRE(s_b != evmc::address{});
    REQUIRE(s_a != s_b);

    Chain c{};
    c.pre_a = build_prestate({{s_a, 0, kBalance}, {s_b, 0, kBalance}, {kRecipient, 0, 1}});
    const ChainSetup setup = make_chain(c.pre_a.prev_root, tx_a, /*beneficiary=*/s_a);
    c.genesis = setup.genesis;
    c.genesis_rlp = setup.genesis_rlp;
    const ShadowRun sr_a =
        shadow_execute(c.pre_a.blob, c.pre_a.nodestore, c.pre_a.prev_root, setup.base.header, tx_a);
    REQUIRE(sr_a.all_succeeded());
    c.a = seal(setup.base, sr_a);
    c.a_rlp = encode(c.a);

    // Zero gas price: the transfers move only their values.
    c.pre_b = build_prestate({{s_a, 1, kBalance - 1}, {s_b, 0, kBalance}, {kRecipient, 0, 2}});
    REQUIRE(c.pre_b.prev_root == c.a.header.state_root);

    silkworm::Block b{};
    b.header.parent_hash = c.a.header.hash();
    b.header.number = 2;
    b.header.beneficiary = s_b;
    b.header.gas_limit = c.a.header.gas_limit;
    b.header.timestamp = c.a.header.timestamp + 1;
    b.header.ommers_hash = silkworm::kEmptyListHash;
    b.header.difficulty = 0;
    b.header.base_fee_per_gas = silkworm::protocol::expected_base_fee_per_gas(c.a.header);
    b.transactions = {tx_b};
    b.withdrawals = std::vector<silkworm::Withdrawal>{};
    b.header.withdrawals_root = silkworm::protocol::compute_withdrawals_root(b);
    b.header.transactions_root = silkworm::protocol::compute_transaction_root(b);
    const ShadowRun sr_b =
        shadow_execute(c.pre_b.blob, c.pre_b.nodestore, c.pre_b.prev_root, b.header, tx_b);
    REQUIRE(sr_b.all_succeeded());
    c.b = seal(b, sr_b);
    c.b_rlp = encode(c.b);

    // Same transactions, receipts and post-state as B; only its place in the chain differs.
    c.b_off = c.b;
    c.b_off.header.parent_hash = c.genesis.header.hash();
    c.b_off.header.number = 1;
    c.b_off.header.timestamp = c.a.header.timestamp;
    c.b_off.header.base_fee_per_gas = silkworm::protocol::expected_base_fee_per_gas(c.genesis.header);
    REQUIRE(c.b_off.header.base_fee_per_gas == c.b.header.base_fee_per_gas);
    c.b_off_rlp = encode(c.b_off);
    return c;
}

/// One flat bundle: `parent_rlp` is its "genesis" block, whose header anchors the first block.
std::vector<uint8_t> bundle(const Bytes& parent_rlp, std::initializer_list<ByteView> blocks,
                            const Prestate& pre) {
    std::vector<uint8_t> flat = build_flat_bundle(
        ByteView{parent_rlp}, std::span<const ByteView>{blocks.begin(), blocks.size()},
        /*ancestors_rlp=*/ByteView{}, pre.blob, pre.nodestore, "Shanghai");
    REQUIRE_FALSE(flat.empty());
    return flat;
}

/// MFBD envelope over several bundles, each 8-aligned.
std::vector<uint8_t> envelope(std::initializer_list<std::vector<uint8_t>> bundles) {
    std::vector<uint8_t> env(kInputHeaderSizeMFBD, 0);
    const uint32_t magic = kInputMagicMFBD;
    const uint32_t version = kInputVersionMFBD;
    const uint64_t n = bundles.size();
    std::memcpy(env.data() + 0, &magic, 4);
    std::memcpy(env.data() + 4, &version, 4);
    std::memcpy(env.data() + 8, &n, 8);
    for (const std::vector<uint8_t>& b : bundles) {
        env.insert(env.end(), b.begin(), b.end());
        env.resize((env.size() + 7) & ~size_t{7}, 0);
    }
    return env;
}

struct Outcome {
    StateTransition::Result r;
    bool failed{true};
    std::string log;
};

Outcome run(std::vector<uint8_t> env) {
    StateTransition st{std::span<uint8_t>{env}};
    Outcome o{};
    {
        StdoutCapture cap;  // keep tight: Catch2 writes to std::cout too
        o.r = st.run();
        o.log = cap.str();
    }
    o.failed = st.failed();
    return o;
}

}  // namespace

TEST_CASE("a single-block run returns its block hash and both state roots",
          "[state_transition][public_output]") {
    const Chain c = make_chain_ab();
    const Outcome o = run(envelope({bundle(c.genesis_rlp, {ByteView{c.a_rlp}}, c.pre_a)}));
    REQUIRE_FALSE(o.failed);
    CHECK(o.r.gas_used == kTransferGas);
    CHECK(o.r.block_hash == c.a.header.hash());
    CHECK(o.r.pre_state_root == c.pre_a.prev_root);
    CHECK(o.r.post_state_root == c.a.header.state_root);
}

TEST_CASE("a run whose blocks extend each other returns the last block's hash",
          "[state_transition][public_output]") {
    const Chain c = make_chain_ab();
    std::vector<uint8_t> env;
    SECTION("one bundle") {
        env = envelope({bundle(c.genesis_rlp, {ByteView{c.a_rlp}, ByteView{c.b_rlp}}, c.pre_a)});
    }
    SECTION("two bundles") {
        env = envelope({bundle(c.genesis_rlp, {ByteView{c.a_rlp}}, c.pre_a),
                        bundle(c.a_rlp, {ByteView{c.b_rlp}}, c.pre_b)});
    }
    const Outcome o = run(env);
    REQUIRE_FALSE(o.failed);
    CHECK(o.r.gas_used == 2 * kTransferGas);
    CHECK(o.r.block_hash == c.b.header.hash());
    CHECK(o.r.pre_state_root == c.pre_a.prev_root);
    CHECK(o.r.post_state_root == c.b.header.state_root);
}

TEST_CASE("a block that does not extend the previous one in its bundle is rejected",
          "[state_transition][public_output][soundness]") {
    const Chain c = make_chain_ab();
    // A alone is accepted: what the case below rejects is the broken link.
    REQUIRE_FALSE(run(envelope({bundle(c.genesis_rlp, {ByteView{c.a_rlp}}, c.pre_a)})).failed);

    // B_off's header names genesis as parent, so its hash would bind the genesis state root as
    // its pre-state, yet it runs on the state A left; its root still matches.
    const Outcome o = run(
        envelope({bundle(c.genesis_rlp, {ByteView{c.a_rlp}, ByteView{c.b_off_rlp}}, c.pre_a)}));
    CHECK(o.failed);
    CHECK(o.r.gas_used == StateTransition::kRunFailure);
    CHECK(o.log.find("does not extend the previous block") != std::string::npos);
}

TEST_CASE("independent bundles return the last bundle's block hash",
          "[state_transition][public_output]") {
    const Chain c = make_chain_ab();
    const auto bundle_a = bundle(c.genesis_rlp, {ByteView{c.a_rlp}}, c.pre_a);
    const auto bundle_b = bundle(c.a_rlp, {ByteView{c.b_rlp}}, c.pre_b);
    // Each bundle is anchored at its own parent header; the output covers the last one's chain.
    const Outcome ba = run(envelope({bundle_b, bundle_a}));
    REQUIRE_FALSE(ba.failed);
    CHECK(ba.r.block_hash == c.a.header.hash());
    CHECK(ba.r.post_state_root == c.a.header.state_root);
    const Outcome aa = run(envelope({bundle_a, bundle_a}));
    REQUIRE_FALSE(aa.failed);
    CHECK(aa.r.block_hash == c.a.header.hash());
}
