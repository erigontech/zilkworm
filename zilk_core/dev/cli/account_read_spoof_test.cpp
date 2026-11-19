// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// End-to-end soundness proof for the created/existing hash clash check.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/state_zz/account_read_test_util.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::ByteView;
using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

// The victim's code.
Bytes victim_code() {
    Bytes c;
    push1(c, 0x00);
    push1(c, 0x00);
    c.push_back(0xfd);  // REVERT
    return c;
}

// Each probe writes what it observed about C into storage[0] and the sentinel 1 into storage[1].

// PUSH20 C; BALANCE; PUSH1 0; SSTORE; PUSH1 1; PUSH1 1; SSTORE; STOP
Bytes probe_balance(const evmc::address& c) {
    Bytes k;
    push20(k, c);
    k.push_back(0x31);  // BALANCE
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH20 C; EXTCODESIZE; PUSH1 0; SSTORE; <sentinel>
Bytes probe_extcodesize(const evmc::address& c) {
    Bytes k;
    push20(k, c);
    k.push_back(0x3b);  // EXTCODESIZE
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH20 C; EXTCODEHASH; PUSH1 0; SSTORE; <sentinel>
Bytes probe_extcodehash(const evmc::address& c) {
    Bytes k;
    push20(k, c);
    k.push_back(0x3f);  // EXTCODEHASH
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH1 32; PUSH1 0; PUSH1 0; PUSH20 C; EXTCODECOPY; PUSH1 0; MLOAD; PUSH1 0; SSTORE; <sentinel>.
Bytes probe_extcodecopy(const evmc::address& c) {
    Bytes k;
    push1(k, 0x20);
    push1(k, 0x00);
    push1(k, 0x00);
    push20(k, c);
    k.push_back(0x3c);  // EXTCODECOPY
    push1(k, 0x00);
    k.push_back(0x51);
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH1 0 x4; PUSH20 C; GAS; STATICCALL; PUSH1 0; SSTORE; <sentinel>.
Bytes probe_staticcall(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push20(k, c);
    k.push_back(0x5a);  // GAS
    k.push_back(0xfa);  // STATICCALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// Same stack shape as STATICCALL.
Bytes probe_delegatecall(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push20(k, c);
    k.push_back(0x5a);  // GAS
    k.push_back(0xf4);  // DELEGATECALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH1 0 x4; PUSH1 1; PUSH20 C; GAS; CALL; PUSH1 0; SSTORE; <sentinel>.
Bytes probe_call_value(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x00);
    push1(k, 0x01);
    push20(k, c);
    k.push_back(0x5a);  // GAS
    k.push_back(0xf1);  // CALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH20 C; BALANCE; POP; PUSH1 1; PUSH1 1; SSTORE; STOP: the read is DISCARDED, so only the clash check can tell.
Bytes probe_balance_discarded(const evmc::address& c) {
    Bytes k;
    push20(k, c);
    k.push_back(0x31);  // BALANCE
    k.push_back(0x50);  // POP
    append_sentinel_and_stop(k);
    return k;
}

evmc::bytes32 word(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

struct ProbeCase {
    const char* name;
    Bytes (*make_code)(const evmc::address&);
    evmc::bytes32 genuine_obs;
    evmc::bytes32 spoofed_obs;
    bool observation_stored{true};
    bool loud_gas{false};
    bool creates_victim{false};
};

}  // namespace

TEST_CASE("StateTransition::run rejects read-only account spoofing across zero-gas-delta reads",
          "[mphf][state_transition][exec][clash]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address C = make_addr(0x33, 0x03);
    const evmc::address C2 = make_addr(0x44, 0x04);

    REQUIRE(addr_key8(C) != addr_key8(C2));

    const silkworm::Transaction tx = make_legacy_txn(D, /*gas_limit=*/1'000'000);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != C);
    REQUIRE(S != C2);

    const bytes32 kS = keccak_addr32(S);
    const bytes32 kD = keccak_addr32(D);
    const bytes32 kC = keccak_addr32(C);
    const bytes32 kC2 = keccak_addr32(C2);

    const Bytes c_code = victim_code();
    const bytes32 c_code_hash = keccak_bytes(ByteView{c_code.data(), c_code.size()});

    constexpr uint64_t kCBalance = 5000;
    constexpr uint64_t kCNonce = 3;
    constexpr uint64_t kDBalance = 1;
    const intx::uint256 s_balance{intx::uint256{1} << 64};

    evmc::bytes32 c_code_word{};
    std::memcpy(c_code_word.bytes, c_code.data(), c_code.size());

    const evmc::bytes32 kAbsentCodeHash{};
    const evmc::bytes32 kEmptyExistingCodeHash = silkworm::kEmptyHash;
    REQUIRE(c_code_hash != kAbsentCodeHash);
    REQUIRE(c_code_hash != kEmptyExistingCodeHash);
    REQUIRE(kEmptyExistingCodeHash != kAbsentCodeHash);

    const std::vector<ProbeCase> cases{
        {"BALANCE", &probe_balance, word(kCBalance), word(0)},
        {"EXTCODESIZE", &probe_extcodesize, word(c_code.size()), word(0)},
        {"EXTCODEHASH", &probe_extcodehash, c_code_hash, kAbsentCodeHash},
        {"EXTCODECOPY", &probe_extcodecopy, c_code_word, word(0)},
        {"STATICCALL", &probe_staticcall, word(0), word(1)},
        {"DELEGATECALL", &probe_delegatecall, word(0), word(1)},
        {"CALL-with-value", &probe_call_value, word(0), word(1),
         /*observation_stored=*/true, /*loud_gas=*/true, /*creates_victim=*/true},
        {"BALANCE-discarded", &probe_balance_discarded, word(0), word(0),
         /*observation_stored=*/false},
    };

    for (const auto& tc : cases) {
        DYNAMIC_SECTION("read = " << tc.name) {
            const Bytes d_code = tc.make_code(C);
            const bytes32 d_code_hash = keccak_bytes(ByteView{d_code.data(), d_code.size()});
            REQUIRE(d_code_hash != c_code_hash);

            const Bytes rlpS = account_rlp(S, 0, s_balance, silkworm::kEmptyHash, silkworm::kEmptyRoot);
            const Bytes rlpD = account_rlp(D, 1, intx::uint256{kDBalance}, d_code_hash, silkworm::kEmptyRoot);
            const Bytes rlpC = account_rlp(C, kCNonce, intx::uint256{kCBalance}, c_code_hash, silkworm::kEmptyRoot);
            const Bytes rlpC2 = account_rlp(C2, 7, intx::uint256{1234}, silkworm::kEmptyHash, silkworm::kEmptyRoot);

            std::vector<uint8_t> nodestore;
            const bytes32 prev_root = build_account_node_store(
                {{kS, rlpS}, {kD, rlpD}, {kC, rlpC}, {kC2, rlpC2}}, nodestore);
            REQUIRE_FALSE(nodestore.empty());

            const std::vector<uint8_t> code_store = build_code_store(
                {{d_code_hash, d_code}, {c_code_hash, c_code}});

            std::vector<DirectState::AccountInfo> accounts{
                make_eoa(S, 0, s_balance),
                make_contract(D, 1, intx::uint256{kDBalance}, d_code_hash,
                              static_cast<uint32_t>(d_code.size())),
                make_contract(C, kCNonce, intx::uint256{kCBalance}, c_code_hash,
                              static_cast<uint32_t>(c_code.size())),
                make_eoa(C2, 7, intx::uint256{1234})};
            const std::vector<uint8_t> genuine_blob =
                DirectState::build_blob_from_accounts(accounts, {}, code_store);
            REQUIRE_FALSE(genuine_blob.empty());
            {
                std::vector<uint8_t> probe = genuine_blob;
                DirectState ds{std::span<uint8_t>{probe}};
                REQUIRE(ds.mphf()->collisions_size == 0);
            }

            std::vector<uint8_t> forged_blob = genuine_blob;
            forge_slot_transposition(forged_blob, C, C2);
            const bool forgery_edited_bytes = (forged_blob != genuine_blob);
            REQUIRE(forgery_edited_bytes);

            const ChainSetup chain = make_chain(prev_root, tx, /*beneficiary=*/S);

            const ShadowRun honest = shadow_execute(genuine_blob, nodestore, prev_root,
                                                    chain.base.header, tx);
            REQUIRE(honest.sanitize_ok);
            REQUIRE(honest.post.missing == 0);
            REQUIRE_FALSE(honest.post.clashed);
            REQUIRE(honest.ds->created_accounts().find(C) == honest.ds->created_accounts().end());
            CHECK(honest.storage(D, 1) == word(1));
            if (tc.observation_stored) {
                CHECK(honest.storage(D, 0) == tc.genuine_obs);
            }

            const ShadowRun spoof = shadow_execute(forged_blob, nodestore, prev_root,
                                                   chain.base.header, tx);
            REQUIRE(spoof.sanitize_ok);
            REQUIRE(spoof.post.missing == 0);

            CHECK(spoof.storage(D, 1) == word(1));
            if (tc.observation_stored) {
                CHECK(spoof.storage(D, 0) == tc.spoofed_obs);
                CHECK(spoof.storage(D, 0) != honest.storage(D, 0));
            }
            if (std::string{tc.name} == "EXTCODEHASH") {
                CHECK(spoof.storage(D, 0) == kAbsentCodeHash);
                CHECK(spoof.storage(D, 0) != kEmptyExistingCodeHash);
                CHECK(honest.storage(D, 0) == c_code_hash);
            }
            const auto it_created = spoof.ds->created_accounts().find(C);
            REQUIRE(it_created != spoof.ds->created_accounts().end());
            CHECK(it_created->second.deleted == !tc.creates_victim);
            REQUIRE(spoof.post.clashed);

            if (tc.loud_gas) {
                CAPTURE(honest.gas_used, spoof.gas_used);
                CHECK(spoof.gas_used >= honest.gas_used + 25'000);
            }
            if (!tc.observation_stored) {
                CHECK(spoof.gas_used == honest.gas_used);
                CHECK(spoof.receipts_root == honest.receipts_root);
                CHECK(spoof.post.rejected);
            }

            {
                std::vector<uint8_t> env = make_envelope(chain, honest, genuine_blob, nodestore);
                REQUIRE_FALSE(env.empty());
                StateTransition st{std::span<uint8_t>{env}};
                uint64_t gas = 0;
                std::string log;
                {
                    StdoutCapture cap;
                    gas = st.run().gas_used;
                    log = cap.str();
                }
                CHECK_FALSE(st.failed());
                CHECK(gas == honest.gas_used);
                CHECK(log.find("Created and existing hashes clash") == std::string::npos);
                CHECK(log.find("New Root") != std::string::npos);
            }

            {
                std::vector<uint8_t> env = make_envelope(chain, spoof, forged_blob, nodestore);
                REQUIRE_FALSE(env.empty());
                StateTransition st{std::span<uint8_t>{env}};
                uint64_t gas = 0;
                std::string log;
                {
                    StdoutCapture cap;
                    gas = st.run().gas_used;
                    log = cap.str();
                }
                CHECK(st.failed());
                CHECK(gas == StateTransition::kRunFailure);
                CHECK(log.find("Created and existing hashes clash") != std::string::npos);
                CHECK(log.find("sanitize") == std::string::npos);
                CHECK(log.find("New Root") == std::string::npos);
                CHECK(log.find("recovered account") == std::string::npos);
            }
        }
    }
}
