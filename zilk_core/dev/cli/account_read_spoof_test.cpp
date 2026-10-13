// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end soundness proof for the created/existing hash clash check:
// a READ-ONLY account access whose witness routing has been sabotaged must be rejected,
// even when the block header is forged so that every other check passes.
//
// Why read-only accesses are the hard case
// ----------------------------------------
// An account that is only READ is not constrained by the post-state root: its leaf is
// unchanged, so the root the guest recomputes is the same whether the account was read
// as "present with its genuine values" or as "absent". Every read in this file funnels
// through `State::find` -> `DirectStateView::get_account`, and on Berlin+
// `Host::access_account` materializes the account via `get_or_insert` before its
// `is_precompile` early return, so ONE probe per address per block is enough to trip the
// routing. The opcodes covered here (BALANCE, EXTCODESIZE, EXTCODEHASH, EXTCODECOPY,
// STATICCALL, DELEGATECALL and a value-bearing CALL) are exactly the reads whose gas
// charge does not depend on whether the account exists, so gas is not a defense either.
// (The probes below DO show a gas difference, but only because the probe itself stores
// what it read; the last case removes even that by discarding the value, and then the
// honest and spoofed bundles are byte-for-byte identical outside the witness.)
// The value-bearing CALL is included as the loud counter-example: spoofing absence costs
// an extra ~25000 gas, which the attacker must (and here does) commit honestly — the
// clash check still rejects, independent of the gas checks.
//
// The forgery: MPHF slot transposition
// ------------------------------------
// C's and C2's `slot_offsets` entries are swapped in the serialized pre-state. `find(C)`
// then lands on C2's body, the 20-byte key comparison fails, and the lookup misses.
// Transposition (rather than slot zeroing) is deliberate: both bodies are still visited
// exactly once by `for_each`, so `sanitize()` resolves code offsets, refills both RLP
// caches with genuine values, and its modified-flag parity still balances. The pre-state
// leaves `GridMPT` sees are genuine, so no downstream RLP or root mismatch fires. The
// only trace left is `find_or_create_account` materializing a `deleted=true` record for
// C in `created_accounts_` — which `check_root` catches because keccak(C) is also an
// `addr_hashes` entry ("Created and existing hashes clash").
//
// Adversarial header
// ------------------
// For every case the block committed to the guest carries the gas, receipts root, logs
// bloom and state root of the SPOOFED execution, derived by shadow-running the very
// bundle the guest receives and mirroring `check_root` minus the clash rejection
// (`mirror_check_root`). Each case additionally runs the GENUINE bundle with its own
// honestly derived header and asserts it is ACCEPTED: that is what proves the header
// derivation is faithful rather than accidentally wrong.
//
// The genuine-bundle acceptance above makes the header derivation known-faithful. The clash is
// not the only check left: C's record also claims that keccak(C) is absent from the account
// trie, and `check_root` walks that claim to C's leaf, where it fails.
//
// NOTE: some helpers in `account_read_test_util.hpp` intentionally duplicate the private
// helpers of `addr_hash_orphan_test.cpp` (PR #101, branch canepat/account_routing_check).
// They can be deduped once that PR lands.

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

// ---------------------------------------------------------------------------
// The victim's code. Any call into C reverts, so an honest STATICCALL /
// DELEGATECALL / CALL returns 0 while a spoofed "absent C" returns 1 (a no-op
// success). It also gives C a non-empty code hash and a non-zero EXTCODESIZE.
//   PUSH1 0x00; PUSH1 0x00; REVERT
// ---------------------------------------------------------------------------
Bytes victim_code() {
    Bytes c;
    push1(c, 0x00);
    push1(c, 0x00);
    c.push_back(0xfd);  // REVERT
    return c;
}

// Each probe writes what it observed about C into storage[0] and the sentinel 1 into
// storage[1]. The sentinel is what makes a ZERO observation meaningful: storage[1] == 1
// proves the probe body ran to completion, so storage[0] == 0 is a real reading of
// "absent", not an absent write.

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

// PUSH1 32; PUSH1 0; PUSH1 0; PUSH20 C; EXTCODECOPY; PUSH1 0; MLOAD; PUSH1 0; SSTORE; <sentinel>
// (EXTCODECOPY pops address, destOffset, offset, size — so they are pushed in reverse.)
Bytes probe_extcodecopy(const evmc::address& c) {
    Bytes k;
    push1(k, 0x20);  // size
    push1(k, 0x00);  // code offset
    push1(k, 0x00);  // memory destOffset
    push20(k, c);    // address
    k.push_back(0x3c);  // EXTCODECOPY
    push1(k, 0x00);
    k.push_back(0x51);  // MLOAD -> first 32 code bytes, zero-padded
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH1 0 x4; PUSH20 C; GAS; STATICCALL; PUSH1 0; SSTORE; <sentinel>
// (STATICCALL pops gas, address, argsOffset, argsSize, retOffset, retSize.)
Bytes probe_staticcall(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push20(k, c);    // address
    k.push_back(0x5a);  // GAS
    k.push_back(0xfa);  // STATICCALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// Same stack shape as STATICCALL.
// PUSH1 0 x4; PUSH20 C; GAS; DELEGATECALL; PUSH1 0; SSTORE; <sentinel>
Bytes probe_delegatecall(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push20(k, c);    // address
    k.push_back(0x5a);  // GAS
    k.push_back(0xf4);  // DELEGATECALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH1 0 x4; PUSH1 1; PUSH20 C; GAS; CALL; PUSH1 0; SSTORE; <sentinel>
// (CALL pops gas, address, value, argsOffset, argsSize, retOffset, retSize.)
// The value makes this the LOUD case: if C is spoofed absent, the CALL is charged an
// extra 25000 for account creation.
Bytes probe_call_value(const evmc::address& c) {
    Bytes k;
    push1(k, 0x00);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push1(k, 0x01);  // value = 1 wei
    push20(k, c);    // address
    k.push_back(0x5a);  // GAS
    k.push_back(0xf1);  // CALL
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

// PUSH20 C; BALANCE; POP; PUSH1 1; PUSH1 1; SSTORE; STOP
// The purest case: the read result is DISCARDED, so honest and spoofed executions are
// indistinguishable — same gas, same receipts, same post-state root. Nothing but the
// clash check can tell them apart.
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
    evmc::bytes32 genuine_obs;   // expected storage[0] after the honest execution
    evmc::bytes32 spoofed_obs;   // expected storage[0] once C is hidden from find()
    bool observation_stored{true};
    bool loud_gas{false};        // spoofed execution costs ~25000 more
    bool creates_victim{false};  // spoofed execution revives the materialized record
};

}  // namespace

TEST_CASE("StateTransition::run rejects read-only account spoofing across zero-gas-delta reads",
          "[mphf][state_transition][exec][clash]") {
    // ---- Fixed account layout (only D's bytecode varies across cases) ----
    const evmc::address D = make_addr(0x22, 0x02);   // probe contract, called by the tx
    const evmc::address C = make_addr(0x33, 0x03);   // victim, read by the probe
    const evmc::address C2 = make_addr(0x44, 0x04);  // transposition partner

    // Precondition for slot transposition: distinct addr_key8 means each account owns a
    // slot of its own, so the two slot_offsets entries exist and can be swapped.
    REQUIRE(addr_key8(C) != addr_key8(C2));

    // Sender comes from the signature: run() RLP-decodes the block, which drops
    // set_sender, so the pre-state has to be built around the recovered address.
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

    // C's distinctive non-zero state: funded, non-zero nonce, real code.
    constexpr uint64_t kCBalance = 5000;
    constexpr uint64_t kCNonce = 3;
    constexpr uint64_t kDBalance = 1;  // enough for the value-bearing CALL case
    const intx::uint256 s_balance{intx::uint256{1} << 64};

    // EXTCODECOPY observation: the first 32 bytes of C's code, zero-padded.
    evmc::bytes32 c_code_word{};
    std::memcpy(c_code_word.bytes, c_code.data(), c_code.size());

    // EXTCODEHASH is an existence oracle with three distinct outcomes. Pin all three so
    // the assertion below cannot be satisfied by the wrong one.
    const evmc::bytes32 kAbsentCodeHash{};                          // account does not exist
    const evmc::bytes32 kEmptyExistingCodeHash = silkworm::kEmptyHash;  // exists, no code
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

            // ---- Pre-state: leaves, node store (=> prev_root), code store, blob ----
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
                // No CHD spill: C and C2 are slot-resident, so transposition is possible.
                REQUIRE(ds.mphf()->collisions_size == 0);
            }

            // The bundle handed to the guest: C and C2's MPHF slots transposed at rest.
            std::vector<uint8_t> forged_blob = genuine_blob;
            forge_slot_transposition(forged_blob, C, C2);
            // Compared as a bool: Catch2 would try to stringify the whole blob.
            const bool forgery_edited_bytes = (forged_blob != genuine_blob);
            REQUIRE(forgery_edited_bytes);

            const ChainSetup chain = make_chain(prev_root, tx, /*beneficiary=*/S);

            // ================= honest producer =================
            const ShadowRun honest = shadow_execute(genuine_blob, nodestore, prev_root,
                                                    chain.base.header, tx);
            REQUIRE(honest.sanitize_ok);
            REQUIRE(honest.post.missing == 0);
            REQUIRE_FALSE(honest.post.clashed);
            REQUIRE(honest.ds->created_accounts().find(C) == honest.ds->created_accounts().end());
            CHECK(honest.storage(D, 1) == word(1));  // probe ran
            if (tc.observation_stored) {
                CHECK(honest.storage(D, 0) == tc.genuine_obs);
            }

            // ================= spoofing producer =================
            // Same sanitize path as the guest, over the very bytes the guest gets.
            const ShadowRun spoof = shadow_execute(forged_blob, nodestore, prev_root,
                                                   chain.base.header, tx);
            // sanitize() must NOT be what rejects this bundle: transposition keeps every
            // body walked, the caches genuine and the modified-flag parity balanced.
            REQUIRE(spoof.sanitize_ok);
            REQUIRE(spoof.post.missing == 0);

            // (a) the spoofed observation really happened.
            CHECK(spoof.storage(D, 1) == word(1));  // probe ran
            if (tc.observation_stored) {
                CHECK(spoof.storage(D, 0) == tc.spoofed_obs);
                CHECK(spoof.storage(D, 0) != honest.storage(D, 0));
            }
            if (std::string{tc.name} == "EXTCODEHASH") {
                // Existence oracle: the spoofed read reported "no account at all",
                // which is distinct from "exists with empty code".
                CHECK(spoof.storage(D, 0) == kAbsentCodeHash);
                CHECK(spoof.storage(D, 0) != kEmptyExistingCodeHash);
                CHECK(honest.storage(D, 0) == c_code_hash);
            }
            // The read routed to nothing and left the trace the PR relies on.
            const auto it_created = spoof.ds->created_accounts().find(C);
            REQUIRE(it_created != spoof.ds->created_accounts().end());
            CHECK(it_created->second.deleted == !tc.creates_victim);
            REQUIRE(spoof.post.clashed);

            if (tc.loud_gas) {
                // Loud by contrast: spoofing absence costs ~25000 extra gas, which the
                // attacker commits honestly in the forged header. Rejection is therefore
                // not coming from any gas check.
                // Observed delta is 44894 = 25000 (G_newaccount, charged because the
                // spoofed C does not exist) + 19900 (the probe's own SSTORE storing 1
                // instead of a no-op 0) - 6 (C's revert body, never executed when C is
                // spoofed absent). Only the 25000 is asserted, so an evmone gas-schedule
                // change elsewhere in the probe cannot silently invalidate this.
                CAPTURE(honest.gas_used, spoof.gas_used);
                CHECK(spoof.gas_used >= honest.gas_used + 25'000);
            }
            if (!tc.observation_stored) {
                // Gas-neutral read with a discarded result: the two executions are
                // observationally identical, so the forged block is byte-identical to
                // the honest one. Only the witness differs, and the walk of the claim
                // that C is absent, which C's record in created_accounts_ makes, fails
                // at C's leaf.
                CHECK(spoof.gas_used == honest.gas_used);
                CHECK(spoof.receipts_root == honest.receipts_root);
                CHECK(spoof.post.rejected);
            }

            // ---- Run 1: honest bundle + honest header must be ACCEPTED ----
            // This is what proves the harness (and therefore the forged header below)
            // is faithful: a wrong root/gas derivation would fail here too.
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
                CHECK(log.find("New Root") != std::string::npos);  // root WAS compared
            }

            // ---- Run 2: forged bundle + the header the spoofed execution justifies ----
            // Gas, receipts root and logs bloom match what the guest recomputes for this
            // witness. Absent the clash check, the walk of the claim that C is absent
            // would reject it next, at C's leaf.
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
                // (b) rejected, and (c) rejected by the clash path specifically.
                CHECK(st.failed());
                CHECK(gas == StateTransition::kRunFailure);
                CHECK(log.find("Created and existing hashes clash") != std::string::npos);
                // Not sanitize (which prints only when it rejects), and the clash fires
                // BEFORE the root is even computed - no "New Root" line was emitted.
                CHECK(log.find("sanitize") == std::string::npos);
                CHECK(log.find("New Root") == std::string::npos);
            }
        }
    }
}
