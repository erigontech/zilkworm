// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// End-to-end tests for the STORAGE blank-read path. An honest read of a storage
// slot that does not exist must be ACCEPTED; a bundle that OMITS a read storage
// slot must be REJECTED (the anchored storage trie still carries the real leaf).
// Extracted from the account-read suite into the stacked storage-blank-read PR.
//
// KNOWN LIMITATION (why this ships as a separate, stacked PR, not on #138):
// real mainnet witnesses carry NO exclusion-proof nodes for absent-slot reads,
// so the storage trie cannot be reconstructed to prove a blank slot. A release
// state-root sweep of 200 honest mainnet blocks fails 22 of them with a
// "missing hash ref" error. This feature needs witness-level storage exclusion
// proofs before it can be enabled in production.

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::ByteView;
using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

evmc::bytes32 word(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

struct RunOutcome {
    uint64_t gas{StateTransition::kRunFailure};
    std::string log;
    bool failed{true};
};

/// Seals `sr`'s honest header into an envelope and drives the PUBLIC guest entry point.
RunOutcome drive_guest(const ChainSetup& chain, const ShadowRun& sr,
                       const std::vector<uint8_t>& blob,
                       const std::vector<uint8_t>& nodestore) {
    std::vector<uint8_t> env = make_envelope(chain, sr, blob, nodestore);
    REQUIRE_FALSE(env.empty());
    StateTransition st{std::span<uint8_t>{env}};
    RunOutcome out{};
    {
        StdoutCapture cap;  // keep tight: Catch2 writes to std::cout too
        out.gas = st.run().gas_used;
        out.log = cap.str();
    }
    out.failed = st.failed();
    return out;
}

/// The acceptance contract every honest case must satisfy.
void expect_accepted(const RunOutcome& o, const ShadowRun& sr) {
    CHECK_FALSE(o.failed);
    CHECK(o.gas == sr.gas_used);
    CHECK(o.gas != StateTransition::kRunFailure);
    // The clash check must not have fired ...
    CHECK(o.log.find("Created and existing hashes clash") == std::string::npos);
    // ... nor anything else: no rejection path prints on an accepted block.
    CHECK(o.log.find("ERROR") == std::string::npos);
    // The root WAS computed and compared, and it is the one the shadow run derived.
    CHECK(o.log.find("New Root") != std::string::npos);
    CHECK(o.log.find("New Root: " + silkworm::to_hex(sr.post.root)) != std::string::npos);
}

/// The witness-side invariants that make the accepted root meaningful.
void expect_witness_complete(const ShadowRun& sr) {
    REQUIRE(sr.sanitize_ok);
    CHECK(sr.post.missing == 0);   // no node the guest would have had to guess
    CHECK_FALSE(sr.post.clashed);  // created and existing address sets stayed disjoint
    // Independent from-scratch root: agreement pins the leaf set of the accepted root.
    const auto scratch = sr.ds->state_root_hash();
    REQUIRE(scratch.has_value());
    CHECK(*scratch == sr.post.root);
}

/// SLOADs every slot in `absent` and writes `1 + sum(reads)` into storage[0], then the
/// sentinel storage[1] = 1. storage[0] == 1 therefore says every read returned zero, and
/// the sentinel says the body ran at all.
Bytes probe_absent_slot_reads(std::initializer_list<uint8_t> absent) {
    Bytes k;
    push1(k, 0x01);  // running total, so a zero sum is not "nothing happened"
    for (const uint8_t slot : absent) {
        push1(k, slot);
        k.push_back(0x54);  // SLOAD
        k.push_back(0x01);  // ADD
    }
    store_observation(k);  // storage[0] = 1 + sum
    append_sentinel_and_stop(k);
    return k;
}

/// `PUSH1 <slot>; SLOAD; PUSH1 1; ADD; PUSH1 <slot>; SSTORE; STOP` — increments a counter
/// slot and halts. (SSTORE pops key then value, so the key is pushed last.)
void increment_slot_and_stop(Bytes& code, uint8_t slot) {
    push1(code, slot);
    code.push_back(0x54);  // SLOAD
    push1(code, 0x01);
    code.push_back(0x01);  // ADD
    push1(code, slot);
    code.push_back(0x55);  // SSTORE
    code.push_back(0x00);  // STOP
}

/// The branching contract: `storage[slot_c]` decides WHICH counter is incremented, so the
/// value read out of one witness slot is observable in the post-state of another.
///
///   0x00  PUSH1 0x0c    ; slot C
///   0x02  SLOAD
///   0x03  PUSH1 0x10    ; the JUMPDEST below
///   0x05  JUMPI         ; C != 0 -> take the A branch
///   0x06  PUSH1 0x0b    ; else (C == 0): storage[B] += 1
///   0x08  SLOAD
///   0x09  PUSH1 0x01
///   0x0b  ADD
///   0x0c  PUSH1 0x0b
///   0x0e  SSTORE
///   0x0f  STOP
///   0x10  JUMPDEST      ; storage[A] += 1
///   0x11  PUSH1 0x0a
///   0x13  SLOAD
///   0x14  PUSH1 0x01
///   0x16  ADD
///   0x17  PUSH1 0x0a
///   0x19  SSTORE
///   0x1a  STOP
Bytes branch_on_slot_code(uint8_t slot_a, uint8_t slot_b, uint8_t slot_c) {
    Bytes k;
    push1(k, slot_c);
    k.push_back(0x54);       // SLOAD
    push1(k, 0x00);          // placeholder, patched to the JUMPDEST offset below
    const std::size_t dest_operand = k.size() - 1;
    k.push_back(0x57);       // JUMPI
    increment_slot_and_stop(k, slot_b);
    k[dest_operand] = static_cast<uint8_t>(k.size());
    k.push_back(0x5b);       // JUMPDEST
    increment_slot_and_stop(k, slot_a);
    return k;
}

constexpr uint64_t kProbeGas = 1'000'000;
const intx::uint256 kSenderBalance{intx::uint256{1} << 64};

}  // namespace

// A contract's storage slot is dropped from the witness, and the omission IS DETECTED.
//
// The dropped slot is read during execution and returns zero. `read_storage` records that
// blank read, `check_root` emits a read assertion for it (initial 0x80 = "value is zero",
// empty current = read-only), and `GridMPT` verifies it against the anchored storage trie.
// The slot's real leaf is still reachable there, so the assertion descends to it and the
// pre-value mismatch (0x80 vs the real value) rejects the block — even though its header is
// consistent with the omitting execution.
//
// The honest bundle (every slot present) still verifies: A is incremented, and reads that
// are genuinely absent confirm against the trie instead of inserting a phantom leaf.
//
// The forgery costs one decremented `slot_count`: the inline slots follow the `Account` POD
// sorted ascending by key, so the highest-keyed slot is the trailing one and dropping it
// moves no other byte. `validate_prestate_layout` and `sanitize()` still accept the shrunken
// record (the leaf RLP `sanitize()` caches is rebuilt from the unedited `storage_root`); the
// block is caught only at root check, by the read assertion.
TEST_CASE("StateTransition::run rejects a bundle omitting a read storage slot",
          "[mphf][state_transition][exec][omission]") {
    const evmc::address D = make_addr(0x55, 0x05);  // the branching contract, called by the tx

    constexpr uint8_t kSlotA = 0x0a;  // counter the HONEST execution increments
    constexpr uint8_t kSlotB = 0x0b;  // counter incremented once C reads as zero
    constexpr uint8_t kSlotC = 0x0c;  // the omitted slot; highest key, so dropping it is a
                                      // single decrement of slot_count
    static_assert(kSlotA < kSlotB && kSlotB < kSlotC);

    const silkworm::Transaction tx = make_legacy_txn(D, /*gas_limit=*/1'000'000);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);

    const Bytes d_code = branch_on_slot_code(kSlotA, kSlotB, kSlotC);
    // Pins the disassembly in the comment above: 27 bytes, JUMPI target 0x10, JUMPDEST there.
    REQUIRE(d_code.size() == 27);
    REQUIRE(d_code[4] == 0x10);
    REQUIRE(d_code[0x10] == 0x5b);
    const bytes32 d_code_hash = keccak_bytes(ByteView{d_code.data(), d_code.size()});

    // ---- Pre-state: A and B start at zero, C at one ----
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = D,
                 .nonce = 1,
                 .balance = 0,
                 .code = d_code,
                 .storage = {{word(kSlotA), word(0)},
                             {word(kSlotB), word(0)},
                             {word(kSlotC), word(1)}}},
    });
    REQUIRE_FALSE(ps.blob.empty());
    REQUIRE_FALSE(ps.nodestore.empty());

    // D's genuine storage root and pre-state account leaf: what the forgery must leave intact.
    bytes32 d_sroot{};
    {
        std::vector<uint8_t> probe_blob = ps.blob;
        DirectState probe{std::span<uint8_t>{probe_blob}};
        // No CHD spill: D is slot-resident, so the forgery can reach its record.
        REQUIRE(probe.mphf()->collisions_size == 0);
        d_sroot = probe.account_storage_root(D);
    }
    CHECK(d_sroot != silkworm::kEmptyRoot);  // C == 1 is the one live pre-state slot
    const Bytes d_leaf = account_rlp(D, 1, 0, d_code_hash, d_sroot);

    // ---- The forgery: drop C, keep the account and its other two slots ----
    std::vector<uint8_t> forged_blob = ps.blob;
    const evmc::bytes32 dropped = forge_drop_highest_slot(forged_blob, D);
    CHECK(dropped == word(kSlotC));  // C, not A or B
    // Compared as bools: Catch2 would try to stringify the whole blob.
    const bool forgery_edited_bytes = (forged_blob != ps.blob);
    REQUIRE(forgery_edited_bytes);
    const bool forgery_kept_the_size = (forged_blob.size() == ps.blob.size());
    CHECK(forgery_kept_the_size);  // one field rewritten, not a re-serialization

    // ---- Both witness-level gates still accept the shrunken record ----
    // `DirectState`'s constructor runs `validate_prestate_layout` and ABORTS if it rejects,
    // so reaching the next line at all is that check's verdict; `sanitize()`'s is explicit.
    {
        std::vector<uint8_t> inspect = forged_blob;
        DirectState ds{std::span<uint8_t>{inspect}};
        REQUIRE(ds.sanitize());
        const Account* pa = ds.find_pre_account_unchecked(D);
        REQUIRE(pa != nullptr);
        CHECK(pa->slot_count == 2);
        // The omitted slot reads back as a plain zero word — the same answer a genuinely
        // empty slot gives, which is exactly why nothing downstream can tell them apart.
        CHECK(ds.read_storage(D, word(kSlotC)) == word(0));
        CHECK(ds.created_accounts().empty());  // a slot miss materializes NOTHING
        // The cached leaf RLP, rebuilt from the untouched storage_root, is still the genuine
        // pre-state account-trie value, so the pre-state leaves `GridMPT` sees are genuine.
        const bool leaf_matches_prestate = (ByteView{pa->acc_rlp_buf, pa->acc_rlp_len} ==
                                            ByteView{d_leaf.data(), d_leaf.size()});
        CHECK(leaf_matches_prestate);
    }

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);

    // ================= honest producer =================
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(honest.sanitize_ok);
    // 0 means the fixture carries every node BOTH tries need — the account trie's and D's
    // storage trie's. Without that, no root derived here would mean anything.
    REQUIRE(honest.post.missing == 0);
    REQUIRE_FALSE(honest.post.clashed);
    REQUIRE(honest.all_succeeded());
    CHECK(honest.storage(D, kSlotA) == word(1));  // C == 1 -> A incremented
    CHECK(honest.storage(D, kSlotB) == word(0));
    CHECK(honest.storage(D, kSlotC) == word(1));  // C itself untouched
    // While the bundle is complete, the anchored root and a from-scratch walk agree.
    const auto honest_scratch = honest.ds->state_root_hash();
    REQUIRE(honest_scratch.has_value());
    CHECK(*honest_scratch == honest.post.root);

    // ================= omitting producer =================
    const ShadowRun forged =
        shadow_execute(forged_blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(forged.sanitize_ok);
    REQUIRE(forged.post.missing == 0);
    REQUIRE_FALSE(forged.post.clashed);  // the account is present: nothing to clash with
    REQUIRE(forged.all_succeeded());
    CHECK(forged.ds->created_accounts().empty());

    // (a) The executions genuinely diverge: the OTHER counter moved.
    CHECK(forged.storage(D, kSlotC) == word(0));  // C read as absent ...
    CHECK(forged.storage(D, kSlotB) == word(1));  // ... so B was incremented ...
    CHECK(forged.storage(D, kSlotA) == word(0));  // ... and A never was.
    CHECK(forged.post.root != honest.post.root);

    // (b) The omitted slot survives inside a folded node hash: the ANCHORED root the guest
    // recomputes still contains C's leaf, while a from-scratch walk over the slots the bundle
    // carries does not. Only the anchored root is ever compared, and it is the one the
    // attacker publishes.
    const auto forged_scratch = forged.ds->state_root_hash();
    REQUIRE(forged_scratch.has_value());
    CHECK(*forged_scratch != forged.post.root);

    // ---- Run 1: honest bundle + honest header must be ACCEPTED ----
    // This is what proves the harness (and therefore the forged header below) is faithful.
    {
        std::vector<uint8_t> env = make_envelope(chain, honest, ps.blob, ps.nodestore);
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
        CHECK(log.find("New Root: " + silkworm::to_hex(honest.post.root)) != std::string::npos);
        CHECK(log.find("ERROR") == std::string::npos);
    }

    // ---- Run 2: forged bundle + the header the omitting execution justifies ----
    // The dropped slot is read blank, so check_root emits a read assertion for it. The real
    // leaf is still reachable under the anchored storage root, so the assertion descends to
    // it and the pre-value mismatch (0x80 vs the real value) rejects the block, even though
    // the header is consistent with the omitting execution.
    {
        std::vector<uint8_t> env = make_envelope(chain, forged, forged_blob, ps.nodestore);
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
        CHECK(log.find("Pre value mismatch in existing leaf") != std::string::npos);
        // Not the clash check, not sanitize: the storage read assertion is what catches it.
        CHECK(log.find("New Root: " + silkworm::to_hex(forged.post.root)) == std::string::npos);
        CHECK(log.find("Created and existing hashes clash") == std::string::npos);
        CHECK(log.find("sanitize") == std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// 7. Reads of storage slots that genuinely do not exist.
// ---------------------------------------------------------------------------
// Reading an untouched slot is the most ordinary thing in the EVM: it answers zero, and the
// block must still verify. The account here also WRITES two slots the bundle does not carry,
// so the accepted root has to move for those two while the three read-only misses leave it
// alone. These are the only cases with storage fixtures on the honest side, so they are also
// what exercises the harness's storage-trie node collection: without it the per-account
// storage walk would report a missing node instead of a root.
//
// The two trie shapes reach different arms of that walk, hence two sections:
//   * a POPULATED storage trie — the writes are inserted into the anchored trie;
//   * an EMPTY storage trie (`storage_root == kEmptyRoot`) — the grid starts empty, i.e. the
//     "(re)seed the trie as a single leaf" arm.
//
// Nothing here asserts that a read leaves a trace behind, because it does not: a slot miss is
// answered with a bare zero word and recorded nowhere. That is the unguarded behaviour the
// omission case in `account_read_spoof_test.cpp` documents.
TEST_CASE("StateTransition::run accepts honest reads of storage slots that do not exist",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);  // the reading contract
    constexpr uint8_t kAbsent1 = 0x21;
    constexpr uint8_t kAbsent2 = 0x22;
    constexpr uint8_t kAbsent3 = 0x23;

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);

    const Bytes d_code = probe_absent_slot_reads({kAbsent1, kAbsent2, kAbsent3});

    auto prestate_with = [&](std::vector<std::pair<evmc::bytes32, evmc::bytes32>> d_storage) {
        const Prestate ps = build_prestate({
            AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
            AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code,
                     .storage = std::move(d_storage)},
        });
        REQUIRE_FALSE(ps.blob.empty());
        return ps;
    };

    // storage[0] and storage[1] are written but absent from the bundle, so both writes land in
    // the overflow map and the storage walk has to insert them; kAbsent1..3 are read-only
    // misses that move nothing.
    auto expect_accepted_run = [&](const Prestate& ps) {
        const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
        const ShadowRun honest =
            shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
        expect_witness_complete(honest);
        REQUIRE(honest.all_succeeded());

        CHECK(honest.storage(D, 1) == word(1));  // sentinel: the body ran ...
        CHECK(honest.storage(D, 0) == word(1));  // ... and 1 + 0 + 0 + 0 came out of it

        expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
    };

    SECTION("populated storage trie") {
        expect_accepted_run(prestate_with({{word(5), word(50)},
                                           {word(6), word(60)},
                                           {word(7), word(70)}}));
    }

    SECTION("empty storage trie") {
        expect_accepted_run(prestate_with({}));
    }
}
