// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// False-reject guard for the created/existing hash clash check: HONEST blocks that
// populate `created_accounts_` must still be ACCEPTED.
//
// Why this file exists
// --------------------
// `DirectState` materializes a `deleted=true` record for every account it is asked about
// but cannot find in the witness (`find_or_create_account` for account reads,
// `observe_account_` for `read_code` / `read_storage` / `has_storage`). On mainnet that
// happens on essentially every block: `Host::access_account` materializes precompiles
// 0x01..0x11 through `get_or_insert` BEFORE its `is_precompile` early return, fresh EOA
// recipients are absent by definition, and so can be the coinbase. So a NON-EMPTY overlay
// can never be a rejection signal — the only discriminator is the hash clash, i.e. a
// created address whose keccak is also an `addr_hashes` entry. A clash that fired on an
// honest block would reject a valid chain, which is why every case here asserts
// acceptance, not merely "no crash":
//
//   * `!st.failed()` and `gas == <honestly derived gas>`,
//   * a `New Root: <the root the shadow run derived>` line in the guest log,
//   * NO "Created and existing hashes clash" and no `ERROR` line at all,
//   * `mirror_check_root(...).clashed == false` and `.missing == 0`, so a witness gap or
//     an unexpected clash surfaces explicitly instead of hiding behind a matching root.
//
// The overlay is inspected on the shadow run's `DirectState` (the one inside
// `StateTransition::run` is private), which is sound because the shadow sanitizes and
// executes the very bytes the guest is handed.
//
// Post-state roots are cross-checked against `DirectState::state_root_hash()`, a
// from-scratch `HashBuilder` walk over every live record. It shares no code with
// `check_root`'s incremental `GridMPT` merge, so agreement between the two also pins down
// WHICH leaves the accepted root contains (see cases 5 and 6).
//
// Cases
// -----
//   1. read of an address absent from the witness entirely  -> materialized, harmless
//   2. precompile reads (0x01 BALANCE, 0x04 STATICCALL)     -> a populated overlay is NORMAL
//   3. control: a witness-resident read materializes NOTHING
//   4. code and storage reads of absent accounts (EVM route + direct route)
//   5. selfdestruct-then-read in the same block             -> deleted, but no clash
//   6. read-absent-then-CREATE2 at the same address         -> revived in place, no twin

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

/// An address as the EVM leaves it on the stack: right-aligned in a 32-byte word.
evmc::bytes32 addr_word(const evmc::address& a) {
    evmc::bytes32 out{};
    std::memcpy(out.bytes + 12, a.bytes, 20);
    return out;
}

/// `PUSH1 <slot>; SSTORE` — stores the top of the stack into `storage[slot]`.
void store_at(Bytes& code, uint8_t slot) {
    push1(code, slot);
    code.push_back(0x55);  // SSTORE
}

/// True iff keccak(addr) is one of the witness's `addr_hashes` entries, i.e. the account
/// has a pre-state leaf and a clash with a created record would be possible.
bool witness_resident(const DirectState& ds, const evmc::address& a) {
    const bytes32 kh = keccak_addr32(a);
    for (const auto& e : ds.addr_hashes()) {
        if (std::memcmp(e.addr_hash, kh.bytes, 32) == 0) return true;
    }
    return false;
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
    CHECK_FALSE(sr.post.rejected);  // every trie walk bound its claims
    // Independent from-scratch root: agreement pins the leaf set of the accepted root.
    const auto scratch = sr.ds->state_root_hash();
    REQUIRE(scratch.has_value());
    CHECK(*scratch == sr.post.root);
}

// ---------------------------------------------------------------------------
// Probe bodies. Each stores what it observed and then the sentinel storage[1] = 1,
// so a ZERO observation is still distinguishable from "the probe never ran".
// ---------------------------------------------------------------------------

/// PUSH20 a; BALANCE; -> storage[0]
Bytes probe_balance(const evmc::address& a) {
    Bytes k;
    push20(k, a);
    k.push_back(0x31);  // BALANCE
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

/// BALANCE of `p1` -> storage[0], then STATICCALL into `p2` -> storage[2].
Bytes probe_two_precompiles(const evmc::address& p1, const evmc::address& p2) {
    Bytes k;
    push20(k, p1);
    k.push_back(0x31);  // BALANCE
    store_observation(k);

    push1(k, 0x00);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push20(k, p2);   // address
    k.push_back(0x5a);  // GAS
    k.push_back(0xfa);  // STATICCALL
    store_at(k, 0x02);

    append_sentinel_and_stop(k);
    return k;
}

/// EXTCODESIZE of `a` -> storage[0]; first 32 code bytes of `a` -> storage[2].
Bytes probe_code_reads(const evmc::address& a) {
    Bytes k;
    push20(k, a);
    k.push_back(0x3b);  // EXTCODESIZE
    store_observation(k);

    push1(k, 0x20);  // size
    push1(k, 0x00);  // code offset
    push1(k, 0x00);  // memory destOffset
    push20(k, a);    // address
    k.push_back(0x3c);  // EXTCODECOPY
    push1(k, 0x00);
    k.push_back(0x51);  // MLOAD
    store_at(k, 0x02);

    append_sentinel_and_stop(k);
    return k;
}

/// BALANCE of `a` -> storage[0]; EXTCODESIZE of `a` -> storage[2].
Bytes probe_balance_and_codesize(const evmc::address& a) {
    Bytes k;
    push20(k, a);
    k.push_back(0x31);  // BALANCE
    store_observation(k);

    push20(k, a);
    k.push_back(0x3b);  // EXTCODESIZE
    store_at(k, 0x02);

    append_sentinel_and_stop(k);
    return k;
}

/// `PUSH1 0x01; PUSH1 0x00; RETURN` — deploys the single byte 0x00 (STOP).
Bytes create2_initcode() {
    Bytes k;
    push1(k, 0x01);     // return size
    push1(k, 0x00);     // return offset
    k.push_back(0xf3);  // RETURN
    return k;
}

/// BALANCE of `a` -> storage[0] (materializing the twin), then CREATE2 at `a` with
/// `salt`, whose returned address goes to storage[2].
Bytes probe_balance_then_create2(const evmc::address& a, uint8_t salt) {
    const Bytes init = create2_initcode();
    REQUIRE(init.size() == 5);

    Bytes k;
    push20(k, a);
    k.push_back(0x31);  // BALANCE
    store_observation(k);

    // PUSH5 <initcode>; PUSH1 0; MSTORE -> mem[27..32) == initcode (right-aligned).
    k.push_back(0x64);  // PUSH5
    k.insert(k.end(), init.begin(), init.end());
    push1(k, 0x00);
    k.push_back(0x52);  // MSTORE

    push1(k, salt);     // salt
    push1(k, 0x05);     // size
    push1(k, 0x1b);     // offset = 32 - 5
    push1(k, 0x00);     // value
    k.push_back(0xf5);  // CREATE2
    store_at(k, 0x02);

    append_sentinel_and_stop(k);
    return k;
}

/// `PUSH20 to; SELFDESTRUCT` — pre-Cancun this really destroys the account.
Bytes selfdestruct_code(const evmc::address& to) {
    Bytes k;
    push20(k, to);
    k.push_back(0xff);  // SELFDESTRUCT
    return k;
}

/// CREATE2 address: keccak(0xff ++ sender ++ salt ++ keccak(initcode))[12:].
evmc::address create2_address(const evmc::address& sender, const evmc::bytes32& salt,
                              ByteView initcode) {
    Bytes buf;
    buf.push_back(0xff);
    buf.insert(buf.end(), sender.bytes, sender.bytes + 20);
    buf.insert(buf.end(), salt.bytes, salt.bytes + 32);
    const bytes32 init_hash = keccak_bytes(initcode);
    buf.insert(buf.end(), init_hash.bytes, init_hash.bytes + 32);
    const bytes32 h = keccak_bytes(ByteView{buf.data(), buf.size()});
    evmc::address out{};
    std::memcpy(out.bytes, h.bytes + 12, 20);
    return out;
}

constexpr uint64_t kProbeGas = 1'000'000;
const intx::uint256 kSenderBalance{intx::uint256{1} << 64};

}  // namespace

// ---------------------------------------------------------------------------
// 1. Read of an address absent from the witness entirely.
// ---------------------------------------------------------------------------
// The everyday mainnet shape: a BALANCE of an address that is in neither the MPHF map nor
// `addr_hashes`. The read materializes a `deleted=true` record, and because keccak(A) is
// NOT an `addr_hashes` entry there is nothing for it to clash with.
TEST_CASE("StateTransition::run accepts an honest read of an address absent from the witness",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);  // probe contract
    const evmc::address A = make_addr(0x77, 0x07);  // never in the witness

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != A);

    const Bytes d_code = probe_balance(A);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
    });
    REQUIRE_FALSE(ps.blob.empty());
    REQUIRE_FALSE(ps.nodestore.empty());

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    expect_witness_complete(honest);
    REQUIRE(honest.all_succeeded());

    // The probe ran and really saw "no account": storage[1] is the sentinel.
    CHECK(honest.storage(D, 1) == word(1));
    CHECK(honest.storage(D, 0) == word(0));

    // A is absent from BOTH witness structures — no pre-state leaf, nothing to clash with.
    CHECK_FALSE(witness_resident(*honest.ds, A));
    CHECK(witness_resident(*honest.ds, S));
    CHECK(witness_resident(*honest.ds, D));

    // Materialization happened, and it was harmless.
    const Account* rec = honest.ds->find_created_account(A);
    REQUIRE(rec != nullptr);
    CHECK(rec->deleted);
    // Only A: witness-resident accounts are never shadowed by an overlay record.
    CHECK(honest.ds->created_accounts().size() == 1);

    expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
}

// ---------------------------------------------------------------------------
// 2. Precompile reads.
// ---------------------------------------------------------------------------
// INTENT: this is the case that proves a POPULATED OVERLAY IS NORMAL. `Host::access_account`
// runs `get_or_insert` before its `is_precompile` early return, so any touch of 0x01..0x11
// materializes a record on a perfectly honest block. If "created_accounts_ is non-empty"
// were ever treated as suspicious, mainnet would stop verifying here.
TEST_CASE("StateTransition::run accepts an honest block whose precompile touches populate the overlay",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address kEcrecover = make_addr(0x00, 0x01);  // 0x00..01
    const evmc::address kIdentity = make_addr(0x00, 0x04);   // 0x00..04

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);

    const Bytes d_code = probe_two_precompiles(kEcrecover, kIdentity);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
    });
    REQUIRE_FALSE(ps.blob.empty());

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    expect_witness_complete(honest);
    REQUIRE(honest.all_succeeded());

    CHECK(honest.storage(D, 1) == word(1));  // probe ran
    CHECK(honest.storage(D, 0) == word(0));  // BALANCE of 0x01
    CHECK(honest.storage(D, 2) == word(1));  // STATICCALL into 0x04 succeeded

    // Both precompiles are now in the overlay, on an honest block, with no forgery in sight.
    const Account* rec1 = honest.ds->find_created_account(kEcrecover);
    const Account* rec4 = honest.ds->find_created_account(kIdentity);
    REQUIRE(rec1 != nullptr);
    REQUIRE(rec4 != nullptr);
    CHECK(rec1->deleted);
    CHECK(rec4->deleted);
    CHECK(honest.ds->created_accounts().size() == 2);
    // Neither has a pre-state leaf, which is exactly why the merge cannot clash.
    CHECK_FALSE(witness_resident(*honest.ds, kEcrecover));
    CHECK_FALSE(witness_resident(*honest.ds, kIdentity));

    expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
}

// ---------------------------------------------------------------------------
// 3. Control: a witness-resident account read does NOT materialize.
// ---------------------------------------------------------------------------
// Materialization must fire only on a TOTAL miss. If every read left a record behind, the
// clash check would reject every block that reads any witness account.
TEST_CASE("DirectState leaves no overlay record when an honest read resolves in the witness",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address R = make_addr(0x33, 0x03);  // properly present in the witness

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != R);

    constexpr uint64_t kRBalance = 4242;
    const Bytes d_code = probe_balance(R);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
        AcctSpec{.addr = R, .nonce = 9, .balance = intx::uint256{kRBalance}},
    });
    REQUIRE_FALSE(ps.blob.empty());

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    expect_witness_complete(honest);
    REQUIRE(honest.all_succeeded());

    // The read resolved to R's genuine balance, so it really did route through the witness.
    CHECK(honest.storage(D, 1) == word(1));
    CHECK(honest.storage(D, 0) == word(kRBalance));

    CHECK(witness_resident(*honest.ds, R));
    CHECK(honest.ds->find_created_account(R) == nullptr);
    // Nothing at all was materialized: no absent address was touched.
    CHECK(honest.ds->created_accounts().empty());

    expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
}

// ---------------------------------------------------------------------------
// 4. Code and storage reads of an absent account.
// ---------------------------------------------------------------------------
// Exercises the `observe_account_` entry points added on top of the account-read path.
// The EVM section covers the code reads end to end; `read_storage` / `has_storage` cannot
// be reached through the EVM for an ABSENT address (evmone resolves the account first, and
// an account with no code never executes SLOAD in its own context), so they are driven
// directly against `DirectState` in the second section — same bundle, same sanitize.
TEST_CASE("DirectState code and storage reads of absent accounts stay harmless",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);
    const evmc::address A1 = make_addr(0x81, 0x11);  // EXTCODESIZE / EXTCODECOPY target
    const evmc::address A2 = make_addr(0x82, 0x12);  // read_code
    const evmc::address A3 = make_addr(0x83, 0x13);  // read_storage
    const evmc::address A4 = make_addr(0x84, 0x14);  // has_storage

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});

    const Bytes d_code = probe_code_reads(A1);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
    });
    REQUIRE_FALSE(ps.blob.empty());

    SECTION("EXTCODESIZE and EXTCODECOPY of an absent account, end to end") {
        const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
        const ShadowRun honest =
            shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
        expect_witness_complete(honest);
        REQUIRE(honest.all_succeeded());

        CHECK(honest.storage(D, 1) == word(1));  // probe ran
        CHECK(honest.storage(D, 0) == word(0));  // EXTCODESIZE == 0
        CHECK(honest.storage(D, 2) == word(0));  // EXTCODECOPY produced zeros

        const Account* rec = honest.ds->find_created_account(A1);
        REQUIRE(rec != nullptr);
        CHECK(rec->deleted);
        CHECK_FALSE(witness_resident(*honest.ds, A1));

        expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
    }

    SECTION("read_code, read_storage and has_storage each observe an absent account") {
        std::vector<uint8_t> blob = ps.blob;
        std::vector<uint8_t> nodestore = ps.nodestore;
        DirectState ds{std::span<uint8_t>{blob}, std::span<uint8_t>{nodestore}};
        REQUIRE(ds.sanitize());
        REQUIRE(ds.created_accounts().empty());  // one address per call, so attribution is exact

        // Returned values must be indistinguishable from "empty account".
        const ByteView code = ds.read_code(A2);
        CHECK(code.empty());
        const evmc::bytes32 slot = word(7);
        CHECK(ds.read_storage(A3, slot) == evmc::bytes32{});  // expected: all-zero word
        CHECK_FALSE(ds.has_storage(A4));

        for (const evmc::address& a : {A2, A3, A4}) {
            const Account* rec = ds.find_created_account(a);
            REQUIRE(rec != nullptr);
            CHECK(rec->deleted);
            CHECK_FALSE(witness_resident(ds, a));
        }
        CHECK(ds.created_accounts().size() == 3);

        // Three absent reads, no clash, and the state root is still the pre-state root:
        // deleted overlay records contribute no leaf.
        const MirrorRoot mirror = mirror_check_root(ds, ps.prev_root);
        CHECK_FALSE(mirror.clashed);
        CHECK(mirror.missing == 0);
        CHECK(mirror.root == ps.prev_root);  // expected: the unchanged pre-state root
    }
}

// ---------------------------------------------------------------------------
// 5. Selfdestruct-then-read in the same block.
// ---------------------------------------------------------------------------
// Two transactions: the first destroys X (Shanghai, so SELFDESTRUCT genuinely destroys),
// the second reads X's balance and code. The read finds X's blob record — flagged
// `deleted`, not missing — so `lookup_account_` succeeds and NOTHING is materialized.
// That is what keeps keccak(X), which IS an `addr_hashes` entry, out of the created set.
TEST_CASE("StateTransition::run accepts an honest selfdestruct followed by a read of the same account",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);  // reader, called by tx 2
    const evmc::address X = make_addr(0x44, 0x04);  // destroyed by tx 1

    // Distinct payloads recover to distinct senders, so both transactions can use nonce 0.
    const silkworm::Transaction tx_kill = make_legacy_txn(X, /*gas_limit=*/200'000);
    const silkworm::Transaction tx_read = make_legacy_txn(D, kProbeGas);
    const evmc::address S1 = recover_sender(tx_kill);
    const evmc::address S2 = recover_sender(tx_read);
    REQUIRE(S1 != evmc::address{});
    REQUIRE(S2 != evmc::address{});
    REQUIRE(S1 != S2);
    REQUIRE(S1 != X);
    REQUIRE(S1 != D);
    REQUIRE(S2 != X);
    REQUIRE(S2 != D);

    constexpr uint64_t kXBalance = 777;
    const Bytes x_code = selfdestruct_code(S1);
    const Bytes d_code = probe_balance_and_codesize(X);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S1, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = S2, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
        AcctSpec{.addr = X,
                 .nonce = 3,
                 .balance = intx::uint256{kXBalance},
                 .code = x_code,
                 .storage = {{word(5), word(0x1234)}}},
    });
    REQUIRE_FALSE(ps.blob.empty());

    const std::vector<silkworm::Transaction> txs{tx_kill, tx_read};
    const ChainSetup chain = make_chain(ps.prev_root, std::span<const silkworm::Transaction>{txs},
                                        /*beneficiary=*/S1);
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header,
                       std::span<const silkworm::Transaction>{txs});
    expect_witness_complete(honest);
    REQUIRE(honest.receipts.size() == 2);
    REQUIRE(honest.all_succeeded());

    // X really is gone: its balance moved to S1, and the post-destruct read saw nothing.
    CHECK(honest.ds->get_balance(S1) == kSenderBalance + kXBalance);
    CHECK(honest.ds->is_deleted(X));
    CHECK(honest.storage(D, 1) == word(1));  // probe ran
    CHECK(honest.storage(D, 0) == word(0));  // BALANCE(X) after destruction
    CHECK(honest.storage(D, 2) == word(0));  // EXTCODESIZE(X) after destruction

    // The heart of the case: X has a pre-state leaf, so an overlay record for X would
    // clash. The deleted blob record is found by lookup, so no record is materialized.
    CHECK(witness_resident(*honest.ds, X));
    CHECK(honest.ds->find_created_account(X) == nullptr);
    CHECK(honest.ds->created_accounts().empty());

    // Post-state root: X's leaf is deleted, so the root moved, and the incremental root
    // agrees with the from-scratch walk that simply omits X (see expect_witness_complete).
    CHECK(honest.post.root != ps.prev_root);

    expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
}

// ---------------------------------------------------------------------------
// 6. Read-absent-then-CREATE2 at the same address.
// ---------------------------------------------------------------------------
// The read materializes a `deleted=true` twin at the CREATE2 address; the deployment then
// has to REVIVE that very record (`revive_if_deleted`) instead of adding a second one.
// A double-counted address would either clash or emit two leaves for one account.
TEST_CASE("StateTransition::run accepts an honest CREATE2 into an address that was read first",
          "[mphf][state_transition][exec][clash][honest]") {
    const evmc::address D = make_addr(0x22, 0x02);  // the CREATE2 sender
    constexpr uint8_t kSalt = 0x2a;

    const Bytes initcode = create2_initcode();
    const evmc::address CA = create2_address(D, word(kSalt), ByteView{initcode.data(), initcode.size()});
    REQUIRE(CA != evmc::address{});
    REQUIRE(CA != D);

    const silkworm::Transaction tx = make_legacy_txn(D, kProbeGas);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != CA);

    const Bytes d_code = probe_balance_then_create2(CA, kSalt);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .nonce = 0, .balance = kSenderBalance},
        AcctSpec{.addr = D, .nonce = 1, .balance = 0, .code = d_code},
    });
    REQUIRE_FALSE(ps.blob.empty());

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);
    const ShadowRun honest =
        shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    expect_witness_complete(honest);
    REQUIRE(honest.all_succeeded());

    // The deployment landed exactly where the read had already looked.
    CHECK(honest.storage(D, 1) == word(1));       // probe ran
    CHECK(honest.storage(D, 0) == word(0));       // BALANCE before creation
    CHECK(honest.storage(D, 2) == addr_word(CA));  // CREATE2 returned CA

    // Revived in place: ONE record, no longer deleted, carrying the deployed account.
    CHECK(honest.ds->created_accounts().count(CA) == 1);
    const Account* rec = honest.ds->find_created_account(CA);
    REQUIRE(rec != nullptr);
    CHECK_FALSE(rec->deleted);
    CHECK(rec->nonce == 1);  // EIP-161: a created contract starts at nonce 1
    const ByteView deployed = honest.ds->read_code(CA);
    REQUIRE(deployed.size() == 1);
    CHECK(deployed[0] == 0x00);  // the STOP byte the initcode returned
    CHECK(honest.ds->created_accounts().size() == 1);
    CHECK_FALSE(witness_resident(*honest.ds, CA));

    // CA's leaf is in the accepted root: `state_root_hash()` builds the account trie from
    // scratch over every live record INCLUDING CA's, and `expect_witness_complete` has
    // already asserted it equals the root `check_root` accepted below.
    CHECK(honest.post.root != ps.prev_root);

    expect_accepted(drive_guest(chain, honest, ps.blob, ps.nodestore), honest);
}
