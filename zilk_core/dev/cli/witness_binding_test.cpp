// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Forged witnesses the guest must reject. Every value the guest executes with has to be bound to
// the parent's state root through the account and storage tries; the bench, EEST and the honest
// tests only feed bundles a real chain produced, so none of them can show such a hole closed.
//
// Each case forges part of a witness, seals the block that executing the forged witness yields (as a
// dishonest producer would: gas, receipts and the state root its own run computes) and drives the
// public entry point, StateTransition::run, with it. The honest twin of every case, sealed the same
// way, is accepted, so a rejection is the forgery's doing. Every case asserts the line the check that
// must fire prints, not just the rejection.

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
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

using Slots = std::vector<std::pair<evmc::bytes32, evmc::bytes32>>;

evmc::bytes32 word(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

constexpr uint64_t kGas = 1'000'000;
const intx::uint256 kSenderBalance{intx::uint256{1} << 64};
const evmc::address kCaller = make_addr(0x22, 0x02);  // calls kHolder and stores what it returns
const evmc::address kHolder = make_addr(0x33, 0x03);  // holds the storage under test

/// PUSH32 <v>
void push32(Bytes& code, const evmc::bytes32& v) {
    code.push_back(0x7f);
    code.append(v.bytes, sizeof(v.bytes));
}

/// Returns storage[key] to the caller.
Bytes return_slot(const evmc::bytes32& key) {
    Bytes k;
    push32(k, key);
    k.push_back(0x54);  // SLOAD
    push1(k, 0x00);
    k.push_back(0x52);  // MSTORE
    push1(k, 0x20);     // size
    push1(k, 0x00);     // offset
    k.push_back(0xf3);  // RETURN
    return k;
}

/// STATICCALLs `holder`, stores the word it returns in storage[0], then the sentinel storage[1] = 1.
Bytes store_call_result(const evmc::address& holder) {
    Bytes k;
    push1(k, 0x20);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push20(k, holder);
    k.push_back(0x5a);  // GAS
    k.push_back(0xfa);  // STATICCALL
    k.push_back(0x50);  // POP
    push1(k, 0x00);
    k.push_back(0x51);  // MLOAD
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

/// The sender of a legacy transaction to `to` (it comes from the fixed signature).
struct Tx {
    silkworm::Transaction tx;
    evmc::address sender;
};

Tx tx_to(const evmc::address& to) {
    Tx t{make_legacy_txn(to, kGas), {}};
    t.sender = recover_sender(t.tx);
    REQUIRE(t.sender != evmc::address{});
    REQUIRE(t.sender != kCaller);
    REQUIRE(t.sender != kHolder);
    return t;
}

AcctSpec sender_of(const Tx& t, uint64_t nonce = 0) {
    return AcctSpec{.addr = t.sender, .nonce = nonce, .balance = kSenderBalance};
}

/// The pre-state blob a producer hands over with `witness`, against the tries of `state`: a record of
/// an account `state` has carries that account's storage root, so its account leaf is the committed
/// one whatever slots or fields the record claims; any other record commits to its own slots.
std::vector<uint8_t> witness_blob(const std::vector<AcctSpec>& state, const std::vector<AcctSpec>& witness) {
    std::vector<std::pair<bytes32, Bytes>> codes;
    std::vector<DirectState::AccountInfo> infos;
    for (const AcctSpec& w : witness) {
        if (!w.code.empty()) codes.emplace_back(w.code_hash(), w.code);
        DirectState::AccountInfo info =
            w.code.empty() ? make_eoa(w.addr, w.nonce, w.balance)
                           : make_contract(w.addr, w.nonce, w.balance, w.code_hash(),
                                           static_cast<uint32_t>(w.code.size()));
        const AcctSpec* committed = &w;
        for (const AcctSpec& s : state) {
            if (s.addr == w.addr) committed = &s;
        }
        std::vector<std::pair<bytes32, Bytes>> unused;
        const bytes32 sroot = collect_trie_nodes(storage_trie_leaves(committed->storage), unused);
        std::memcpy(info.account.storage_root, sroot.bytes, 32);
        info.storage = w.storage;
        infos.push_back(std::move(info));
    }
    return DirectState::build_blob_from_accounts(std::move(infos), {}, build_code_store(codes));
}

/// The node store build_prestate() makes for `state`, without the nodes `omit(hash, in_account_trie)`
/// picks.
template <class Omit>
std::vector<uint8_t> node_store_omitting(const std::vector<AcctSpec>& state, Omit omit) {
    std::vector<std::pair<bytes32, Bytes>> storage_nodes;
    std::vector<std::pair<bytes32, Bytes>> account_nodes;
    std::vector<std::pair<bytes32, Bytes>> leaves;
    for (const AcctSpec& s : state) {
        const bytes32 sroot = collect_trie_nodes(storage_trie_leaves(s.storage), storage_nodes);
        leaves.emplace_back(keccak_addr32(s.addr),
                            account_rlp(s.addr, s.nonce, s.balance, s.code_hash(), sroot));
    }
    collect_trie_nodes(std::move(leaves), account_nodes);
    std::vector<std::pair<bytes32, Bytes>> kept;
    for (const auto& n : storage_nodes) {
        if (!omit(n.first, false)) kept.push_back(n);
    }
    for (const auto& n : account_nodes) {
        if (!omit(n.first, true)) kept.push_back(n);
    }
    REQUIRE(kept.size() < storage_nodes.size() + account_nodes.size());
    return build_node_store(kept);
}

/// The storage root of `storage`, as the account trie commits to it.
bytes32 storage_root_of(const Slots& storage) {
    std::vector<std::pair<bytes32, Bytes>> unused;
    return collect_trie_nodes(storage_trie_leaves(storage), unused);
}

/// A block as a producer seals it: its header carries what executing `blob` against the tries yields.
struct Sealed {
    ChainSetup chain;
    ShadowRun sr;
};

Sealed seal(const Tx& t, const bytes32& prev_root, const std::vector<uint8_t>& blob,
            const std::vector<uint8_t>& nodestore) {
    Sealed s{make_chain(prev_root, t.tx, /*beneficiary=*/t.sender), {}};
    s.sr = shadow_execute(blob, nodestore, prev_root, s.chain.base.header, t.tx);
    REQUIRE(s.sr.sanitize_ok);
    REQUIRE(s.sr.all_succeeded());
    return s;
}

struct Outcome {
    uint64_t gas{StateTransition::kRunFailure};
    bool failed{true};
    std::string log;
};

/// Runs the guest on `s`'s block with `blob` and `nodestore` as its witness.
Outcome run_guest(const Sealed& s, const std::vector<uint8_t>& blob, const std::vector<uint8_t>& nodestore) {
    std::vector<uint8_t> env = make_envelope(s.chain, s.sr, blob, nodestore);
    REQUIRE_FALSE(env.empty());
    StateTransition st{std::span<uint8_t>{env}};
    Outcome o{};
    {
        StdoutCapture cap;  // keep tight: Catch2 writes to std::cout too
        o.gas = st.run().gas_used;
        o.log = cap.str();
    }
    o.failed = st.failed();
    return o;
}

void expect_accepted(const Outcome& o, const Sealed& s) {
    CAPTURE(o.log);
    CHECK_FALSE(o.failed);
    CHECK(o.gas == s.sr.gas_used);
    CHECK(o.log.find("New Root: " + silkworm::to_hex(s.sr.post.root)) != std::string::npos);
}

/// Rejected, and `why`, a line the check that must reject prints, is in the guest's log.
void expect_rejected(const Outcome& o, std::string_view why) {
    CAPTURE(o.log);
    CHECK(o.failed);
    CHECK(o.gas == StateTransition::kRunFailure);
    CHECK(o.log.find(why) != std::string::npos);
}

/// kCaller reads storage[key] of kHolder through a STATICCALL; kHolder holds `storage`.
std::vector<AcctSpec> read_through_call(const Tx& t, const evmc::bytes32& key, Slots storage) {
    return {
        sender_of(t),
        AcctSpec{.addr = kCaller, .nonce = 1, .code = store_call_result(kHolder)},
        AcctSpec{.addr = kHolder, .nonce = 1, .code = return_slot(key), .storage = std::move(storage)},
    };
}

AcctSpec& spec_of(std::vector<AcctSpec>& specs, const evmc::address& a) {
    for (AcctSpec& s : specs) {
        if (s.addr == a) return s;
    }
    FAIL("no such account");
    return specs.front();
}

}  // namespace

TEST_CASE("the guest accepts an honest bundle whose reads are all bound",
          "[witness][binding][honest]") {
    const Tx t = tx_to(kCaller);
    const std::vector<AcctSpec> state = read_through_call(t, word(1), {{word(1), word(5)}, {word(2), word(6)}});
    const Prestate ps = build_prestate(state);

    const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
    CHECK(s.sr.storage(kCaller, 0) == word(5));  // the read happened
    CHECK(s.sr.storage(kCaller, 1) == word(1));
    expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
}

// A slot whose witness value differs from its storage leaf fails the storage walk. The walk of an
// account the block only reads used to be computed and dropped, and a failed walk only returned a
// zero root, so nothing rejected the forged value.
TEST_CASE("check_root rejects a forged value of a slot an unmodified account holds",
          "[witness][binding][trie_failed]") {
    const Tx t = tx_to(kCaller);
    const std::vector<AcctSpec> state = read_through_call(t, word(1), {{word(1), word(5)}});
    const Prestate ps = build_prestate(state);

    std::vector<AcctSpec> forged = state;
    spec_of(forged, kHolder).storage = {{word(1), word(0x77)}};
    const std::vector<uint8_t> blob = witness_blob(state, forged);
    const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
    REQUIRE(s.sr.storage(kCaller, 0) == word(0x77));  // the forged value is what executes
    expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value mismatch in existing leaf");

    const Sealed honest = seal(t, ps.prev_root, ps.blob, ps.nodestore);
    expect_accepted(run_guest(honest, ps.blob, ps.nodestore), honest);
}

// A failed account-trie walk used to return a zero root, which a header with a zero state root matched.
TEST_CASE("check_root rejects a failed account-trie walk whatever the header's state root",
          "[witness][binding][trie_failed]") {
    const Tx t = tx_to(kCaller);
    const std::vector<AcctSpec> state = read_through_call(t, word(1), {{word(1), word(5)}});
    const Prestate ps = build_prestate(state);

    SECTION("a forged pre-state balance of the sender") {
        std::vector<AcctSpec> forged = state;
        spec_of(forged, t.sender).balance = kSenderBalance + 1;
        const std::vector<uint8_t> blob = witness_blob(state, forged);
        Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
        s.sr.post.root = bytes32{};
        expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value mismatch in existing leaf");
    }
    SECTION("account-trie nodes below the root missing from the witness") {
        const std::vector<uint8_t> nodestore = node_store_omitting(
            state, [&](const bytes32& h, bool in_account_trie) { return in_account_trie && h != ps.prev_root; });
        Sealed s = seal(t, ps.prev_root, ps.blob, nodestore);
        s.sr.post.root = bytes32{};
        expect_rejected(run_guest(s, ps.blob, nodestore), "missing hash ref in node store");
    }

    const Sealed honest = seal(t, ps.prev_root, ps.blob, ps.nodestore);
    expect_accepted(run_guest(honest, ps.blob, ps.nodestore), honest);
}

// Without its root node a trie used to start empty: the walk then rebuilt a trie of the updated keys
// alone, and the root a producer computed the same way was accepted.
TEST_CASE("check_root rejects a witness that omits a pre-state root node",
          "[witness][binding][trie_failed]") {
    const Tx t = tx_to(kCaller);
    std::vector<AcctSpec> state = read_through_call(t, word(1), {{word(1), word(5)}});
    // kCaller writes storage[0] and storage[1] next to a slot it already holds.
    spec_of(state, kCaller).storage = {{word(7), word(9)}};
    const Prestate ps = build_prestate(state);

    SECTION("the account trie's") {
        const std::vector<uint8_t> nodestore =
            node_store_omitting(state, [&](const bytes32& h, bool) { return h == ps.prev_root; });
        const Sealed s = seal(t, ps.prev_root, ps.blob, nodestore);
        expect_rejected(run_guest(s, ps.blob, nodestore), "no_rlp");
    }
    SECTION("the storage trie's of a modified account") {
        const bytes32 sroot = storage_root_of(spec_of(state, kCaller).storage);
        const std::vector<uint8_t> nodestore =
            node_store_omitting(state, [&](const bytes32& h, bool) { return h == sroot; });
        const Sealed s = seal(t, ps.prev_root, ps.blob, nodestore);
        expect_rejected(run_guest(s, ps.blob, nodestore), "no_rlp");
    }

    const Sealed honest = seal(t, ps.prev_root, ps.blob, ps.nodestore);
    expect_accepted(run_guest(honest, ps.blob, ps.nodestore), honest);
}

// ---------------------------------------------------------------------------
// Claims for keys absent from the trie
// ---------------------------------------------------------------------------
// A key the walk has to insert is absent from the pre-state trie, so its claimed pre-value must be
// empty: no value for a created account or slot, 0x80 (zero) for a slot read as absent. A read-only
// claim of anything else used to insert an empty leaf that folded away again, returning the
// committed root while the block executed with the claimed value.

namespace {

/// Nibble `i` of slot `slot`'s path in the storage trie.
unsigned path_nibble(const evmc::bytes32& slot, unsigned i) {
    const bytes32 h = keccak_bytes32(slot);
    return (i % 2 == 0 ? h.bytes[i / 2] >> 4 : h.bytes[i / 2]) & 0x0f;
}

/// The first slot from `from` on whose storage-trie path satisfies `pred`.
template <class Pred>
evmc::bytes32 find_slot(uint64_t from, Pred pred) {
    for (uint64_t i = from;; ++i) {
        if (pred(word(i))) return word(i);
    }
}

/// A storage trie and a slot absent from it, inserted at one of the four places
/// calc_root_from_updates inserts a leaf.
struct AbsentKey {
    const char* shape;
    Slots present;
    evmc::bytes32 absent;
};

std::vector<AbsentKey> absent_keys() {
    const evmc::bytes32 a = word(1);
    const auto n = [&](unsigned i) { return path_nibble(a, i); };
    // b shares no nibble with a: the root is a branch.
    const evmc::bytes32 b = find_slot(2, [&](const evmc::bytes32& s) { return path_nibble(s, 0) != n(0); });
    // c shares two nibbles with a: the root is an extension.
    const evmc::bytes32 c = find_slot(2, [&](const evmc::bytes32& s) {
        return path_nibble(s, 0) == n(0) && path_nibble(s, 1) == n(1);
    });
    const auto first_differs = [&](const evmc::bytes32& s) { return path_nibble(s, 0) != n(0); };
    const auto second_differs = [&](const evmc::bytes32& s) {
        return path_nibble(s, 0) == n(0) && path_nibble(s, 1) != n(1);
    };
    return {
        {"an empty trie", {}, find_slot(2, first_differs)},
        {"an empty slot of a branch",
         {{a, word(5)}, {b, word(6)}},
         find_slot(2, [&](const evmc::bytes32& s) {
             return path_nibble(s, 0) != n(0) && path_nibble(s, 0) != path_nibble(b, 0);
         })},
        {"an extension, diverging at its first nibble", {{a, word(5)}, {c, word(6)}}, find_slot(2, first_differs)},
        {"an extension, diverging inside it", {{a, word(5)}, {c, word(6)}}, find_slot(2, second_differs)},
        {"a leaf, diverging at its first nibble", {{a, word(5)}}, find_slot(2, first_differs)},
        {"a leaf, diverging after a shared nibble", {{a, word(5)}}, find_slot(2, second_differs)},
    };
}

/// storage[to] = storage[from].
Bytes copy_slot(const evmc::bytes32& from, const evmc::bytes32& to) {
    Bytes k;
    push32(k, from);
    k.push_back(0x54);  // SLOAD
    push32(k, to);
    k.push_back(0x55);  // SSTORE
    k.push_back(0x00);  // STOP
    return k;
}

/// storage[key] = 0x2a.
Bytes write_slot(const evmc::bytes32& key) {
    Bytes k;
    push1(k, 0x2a);
    push32(k, key);
    k.push_back(0x55);  // SSTORE
    k.push_back(0x00);  // STOP
    return k;
}

/// BALANCE of `a` in storage[0], then the sentinel.
Bytes store_balance(const evmc::address& a) {
    Bytes k;
    push20(k, a);
    k.push_back(0x31);  // BALANCE
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

constexpr uint64_t kCopyTarget = 0x99;  // a slot of kHolder that no shape has present

}  // namespace

TEST_CASE("check_root rejects a claimed value for a slot absent from the storage trie",
          "[witness][binding][absent]") {
    for (const AbsentKey& k : absent_keys()) {
        DYNAMIC_SECTION("read through a call, absent key at " << k.shape) {
            const Tx t = tx_to(kCaller);
            const std::vector<AcctSpec> state = read_through_call(t, k.absent, k.present);
            const Prestate ps = build_prestate(state);

            std::vector<AcctSpec> forged = state;
            spec_of(forged, kHolder).storage.emplace_back(k.absent, word(0x77));
            const std::vector<uint8_t> blob = witness_blob(state, forged);
            const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
            REQUIRE(s.sr.storage(kCaller, 0) == word(0x77));
            expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value claimed for a key absent from the trie");
        }
        DYNAMIC_SECTION("copied by its modified holder, absent key at " << k.shape) {
            const Tx t = tx_to(kHolder);
            const std::vector<AcctSpec> state = {
                sender_of(t),
                AcctSpec{.addr = kHolder, .nonce = 1, .code = copy_slot(k.absent, word(kCopyTarget)),
                         .storage = k.present},
            };
            const Prestate ps = build_prestate(state);

            std::vector<AcctSpec> forged = state;
            spec_of(forged, kHolder).storage.emplace_back(k.absent, word(0x77));
            const std::vector<uint8_t> blob = witness_blob(state, forged);
            const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
            REQUIRE(s.sr.storage(kHolder, kCopyTarget) == word(0x77));
            expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value claimed for a key absent from the trie");
        }
    }
}

// The claims an honest witness makes for absent slots: a zero read (0x80) and a fresh write (no value),
// in every insertion shape. The zero read of an account the block does not modify also has to fold
// back to the committed root exactly.
TEST_CASE("check_root accepts zero and fresh-write claims for absent slots",
          "[witness][binding][absent][honest]") {
    for (const AbsentKey& k : absent_keys()) {
        DYNAMIC_SECTION("zero read through a call, absent key at " << k.shape) {
            const Tx t = tx_to(kCaller);
            Slots storage = k.present;
            storage.emplace_back(k.absent, evmc::bytes32{});
            const Prestate ps = build_prestate(read_through_call(t, k.absent, std::move(storage)));
            const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
            CHECK(s.sr.storage(kCaller, 1) == word(1));
            CHECK(s.sr.storage(kCaller, 0) == evmc::bytes32{});
            expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
        }
        DYNAMIC_SECTION("zero read by its modified holder, absent key at " << k.shape) {
            const Tx t = tx_to(kHolder);
            Slots storage = k.present;
            storage.emplace_back(k.absent, evmc::bytes32{});
            const Prestate ps = build_prestate({
                sender_of(t),
                AcctSpec{.addr = kHolder, .nonce = 1, .code = copy_slot(k.absent, word(kCopyTarget)),
                         .storage = std::move(storage)},
            });
            const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
            expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
        }
        DYNAMIC_SECTION("fresh write, absent key at " << k.shape) {
            const Tx t = tx_to(kHolder);
            const Prestate ps = build_prestate({
                sender_of(t),
                AcctSpec{.addr = kHolder, .nonce = 1, .code = write_slot(k.absent), .storage = k.present},
            });
            const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
            CHECK(s.sr.ds->read_storage(kHolder, k.absent) == word(0x2a));
            expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
        }
    }
}

// An account record whose key is absent from the account trie claims a pre-value for that key.
TEST_CASE("check_root rejects an account the witness invents", "[witness][binding][absent]") {
    SECTION("an account the block only reads") {
        const evmc::address invented = make_addr(0x44, 0x04);
        const Tx t = tx_to(kCaller);
        REQUIRE(t.sender != invented);
        const std::vector<AcctSpec> state = {
            sender_of(t),
            AcctSpec{.addr = kCaller, .nonce = 1, .code = store_balance(invented)},
        };
        const Prestate ps = build_prestate(state);

        std::vector<AcctSpec> forged = state;
        forged.push_back(AcctSpec{.addr = invented, .nonce = 0, .balance = 1000});
        const std::vector<uint8_t> blob = witness_blob(state, forged);
        const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
        REQUIRE(s.sr.storage(kCaller, 0) == word(1000));
        expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value claimed for a key absent from the trie");

        const Sealed honest = seal(t, ps.prev_root, ps.blob, ps.nodestore);
        CHECK(honest.sr.storage(kCaller, 0) == evmc::bytes32{});
        expect_accepted(run_guest(honest, ps.blob, ps.nodestore), honest);
    }
    SECTION("the sender, spending a balance the trie does not give it") {
        Tx t{make_legacy_txn(kCaller, kGas, /*value=*/600), {}};
        t.sender = recover_sender(t.tx);
        REQUIRE(t.sender != evmc::address{});
        REQUIRE(t.sender != kCaller);
        const AcctSpec recipient{.addr = kCaller, .nonce = 0, .balance = 1};
        const AcctSpec sender{.addr = t.sender, .nonce = 0, .balance = 1000};

        const Prestate ps = build_prestate({recipient});
        const std::vector<uint8_t> blob = witness_blob({recipient}, {recipient, sender});
        const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
        REQUIRE(s.sr.ds->get_balance(kCaller) == 601);
        expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value claimed for a key absent from the trie");

        const Prestate with_sender = build_prestate({recipient, sender});
        const Sealed honest = seal(t, with_sender.prev_root, with_sender.blob, with_sender.nodestore);
        expect_accepted(run_guest(honest, with_sender.blob, with_sender.nodestore), honest);
    }
}
