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

Tx tx_to(const evmc::address& to, const intx::uint256& value = 0) {
    Tx t{make_legacy_txn(to, kGas, value), {}};
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
    const char* network{"Shanghai"};
};

/// The block of `txs`, under the fork `network` names; the first sender is its beneficiary.
Sealed seal(std::span<const Tx> txs, const bytes32& prev_root, const std::vector<uint8_t>& blob,
            const std::vector<uint8_t>& nodestore, const char* network = "Shanghai") {
    std::vector<silkworm::Transaction> block_txs;
    for (const Tx& t : txs) block_txs.push_back(t.tx);
    Sealed s{make_chain(prev_root, block_txs, /*beneficiary=*/txs.front().sender), {}, network};
    const silkworm::ChainConfig& cfg = silkworm::test::kNetworkConfig.at(network);
    silkworm::BlockHeader& header = s.chain.base.header;
    if (cfg.revision(header.number, header.timestamp) >= EVMC_CANCUN) {
        header.blob_gas_used = 0;
        header.excess_blob_gas = 0;
        header.parent_beacon_block_root = evmc::bytes32{};
    }
    s.sr = shadow_execute(blob, nodestore, prev_root, header, block_txs, cfg);
    REQUIRE(s.sr.sanitize_ok);
    REQUIRE(s.sr.all_succeeded());
    return s;
}

Sealed seal(const Tx& t, const bytes32& prev_root, const std::vector<uint8_t>& blob,
            const std::vector<uint8_t>& nodestore, const char* network = "Shanghai") {
    return seal(std::span<const Tx>{&t, 1}, prev_root, blob, nodestore, network);
}

struct Outcome {
    uint64_t gas{StateTransition::kRunFailure};
    bool failed{true};
    std::string log;
};

/// Runs the guest on `s`'s block with `blob` and `nodestore` as its witness.
Outcome run_guest(const Sealed& s, const std::vector<uint8_t>& blob, const std::vector<uint8_t>& nodestore) {
    std::vector<uint8_t> env = make_envelope(s.chain, s.sr, blob, nodestore, s.network);
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

// ---------------------------------------------------------------------------
// The value a slot executes with
// ---------------------------------------------------------------------------
// A witness slot has an initial and a current value. check_root binds only the initial one to the
// storage root, so execution has to start from it too: a current value the witness sets apart used
// to be what the block read, and what a modified account then carried into the post-state.

namespace {

/// Sets the current value of slot `key` of `addr` in `blob`, leaving its initial value as it is.
void forge_slot_current(std::vector<uint8_t>& blob, const evmc::address& addr, const evmc::bytes32& key,
                        const evmc::bytes32& value) {
    DirectState ds{std::span<uint8_t>{blob}};
    Account* pa = ds.find_pre_account_unchecked(addr);
    REQUIRE(pa != nullptr);
    for (Slot& slot : ds.slots_for(*pa)) {
        if (std::memcmp(slot.key, key.bytes, 32) == 0) {
            std::memcpy(slot.current, value.bytes, 32);
            return;
        }
    }
    FAIL("slot not in the witness");
}

/// A witness whose slot storage[1] of kHolder is 5 by its initial value and 0x77 by its current one,
/// and the blocks sealed for it: by a producer that executed with 0x77, and by an honest one.
struct ForgedCurrent {
    Prestate ps;
    std::vector<uint8_t> blob;
    Sealed forged;
    Sealed honest;
};

/// `post(v)` is the post-state if the block read v from storage[1] of kHolder.
template <class Post>
ForgedCurrent forge_current(const Tx& t, const std::vector<AcctSpec>& state, Post post) {
    ForgedCurrent f{build_prestate(state), {}, {}, {}};
    f.blob = f.ps.blob;
    forge_slot_current(f.blob, kHolder, word(1), word(0x77));

    // What executing with 0x77 yields: the gas and receipts of a run whose witness holds 0x77, and the
    // root the forged witness used to be checked against, that of the post-state with 0x77 read.
    std::vector<AcctSpec> with_forged = state;
    spec_of(with_forged, kHolder).storage = {{word(1), word(0x77)}};
    f.forged = seal(t, f.ps.prev_root, witness_blob(state, with_forged), f.ps.nodestore);
    f.forged.sr.post.root = build_prestate(post(word(0x77))).prev_root;

    f.honest = seal(t, f.ps.prev_root, f.ps.blob, f.ps.nodestore);
    REQUIRE(build_prestate(post(word(5))).prev_root == f.honest.sr.post.root);
    return f;
}

ForgedCurrent forge_current_read_through_call(const Tx& t) {
    return forge_current(t, read_through_call(t, word(1), {{word(1), word(5)}}), [&](const evmc::bytes32& v) {
        std::vector<AcctSpec> post = read_through_call(t, word(1), {{word(1), word(5)}});
        spec_of(post, t.sender).nonce = 1;
        spec_of(post, kCaller).storage = {{word(0), v}, {word(1), word(1)}};
        return post;
    });
}

// The holder copies storage[1] to storage[kCopyTarget]. A current value apart from the initial one
// used to be written back as storage[1]'s new value too.
ForgedCurrent forge_current_copied_by_holder(const Tx& t) {
    const auto holder = [&](Slots storage) {
        return std::vector<AcctSpec>{
            sender_of(t),
            AcctSpec{.addr = kHolder, .nonce = 1, .code = copy_slot(word(1), word(kCopyTarget)),
                     .storage = std::move(storage)},
        };
    };
    return forge_current(t, holder({{word(1), word(5)}}), [&](const evmc::bytes32& v) {
        std::vector<AcctSpec> post = holder({{word(1), v}, {word(kCopyTarget), v}});
        spec_of(post, t.sender).nonce = 1;
        return post;
    });
}

}  // namespace

TEST_CASE("check_root rejects a block executed with a slot value the witness sets apart",
          "[witness][binding][slot_current]") {
    SECTION("an unmodified account's slot, read through a call") {
        const Tx t = tx_to(kCaller);
        const ForgedCurrent f = forge_current_read_through_call(t);
        expect_rejected(run_guest(f.forged, f.blob, f.ps.nodestore), "State Root Mismatch");
    }
    SECTION("a slot its modified holder copies") {
        const Tx t = tx_to(kHolder);
        const ForgedCurrent f = forge_current_copied_by_holder(t);
        expect_rejected(run_guest(f.forged, f.blob, f.ps.nodestore), "State Root Mismatch");
    }
}

TEST_CASE("the guest executes a slot with the value its storage root binds",
          "[witness][binding][slot_current]") {
    SECTION("an unmodified account's slot, read through a call") {
        const Tx t = tx_to(kCaller);
        const ForgedCurrent f = forge_current_read_through_call(t);
        expect_accepted(run_guest(f.honest, f.blob, f.ps.nodestore), f.honest);
    }
    SECTION("a slot its modified holder copies") {
        const Tx t = tx_to(kHolder);
        const ForgedCurrent f = forge_current_copied_by_holder(t);
        expect_accepted(run_guest(f.honest, f.blob, f.ps.nodestore), f.honest);
    }
}

// ---------------------------------------------------------------------------
// Storage the block wipes
// ---------------------------------------------------------------------------
// Before Cancun SELFDESTRUCT deletes an account, storage and all, and a later transaction can create it
// again with empty storage. Neither post-state holds the slots the witness carried for it, but the block
// may have executed with them first. check_root used to skip the storage walk of a deleted account, and
// that of a recreated one walked only its new slots, so a forged value it read was never checked.

namespace {

/// With calldata, sends its balance to the caller and deletes itself; without, returns storage[key].
Bytes return_slot_or_selfdestruct(const evmc::bytes32& key) {
    const Bytes ret = return_slot(key);
    Bytes k;
    k.push_back(0x36);  // CALLDATASIZE
    push1(k, static_cast<uint8_t>(4 + ret.size()));
    k.push_back(0x57);  // JUMPI
    k.append(ret);
    k.push_back(0x5b);  // JUMPDEST
    k.push_back(0x33);  // CALLER
    k.push_back(0xff);  // SELFDESTRUCT
    return k;
}

/// STATICCALLs `holder` and stores the word it returns in storage[0], CALLs it with calldata, which
/// has it SELFDESTRUCT, then the sentinel.
Bytes store_call_result_then_selfdestruct(const evmc::address& holder) {
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
    push1(k, 0x00);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x01);  // argsSize
    push1(k, 0x00);  // argsOffset
    push1(k, 0x00);  // value
    push20(k, holder);
    k.push_back(0x5a);  // GAS
    k.push_back(0xf1);  // CALL
    k.push_back(0x50);  // POP
    append_sentinel_and_stop(k);
    return k;
}

/// storage[key] = 0x2a, then sends its balance to the caller and deletes itself.
Bytes write_slot_then_selfdestruct(const evmc::bytes32& key) {
    Bytes k;
    push1(k, 0x2a);
    push32(k, key);
    k.push_back(0x55);  // SSTORE
    k.push_back(0x33);  // CALLER
    k.push_back(0xff);  // SELFDESTRUCT
    return k;
}

/// The init code create2_stop() runs: STOP, so the account it creates has no code.
const Bytes kStopInit{0x00};
constexpr uint8_t kSalt = 0x01;

/// CREATE2s kStopInit with kSalt and stores the address it returns in storage[0], then the sentinel.
Bytes create2_stop() {
    Bytes k;
    push1(k, kSalt);    // salt
    push1(k, 0x01);     // size: memory[0] is 0x00, kStopInit
    push1(k, 0x00);     // offset
    push1(k, 0x00);     // value
    k.push_back(0xf5);  // CREATE2
    store_observation(k);
    append_sentinel_and_stop(k);
    return k;
}

/// The address CREATE2 gives kStopInit with kSalt from `creator`.
evmc::address create2_stop_address(const evmc::address& creator) {
    Bytes buf;
    buf.push_back(0xff);
    buf.append(creator.bytes, sizeof(creator.bytes));
    buf.append(word(kSalt).bytes, 32);
    buf.append(keccak_bytes(ByteView{kStopInit}).bytes, 32);
    const bytes32 h = keccak_bytes(ByteView{buf});
    evmc::address out{};
    std::memcpy(out.bytes, h.bytes + 12, 20);
    return out;
}

const evmc::address kFactory = make_addr(0x55, 0x05);  // CREATE2s the destructed account back

/// kCaller reads storage[1] of `holder` through a STATICCALL, then has it SELFDESTRUCT; `holder` holds
/// `storage`.
std::vector<AcctSpec> read_then_selfdestruct(const Tx& t, const evmc::address& holder, Slots storage) {
    return {
        sender_of(t),
        AcctSpec{.addr = kCaller, .nonce = 1, .code = store_call_result_then_selfdestruct(holder)},
        AcctSpec{.addr = holder, .nonce = 1, .code = return_slot_or_selfdestruct(word(1)),
                 .storage = std::move(storage)},
    };
}

/// A witness of `state` whose storage[1] of `holder` claims 0x77 instead of its committed value.
std::vector<uint8_t> forge_slot(const std::vector<AcctSpec>& state, const evmc::address& holder) {
    std::vector<AcctSpec> forged = state;
    spec_of(forged, holder).storage = {{word(1), word(0x77)}};
    return witness_blob(state, forged);
}

/// A block whose first transaction has kCaller read storage[1] of `holder` and have it SELFDESTRUCT,
/// and whose second creates `holder` again.
struct Recreated {
    std::vector<Tx> txs;
    evmc::address holder;
    std::vector<AcctSpec> state;
};

Recreated recreated_by_transfer() {
    Recreated r{{tx_to(kCaller), tx_to(kHolder, /*value=*/1)}, kHolder, {}};
    r.state = read_then_selfdestruct(r.txs[0], r.holder, {{word(1), word(5)}});
    r.state.push_back(sender_of(r.txs[1]));
    return r;
}

Recreated recreated_by_create2() {
    Recreated r{{tx_to(kCaller), tx_to(kFactory)}, create2_stop_address(kFactory), {}};
    REQUIRE(r.txs[0].sender != r.holder);
    r.state = read_then_selfdestruct(r.txs[0], r.holder, {{word(1), word(5)}});
    r.state.push_back(sender_of(r.txs[1]));
    r.state.push_back(AcctSpec{.addr = kFactory, .nonce = 1, .code = create2_stop()});
    return r;
}

}  // namespace

TEST_CASE("check_root rejects a forged slot of an account the block destructs",
          "[witness][binding][wiped]") {
    SECTION("read before SELFDESTRUCT") {
        const Tx t = tx_to(kCaller);
        const std::vector<AcctSpec> state = read_then_selfdestruct(t, kHolder, {{word(1), word(5)}});
        const Prestate ps = build_prestate(state);

        const std::vector<uint8_t> blob = forge_slot(state, kHolder);
        const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
        REQUIRE(s.sr.storage(kCaller, 0) == word(0x77));
        REQUIRE(s.sr.ds->is_deleted(kHolder));
        CHECK(s.sr.post.rejected);
        expect_rejected(run_guest(s, blob, ps.nodestore), "storage walk of a wiped account failed");
    }
    SECTION("written before SELFDESTRUCT") {
        const Tx t = tx_to(kHolder);
        const std::vector<AcctSpec> state = {
            sender_of(t),
            AcctSpec{.addr = kHolder, .nonce = 1, .code = write_slot_then_selfdestruct(word(1)),
                     .storage = {{word(1), word(5)}}},
        };
        const Prestate ps = build_prestate(state);

        // The write costs the same from 0x77 as from 5: the block is the honest one.
        const std::vector<uint8_t> blob = forge_slot(state, kHolder);
        const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore);
        REQUIRE(s.sr.ds->is_deleted(kHolder));
        CHECK(s.sr.post.rejected);
        expect_rejected(run_guest(s, blob, ps.nodestore), "storage walk of a wiped account failed");
    }
}

TEST_CASE("check_root rejects a forged slot of an account the block destructs and creates again",
          "[witness][binding][wiped]") {
    for (const bool by_create2 : {false, true}) {
        DYNAMIC_SECTION((by_create2 ? "by CREATE2" : "by a value transfer")) {
            const Recreated r = by_create2 ? recreated_by_create2() : recreated_by_transfer();
            const Prestate ps = build_prestate(r.state);

            const std::vector<uint8_t> blob = forge_slot(r.state, r.holder);
            const Sealed s = seal(r.txs, ps.prev_root, blob, ps.nodestore);
            REQUIRE(s.sr.storage(kCaller, 0) == word(0x77));
            REQUIRE_FALSE(s.sr.ds->is_deleted(r.holder));
            CHECK(s.sr.post.rejected);
            expect_rejected(run_guest(s, blob, ps.nodestore), "storage walk of a wiped account failed");
        }
    }
}

TEST_CASE("the guest accepts the slots of an account the block wipes, as its storage root binds them",
          "[witness][binding][wiped][honest]") {
    SECTION("read before SELFDESTRUCT") {
        const Tx t = tx_to(kCaller);
        const Slots storage = {{word(1), word(5)}, {word(2), word(6)}};
        const Prestate ps = build_prestate(read_then_selfdestruct(t, kHolder, storage));
        const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
        CHECK(s.sr.storage(kCaller, 0) == word(5));
        CHECK(s.sr.storage(kCaller, 1) == word(1));
        CHECK(s.sr.ds->is_deleted(kHolder));
        CHECK_FALSE(s.sr.post.rejected);
        expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
    }
    SECTION("written before SELFDESTRUCT") {
        const Tx t = tx_to(kHolder);
        const Prestate ps = build_prestate({
            sender_of(t),
            AcctSpec{.addr = kHolder, .nonce = 1, .code = write_slot_then_selfdestruct(word(1)),
                     .storage = {{word(1), word(5)}}},
        });
        const Sealed s = seal(t, ps.prev_root, ps.blob, ps.nodestore);
        CHECK(s.sr.ds->is_deleted(kHolder));
        CHECK_FALSE(s.sr.post.rejected);
        expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
    }
    for (const bool by_create2 : {false, true}) {
        DYNAMIC_SECTION((by_create2 ? "recreated by CREATE2" : "recreated by a value transfer")) {
            const Recreated r = by_create2 ? recreated_by_create2() : recreated_by_transfer();
            const Prestate ps = build_prestate(r.state);
            const Sealed s = seal(r.txs, ps.prev_root, ps.blob, ps.nodestore);
            CHECK(s.sr.storage(kCaller, 0) == word(5));
            CHECK_FALSE(s.sr.ds->is_deleted(r.holder));
            CHECK(s.sr.ds->read_storage(r.holder, word(1)) == evmc::bytes32{});
            if (by_create2) {
                evmc::bytes32 created{};
                std::memcpy(created.bytes + 12, r.holder.bytes, 20);
                CHECK(s.sr.storage(kFactory, 0) == created);
            }
            CHECK_FALSE(s.sr.post.rejected);
            expect_accepted(run_guest(s, ps.blob, ps.nodestore), s);
        }
    }
}

// Since Cancun (EIP-6780) SELFDESTRUCT deletes only an account the same transaction created, which has no
// pre-state storage. Any other account keeps its storage, and its walk binds the slots as it always did.
TEST_CASE("from Cancun on, an account SELFDESTRUCT leaves in place binds its slots as before",
          "[witness][binding][wiped]") {
    const Tx t = tx_to(kCaller);
    const std::vector<AcctSpec> state = read_then_selfdestruct(t, kHolder, {{word(1), word(5)}});
    const Prestate ps = build_prestate(state);

    const std::vector<uint8_t> blob = forge_slot(state, kHolder);
    const Sealed s = seal(t, ps.prev_root, blob, ps.nodestore, "Cancun");
    REQUIRE(s.sr.storage(kCaller, 0) == word(0x77));
    REQUIRE_FALSE(s.sr.ds->is_deleted(kHolder));
    expect_rejected(run_guest(s, blob, ps.nodestore), "Pre value mismatch in existing leaf");

    const Sealed honest = seal(t, ps.prev_root, ps.blob, ps.nodestore, "Cancun");
    CHECK(honest.sr.storage(kCaller, 0) == word(5));
    CHECK_FALSE(honest.sr.ds->is_deleted(kHolder));
    expect_accepted(run_guest(honest, ps.blob, ps.nodestore), honest);
}
