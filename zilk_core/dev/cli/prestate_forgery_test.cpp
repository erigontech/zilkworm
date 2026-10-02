// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// sanitize() on pre-state bytes that are well laid out but forged in content.
//
// Slot values. Each pre-state Slot carries `initial` (what check_root proves against the
// account's storage_root) and `current` (what the EVM reads). For an account the block
// leaves unmodified check_root never looks at `current`, so a witness that ships the two
// different hands the EVM an unproven value. The end-to-end case below builds exactly
// that: a probe copies a read-only contract's slot into its own storage, and the forged
// header commits to the forged copy.
//
// Slot keys. read_storage() and set_storage_slot() binary-search the inline keys, so keys
// out of order or repeated can hide a proven slot from the EVM.
//
// Routing. check_root reads the account at each addr_hashes row's entry_offset, the EVM
// reads whatever find() returns. A row whose entry_offset is not where find() routes its
// address splits the two: a transposed slot_offsets pair, or a phantom row pointing into
// another account's slot bytes for an address the map does not hold.

#include <algorithm>
#include <cstdint>
#include <cstring>
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

evmc::bytes32 word(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

/// A key whose first byte is `b0`: sorts after every key that starts lower.
evmc::bytes32 high_key(uint8_t b0) {
    evmc::bytes32 k{};
    k.bytes[0] = b0;
    return k;
}

const AddrHashEntry* addr_hashes_of(const std::vector<uint8_t>& blob) {
    const auto* meta = reinterpret_cast<const PreStateMeta*>(blob.data());
    return reinterpret_cast<const AddrHashEntry*>(blob.data() + meta->addr_hashes_offset);
}

uint32_t entry_offset_of(const std::vector<uint8_t>& blob, const evmc::address& a) {
    const auto* meta = reinterpret_cast<const PreStateMeta*>(blob.data());
    const AddrHashEntry* rows = addr_hashes_of(blob);
    for (uint32_t i = 0; i < meta->n_accounts; ++i) {
        if (std::memcmp(rows[i].addr, a.bytes, 20) == 0) return rows[i].entry_offset;
    }
    return ~uint32_t{0};
}

/// The addr map's data[] in a serialized pre-state.
uint8_t* addr_map_data(std::vector<uint8_t>& blob) {
    const auto* meta = reinterpret_cast<const PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    return reinterpret_cast<uint8_t*>(mh) + mh->data_offset;
}

/// `a`'s inline slots in a serialized pre-state.
Slot* slots_of(std::vector<uint8_t>& blob, const evmc::address& a) {
    return reinterpret_cast<Slot*>(addr_map_data(blob) + entry_offset_of(blob, a) + 8u + sizeof(Account));
}

/// Inserts an addr_hashes row for `addr` at `entry_offset`, keeping the rows sorted and the
/// blob's sections back to back, so the layout checks still pass.
std::vector<uint8_t> with_addr_hashes_row(const std::vector<uint8_t>& blob, const evmc::address& addr,
                                          uint32_t entry_offset) {
    AddrHashEntry row{};
    const bytes32 h = keccak_addr32(addr);
    std::memcpy(row.addr_hash, h.bytes, 32);
    std::memcpy(row.addr, addr.bytes, 20);
    row.entry_offset = entry_offset;

    const auto* meta = reinterpret_cast<const PreStateMeta*>(blob.data());
    const AddrHashEntry* rows = addr_hashes_of(blob);
    const auto pos = static_cast<size_t>(std::lower_bound(rows, rows + meta->n_accounts, row) - rows);
    const size_t at = meta->addr_hashes_offset + pos * sizeof(AddrHashEntry);

    std::vector<uint8_t> out(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(at));
    const auto* rb = reinterpret_cast<const uint8_t*>(&row);
    out.insert(out.end(), rb, rb + sizeof(AddrHashEntry));
    out.insert(out.end(), blob.begin() + static_cast<std::ptrdiff_t>(at), blob.end());

    auto* m = reinterpret_cast<PreStateMeta*>(out.data());
    m->n_accounts += 1;
    m->block_hashes_offset += sizeof(AddrHashEntry);
    m->code_store_offset += sizeof(AddrHashEntry);
    return out;
}

struct Sanitized {
    bool ok{false};
    std::string log;
};

/// sanitize() over a private copy of `blob`, with its output captured.
Sanitized sanitize_copy(std::vector<uint8_t> blob) {
    DirectState ds{std::span<uint8_t>{blob}};
    Sanitized s{};
    StdoutCapture cap;
    s.ok = ds.sanitize();
    s.log = cap.str();
    return s;
}

// V's code returns its own storage[0]:
//   PUSH1 0; SLOAD; PUSH1 0; MSTORE; PUSH1 32; PUSH1 0; RETURN
Bytes victim_code() {
    Bytes c;
    push1(c, 0x00);
    c.push_back(0x54);  // SLOAD
    push1(c, 0x00);
    c.push_back(0x52);  // MSTORE
    push1(c, 0x20);
    push1(c, 0x00);
    c.push_back(0xf3);  // RETURN
    return c;
}

// D's code STATICCALLs V and stores the returned word in its own storage[0]. V stays
// read-only, which is the point: check_root proves V's slot `initial` and nothing else.
//   PUSH1 32; PUSH1 0; PUSH1 0; PUSH1 0; PUSH20 V; GAS; STATICCALL; POP;
//   PUSH1 0; MLOAD; PUSH1 0; SSTORE; STOP
Bytes probe_code(const evmc::address& v) {
    Bytes k;
    push1(k, 0x20);  // retSize
    push1(k, 0x00);  // retOffset
    push1(k, 0x00);  // argsSize
    push1(k, 0x00);  // argsOffset
    push20(k, v);
    k.push_back(0x5a);  // GAS
    k.push_back(0xfa);  // STATICCALL
    k.push_back(0x50);  // POP
    push1(k, 0x00);
    k.push_back(0x51);  // MLOAD
    push1(k, 0x00);
    k.push_back(0x55);  // SSTORE
    k.push_back(0x00);  // STOP
    return k;
}

}  // namespace

TEST_CASE("StateTransition::run rejects a pre-state slot whose current differs from initial",
          "[sanitize][state_transition][exec]") {
    const evmc::address D = make_addr(0x22, 0x02);  // probe, called by the tx
    const evmc::address V = make_addr(0x33, 0x03);  // victim, read-only

    const silkworm::Transaction tx = make_legacy_txn(D, /*gas_limit=*/1'000'000);
    const evmc::address S = recover_sender(tx);
    REQUIRE(S != evmc::address{});
    REQUIRE(S != D);
    REQUIRE(S != V);

    constexpr uint64_t kGenuine = 5;
    constexpr uint64_t kForged = 999;
    const Prestate ps = build_prestate({
        AcctSpec{.addr = S, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = D, .nonce = 1, .code = probe_code(V)},
        AcctSpec{.addr = V, .nonce = 1, .code = victim_code(), .storage = {{word(0), word(kGenuine)}}},
    });
    REQUIRE_FALSE(ps.nodestore.empty());

    auto forge = [&](std::vector<uint8_t>& b) {
        std::memcpy(slots_of(b, V)[0].current, word(kForged).bytes, 32);
    };
    std::vector<uint8_t> forged_blob = ps.blob;
    forge(forged_blob);
    REQUIRE(std::bit_cast<evmc::bytes32>(slots_of(forged_blob, V)[0].initial) == word(kGenuine));

    const ChainSetup chain = make_chain(ps.prev_root, tx, /*beneficiary=*/S);

    // ================= honest producer =================
    const ShadowRun honest = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(honest.sanitize_ok);
    REQUIRE(honest.all_succeeded());
    REQUIRE(honest.post.missing == 0);
    REQUIRE_FALSE(honest.post.clashed);
    CHECK(honest.storage(D, 0) == word(kGenuine));

    // ================= forging producer =================
    const Sanitized forged_sanitize = sanitize_copy(forged_blob);
    CHECK_FALSE(forged_sanitize.ok);
    CHECK(forged_sanitize.log.find("sanitize: pre-state slot current != initial") != std::string::npos);

    // What the guest executed over the forged bytes before the check: sanitize() never
    // looked at slot values, so forging after it gives the same run.
    const ShadowRun spoof = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx,
                                           silkworm::test::kShanghaiConfig, forge);
    REQUIRE(spoof.sanitize_ok);
    REQUIRE(spoof.all_succeeded());
    REQUIRE(spoof.post.missing == 0);
    REQUIRE_FALSE(spoof.post.clashed);
    // The EVM read the forged value; the root check proved the genuine one and moved on.
    CHECK(spoof.storage(D, 0) == word(kForged));
    CHECK(spoof.gas_used == honest.gas_used);
    CHECK(spoof.post.root != honest.post.root);

    // ---- Run 1: honest bundle + honest header must be ACCEPTED ----
    {
        std::vector<uint8_t> env = make_envelope(chain, honest, ps.blob, ps.nodestore);
        REQUIRE_FALSE(env.empty());
        StateTransition st{std::span<uint8_t>{env}};
        std::string log;
        uint64_t gas = 0;
        {
            StdoutCapture cap;
            gas = st.run().gas_used;
            log = cap.str();
        }
        CHECK_FALSE(st.failed());
        CHECK(gas == honest.gas_used);
        CHECK(log.find("New Root") != std::string::npos);
    }

    // ---- Run 2: forged bundle + the header its execution justifies must be REJECTED ----
    // Gas, receipts root, logs bloom and state root all match what the guest computed for
    // this witness without the slot check, so without it the bundle verifies.
    {
        std::vector<uint8_t> env = make_envelope(chain, spoof, forged_blob, ps.nodestore);
        REQUIRE_FALSE(env.empty());
        StateTransition st{std::span<uint8_t>{env}};
        std::string log;
        uint64_t gas = 0;
        {
            StdoutCapture cap;
            gas = st.run().gas_used;
            log = cap.str();
        }
        CHECK(st.failed());
        CHECK(gas == StateTransition::kRunFailure);
        CHECK(log.find("sanitize: pre-state slot current != initial") != std::string::npos);
        CHECK(log.find("New Root") == std::string::npos);
    }
}

TEST_CASE("sanitize rejects pre-state slot keys out of order or repeated", "[sanitize]") {
    const evmc::address V = make_addr(0x33, 0x03);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = V, .nonce = 1, .code = victim_code(),
                 .storage = {{word(1), word(10)}, {word(2), word(20)}, {word(3), word(30)}}},
    });

    REQUIRE(sanitize_copy(ps.blob).ok);

    SECTION("two slots swapped") {
        std::vector<uint8_t> blob = ps.blob;
        Slot* s = slots_of(blob, V);
        std::swap(s[0], s[1]);
        const Sanitized r = sanitize_copy(blob);
        CHECK_FALSE(r.ok);
        CHECK(r.log.find("sanitize: pre-state slot keys not strictly ascending") != std::string::npos);
    }
    SECTION("one slot repeated") {
        std::vector<uint8_t> blob = ps.blob;
        Slot* s = slots_of(blob, V);
        s[2] = s[1];
        const Sanitized r = sanitize_copy(blob);
        CHECK_FALSE(r.ok);
        CHECK(r.log.find("sanitize: pre-state slot keys not strictly ascending") != std::string::npos);
    }
}

TEST_CASE("sanitize requires each addr_hashes entry_offset to be where find() routes",
          "[sanitize][mphf]") {
    const evmc::address B = make_addr(0x22, 0x02);   // holds the phantom in its slots
    const evmc::address C = make_addr(0x33, 0x03);
    const evmc::address C2 = make_addr(0x44, 0x04);
    const evmc::address X = make_addr(0x10, 0x01);   // in no map entry
    REQUIRE(addr_key8(C) != addr_key8(C2));

    // B's lowest slot key starts with X's 20 bytes, so an Account read 8 bytes before it
    // has X's address. Three higher slots leave room for the whole phantom Account.
    evmc::bytes32 x_key{};
    std::memcpy(x_key.bytes, X.bytes, 20);
    const Prestate ps = build_prestate({
        AcctSpec{.addr = B, .nonce = 1, .code = victim_code(),
                 .storage = {{x_key, word(1)}, {high_key(0xf1), word(2)},
                             {high_key(0xf2), word(3)}, {high_key(0xf3), word(4)}}},
        AcctSpec{.addr = C, .nonce = 3, .balance = intx::uint256{5000}},
        AcctSpec{.addr = C2, .nonce = 7, .balance = intx::uint256{1234}},
    });
    REQUIRE(sanitize_copy(ps.blob).ok);

    SECTION("transposed slot_offsets") {
        {
            std::vector<uint8_t> probe = ps.blob;
            DirectState ds{std::span<uint8_t>{probe}};
            REQUIRE(ds.mphf()->collisions_size == 0);  // C and C2 each own a slot
        }
        std::vector<uint8_t> blob = ps.blob;
        forge_slot_transposition(blob, C, C2);
        const Sanitized r = sanitize_copy(blob);
        CHECK_FALSE(r.ok);
        CHECK(r.log.find("sanitize: addr_hashes entry_offset is not where find() routes") != std::string::npos);
    }
    SECTION("phantom row inside another account's slots") {
        std::vector<uint8_t> blob = ps.blob;
        REQUIRE(std::memcmp(slots_of(blob, B)[0].key, x_key.bytes, 32) == 0);
        // The phantom's [len] header would sit 8 bytes before B's first slot key.
        const uint32_t phantom = entry_offset_of(blob, B) + static_cast<uint32_t>(sizeof(Account));
        const std::vector<uint8_t> forged = with_addr_hashes_row(blob, X, phantom);
        REQUIRE(validate_direct_state_layout(std::span<const uint8_t>{forged}, {}));
        const Sanitized r = sanitize_copy(forged);
        CHECK_FALSE(r.ok);
        CHECK(r.log.find("sanitize: addr_hashes entry_offset is not where find() routes") != std::string::npos);
    }
}
