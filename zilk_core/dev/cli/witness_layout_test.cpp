// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Forged witnesses whose pre-state sections or MphfMap entries overlap. The reader locates a
// record, a code entry and a node by offsets a producer controls, and sanitize() (the
// initial->current slot copy) and the EVM write through the records in place. Nothing bound the
// regions to be disjoint, so a producer could point the code store onto a record's writable slot,
// or a record onto another's, and have a write change bytes after they were hashed or bound.
//
// Each case seals a block whose execution the forged witness and an honest twin produce identically
// (so the block is well-formed) and drives the public entry point, StateTransition::run. The honest
// twin is accepted; the forgery is rejected, at the line sanitize() prints.

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/state_zz/account_read_test_util.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::ByteView;
using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

const evmc::address kC = make_addr(0x55, 0x05);

evmc::bytes32 word_(uint64_t v) {
    evmc::bytes32 out{};
    intx::be::store(out.bytes, intx::uint256{v});
    return out;
}

struct Outcome {
    uint64_t gas{StateTransition::kRunFailure};
    bool failed{true};
    std::string log;
};

Outcome run_guest(const ChainSetup& chain, const ShadowRun& sr,
                  const std::vector<uint8_t>& blob, const std::vector<uint8_t>& nodestore) {
    std::vector<uint8_t> env = make_envelope(chain, sr, blob, nodestore);
    REQUIRE_FALSE(env.empty());
    StateTransition st{std::span<uint8_t>{env}};
    Outcome o{};
    { StdoutCapture cap; o.gas = st.run().gas_used; o.log = cap.str(); }
    o.failed = st.failed();
    return o;
}

void expect_accepted(const Outcome& o, const ShadowRun& sr) {
    CAPTURE(o.log);
    CHECK_FALSE(o.failed);
    CHECK(o.gas == sr.gas_used);
}

void expect_rejected(const Outcome& o, std::string_view why) {
    CAPTURE(o.log);
    CHECK(o.failed);
    CHECK(o.gas == StateTransition::kRunFailure);
    CHECK(o.log.find(why) != std::string::npos);
}

// 32 code bytes B0 such that B0 and keccak(B0) both begin with 0x00 (STOP): the committed code (B0)
// and the code a drift would substitute (keccak(B0)) then execute identically, so one sealed block
// serves the honest twin and the forgery.
struct StopPair {
    std::array<uint8_t, 32> b0{};
    bytes32 hash{};
};
StopPair find_stop_pair() {
    StopPair p;
    for (uint32_t n = 1; n < 5'000'000u; ++n) {
        std::memcpy(p.b0.data(), &n, 4);
        p.b0[0] = 0x00;  // committed code starts with STOP
        p.hash = keccak_bytes(ByteView{p.b0.data(), 32});
        if (p.hash.bytes[0] == 0x00) return p;  // keccak(B0) also starts with STOP
    }
    FAIL("no STOP/STOP preimage found");
    return p;
}

uint32_t record_offset(std::vector<uint8_t>& blob, const evmc::address& a, uint32_t& data_off_abs) {
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(blob.data() + meta->prestate_offset);
    data_off_abs = meta->prestate_offset + mh->data_offset;
    DirectState ds{std::span<uint8_t>{blob}};
    Account* pc = ds.find_pre_account_unchecked(a);
    REQUIRE(pc);
    return static_cast<uint32_t>(reinterpret_cast<uint8_t*>(pc) - 8 - (blob.data() + data_off_abs));
}

// A pre-state blob for {sender, C} whose code store is laid over C's single storage slot: the code
// payload coincides with slot0.current and the code hash with slot0.initial. sanitize() hashes the
// code (B0) first, then copies slot0.initial over slot0.current, so the executable bytes become
// keccak(B0) after the hash was checked. Reports C's resulting slot0 key and storage root so the
// honest twin can commit the identical account leaf.
std::vector<uint8_t> forged_code_overlap(const StopPair& p, const DirectState::AccountInfo& sender_info,
                                         evmc::bytes32& actual_key_out, bytes32& c_sroot_out) {
    DirectState::AccountInfo ci{};
    ci.addr = kC; std::memcpy(ci.account.addr, kC.bytes, 20);
    std::memcpy(ci.account.code_hash, p.hash.bytes, 32);  // committed code hash = keccak(B0)
    std::memcpy(ci.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    ci.account.code_store_len = 32;
    bytes32 slotkey{}; slotkey.bytes[31] = 0x07;
    ci.storage = {{slotkey, std::bit_cast<evmc::bytes32>(p.hash)}};
    std::vector<DirectState::AccountInfo> infos{sender_info, ci};
    std::vector<uint8_t> blob = DirectState::build_blob_from_accounts(std::move(infos), {}, {});

    uint32_t data_off_abs = 0;
    const uint32_t recoff = record_offset(blob, kC, data_off_abs);
    const uint32_t O_cur = data_off_abs + recoff + 8u + static_cast<uint32_t>(sizeof(Account)) + 64u;
    REQUIRE((O_cur % 8u) == 0u);
    std::memcpy(blob.data() + O_cur, p.b0.data(), 32);  // original code at slot0.current (hashed)

    const uint32_t cs = O_cur - 120u;  // code-store header; entry past the 0 sentinel (off 8)
    auto wr32 = [&](uint32_t off, uint32_t v) { std::memcpy(blob.data() + off, &v, 4); };
    auto wr64 = [&](uint32_t off, uint64_t v) { std::memcpy(blob.data() + off, &v, 8); };
    wr32(cs + 0, kMphfCodeStoreMagic); wr32(cs + 4, kMphfMapVersion);
    wr32(cs + 8, 1u); wr32(cs + 12, 1u);
    wr64(cs + 16, 0u); wr64(cs + 24, 0u);
    wr32(cs + 32, 0u); wr32(cs + 36, 0u);
    wr32(cs + 40, 56u); wr32(cs + 44, 64u); wr32(cs + 48, 72u); wr32(cs + 52, 80u);
    wr64(cs + 56, 0u); wr32(cs + 64, 8u); wr64(cs + 80, 64u);  // displacement, slot_offsets[0], [len]
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    meta->code_store_offset = cs; meta->code_store_size = 152u;

    std::memcpy(actual_key_out.bytes, blob.data() + O_cur - 64, 32);  // slot0.key (partly code-store bytes)
    std::vector<std::pair<bytes32, Bytes>> unused;
    c_sroot_out = collect_trie_nodes(storage_trie_leaves({{actual_key_out,
        std::bit_cast<evmc::bytes32>(p.hash)}}), unused);
    auto* pc = reinterpret_cast<Account*>(blob.data() + data_off_abs + recoff + 8u);
    std::memcpy(pc->storage_root, c_sroot_out.bytes, 32);
    return blob;
}

}  // namespace

// THE HOLE: a code-store entry overlapping a record's own writable storage slot. Before the fix the
// guest executed keccak(B0) while committing code_hash = keccak(B0), i.e. the hash of a DIFFERENT
// 32-byte program B0. Here B0 and keccak(B0) are both STOP, so the forged and honest runs coincide
// and one sealed block serves both; a producer could instead pick keccak(B0) to be any program.
TEST_CASE("the guest rejects a witness whose code store overlaps a record slot",
          "[witness][layout][sections]") {
    const StopPair p = find_stop_pair();
    const auto tx = make_legacy_txn(kC, 1'000'000, 0);
    const evmc::address sender = recover_sender(tx);
    REQUIRE(sender != evmc::address{});
    REQUIRE(sender != kC);
    const DirectState::AccountInfo sender_info = make_eoa(sender, 0, intx::uint256{1} << 64);

    evmc::bytes32 actual_key{}; bytes32 c_sroot{};
    const std::vector<uint8_t> forged = forged_code_overlap(p, sender_info, actual_key, c_sroot);

    // Honest twin: C commits the SAME leaf (code_hash = keccak(B0), same storage) but its code B0
    // lives in a disjoint code store. It executes B0 (STOP), identical to the forged keccak(B0).
    Bytes b0_code{p.b0.begin(), p.b0.end()};
    const std::vector<AcctSpec> state = {
        AcctSpec{.addr = sender, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = kC, .nonce = 0, .balance = 0, .code = b0_code,
                 .storage = {{actual_key, std::bit_cast<evmc::bytes32>(p.hash)}}},
    };
    const Prestate ps = build_prestate(state);
    REQUIRE(keccak_bytes(ByteView{b0_code.data(), b0_code.size()}) == p.hash);  // code_hash == keccak(B0)

    // Seal the block from the honest run; both witnesses must round-trip to the same roots.
    ChainSetup chain = make_chain(ps.prev_root, tx, sender);
    ShadowRun sr = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(sr.sanitize_ok);
    REQUIRE(sr.all_succeeded());

    // Honest twin accepted; the forged (overlapping) witness rejected.
    expect_accepted(run_guest(chain, sr, ps.blob, ps.nodestore), sr);
    expect_rejected(run_guest(chain, sr, forged, ps.nodestore),
                    "sanitize: pre-state sections overlap or out of builder order");
}

// A record placed inside another record's slot array (an entry offset pointing into another entry).
// Its body shares bytes with the host record's writable slots, so sanitize()'s initial->current copy
// and the EVM's SSTOREs would write through both. The tiling check rejects it at the layout stage,
// before the copy. (A record overlap also fails the strictly-ascending slot-key check further down,
// since the host's slots then carry the guest's record bytes as keys; the layout check fires first.)
TEST_CASE("the guest rejects a witness whose address-map records overlap",
          "[witness][layout][records]") {
    const evmc::address kA = make_addr(0x66, 0x06);
    const auto tx = make_legacy_txn(kC, 1'000'000, 0);
    const evmc::address sender = recover_sender(tx);
    REQUIRE(sender != evmc::address{});
    REQUIRE(sender != kC);
    REQUIRE(sender != kA);

    // Honest: sender, C (five slots), A (one slot) — all disjoint.
    const std::vector<AcctSpec> state = {
        AcctSpec{.addr = sender, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = kC, .nonce = 0, .balance = 0,
                 .storage = {{word_(1), word_(10)}, {word_(2), word_(11)}, {word_(3), word_(12)},
                             {word_(4), word_(13)}, {word_(5), word_(14)}}},
        AcctSpec{.addr = kA, .nonce = 0, .balance = 0, .storage = {{word_(9), word_(99)}}},
    };
    const Prestate ps = build_prestate(state);
    ChainSetup chain = make_chain(ps.prev_root, tx, sender);
    ShadowRun sr = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(sr.sanitize_ok);
    REQUIRE(sr.all_succeeded());
    expect_accepted(run_guest(chain, sr, ps.blob, ps.nodestore), sr);

    // Forge: relocate A's record so it starts inside C's slot array (its [len]/Account/slot bytes now
    // share C's writable slots), and repoint A's slot_offsets slot and addr_hashes entry to it.
    std::vector<uint8_t> forged = ps.blob;
    uint32_t data_off_abs = 0;
    const uint32_t recC = record_offset(forged, kC, data_off_abs);
    uint32_t data_off_a = 0;
    const uint32_t recA = record_offset(forged, kA, data_off_a);
    const uint32_t a_len = 8u + static_cast<uint32_t>(sizeof(Account)) + 1u * static_cast<uint32_t>(sizeof(Slot));
    const uint32_t new_a = recC + 8u + static_cast<uint32_t>(sizeof(Account)) + 96u;  // C.slot1 start
    uint8_t* data = forged.data() + data_off_abs;
    std::memcpy(data + new_a, data + recA, a_len);  // A's record now lives inside C's slots

    auto* meta = reinterpret_cast<PreStateMeta*>(forged.data());
    auto* mh = reinterpret_cast<MphfMapHeader*>(forged.data() + meta->prestate_offset);
    auto* slots = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(mh) + mh->slot_offsets_offset);
    bool repointed = false;
    const uint32_t idxA = mh->index_lookup(addr_key8(kA));
    if (slots[idxA] == recA) { slots[idxA] = new_a; repointed = true; }
    if (!repointed && mh->collisions_size > 0) {
        auto* coll = reinterpret_cast<MphfCollisionEntry*>(
            reinterpret_cast<uint8_t*>(mh) + mh->collisions_offset);
        const uint32_t nc = mh->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
        for (uint32_t i = 0; i < nc; ++i)
            if (coll[i].offset == recA) { coll[i].offset = new_a; repointed = true; }
    }
    REQUIRE(repointed);
    auto* ahe = reinterpret_cast<AddrHashEntry*>(forged.data() + meta->addr_hashes_offset);
    for (uint32_t i = 0; i < meta->n_accounts; ++i)
        if (std::memcmp(ahe[i].addr, kA.bytes, 20) == 0) ahe[i].entry_offset = new_a;

    expect_rejected(run_guest(chain, sr, forged, ps.nodestore),
                    "sanitize: witness MphfMap entries overlap or leave gaps");
}
