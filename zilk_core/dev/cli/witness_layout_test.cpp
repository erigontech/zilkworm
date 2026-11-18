// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// Forged witnesses whose pre-state sections or MphfMap entries overlap.

#include <sys/wait.h>
#include <unistd.h>

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

// The DirectState constructor validates the pre-state layout before reading any field and aborts on a malformed one.
void expect_rejected_at_construction(const ChainSetup& chain, const ShadowRun& sr,
                                     const std::vector<uint8_t>& blob,
                                     const std::vector<uint8_t>& nodestore,
                                     std::string_view why) {
    std::vector<uint8_t> env = make_envelope(chain, sr, blob, nodestore);
    REQUIRE_FALSE(env.empty());
    int fds[2];
    REQUIRE(pipe(fds) == 0);
    const pid_t pid = fork();
    REQUIRE(pid >= 0);
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        StateTransition st{std::span<uint8_t>{env}};
        st.run();
        _exit(0);
    }
    close(fds[1]);
    std::string out;
    char buf[256];
    for (ssize_t n; (n = read(fds[0], buf, sizeof(buf))) > 0;) out.append(buf, static_cast<size_t>(n));
    close(fds[0]);
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    INFO(out);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
    CHECK(out.find(why) != std::string::npos);
}

// 32 code bytes B0 such that B0 and keccak(B0) both begin with 0x00 (STOP): the committed code.
struct StopPair {
    std::array<uint8_t, 32> b0{};
    bytes32 hash{};
};
StopPair find_stop_pair() {
    StopPair p;
    for (uint32_t n = 1; n < 5'000'000u; ++n) {
        std::memcpy(p.b0.data(), &n, 4);
        p.b0[0] = 0x00;
        p.hash = keccak_bytes(ByteView{p.b0.data(), 32});
        if (p.hash.bytes[0] == 0x00) return p;
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

// A pre-state blob for {sender, C} whose code store is laid over C's single storage slot.
std::vector<uint8_t> forged_code_overlap(const StopPair& p, const DirectState::AccountInfo& sender_info,
                                         evmc::bytes32& actual_key_out, bytes32& c_sroot_out) {
    DirectState::AccountInfo ci{};
    ci.addr = kC; std::memcpy(ci.account.addr, kC.bytes, 20);
    std::memcpy(ci.account.code_hash, p.hash.bytes, 32);
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
    std::memcpy(blob.data() + O_cur, p.b0.data(), 32);

    const uint32_t cs = O_cur - 120u;
    auto wr32 = [&](uint32_t off, uint32_t v) { std::memcpy(blob.data() + off, &v, 4); };
    auto wr64 = [&](uint32_t off, uint64_t v) { std::memcpy(blob.data() + off, &v, 8); };
    wr32(cs + 0, kMphfCodeStoreMagic); wr32(cs + 4, kMphfMapVersion);
    wr32(cs + 8, 1u); wr32(cs + 12, 1u);
    wr64(cs + 16, 0u); wr64(cs + 24, 0u);
    wr32(cs + 32, 0u); wr32(cs + 36, 0u);
    wr32(cs + 40, 56u); wr32(cs + 44, 64u); wr32(cs + 48, 72u); wr32(cs + 52, 80u);
    wr64(cs + 56, 0u); wr32(cs + 64, 8u); wr64(cs + 80, 64u);
    auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
    meta->code_store_offset = cs; meta->code_store_size = 152u;

    std::memcpy(actual_key_out.bytes, blob.data() + O_cur - 64, 32);
    std::vector<std::pair<bytes32, Bytes>> unused;
    c_sroot_out = collect_trie_nodes(storage_trie_leaves({{actual_key_out,
        std::bit_cast<evmc::bytes32>(p.hash)}}), unused);
    auto* pc = reinterpret_cast<Account*>(blob.data() + data_off_abs + recoff + 8u);
    std::memcpy(pc->storage_root, c_sroot_out.bytes, 32);
    return blob;
}

}  // namespace

// THE HOLE: a code-store entry overlapping a record's own writable storage slot.
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

    Bytes b0_code{p.b0.begin(), p.b0.end()};
    const std::vector<AcctSpec> state = {
        AcctSpec{.addr = sender, .nonce = 0, .balance = intx::uint256{1} << 64},
        AcctSpec{.addr = kC, .nonce = 0, .balance = 0, .code = b0_code,
                 .storage = {{actual_key, std::bit_cast<evmc::bytes32>(p.hash)}}},
    };
    const Prestate ps = build_prestate(state);
    REQUIRE(keccak_bytes(ByteView{b0_code.data(), b0_code.size()}) == p.hash);

    ChainSetup chain = make_chain(ps.prev_root, tx, sender);
    ShadowRun sr = shadow_execute(ps.blob, ps.nodestore, ps.prev_root, chain.base.header, tx);
    REQUIRE(sr.sanitize_ok);
    REQUIRE(sr.all_succeeded());

    expect_accepted(run_guest(chain, sr, ps.blob, ps.nodestore), sr);
    expect_rejected_at_construction(chain, sr, forged, ps.nodestore,
                                    "DirectState: prestate sections overlap");
}

// A record placed inside another record's slot array (an entry offset pointing into another entry).
TEST_CASE("the guest rejects a witness whose address-map records overlap",
          "[witness][layout][records]") {
    const evmc::address kA = make_addr(0x66, 0x06);
    const auto tx = make_legacy_txn(kC, 1'000'000, 0);
    const evmc::address sender = recover_sender(tx);
    REQUIRE(sender != evmc::address{});
    REQUIRE(sender != kC);
    REQUIRE(sender != kA);

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

    std::vector<uint8_t> forged = ps.blob;
    uint32_t data_off_abs = 0;
    const uint32_t recC = record_offset(forged, kC, data_off_abs);
    uint32_t data_off_a = 0;
    const uint32_t recA = record_offset(forged, kA, data_off_a);
    const uint32_t a_len = 8u + static_cast<uint32_t>(sizeof(Account)) + 1u * static_cast<uint32_t>(sizeof(Slot));
    const uint32_t new_a = recC + 8u + static_cast<uint32_t>(sizeof(Account)) + 96u;
    uint8_t* data = forged.data() + data_off_abs;
    std::memcpy(data + new_a, data + recA, a_len);

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
