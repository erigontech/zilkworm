// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The result of a call frame on its way back to the frame that made the call. With evmc::Host's
// own interface, CALL and CREATE take the evmc::Result from the C++ Host as is, and a frame builds
// its result in the caller's return slot; any other interface goes through the C callback, which
// releases the result to a raw evmc_result and wraps it again. Each program here runs its calls
// both ways, and through the evmc_vm C entry, and every run must leave the same status, gas left,
// refund, state gas, output, logs and state. The programs make every kind of call and creation to
// callees that stop, return or revert with data of several sizes, fail, run out of gas, clear a
// slot (a refund), log, call again, and report the message they received. The outcomes are also
// pinned to a digest taken from the code before results were passed by value.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <pthread.h>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/baseline.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>
#include <evmone_precompiles/keccak.hpp>

namespace {

using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using namespace evmc::literals;

constexpr address kCaller = 0xaa00000000000000000000000000000000000001_address;
constexpr address kSender = 0x5e00000000000000000000000000000000000004_address;
constexpr address kRecursive = 0xcc00000000000000000000000000000000000003_address;

enum : uint8_t {
    STOP = 0x00, ADD = 0x01, ADDRESS = 0x30, CALLER = 0x33, CALLVALUE = 0x34, CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37, RETURNDATASIZE = 0x3d, RETURNDATACOPY = 0x3e, POP = 0x50, MLOAD = 0x51,
    MSTORE = 0x52, SSTORE = 0x55, JUMP = 0x56, GAS = 0x5a, JUMPDEST = 0x5b, PUSH1 = 0x60,
    PUSH20 = 0x73, PUSH32 = 0x7f, LOG0 = 0xa0, CREATE = 0xf0, CALL = 0xf1,
    CALLCODE = 0xf2, RETURN = 0xf3, DELEGATECALL = 0xf4, CREATE2 = 0xf5, STATICCALL = 0xfa,
    REVERT = 0xfd, INVALID = 0xfe
};

struct Asm {
    bytes code;
    Asm& op(uint8_t o) { code.push_back(o); return *this; }
    Asm& push(uint64_t v) {
        unsigned n = 1;
        while (n < 8 && (v >> (8 * n)) != 0)
            ++n;
        code.push_back(static_cast<uint8_t>(PUSH1 + n - 1));
        for (unsigned i = n; i-- > 0;)
            code.push_back(static_cast<uint8_t>(v >> (8 * i)));
        return *this;
    }
    Asm& push_word(const bytes32& w) {
        code.push_back(PUSH32);
        code.insert(code.end(), w.bytes, w.bytes + 32);
        return *this;
    }
    Asm& push_addr(const address& a) {
        code.push_back(PUSH20);
        code.insert(code.end(), a.bytes, a.bytes + 20);
        return *this;
    }
    Asm& mstore(uint64_t offset, const bytes32& w) { return push_word(w).push(offset).op(MSTORE); }
    Asm& ret(uint64_t offset, uint64_t size) { return push(size).push(offset).op(RETURN); }
    Asm& revert(uint64_t offset, uint64_t size) { return push(size).push(offset).op(REVERT); }
    // A call of any kind: CALL and CALLCODE take a value, DELEGATECALL and STATICCALL do not.
    Asm& call(uint8_t kind, const address& to, uint64_t gas, uint64_t value, uint64_t in,
        uint64_t in_size, uint64_t out, uint64_t out_size) {
        push(out_size).push(out).push(in_size).push(in);
        if (kind == CALL || kind == CALLCODE)
            push(value);
        return push_addr(to).push(gas).op(kind);
    }
};

// Bytes base, base + 1, ... so that every returned byte tells where it came from.
bytes32 ramp(uint8_t base) {
    bytes32 w;
    for (unsigned i = 0; i < 32; ++i)
        w.bytes[i] = static_cast<uint8_t>(base + i);
    return w;
}

constexpr size_t kCallees = 12;

address callee(size_t v) {
    address a{};
    a.bytes[0] = 0xbb;
    a.bytes[19] = static_cast<uint8_t>(v + 1);
    return a;
}

// The callees, also used as init code.
bytes callee_code(size_t v) {
    switch (v) {
    case 0: return Asm{}.op(STOP).code;
    case 1: return Asm{}.mstore(0, ramp(0x10)).ret(1, 3).code;
    case 2: return Asm{}.mstore(0, ramp(0x20)).mstore(32, ramp(0x40)).ret(0, 33).code;
    case 3:
        return Asm{}.mstore(0, ramp(0x60)).mstore(32, ramp(0x80)).mstore(64, ramp(0xa0))
            .ret(5, 70).code;
    case 4: return Asm{}.mstore(0, ramp(0xc0)).revert(2, 5).code;
    case 5: return Asm{}.revert(0, 0).code;
    case 6: return Asm{}.op(INVALID).code;
    case 7: return Asm{}.op(JUMPDEST).op(PUSH1).op(0).op(JUMP).code;  // runs out of gas
    case 8:
        // Sets a slot and clears it again: the refund travels back in the result.
        return Asm{}.push(1).push(1).op(SSTORE).push(0).push(1).op(SSTORE)
            .mstore(0, ramp(0xe0)).ret(0, 4).code;
    case 9: {
        // Calls the 70-byte callee and returns what it returned.
        Asm a;
        a.call(CALL, callee(3), 100000, 0, 0, 0, 0, 0).op(POP);
        a.op(RETURNDATASIZE).push(0).push(0).op(RETURNDATACOPY);
        return a.op(RETURNDATASIZE).push(0).op(RETURN).code;
    }
    case 10:
        // Logs its calldata and returns it.
        return Asm{}.op(CALLDATASIZE).push(0).push(0).op(CALLDATACOPY)
            .op(CALLDATASIZE).push(0).op(LOG0)
            .op(CALLDATASIZE).push(0).op(RETURN).code;
    default:
        // Reports the message: gas, caller, value and calldata size.
        return Asm{}.op(GAS).push(0).op(MSTORE).op(CALLER).push(32).op(MSTORE)
            .op(CALLVALUE).push(64).op(MSTORE).op(CALLDATASIZE).push(96).op(MSTORE)
            .ret(0, 128).code;
    }
}

// The recursive callee: returns one more than its own call returned, so the top frame returns
// the number of frames below the depth limit.
bytes recursive_code() {
    Asm a;
    a.push(0).push(0).push(0).push(0).push(0).op(ADDRESS).op(GAS).op(CALL).op(POP);
    a.op(RETURNDATASIZE).push(0).push(0).op(RETURNDATACOPY);
    a.push(0).op(MLOAD).push(1).op(ADD).push(0).op(MSTORE);
    return a.ret(0, 32).code;
}

struct Rng {
    uint64_t s;
    uint64_t next() {
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        return s >> 33;
    }
    uint64_t below(uint64_t n) { return next() % n; }
};

// Every step records its stack result, RETURNDATASIZE, GAS and the return data here.
constexpr uint64_t kRecords = 0x1000;
constexpr uint64_t kRecordSize = 224;
constexpr uint64_t kInitCode = 0x200;

// Calls and creations to the callees below `targets`; a target past kCallees has no account.
bytes random_program(Rng& rng, unsigned steps, uint64_t targets = kCallees) {
    Asm a;
    // Arguments for the callees in the scratch area.
    a.mstore(0, ramp(0x01)).mstore(32, ramp(0x31)).mstore(64, ramp(0x71));
    for (unsigned i = 0; i < steps; ++i) {
        const auto v = static_cast<size_t>(rng.below(targets));
        const uint64_t gas = rng.below(4) == 0 ? rng.below(3000) : 300000;
        const auto kind = rng.below(6);
        if (kind < 4) {
            static constexpr uint8_t kinds[] = {CALL, CALLCODE, DELEGATECALL, STATICCALL};
            a.call(kinds[kind], callee(v), gas, rng.below(2), rng.below(40), rng.below(60),
                rng.below(100), rng.below(80));
        } else {
            // The init code goes to memory in 32-byte chunks, then CREATE or CREATE2 runs it.
            const auto init = callee_code(v);
            for (size_t off = 0; off < init.size(); off += 32) {
                bytes32 w{};
                std::memcpy(w.bytes, init.data() + off, std::min<size_t>(32, init.size() - off));
                a.mstore(kInitCode + off, w);
            }
            if (kind == 5)
                a.push(i);  // the salt
            a.push(init.size()).push(kInitCode).push(rng.below(2)).op(kind == 4 ? CREATE : CREATE2);
        }
        const auto rec = kRecords + i * kRecordSize;
        a.push(rec).op(MSTORE);
        a.op(RETURNDATASIZE).push(rec + 32).op(MSTORE);
        a.op(GAS).push(rec + 64).op(MSTORE);
        a.op(RETURNDATASIZE).push(0).push(rec + 96).op(RETURNDATACOPY);
    }
    // Some programs end in a revert, which keeps the gas but not the refund.
    if (rng.below(5) == 0)
        return a.revert(0, kRecords + steps * kRecordSize).code;
    return a.ret(0, kRecords + steps * kRecordSize).code;
}

struct EmptyView final : evmone::state::StateView {
    std::optional<Account> get_account(const address&) const noexcept override {
        return std::nullopt;
    }
    evmc::bytes_view get_account_code(const address&) const noexcept override { return {}; }
    bytes32 get_storage(const address&, const bytes32&) const noexcept override { return {}; }
};

struct NoHashes final : evmone::state::BlockHashes {
    bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// The interface the C++ Host exposes, at another address: a frame running with it makes its
// calls through the C callback.
const evmc_host_interface kCInterface = evmc::Host::get_interface();

enum class Entry {
    cpp,       // baseline::execute(VM&) with evmc::Host's interface: the direct path
    c_iface,   // baseline::execute(VM&) with the copied interface: the C callback
    c_vm,      // the evmc_vm C entry with evmc::Host's interface
    c_vm_c,    // the evmc_vm C entry with the copied interface
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    int64_t gas_refund = 0;
    int64_t state_gas_left = 0;
    int64_t state_gas_spilled = 0;
    bytes output;
    std::vector<evmone::state::Log> logs;
    evmone::state::StateDiff diff;
};

// From Amsterdam on a frame also carries state gas: `state_gas` is the reservoir of the top frame.
Outcome run(const bytes& code, Entry entry, int64_t gas = 10000000,
    evmc_revision rev = EVMC_PRAGUE, int64_t state_gas = 0) {
    EmptyView view;
    NoHashes hashes;
    evmone::state::State state{view};
    const auto add = [&state](const address& a, const bytes& c) {
        evmone::state::Account acc;
        acc.code = c;
        std::memcpy(acc.code_hash.bytes, ethash::keccak256(c.data(), c.size()).bytes, 32);
        acc.balance = 1000000;
        state.insert(a, std::move(acc));
    };
    add(kCaller, code);
    add(kRecursive, recursive_code());
    for (size_t v = 0; v < kCallees; ++v)
        add(callee(v), callee_code(v));
    evmone::state::Account sender;
    sender.balance = 1000000;
    state.insert(kSender, std::move(sender));

    auto* const evmone_vm = new evmone::VM{};
    evmc::VM vm{evmone_vm};
    evmone::state::BlockInfo block;
    block.gas_limit = 30000000;
    block.number = 1;
    block.timestamp = 1;
    evmone::state::Transaction tx;
    evmone::state::Host host{rev, vm, state, block, hashes, tx};

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = gas;
    msg.recipient = kCaller;
    msg.code_address = kCaller;
    msg.sender = kSender;
    msg.state_gas = state_gas;

    const auto& iface = (entry == Entry::cpp || entry == Entry::c_vm) ?
                            evmc::Host::get_interface() :
                            kCInterface;
    // Built from either kind of return, so that the same test runs against the raw evmc_result
    // that baseline::execute(VM&) returned before.
    const auto result = [&] {
        if (entry == Entry::cpp || entry == Entry::c_iface) {
            const auto analysis = evmone::baseline::analyze(code);
            return evmc::Result{evmone::baseline::execute(
                *evmone_vm, iface, host.to_context(), rev, msg, analysis)};
        }
        return evmc::Result{evmone_vm->execute(
            evmone_vm, &iface, host.to_context(), rev, &msg, code.data(), code.size())};
    }();

    Outcome o;
    o.status = result.status_code;
    o.gas_left = result.gas_left;
    o.gas_refund = result.gas_refund;
    o.state_gas_left = result.state_gas.left;
    o.state_gas_spilled = result.state_gas.spilled;
    o.output.assign(result.output_data, result.output_size);
    o.logs = host.take_logs();
    o.diff = state.build_diff(rev);
    std::sort(o.diff.modified_accounts.begin(), o.diff.modified_accounts.end(),
        [](const auto& x, const auto& y) { return x.addr < y.addr; });
    for (auto& e : o.diff.modified_accounts)
        std::sort(e.modified_storage.begin(), e.modified_storage.end());
    std::sort(o.diff.deleted_accounts.begin(), o.diff.deleted_accounts.end());
    return o;
}

void require_same(const Outcome& a, const Outcome& b) {
    REQUIRE(a.status == b.status);
    REQUIRE(a.gas_left == b.gas_left);
    REQUIRE(a.gas_refund == b.gas_refund);
    REQUIRE(a.state_gas_left == b.state_gas_left);
    REQUIRE(a.state_gas_spilled == b.state_gas_spilled);
    REQUIRE(a.output == b.output);
    REQUIRE(a.logs.size() == b.logs.size());
    for (size_t i = 0; i < a.logs.size(); ++i) {
        REQUIRE(a.logs[i].addr == b.logs[i].addr);
        REQUIRE(a.logs[i].data == b.logs[i].data);
        REQUIRE(a.logs[i].topics == b.logs[i].topics);
    }
    REQUIRE(a.diff.modified_accounts.size() == b.diff.modified_accounts.size());
    for (size_t i = 0; i < a.diff.modified_accounts.size(); ++i) {
        const auto& x = a.diff.modified_accounts[i];
        const auto& y = b.diff.modified_accounts[i];
        REQUIRE(x.addr == y.addr);
        REQUIRE(x.nonce == y.nonce);
        REQUIRE(x.balance == y.balance);
        REQUIRE(x.code == y.code);
        REQUIRE(x.modified_storage == y.modified_storage);
    }
    REQUIRE(a.diff.deleted_accounts == b.diff.deleted_accounts);
}

// FNV-1a over everything an outcome holds.
struct Digest {
    uint64_t h = 0xcbf29ce484222325ull;
    void add(const void* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            h ^= static_cast<const uint8_t*>(p)[i];
            h *= 0x100000001b3ull;
        }
    }
    void add_int(uint64_t v) { add(&v, sizeof(v)); }
    void add(const Outcome& o) {
        add_int(static_cast<uint64_t>(o.status));
        add_int(static_cast<uint64_t>(o.gas_left));
        add_int(static_cast<uint64_t>(o.gas_refund));
        add_int(static_cast<uint64_t>(o.state_gas_left));
        add_int(static_cast<uint64_t>(o.state_gas_spilled));
        add_int(o.output.size());
        add(o.output.data(), o.output.size());
        for (const auto& l : o.logs) {
            add(l.addr.bytes, 20);
            add_int(l.data.size());
            add(l.data.data(), l.data.size());
        }
        for (const auto& e : o.diff.modified_accounts) {
            add(e.addr.bytes, 20);
            add_int(e.nonce);
            add_int(static_cast<uint64_t>(e.balance));
            add_int(e.code ? e.code->size() : ~uint64_t{0});
            if (e.code)
                add(e.code->data(), e.code->size());
            for (const auto& [k, v] : e.modified_storage) {
                add(k.bytes, 32);
                add(v.bytes, 32);
            }
        }
    }
};

// Runs f on a thread with a 256 MiB stack.
template <typename F>
void run_on_large_stack(F f) {
    pthread_attr_t attr;
    REQUIRE(pthread_attr_init(&attr) == 0);
    REQUIRE(pthread_attr_setstacksize(&attr, size_t{256} << 20) == 0);
    pthread_t thread;
    const auto body = [](void* arg) -> void* {
        (*static_cast<F*>(arg))();
        return nullptr;
    };
    REQUIRE(pthread_create(&thread, &attr, body, &f) == 0);
    REQUIRE(pthread_join(thread, nullptr) == 0);
    pthread_attr_destroy(&attr);
}

}  // namespace

TEST_CASE("a call's result is the same through the C++ Host and the C callback", "[call_frame]") {
    // The callees one by one, by every kind of call and creation, with plenty of gas and with a
    // little.
    for (size_t v = 0; v < kCallees; ++v) {
        for (uint8_t kind : {CALL, CALLCODE, DELEGATECALL, STATICCALL}) {
            for (uint64_t gas : {300000u, 2500u}) {
                Asm a;
                a.mstore(0, ramp(0x01)).call(kind, callee(v), gas, 1, 3, 33, 7, 80).push(0)
                    .op(MSTORE).op(RETURNDATASIZE).push(0).push(32).op(RETURNDATACOPY).ret(0, 160);
                const auto cpp = run(a.code, Entry::cpp);
                REQUIRE(cpp.status == EVMC_SUCCESS);
                require_same(cpp, run(a.code, Entry::c_iface));
                require_same(cpp, run(a.code, Entry::c_vm));
                require_same(cpp, run(a.code, Entry::c_vm_c));
            }
        }
    }
}

TEST_CASE("frame results of random call programs", "[call_frame]") {
    Rng rng{0x9E3779B97F4A7C15ull};
    Digest digest;
    for (int program = 0; program < 300; ++program) {
        const auto code = random_program(rng, 4 + static_cast<unsigned>(rng.below(8)));
        const auto cpp = run(code, Entry::cpp);
        require_same(cpp, run(code, Entry::c_iface));
        require_same(cpp, run(code, Entry::c_vm));
        require_same(cpp, run(code, Entry::c_vm_c));
        digest.add(cpp);
    }
    // The outcomes of the code that returned raw evmc_result frames through release_raw().
    CHECK(digest.h == 0x7366c5e27467ccc0);
}

TEST_CASE("frame results of random call programs with state gas", "[call_frame]") {
    // Amsterdam: the frames carry a state-gas reservoir that comes back in the result, and a call
    // with value to a missing account charges a new account.
    Rng rng{0xD1B54A32D192ED03ull};
    Digest digest;
    int with_state_gas = 0, with_spill = 0, with_refund = 0, with_output = 0;
    for (int program = 0; program < 300; ++program) {
        const auto code = random_program(rng, 4 + static_cast<unsigned>(rng.below(8)), kCallees + 1);
        const int64_t reservoir = program % 3 == 0 ? 0 : 20000 * (program % 5);
        const auto cpp = run(code, Entry::cpp, 10000000, EVMC_AMSTERDAM, reservoir);
        require_same(cpp, run(code, Entry::c_iface, 10000000, EVMC_AMSTERDAM, reservoir));
        require_same(cpp, run(code, Entry::c_vm, 10000000, EVMC_AMSTERDAM, reservoir));
        require_same(cpp, run(code, Entry::c_vm_c, 10000000, EVMC_AMSTERDAM, reservoir));
        digest.add(cpp);
        with_state_gas += cpp.state_gas_left != reservoir;
        with_spill += cpp.state_gas_spilled != 0;
        with_refund += cpp.gas_refund != 0;
        with_output += !cpp.output.empty();
    }
    // The programs do reach the cases the digest is for.
    CHECK(with_state_gas > 20);
    CHECK(with_spill > 20);
    CHECK(with_refund > 20);
    CHECK(with_output > 100);
    // Taken from the code before results were passed by value (frames at Amsterdam).
    CHECK(digest.h == 0xf8f962e259faf3fe);
}

TEST_CASE("known results of calls", "[call_frame]") {
    // REVERT data, a refund through two frames and the message the callee saw.
    Asm a;
    a.call(CALL, callee(4), 300000, 0, 0, 0, 0, 0).push(0).op(MSTORE);
    a.op(RETURNDATASIZE).push(0).push(32).op(RETURNDATACOPY);
    a.call(DELEGATECALL, callee(8), 300000, 0, 0, 0, 64, 4).op(POP);
    a.call(CALL, callee(11), 50000, 7, 0, 9, 96, 128).op(POP);
    a.ret(0, 224);
    for (auto entry : {Entry::cpp, Entry::c_iface, Entry::c_vm, Entry::c_vm_c}) {
        const auto o = run(a.code, entry);
        REQUIRE(o.status == EVMC_SUCCESS);
        REQUIRE(o.output.size() == 224);
        CHECK(o.output[31] == 0);  // the revert
        for (unsigned i = 0; i < 5; ++i)
            CHECK(o.output[32 + i] == 0xc0 + 2 + i);
        CHECK(o.output[37] == 0);
        for (unsigned i = 0; i < 4; ++i)
            CHECK(o.output[64 + i] == 0xe0 + i);
        // The slot set and cleared in the caller's storage: 20000 - 100 back.
        CHECK(o.gas_refund == 19900);
        // The callee saw the caller, the value and 9 bytes of calldata.
        CHECK(std::equal(kCaller.bytes, kCaller.bytes + 20, &o.output[96 + 32 + 12]));
        CHECK(o.output[96 + 64 + 31] == 7);
        CHECK(o.output[96 + 96 + 31] == 9);
    }
}

TEST_CASE("a call at the depth limit fails as a light failure", "[call_frame]") {
    // The top frame, at depth 0, gives all its gas to the recursive callee, which runs at depths
    // 1 to 1024: the frame at depth 1024 cannot call and returns 1. 63/64 of the gas goes one
    // level deeper each time, so the deepest frames need the top one to start with 10^11.
    Asm a;
    a.push(32).push(0).push(0).push(0).push(0).push_addr(kRecursive).op(GAS).op(CALL).op(POP)
        .ret(0, 32);
    std::optional<Outcome> cpp, c_iface;
    // 1025 nested frames need more than the default stack of the main thread in some builds.
    run_on_large_stack([&] {
        cpp = run(a.code, Entry::cpp, 100000000000);
        c_iface = run(a.code, Entry::c_iface, 100000000000);
    });
    REQUIRE(cpp->status == EVMC_SUCCESS);
    REQUIRE(cpp->output.size() == 32);
    CHECK(cpp->output[30] == 0x04);
    CHECK(cpp->output[31] == 0x00);
    require_same(*cpp, *c_iface);
}
