// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The instructions that push a value of the environment (CALLVALUE, CALLER, ADDRESS, ORIGIN,
// COINBASE, SELFBALANCE), KECCAK256 and LOG0-LOG4 convert big-endian bytes straight into the stack
// slot, or the stack items straight into the log's topics, on rv32. Each case here checks the
// result against a byte-order model through the state Host: the pushed value as returned memory,
// and the log's address, topics (the first popped is topics[0]) and data. The values have leading
// zero words or none, addresses have leading zero bytes or none, and every push lands on a stack
// slot that held all ones before. LOG runs at every gas limit around the exact cost (out of gas
// leaves no log), in static mode, and with each topic pattern (zero, one, an address, 2^255,
// 2^256 - 1, a hash). The pushes also run with the stack full. Both dispatch loops run every case.
// The native build runs the portable conversions (the LOG storage and host call are shared); the
// guest's word-wise and byte-wise conversions are covered by the bench and EEST, and were also run
// in an RV32IM emulator during development (that harness is not part of the repo).

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <intx/intx.hpp>

namespace {

using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using intx::uint256;
using namespace evmc::literals;

constexpr address kContract = 0xc0ffee0000000000000000000000000000000001_address;

enum : uint8_t {
    STOP = 0x00, KECCAK = 0x20, ADDRESS = 0x30, ORIGIN = 0x32, CALLER = 0x33, CALLVALUE = 0x34,
    COINBASE = 0x41, SELFBALANCE = 0x47, POP = 0x50, MSTORE = 0x52, PUSH1 = 0x60, PUSH2 = 0x61,
    PUSH32 = 0x7f, LOG0 = 0xa0, RETURN = 0xf3
};

bytes be32(const uint256& v) {
    bytes out(32, 0);
    for (unsigned i = 0; i < 32; ++i)
        out[31 - i] = static_cast<uint8_t>(v[i / 8] >> (8 * (i % 8)));
    return out;
}

uint256 from_address(const address& a) {
    uint256 v;
    for (const auto b : a.bytes)
        v = (v << 8) | b;
    return v;
}

struct Asm {
    bytes code;
    Asm& op(uint8_t o) { code.push_back(o); return *this; }
    Asm& push(uint64_t v) {
        code.insert(code.end(), {PUSH2, static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)});
        return *this;
    }
    Asm& push(const uint256& v) {
        code.push_back(PUSH32);
        const auto w = be32(v);
        code.insert(code.end(), w.begin(), w.end());
        return *this;
    }
    // Leaves a stack slot that held 2^256 - 1 on top of the stack for the next push.
    Asm& dirty_slot() { return push(~uint256{0}).op(POP); }
    // Returns the top item as 32 bytes.
    Asm& ret_top()
    {
        return push(uint64_t{0}).op(MSTORE).push(uint64_t{32}).push(uint64_t{0}).op(RETURN);
    }
};

struct Env {
    uint256 value;
    address sender = 0x5e00000000000000000000000000000000000004_address;
    address origin = 0x0000000000000000000000000000000000000077_address;
    address coinbase = 0xc0ffee000000000000000000000000000000c0de_address;
    address recipient = kContract;
    uint256 balance = 1000000;
    bool is_static = false;
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
    std::vector<evmone::state::Log> logs;
};

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

Outcome run(const bytes& code, const Env& env, int64_t gas, bool cgoto) {
    EmptyView view;
    NoHashes hashes;
    evmone::state::State state{view};
    evmone::state::Account acc;
    acc.code = code;
    acc.balance = env.balance;
    state.insert(env.recipient, std::move(acc));

    evmc::VM vm{new evmone::VM{}};
    if (!cgoto)
        REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    evmone::state::BlockInfo block;
    block.gas_limit = 30000000;
    block.number = 1;
    block.timestamp = 1;
    block.coinbase = env.coinbase;
    evmone::state::Transaction tx;
    tx.sender = env.origin;
    evmone::state::Host host{EVMC_PRAGUE, vm, state, block, hashes, tx};

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = gas;
    msg.recipient = env.recipient;
    msg.code_address = env.recipient;
    msg.sender = env.sender;
    msg.value = intx::be::store<evmc::uint256be>(env.value);
    if (env.is_static)
        msg.flags = EVMC_STATIC;
    const auto r = vm.execute(host, EVMC_PRAGUE, msg, code.data(), code.size());
    Outcome o;
    o.status = r.status_code;
    o.gas_left = r.gas_left;
    o.output.assign(r.output_data, r.output_data + r.output_size);
    o.logs = host.take_logs();
    return o;
}

// The pushed value of op, returned as memory: must be the big-endian bytes of expected.
void check_push(uint8_t op, const Env& env, const uint256& expected) {
    const auto code = Asm{}.dirty_slot().op(op).ret_top().code;
    for (const bool cgoto : {true, false}) {
        INFO("op " << int{op} << " cgoto " << cgoto << " expected " << intx::hex(expected));
        const auto o = run(code, env, 100000, cgoto);
        REQUIRE(o.status == EVMC_SUCCESS);
        CHECK(o.output == be32(expected));
    }
}

// op with 1024 items on the stack: a stack overflow, all gas consumed.
void check_overflow(uint8_t op, const Env& env) {
    Asm a;
    for (int i = 0; i < 1024; ++i)
        a.op(PUSH1).op(0xff);
    const auto code = a.op(op).ret_top().code;
    for (const bool cgoto : {true, false}) {
        INFO("op " << int{op} << " cgoto " << cgoto);
        const auto o = run(code, env, 100000, cgoto);
        CHECK(o.status == EVMC_STACK_OVERFLOW);
        CHECK(o.gas_left == 0);
    }
}

const std::vector<uint256>& values() {
    static const std::vector<uint256> v = [] {
        const uint256 m255 = uint256{1} << 255;
        std::vector<uint256> r = {0, 1, 0xff, uint256{1} << 32, uint256{1} << 64,
            (uint256{1} << 160) - 1, uint256{1} << 224, m255, ~uint256{0}, m255 | 1,
            uint256{0x1234} << 100, ~uint256{0} >> 32};
        uint256 x = 0x9e3779b97f4a7c15;
        for (int i = 0; i < 64; ++i) {
            x = x * 0x5851f42d4c957f2d + 0x14057b7ef767814f;
            const auto words = static_cast<unsigned>(x[3] % 9);  // 0 to 8 significant words
            r.push_back(words == 0 ? uint256{0} : (x | 1) >> (32 * (8 - words)));
        }
        return r;
    }();
    return v;
}

const std::vector<address>& addresses() {
    static const std::vector<address> v = {
        0x0000000000000000000000000000000000000000_address,
        0x0000000000000000000000000000000000000001_address,
        0x00000000000000000000000000000000000000ff_address,
        0x0000000000000000000000000000000100000000_address,
        0x000000000000000000000000000000000000ffff_address,
        0x0102030405060708090a0b0c0d0e0f1011121314_address,
        0x8000000000000000000000000000000000000000_address,
        0xffffffffffffffffffffffffffffffffffffffff_address,
        0x00000000219ab540356cbb839cbe05303d7705fa_address,
        0xdac17f958d2ee523a2206206994597c13d831ec7_address,
    };
    return v;
}

uint256 hash_of(const bytes& b) {
    const auto h = ethash::keccak256(b.data(), b.size());
    return intx::be::unsafe::load<uint256>(h.bytes);
}

}  // namespace

TEST_CASE("CALLVALUE pushes the message's value", "[env_push]") {
    for (const auto& v : values()) {
        Env env;
        env.value = v;
        check_push(CALLVALUE, env, v);
    }
    check_overflow(CALLVALUE, Env{});
}

TEST_CASE("CALLER, ADDRESS, ORIGIN and COINBASE push their address", "[env_push]") {
    for (const auto& a : addresses()) {
        Env env;
        env.sender = a;
        check_push(CALLER, env, from_address(a));
        env = {};
        env.recipient = a;
        check_push(ADDRESS, env, from_address(a));
        env = {};
        env.origin = a;
        check_push(ORIGIN, env, from_address(a));
        env = {};
        env.coinbase = a;
        check_push(COINBASE, env, from_address(a));
    }
    for (const auto op : {CALLER, ADDRESS, ORIGIN, COINBASE})
        check_overflow(op, Env{});
}

TEST_CASE("SELFBALANCE pushes the balance of the executing account", "[env_push]") {
    for (const auto& v : values()) {
        Env env;
        env.balance = v;
        check_push(SELFBALANCE, env, v);
    }
    check_overflow(SELFBALANCE, Env{});
}

TEST_CASE("KECCAK256 pushes the hash of the memory range", "[env_push]") {
    // Memory 0..95 holds the bytes 1, 2, ..., 96.
    bytes mem(96, 0);
    for (size_t i = 0; i < mem.size(); ++i)
        mem[i] = static_cast<uint8_t>(i + 1);
    for (const uint64_t offset : std::vector<uint64_t>{0, 1, 2, 3, 4, 31}) {
        for (const uint64_t size : std::vector<uint64_t>{0, 1, 31, 32, 33, 63, 64, 65}) {
            Asm a;
            for (uint64_t w = 0; w < 3; ++w)
                a.push(intx::be::unsafe::load<uint256>(&mem[32 * w])).push(32 * w).op(MSTORE);
            a.dirty_slot().push(size).push(offset).op(KECCAK).ret_top();
            const auto expected = hash_of(bytes(&mem[offset], size));
            for (const bool cgoto : {true, false}) {
                INFO("offset " << offset << " size " << size << " cgoto " << cgoto);
                const auto o = run(a.code, Env{}, 100000, cgoto);
                REQUIRE(o.status == EVMC_SUCCESS);
                CHECK(o.output == be32(expected));
            }
        }
    }
}

TEST_CASE("LOG0-LOG4 emit the recipient, the topics in pop order and the data", "[env_push]") {
    // Memory 0..63 holds the bytes 0xa0, 0xa1, ..., 0xdf.
    bytes mem(64, 0);
    for (size_t i = 0; i < mem.size(); ++i)
        mem[i] = static_cast<uint8_t>(0xa0 + i);
    const uint256 hash = hash_of(bytes{0x61, 0x62, 0x63});
    const std::vector<uint256> patterns = {0, 1, from_address(addresses()[9]), uint256{1} << 255,
        ~uint256{0}, hash, from_address(addresses()[1]), uint256{1} << 32};

    for (unsigned n = 0; n <= 4; ++n) {
        for (size_t first = 0; first < patterns.size(); ++first) {
            if (n == 0 && first != 0)
                break;
            // topics[i] = patterns[(first + 3 i) % size]: each pattern at each position.
            std::vector<uint256> topics;
            for (unsigned i = 0; i < n; ++i)
                topics.push_back(patterns[(first + 3 * i) % patterns.size()]);
            for (const auto& [offset, size] : std::vector<std::pair<uint64_t, uint64_t>>{
                     {0, 0}, {0, 1}, {0, 32}, {0, 33}, {1, 32}, {3, 33}, {31, 33}, {5, 0}}) {
                Asm a;
                for (uint64_t w = 0; w < 2; ++w)
                    a.push(intx::be::unsafe::load<uint256>(&mem[32 * w])).push(32 * w).op(MSTORE);
                for (unsigned i = n; i-- > 0;)  // topics[0] is pushed last: the first popped
                    a.push(topics[i]);
                a.push(size).push(offset).op(static_cast<uint8_t>(LOG0 + n)).op(STOP);
                // 2 MSTOREs with their pushes and 2 words of memory, the pushes of the topics
                // and of the range, then LOG: 375 per topic and 8 per byte, its memory paid.
                const int64_t used = 2 * 9 + 6 + 3 * (n + 2) + 375 * (n + 1) + 8 * int64_t(size);
                const bytes data(&mem[offset], size);
                for (const bool cgoto : {true, false}) {
                    INFO("LOG" << n << " first " << first << " offset " << offset << " size "
                               << size << " cgoto " << cgoto);
                    for (int64_t gas = used - 3 * (n + 3); gas <= used + 1; ++gas) {
                        INFO("gas " << gas << " of " << used);
                        const auto o = run(a.code, Env{}, gas, cgoto);
                        if (gas < used) {
                            CHECK(o.status == EVMC_OUT_OF_GAS);
                            CHECK(o.logs.empty());
                            continue;
                        }
                        REQUIRE(o.status == EVMC_SUCCESS);
                        CHECK(o.gas_left == gas - used);
                        REQUIRE(o.logs.size() == 1);
                        const auto& log = o.logs[0];
                        CHECK(log.addr == kContract);
                        CHECK(log.data == data);
                        REQUIRE(log.topics.size() == n);
                        for (unsigned i = 0; i < n; ++i)
                            CHECK(bytes(log.topics[i].bytes, log.topics[i].bytes + 32) ==
                                  be32(topics[i]));
                    }
                    Env st;
                    st.is_static = true;
                    const auto o = run(a.code, st, used + 100, cgoto);
                    CHECK(o.status == EVMC_STATIC_MODE_VIOLATION);
                    CHECK(o.logs.empty());
                }
            }
        }
    }
}
