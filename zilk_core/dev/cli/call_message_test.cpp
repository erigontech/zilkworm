// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The CALL family builds its evmc_message field by field, with no clearing first, and on rv32 it
// writes the target address and the value with byte copies of its own. The state Host runs a
// call to the recipient's own code on the account it already holds for the recipient, and
// is_precompile() tests an address from its first byte on.
//
// The messages are checked field by field against the rules of each instruction, twice, with the
// native stack below the interpreter filled with two different patterns, so that a field left
// unwritten shows. The state Host calls cover a recipient that exists, is absent, or is only an
// access-list placeholder, with and without value, and messages whose code address is another
// account, a delegate or a precompile. is_precompile() is compared with the comparison of whole
// addresses it replaced, over every address of 18 leading zero bytes, every single non-zero
// byte, and random addresses with 0 to 20 leading zero bytes, in every revision.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/precompiles.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/word_layout.hpp>
#include <intx/intx.hpp>

namespace {

using evmc::address;
using evmc::bytes32;
using intx::uint256;
using bytes = std::vector<uint8_t>;
using namespace evmc::literals;

enum : uint8_t {
    STOP = 0x00, MSTORE = 0x52, MSTORE8 = 0x53, PUSH1 = 0x60, PUSH2 = 0x61, PUSH32 = 0x7f,
    CALL = 0xf1, CALLCODE = 0xf2, RETURN = 0xf3, DELEGATECALL = 0xf4, STATICCALL = 0xfa
};

constexpr address kCaller = 0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c001_address;
constexpr address kOrigin = 0x5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e01_address;
constexpr address kTarget = 0x00000000ffeeddccbbaa99887766554433221100_address;
constexpr address kDelegate = 0xdddddddddddddddddddddddddddddddddddddd03_address;
constexpr address kAbsent = 0xabababababababababababababababababab0001_address;

void push32(bytes& code, const uint256& v) {
    code.push_back(PUSH32);
    uint8_t w[32];
    intx::be::store(w, v);
    code.insert(code.end(), w, w + 32);
}

bytes designation(const address& to) {
    bytes code{0xef, 0x01, 0x00};
    code.insert(code.end(), to.bytes, to.bytes + sizeof(to.bytes));
    return code;
}

// Fills the native stack below the caller with a pattern: a message field that the interpreter
// leaves unwritten then holds the pattern instead of what an earlier run left there.
[[gnu::noinline]] void fill_stack(uint8_t pattern) {
    volatile uint8_t area[64 * 1024];
    for (auto& b : area)
        b = pattern;
}

struct CallCase {
    uint8_t op = CALL;
    evmc_revision rev = EVMC_OSAKA;
    uint256 value;
    uint256 in_offset;
    uint256 in_size;
    uint256 out_offset = 0x80;
    uint256 out_size;
    uint256 gas;
    bytes target_code;           // the code of kTarget
    bool target_exists = true;
    uint32_t parent_flags = 0;
    uint256 parent_value;
    bool rich = true;            // the caller can pay the value
    int64_t parent_gas = 1'000'000;
    int64_t parent_state_gas = 0;
};

// The parts of a recorded message the instruction writes; the input as bytes.
struct Message {
    evmc_call_kind kind{};
    uint32_t flags = 0;
    int32_t depth = 0;
    int64_t gas = 0;
    int64_t state_gas = 0;
    address recipient;
    address sender;
    bool input_null = false;
    bytes input;
    bytes32 value;
    address code_address;
    const uint8_t* code = nullptr;
    size_t code_size = 0;
    bool operator==(const Message&) const = default;
};

// The fields where a and b differ, by name; empty when they are equal.
std::string mismatch(const Message& a, const Message& b) {
    std::string r;
    const auto field = [&r](bool same, const char* name) {
        if (!same)
            r += std::string{r.empty() ? "" : " "} + name;
    };
    field(a.kind == b.kind, "kind");
    field(a.flags == b.flags, "flags");
    field(a.depth == b.depth, "depth");
    field(a.gas == b.gas, "gas");
    field(a.state_gas == b.state_gas, "state_gas");
    field(a.recipient == b.recipient, "recipient");
    field(a.sender == b.sender, "sender");
    field(a.input_null == b.input_null && a.input == b.input, "input");
    field(a.value == b.value, "value");
    field(a.code_address == b.code_address, "code_address");
    field(a.code == b.code && a.code_size == b.code_size, "code");
    return r;
}

#ifdef EVMONE_WORD_LAYOUT
// The test build keeps EVM memory in the word layout (see evmone/word_layout.hpp): a frame's
// messages carry these flags, their input is a pointer into it, and their output is wanted in it.
constexpr uint32_t kWordFlags = evmone::wl::FLAG_WORD_INPUT | evmone::wl::FLAG_WORD_OUTPUT;
#else
constexpr uint32_t kWordFlags = 0;
#endif

Message message_of(const evmc_message& m) {
    Message r{m.kind, m.flags, m.depth, m.gas, m.state_gas, m.recipient, m.sender,
              m.input_data == nullptr, {}, m.value, m.code_address, m.code, m.code_size};
    for (size_t i = 0; i < m.input_size; ++i) {
#ifdef EVMONE_WORD_LAYOUT
        if ((m.flags & evmone::wl::FLAG_WORD_INPUT) != 0) {
            r.input.push_back(*evmone::wl::at(m.input_data, i));
            continue;
        }
#endif
        r.input.push_back(m.input_data[i]);
    }
    return r;
}

// Records the messages it gets, and returns success with 123 gas left and the output "returned",
// in the layout the message wants.
class RecordingHost final : public evmc::MockedHost {
public:
    std::vector<Message> messages;
    int64_t child_state_gas_left = 0;  // the state gas the child hands back

    evmc::Result call(const evmc_message& msg) noexcept override {
        messages.push_back(message_of(msg));
        alignas(4) uint8_t output[8];
        for (size_t i = 0; i < sizeof(output); ++i)
            output[(msg.flags & kWordFlags) != 0 ? i ^ 3 : i] = static_cast<uint8_t>("returned"[i]);
        return evmc::Result{EVMC_SUCCESS, 123, 0, output, sizeof(output),
                            {.left = child_state_gas_left}};
    }
};

struct CallOutcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
    std::optional<Message> message;
    int64_t state_gas_left = 0;  // the state gas the frame returns
};

constexpr uint256 kMemory0{0x0102030405060708, 0x1112131415161718, 0x2122232425262728,
                           0x3132333435363738};
constexpr uint256 kMemory1{0x4142434445464748, 0x5152535455565758, 0x6162636465666768,
                           0x7172737475767778};
constexpr int32_t kParentDepth = 3;

CallOutcome run_call(const CallCase& c, uint8_t pattern, int64_t child_state_gas_left = 0) {
    evmc::VM vm{evmc_create_evmone()};
    RecordingHost host;
    host.child_state_gas_left = child_state_gas_left;
    std::memset(host.accounts[kCaller].balance.bytes, c.rich ? 0xff : 0x00, 32);
    if (c.target_exists) {
        // Not from an empty vector's iterators: they are null pointers, which memcpy must not get.
        if (!c.target_code.empty())
            host.accounts[kTarget].code = evmc::bytes(c.target_code.begin(), c.target_code.end());
        host.accounts[kTarget].nonce = 1;
    }
    host.accounts[kDelegate].code = evmc::bytes{STOP};

    bytes code;
    push32(code, kMemory0);
    code.insert(code.end(), {PUSH1, 0, MSTORE});
    push32(code, kMemory1);
    code.insert(code.end(), {PUSH1, 32, MSTORE});
    push32(code, c.out_size);
    push32(code, c.out_offset);
    push32(code, c.in_size);
    push32(code, c.in_offset);
    if (c.op == CALL || c.op == CALLCODE)
        push32(code, c.value);
    // The address operand with high bytes the instruction must drop.
    push32(code, (uint256{0xa5a5a5a5a5a5a5a5, 0x5a5a5a5a5a5a5a5a, 0xa5a5a5a5a5a5a5a5,
                          0x5a5a5a5a5a5a5a5a} << 160) | intx::be::load<uint256>(kTarget));
    push32(code, c.gas);
    code.push_back(c.op);
    code.insert(code.end(), {PUSH2, 0x02, 0x00, MSTORE, PUSH2, 0x02, 0x20, PUSH1, 0, RETURN});

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.flags = c.parent_flags;
    msg.depth = kParentDepth;
    msg.gas = c.parent_gas;
    msg.state_gas = c.parent_state_gas;
    msg.recipient = kCaller;
    msg.sender = kOrigin;
    msg.code_address = kCaller;
    msg.value = intx::be::store<evmc::uint256be>(c.parent_value);

    fill_stack(pattern);
    const auto r = vm.execute(host, c.rev, msg, code.data(), code.size());
    CallOutcome out{r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size),
                    {}, r.state_gas.left};
    REQUIRE(host.messages.size() <= 1);
    if (!host.messages.empty())
        out.message = host.messages.front();
    return out;
}

std::string describe(const CallCase& c) {
    return "op " + std::to_string(c.op) + " rev " + std::to_string(static_cast<int>(c.rev)) +
           " value " + intx::hex(c.value) + " in " + intx::hex(c.in_offset) + "+" +
           intx::hex(c.in_size) + " out " + intx::hex(c.out_offset) + "+" + intx::hex(c.out_size) + " gas " + intx::hex(c.gas) +
           " code " + std::to_string(c.target_code.size()) + (c.target_exists ? "" : " absent") +
           " flags " + std::to_string(c.parent_flags) + (c.rich ? "" : " poor");
}

// The message the instruction must send for c, which runs with plenty of gas.
Message expected_message(const CallCase& c) {
    const bool has_value_arg = c.op == CALL || c.op == CALLCODE;
    const bool transfers = has_value_arg && c.value != 0;
    Message m;
    m.kind = c.op == DELEGATECALL ? EVMC_DELEGATECALL : c.op == CALLCODE ? EVMC_CALLCODE : EVMC_CALL;
    m.flags = (c.op == STATICCALL ? uint32_t{EVMC_STATIC} : c.parent_flags & ~uint32_t{EVMC_DELEGATED}) |
              kWordFlags;
    m.code_address = kTarget;
    if (c.rev >= EVMC_PRAGUE && c.target_code.size() == 23 && c.target_code[0] == 0xef) {
        std::memcpy(m.code_address.bytes, &c.target_code[3], 20);
        if (m.code_address != kTarget)
            m.flags |= EVMC_DELEGATED;
    }
    m.depth = kParentDepth + 1;
    m.gas = static_cast<int64_t>(c.gas) + (transfers ? 2300 : 0);
    m.state_gas = c.parent_state_gas;
    m.recipient = (c.op == CALL || c.op == STATICCALL) ? kTarget : kCaller;
    m.sender = c.op == DELEGATECALL ? kOrigin : kCaller;
    m.value = c.op == DELEGATECALL ? intx::be::store<evmc::uint256be>(c.parent_value) :
              has_value_arg       ? intx::be::store<evmc::uint256be>(c.value) :
                                    evmc::uint256be{};
    m.input_null = c.in_size == 0;
    if (c.in_size != 0) {
        uint8_t memory[64];
        intx::be::unsafe::store(memory, kMemory0);
        intx::be::unsafe::store(memory + 32, kMemory1);
        const auto offset = static_cast<size_t>(c.in_offset);
        const auto size = static_cast<size_t>(c.in_size);
        for (size_t i = offset; i < offset + size; ++i)
            m.input.push_back(i < 64 ? memory[i] : 0);
    }
    return m;
}

}  // namespace

TEST_CASE("CALL family messages are written in full", "[call_message]") {
    const uint256 huge = uint256{1} << 255;
    const uint256 values[] = {0, 1, 0xde0b6b3a7640000, (uint256{1} << 200) + 5, ~uint256{} >> 8};
    const std::pair<uint256, uint256> inputs[] = {{0, 0}, {huge, 0}, {3, 37}, {60, 10}};
    const bytes codes[] = {{STOP}, designation(kDelegate), designation(kTarget), {}};
    const evmc_revision revs[] = {EVMC_ISTANBUL, EVMC_CANCUN, EVMC_PRAGUE, EVMC_OSAKA};
    const uint32_t parent_flags[] = {0, EVMC_DELEGATED};
    int checked = 0;
    for (const uint8_t op : {CALL, CALLCODE, DELEGATECALL, STATICCALL})
        for (const auto rev : revs)
            for (const auto& value : values)
                for (const auto& [in_offset, in_size] : inputs)
                    for (const auto& code : codes)
                        for (const auto flags : parent_flags) {
                            if (op != CALL && op != CALLCODE && value != values[3])
                                continue;  // no value operand: one value, the parent's
                            CallCase c;
                            c.op = op;
                            c.rev = rev;
                            c.value = value;
                            c.parent_value = op == DELEGATECALL ? value : 7;
                            c.in_offset = in_offset;
                            c.in_size = in_size;
                            // With no input, no output either, at an offset never checked.
                            c.out_offset = in_size == 0 ? huge : 0x80;
                            c.out_size = in_size == 0 ? 0 : 5;
                            c.gas = 7000;
                            c.target_code = code;
                            c.parent_flags = flags;
                            INFO(describe(c));
                            const auto a = run_call(c, 0xa5);
                            const auto b = run_call(c, 0x5a);
                            REQUIRE(a.status == EVMC_SUCCESS);
                            REQUIRE(a.message.has_value());
                            CHECK(mismatch(*a.message, expected_message(c)) == "");
                            CHECK(b.status == a.status);
                            CHECK(b.gas_left == a.gas_left);
                            CHECK(b.output == a.output);
                            REQUIRE(b.message.has_value());
                            CHECK(mismatch(*b.message, *a.message) == "");
                            // The pushed status and the copied output.
                            REQUIRE(a.output.size() == 0x220);
                            CHECK(a.output[0x21f] == 1);
                            const auto copied = std::min<size_t>(static_cast<size_t>(c.out_size), 8);
                            CHECK(std::memcmp(&a.output[0x80], "returned", copied) == 0);
                            for (size_t i = 0x80 + copied; i < 0x200; ++i)
                                CHECK(a.output[i] == 0);
                            ++checked;
                        }
    CHECK(checked > 400);
}

TEST_CASE("CALL family gas and failures before the message", "[call_message]") {
    SECTION("an absent target pays for the account it creates") {
        CallCase c;
        c.value = 1;
        c.gas = 7000;
        c.target_exists = false;
        const auto a = run_call(c, 0xa5);
        REQUIRE(a.message.has_value());
        CHECK(mismatch(*a.message, expected_message(c)) == "");
    }
    SECTION("a gas operand above int64 is capped at all but a 64th") {
        CallCase c;
        c.op = STATICCALL;
        c.gas = (uint256{1} << 64) + 7;
        c.target_code = {STOP};
        const auto a = run_call(c, 0xa5);
        REQUIRE(a.message.has_value());
        CHECK(a.message->gas > 900'000);
        CHECK(a.message->gas < 1'000'000);
        CHECK(a.message->kind == EVMC_CALL);
        CHECK(a.message->flags == (EVMC_STATIC | kWordFlags));
        CHECK(a.message->value == evmc::uint256be{});
    }
    SECTION("a value the caller cannot pay sends nothing and pushes 0") {
        CallCase c;
        c.value = 1;
        c.gas = 7000;
        c.target_code = {STOP};
        c.rich = false;
        const auto a = run_call(c, 0xa5);
        CHECK(a.status == EVMC_SUCCESS);
        CHECK_FALSE(a.message.has_value());
        REQUIRE(a.output.size() == 0x220);
        CHECK(a.output[0x21f] == 0);
    }
    SECTION("a value in a static frame fails before anything else") {
        CallCase c;
        c.value = 1;
        c.gas = 7000;
        c.target_code = {STOP};
        c.parent_flags = EVMC_STATIC;
        const auto a = run_call(c, 0xa5);
        CHECK(a.status == EVMC_STATIC_MODE_VIOLATION);
        CHECK_FALSE(a.message.has_value());
    }
    SECTION("no value in a static frame inherits the flag") {
        CallCase c;
        c.gas = 7000;
        c.target_code = {STOP};
        c.parent_flags = EVMC_STATIC | EVMC_DELEGATED;
        const auto a = run_call(c, 0xa5);
        REQUIRE(a.message.has_value());
        CHECK(a.message->flags == (EVMC_STATIC | kWordFlags));
        CHECK(mismatch(*a.message, expected_message(c)) == "");
    }
    SECTION("the child's state gas is taken back from Amsterdam on") {
        CallCase c;
        c.gas = 7000;
        c.target_code = {STOP};
        for (const auto rev : {EVMC_OSAKA, EVMC_AMSTERDAM, EVMC_MAX_REVISION}) {
            c.rev = rev;
            const auto a = run_call(c, 0xa5, 500);
            REQUIRE(a.message.has_value());
            CHECK(a.status == EVMC_SUCCESS);
#if defined(AIRBENDER) || defined(EVMONE_RV32_DISPATCH_TEST)
            // The state Host never gives a frame state gas before Amsterdam, so the call skips it.
            CHECK(a.state_gas_left == (rev >= EVMC_AMSTERDAM ? 500 : 0));
#else
            CHECK(a.state_gas_left == 500);
#endif
        }
    }
    SECTION("an output region past the gas fails with out of gas") {
        CallCase c;
        c.gas = 7000;
        c.target_code = {STOP};
        c.out_size = uint256{1} << 32;
        const auto a = run_call(c, 0xa5);
        CHECK(a.status == EVMC_OUT_OF_GAS);
        CHECK_FALSE(a.message.has_value());
    }
}

namespace {

// Accounts with code, each with its own code hash (the VM caches analyses by it).
class MapView final : public evmone::state::StateView {
public:
    struct Entry {
        Account account;
        bytes code;
    };
    std::map<address, Entry> accounts;

    void add(const address& addr, uint64_t balance, bytes code) {
        bytes32 hash = evmone::state::Account::EMPTY_CODE_HASH;
        if (!code.empty()) {
            hash = bytes32{};
            hash.bytes[0] = 0x77;
            hash.bytes[31] = static_cast<uint8_t>(accounts.size() + 1);
        }
        accounts[addr] = {{.nonce = 1, .balance = balance, .code_hash = hash}, std::move(code)};
    }

    std::optional<Account> get_account(const address& addr) const noexcept override {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return std::nullopt;
        return it->second.account;
    }
    evmc::bytes_view get_account_code(const address& addr) const noexcept override {
        const auto it = accounts.find(addr);
        if (it == accounts.end())
            return {};
        return {it->second.code.data(), it->second.code.size()};
    }
    bytes32 get_storage(const address&, const bytes32&) const noexcept override { return {}; }
};

class NoBlockHashes final : public evmone::state::BlockHashes {
public:
    bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// Code that returns the one byte b.
bytes returns_byte(uint8_t b) {
    return {PUSH1, b, PUSH1, 0, MSTORE8, PUSH1, 1, PUSH1, 0, RETURN};
}

constexpr address kSender = 0x5555555555555555555555555555555555555501_address;
constexpr address kRecipient = 0x7777777777777777777777777777777777777701_address;
constexpr address kPlaceholder = 0x7777777777777777777777777777777777777702_address;
constexpr address kOther = 0x7777777777777777777777777777777777777703_address;
constexpr address kNoCode = 0x7777777777777777777777777777777777777704_address;
constexpr address kIdentity = 0x0000000000000000000000000000000000000004_address;
// A vanity address with 18 leading zero bytes that is not a precompile.
constexpr address kVanity = 0x0000000000000000000000000000000000000200_address;

struct HostFixture {
    MapView view;
    evmone::state::State state{view};
    evmc::VM vm{evmc_create_evmone()};
    evmone::state::BlockInfo block;
    NoBlockHashes block_hashes;
    evmone::state::Transaction tx;
    evmone::state::Host host{EVMC_OSAKA, vm, state, block, block_hashes, tx};

    HostFixture() {
        view.add(kSender, 1000, {});
        view.add(kRecipient, 50, returns_byte(0xaa));
        view.add(kPlaceholder, 0, returns_byte(0xbb));
        view.add(kOther, 0, returns_byte(0xcc));
        view.add(kDelegate, 0, returns_byte(0xdd));
        view.add(kNoCode, 0, {});
        view.add(kVanity, 0, returns_byte(0xee));
        // Warmed by an access list: in the State as a placeholder, not yet loaded.
        state.get_or_insert_for_access(kPlaceholder);
    }

    evmc::Result call(evmc_call_kind kind, const address& recipient, const address& code_address,
                      uint64_t value = 0, uint32_t flags = 0) {
        evmc_message msg{};
        msg.kind = kind;
        msg.flags = flags;
        msg.depth = 1;
        msg.gas = 100'000;
        msg.recipient = recipient;
        msg.sender = kSender;
        msg.code_address = code_address;
        msg.value = intx::be::store<evmc::uint256be>(uint256{value});
        static constexpr uint8_t input[] = {'x', 'y', 'z'};
        msg.input_data = input;
        msg.input_size = sizeof(input);
        return host.call(msg);
    }
};

bytes output_of(const evmc::Result& r) {
    return bytes(r.output_data, r.output_data + r.output_size);
}

const bytes kXyz{'x', 'y', 'z'};

}  // namespace

TEST_CASE("a call runs its recipient's code from the recipient's account", "[call_message]") {
    HostFixture f;
    SECTION("an existing recipient, without and with value") {
        auto r = f.call(EVMC_CALL, kRecipient, kRecipient);
        CHECK(r.status_code == EVMC_SUCCESS);
        CHECK(output_of(r) == bytes{0xaa});
        r = f.call(EVMC_CALL, kRecipient, kRecipient, 5);
        CHECK(r.status_code == EVMC_SUCCESS);
        CHECK(output_of(r) == bytes{0xaa});
        CHECK(f.state.get(kRecipient).balance == 55);
        CHECK(f.state.get(kSender).balance == 995);
    }
    SECTION("an absent recipient, without and with value") {
        auto r = f.call(EVMC_CALL, kAbsent, kAbsent);
        CHECK(r.status_code == EVMC_SUCCESS);
        CHECK(r.output_size == 0);
        CHECK(r.gas_left == 100'000);
        REQUIRE(f.state.find(kAbsent) != nullptr);
        CHECK(f.state.find(kAbsent)->erase_if_empty);
        const auto other = 0xabababababababababababababababababab0002_address;
        r = f.call(EVMC_CALL, other, other, 9);
        CHECK(r.status_code == EVMC_SUCCESS);
        CHECK(r.output_size == 0);
        REQUIRE(f.state.find(other) != nullptr);
        CHECK(f.state.find(other)->balance == 9);
    }
    SECTION("a recipient that was only a placeholder is loaded, and its code runs") {
        auto r = f.call(EVMC_CALL, kPlaceholder, kPlaceholder);
        CHECK(output_of(r) == bytes{0xbb});
        r = f.call(EVMC_CALL, kPlaceholder, kPlaceholder, 3);
        CHECK(output_of(r) == bytes{0xbb});
        CHECK(f.state.get(kPlaceholder).balance == 3);
    }
    SECTION("a code address apart from the recipient runs its own code") {
        CHECK(output_of(f.call(EVMC_CALL, kRecipient, kOther)) == bytes{0xcc});
        CHECK(output_of(f.call(EVMC_CALL, kRecipient, kOther, 4)) == bytes{0xcc});
        CHECK(output_of(f.call(EVMC_CALL, kNoCode, kOther)) == bytes{0xcc});
        CHECK(output_of(f.call(EVMC_CALL, kAbsent, kOther)) == bytes{0xcc});
        CHECK(f.call(EVMC_CALL, kRecipient, kNoCode).output_size == 0);
        CHECK(f.call(EVMC_CALL, kRecipient, kAbsent).output_size == 0);
        CHECK(output_of(f.call(EVMC_CALL, kRecipient, kDelegate, 0, EVMC_DELEGATED)) ==
              bytes{0xdd});
        CHECK(output_of(f.call(EVMC_CALLCODE, kSender, kOther)) == bytes{0xcc});
        CHECK(output_of(f.call(EVMC_DELEGATECALL, kRecipient, kOther)) == bytes{0xcc});
        CHECK(output_of(f.call(EVMC_DELEGATECALL, kRecipient, kRecipient)) == bytes{0xaa});
    }
    SECTION("precompiles, not through a delegation") {
        CHECK(output_of(f.call(EVMC_CALL, kIdentity, kIdentity)) == kXyz);
        CHECK(output_of(f.call(EVMC_CALL, kIdentity, kIdentity, 2)) == kXyz);
        CHECK(output_of(f.call(EVMC_CALL, kRecipient, kIdentity)) == kXyz);
        CHECK(f.call(EVMC_CALL, kRecipient, kIdentity, 0, EVMC_DELEGATED).output_size == 0);
        CHECK(output_of(f.call(EVMC_CALL, kVanity, kVanity)) == bytes{0xee});
    }
}

namespace {

// The rule is_precompile() had: the address as a number below the lookup table's size, then the
// revision the table gives that number.
std::optional<evmc_revision> precompile_since(unsigned n) {
    if (n >= 1 && n <= 4)
        return EVMC_FRONTIER;
    if (n >= 5 && n <= 8)
        return EVMC_BYZANTIUM;
    if (n == 9)
        return EVMC_ISTANBUL;
    if (n == 0x0a)
        return EVMC_CANCUN;
    if (n >= 0x0b && n <= 0x11)
        return EVMC_PRAGUE;
    if (n == 0x100)
        return EVMC_OSAKA;
    return std::nullopt;
}

bool reference_is_precompile(evmc_revision rev, const address& addr) {
    if (addr >= address{0x101})
        return false;
    const auto since = precompile_since((unsigned{addr.bytes[18]} << 8) | addr.bytes[19]);
    return since && *since <= rev;
}

}  // namespace

TEST_CASE("is_precompile tests the address from its first byte on", "[call_message]") {
    CHECK_FALSE(evmone::state::is_precompile(EVMC_PRAGUE, 0x0100_address));
    CHECK(evmone::state::is_precompile(EVMC_OSAKA, 0x0100_address));
    CHECK_FALSE(evmone::state::is_precompile(EVMC_EXPERIMENTAL, 0x0101_address));
    CHECK_FALSE(evmone::state::is_precompile(EVMC_EXPERIMENTAL, 0x0200_address));
    CHECK_FALSE(evmone::state::is_precompile(EVMC_EXPERIMENTAL, 0x00_address));
    CHECK(evmone::state::is_precompile(EVMC_FRONTIER, 0x01_address));
    CHECK_FALSE(evmone::state::is_precompile(EVMC_CANCUN, 0x0b_address));
    CHECK(evmone::state::is_precompile(EVMC_PRAGUE, 0x11_address));
    CHECK_FALSE(evmone::state::is_precompile(EVMC_EXPERIMENTAL, 0x12_address));

    uint64_t cases = 0;
    uint64_t mismatches = 0;
    std::string first;
    const auto check = [&](const address& a) {
        for (int r = EVMC_FRONTIER; r <= EVMC_MAX_REVISION; ++r) {
            const auto rev = static_cast<evmc_revision>(r);
            if (evmone::state::is_precompile(rev, a) != reference_is_precompile(rev, a) &&
                mismatches++ == 0)
                first = evmc::hex({a.bytes, sizeof(a.bytes)}) + " rev " + std::to_string(r);
            ++cases;
        }
    };
    address a;
    for (unsigned b18 = 0; b18 < 256; ++b18)
        for (unsigned b19 = 0; b19 < 256; ++b19) {
            a = {};
            a.bytes[18] = static_cast<uint8_t>(b18);
            a.bytes[19] = static_cast<uint8_t>(b19);
            check(a);
        }
    for (size_t pos = 0; pos < sizeof(a.bytes); ++pos)
        for (unsigned v = 1; v < 256; ++v)
            for (const uint8_t low : {0x00, 0x01, 0x11}) {
                a = {};
                a.bytes[pos] = static_cast<uint8_t>(v);
                a.bytes[19] |= low;
                check(a);
            }
    std::mt19937_64 rng{11};
    for (int k = 0; k < 100'000; ++k) {
        for (auto& b : a.bytes)
            b = static_cast<uint8_t>(rng());
        const auto zeros = rng() % 21;
        for (size_t i = 0; i < zeros; ++i)
            a.bytes[i] = 0;
        check(a);
    }
    INFO(first);
    CHECK(mismatches == 0);
    CHECK(cases > 2'800'000);
}
