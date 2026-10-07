// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// EVM memory, calldata and return data against a byte-order model, through the state Host. The
// native build sets -DEVMONE_RV32_DISPATCH_TEST, which keeps them in the big-endian word layout
// (evmone/word_layout.hpp), where the bytes of every copy that crosses a byte-order boundary or
// ends inside a word are at risk: calldata at an offset that is not a multiple of 4, a callee that
// returns or reads a few bytes, memory that is not zero around a partial copy, init code and
// deployed code at odd offsets. No fixture covers these residues, and the model does not depend on
// the layout, so the same test holds on a build without it.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/precompiles.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>
#include <evmone/word_layout.hpp>
#include <evmone_precompiles/keccak.hpp>

namespace {

using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using namespace evmc::literals;

constexpr address kCaller = 0xaa00000000000000000000000000000000000001_address;
constexpr address kEcho = 0xbb00000000000000000000000000000000000002_address;
constexpr address kSender = 0x5e00000000000000000000000000000000000004_address;
constexpr address kIdentity = 0x0000000000000000000000000000000000000004_address;

enum : uint8_t {
    STOP = 0x00, ADD = 0x01, SUB = 0x03, KECCAK = 0x20, CALLDATALOAD = 0x35, CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37, CODECOPY = 0x39, EXTCODESIZE = 0x3b, RETURNDATASIZE = 0x3d,
    RETURNDATACOPY = 0x3e, POP = 0x50, MLOAD = 0x51, MSTORE = 0x52, MSTORE8 = 0x53, MCOPY = 0x5e,
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH4 = 0x63, PUSH20 = 0x73, PUSH32 = 0x7f, DUP1 = 0x80,
    LOG0 = 0xa0, CREATE = 0xf0, CALL = 0xf1, RETURN = 0xf3, REVERT = 0xfd
};

struct Asm {
    bytes code;
    Asm& op(uint8_t o) { code.push_back(o); return *this; }
    Asm& push(uint64_t v) {
        code.push_back(PUSH2);
        code.push_back(static_cast<uint8_t>(v >> 8));
        code.push_back(static_cast<uint8_t>(v));
        return *this;
    }
    Asm& push4(uint32_t v) {
        code.push_back(PUSH4);
        for (int shift = 24; shift >= 0; shift -= 8)
            code.push_back(static_cast<uint8_t>(v >> shift));
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
    Asm& mstore8(uint64_t offset, uint8_t v) { return push(v).push(offset).op(MSTORE8); }
    Asm& ret(uint64_t offset, uint64_t size) { return push(size).push(offset).op(RETURN); }
    Asm& revert(uint64_t offset, uint64_t size) { return push(size).push(offset).op(REVERT); }
    Asm& copy(uint8_t kind, uint64_t dst, uint64_t src, uint64_t size) {
        return push(size).push(src).push(dst).op(kind);
    }
    Asm& call(const address& to, uint64_t in, uint64_t in_size, uint64_t out, uint64_t out_size) {
        push(out_size).push(out).push(in_size).push(in).push(0);
        return push_addr(to).push(100000).op(CALL);
    }
};

bytes32 filled(uint8_t b) {
    bytes32 w;
    std::memset(w.bytes, b, 32);
    return w;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    bytes output;
    std::vector<bytes> logs;
    int64_t gas_used = 0;
#ifdef EVMONE_RV32_DISPATCH_TEST
    uint64_t converted = 0;  // Bytes converted from the word layout into byte order.
#endif
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

// The callee at kEcho: returns its calldata.
bytes echo_code() {
    return Asm{}.op(CALLDATASIZE).push(0).push(0).op(CALLDATACOPY)
        .op(CALLDATASIZE).push(0).op(RETURN).code;
}

Outcome run(const bytes& code, const bytes& calldata, const bytes& echo = echo_code(),
           evmc_revision rev = EVMC_PRAGUE) {
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
    add(kEcho, echo);
    evmone::state::Account sender;
    sender.balance = 1000000;
    state.insert(kSender, std::move(sender));

    evmc::VM vm{new evmone::VM{}};
    evmone::state::BlockInfo block;
    block.gas_limit = 30000000;
    block.number = 1;
    block.timestamp = 1;
    evmone::state::Transaction tx;
    evmone::state::Host host{rev, vm, state, block, hashes, tx};

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 10000000;
    msg.recipient = kCaller;
    msg.code_address = kCaller;
    msg.sender = kSender;
    msg.input_data = calldata.data();
    msg.input_size = calldata.size();
#ifdef EVMONE_RV32_DISPATCH_TEST
    const auto converted_before = evmone::wl::usage.converted;
#endif
    const auto result = host.call(msg);

    Outcome o;
    o.status = result.status_code;
    o.output.assign(result.output_data, result.output_size);
    for (auto& l : host.take_logs())
        o.logs.push_back(l.data);
    o.gas_used = msg.gas - result.gas_left;
#ifdef EVMONE_RV32_DISPATCH_TEST
    o.converted = evmone::wl::usage.converted - converted_before;
#endif
    return o;
}

// The memory as the program sees it, as bytes.
struct Model {
    std::vector<uint8_t> mem = std::vector<uint8_t>(2048, 0);
    bytes return_data;

    void store(uint64_t offset, const bytes32& w) { std::memcpy(&mem[offset], w.bytes, 32); }
    void copy_from(uint64_t dst, const bytes& src_bytes, uint64_t src, uint64_t size) {
        for (uint64_t i = 0; i < size; ++i)
            mem[dst + i] = src + i < src_bytes.size() ? src_bytes[src + i] : 0;
    }
};

struct Rng {
    uint64_t s;
    uint64_t next() {
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        return s >> 33;
    }
    uint64_t below(uint64_t n) { return next() % n; }
};

}  // namespace

TEST_CASE("CALLDATACOPY pads with zeros in the bytes after the calldata", "[word_layout]") {
    const bytes calldata{1, 2, 3, 4, 5};
    for (uint64_t dst = 0; dst < 4; ++dst) {
        const auto out = run(Asm{}.mstore(0, filled(0xff)).copy(CALLDATACOPY, dst, 0, 8).ret(0, 32).code,
            calldata);
        REQUIRE(out.status == EVMC_SUCCESS);
        bytes expected(32, 0xff);
        for (uint64_t i = 0; i < 8; ++i)
            expected[dst + i] = i < 5 ? calldata[i] : 0;
        CHECK(out.output == expected);
    }
}

TEST_CASE("a callee's calldata ends at the size of the arguments", "[word_layout]") {
    // The caller's memory holds 0x11 bytes around the 5 argument bytes; the callee loads its
    // calldata as a word and must see zeros after the fifth byte.
    const bytes loader = Asm{}.push(0).op(CALLDATALOAD).push(0).op(MSTORE).ret(0, 32).code;
    for (uint64_t in = 0; in < 8; ++in) {
        const auto out = run(Asm{}.mstore(0, filled(0x11)).mstore(32, filled(0x11))
                                 .call(kEcho, in, 5, 64, 32).ret(64, 32).code,
            {}, loader);
        REQUIRE(out.status == EVMC_SUCCESS);
        bytes expected(32, 0);
        std::fill_n(expected.begin(), 5, uint8_t{0x11});
        CHECK(out.output == expected);
    }
}

TEST_CASE("a CALL writes only the bytes of the output range", "[word_layout]") {
    // The callee returns 3 bytes; with the memory full of 0xff the byte after them stays.
    const bytes three = Asm{}.mstore(0, filled(0xab)).ret(0, 3).code;
    for (uint64_t out_offset = 0; out_offset < 8; ++out_offset) {
        const auto out = run(Asm{}.mstore(0, filled(0xff)).mstore(32, filled(0xff))
                                 .call(kEcho, 0, 0, out_offset, 32).ret(0, 64).code,
            {}, three);
        REQUIRE(out.status == EVMC_SUCCESS);
        bytes expected(64, 0xff);
        std::fill_n(expected.begin() + static_cast<std::ptrdiff_t>(out_offset), 3, uint8_t{0xab});
        CHECK(out.output == expected);
    }
}

TEST_CASE("RETURNDATACOPY past the return data fails", "[word_layout]") {
    const bytes thirty_three = Asm{}.ret(0, 33).code;
    auto out = run(Asm{}.call(kEcho, 0, 0, 0, 0).copy(RETURNDATACOPY, 0, 1, 33).ret(0, 32).code, {},
        thirty_three);
    CHECK(out.status == EVMC_INVALID_MEMORY_ACCESS);
    out = run(Asm{}.call(kEcho, 0, 0, 0, 0).copy(RETURNDATACOPY, 1, 1, 32).ret(0, 40).code, {},
        thirty_three);
    CHECK(out.status == EVMC_SUCCESS);
}

TEST_CASE("deployed code starting with 0xEF is rejected at its first byte only", "[word_layout]") {
    // The init code returns 8 bytes of memory with a 0xEF in the byte under test, from an offset
    // of every residue modulo 4: the first logical byte of the code and the fourth are physical
    // bytes 0 and 3 of a word in the layout, and EIP-3541 looks at the first only.
    for (uint64_t ef_at = 0; ef_at < 8; ++ef_at) {
        for (uint64_t offset = 0; offset < 4; ++offset) {
            Asm init;
            init.mstore(0, filled(0x00)).mstore8(offset + ef_at, 0xef).ret(offset, 8);
            // The init code follows the program and is created from memory at an odd offset.
            const uint64_t at = 37;
            const auto program = [&](uint64_t init_at) {
                Asm p;
                p.push(init.code.size()).push(init_at).push(at).op(CODECOPY);
                p.push(init.code.size()).push(at).push(0).op(CREATE);
                p.op(DUP1).op(EXTCODESIZE).push(0).op(MSTORE).ret(0, 32);
                return p;
            };
            auto full = program(0);
            full = program(full.code.size());
            full.code.insert(full.code.end(), init.code.begin(), init.code.end());
            const auto out = run(full.code, {});
            REQUIRE(out.status == EVMC_SUCCESS);
            REQUIRE(out.output.size() == 32);
            CHECK(out.output[31] == (ef_at == 0 ? 0 : 8));
        }
    }
}

TEST_CASE("a CREATE inside init code keeps both init codes", "[word_layout]") {
    // The init code of the outer CREATE creates another contract from its own memory, and deploys
    // the size of that contract's code as the code of the outer one. Both init codes sit at odd
    // offsets in the memory of their frames.
    Asm inner;
    inner.mstore(0, filled(0x42)).ret(3, 8);
    const auto create_from_code = [](Asm& a, uint64_t code_at, size_t code_size, uint64_t at) {
        // code_at: the offset of the init code to create, patched by the caller through `at`.
        a.push(code_size).push(code_at).push(at).op(CODECOPY);
        a.push(code_size).push(at).push(0).op(CREATE);
    };
    const auto build = [&](uint64_t inner_at) {
        Asm middle;
        create_from_code(middle, inner_at, inner.code.size(), 37);
        middle.op(EXTCODESIZE).push(0).op(MSTORE).ret(0, 32);
        return middle;
    };
    auto middle = build(0);
    middle = build(middle.code.size());
    middle.code.insert(middle.code.end(), inner.code.begin(), inner.code.end());

    const auto program = [&](uint64_t middle_at) {
        Asm outer;
        create_from_code(outer, middle_at, middle.code.size(), 21);
        outer.push(32).push(0).push(0).op(DUP1 + 3).op(0x3c).ret(0, 32);  // EXTCODECOPY(created, 0, 0, 32)
        return outer;
    };
    auto outer = program(0);
    outer = program(outer.code.size());
    outer.code.insert(outer.code.end(), middle.code.begin(), middle.code.end());
    const auto out = run(outer.code, {});
    REQUIRE(out.status == EVMC_SUCCESS);
    REQUIRE(out.output.size() == 32);
    CHECK(out.output[31] == 8);
}

TEST_CASE("memory operations equal a byte-order model", "[word_layout]") {
    Rng rng{0x2545F4914F6CDD1Dull};
    for (int program = 0; program < 400; ++program) {
        Asm a;
        Model m;
        const bytes calldata = [&] {
            bytes c(rng.below(100), 0);
            for (auto& b : c)
                b = static_cast<uint8_t>(rng.next());
            return c;
        }();
        const auto offset = [&] { return rng.below(4) == 0 ? rng.below(200) : 32 * rng.below(6) + rng.below(4); };
        const auto size = [&] { return rng.below(3) == 0 ? rng.below(12) : rng.below(70); };
        // The code is also CODECOPY's source, so the model replays the steps once it is complete.
        enum Kind { MSTORE_K, MSTORE8_K, MCOPY_K, CALLDATACOPY_K, CODECOPY_K, CALLECHO_K };
        struct Step { Kind kind; uint64_t a, b, c; bytes32 w; };
        std::vector<Step> steps;
        for (unsigned i = 0, n = 6 + static_cast<unsigned>(rng.below(10)); i < n; ++i) {
            Step s{static_cast<Kind>(rng.below(6)), offset(), offset(), size(), {}};
            for (auto& b : s.w.bytes)
                b = static_cast<uint8_t>(rng.next());
            switch (s.kind) {
            case MSTORE_K: a.mstore(s.a, s.w); break;
            case MSTORE8_K: a.mstore8(s.a, s.w.bytes[0]); break;
            case MCOPY_K: a.copy(MCOPY, s.a, s.b, s.c); break;
            case CALLDATACOPY_K: a.copy(CALLDATACOPY, s.a, s.b % 120, s.c); break;
            case CODECOPY_K: a.copy(CODECOPY, s.a, s.b, s.c); break;
            case CALLECHO_K:
                // Identity precompile: arguments s.b..s.b+s.c, output s.a with a size of its own.
                a.call(kIdentity, s.b, s.c, s.a, s.w.bytes[1] % 40);
                a.op(0x50);  // POP the success flag
                break;
            }
            steps.push_back(s);
        }
        a.ret(0, 256);
        // Replay on the model, now that the code is known.
        for (const auto& s : steps) {
            switch (s.kind) {
            case MSTORE_K: m.store(s.a, s.w); break;
            case MSTORE8_K: m.mem[s.a] = s.w.bytes[0]; break;
            case MCOPY_K: std::memmove(&m.mem[s.a], &m.mem[s.b], s.c); break;
            case CALLDATACOPY_K: m.copy_from(s.a, calldata, s.b % 120, s.c); break;
            case CODECOPY_K: m.copy_from(s.a, a.code, s.b, s.c); break;
            case CALLECHO_K: {
                const uint64_t out_size = s.w.bytes[1] % 40;
                const bytes input(m.mem.begin() + static_cast<std::ptrdiff_t>(s.b),
                    m.mem.begin() + static_cast<std::ptrdiff_t>(s.b + s.c));
                for (uint64_t i = 0; i < std::min<uint64_t>(out_size, input.size()); ++i)
                    m.mem[s.a + i] = input[i];
                break;
            }
            }
        }
        const auto out = run(a.code, calldata);
        REQUIRE(out.status == EVMC_SUCCESS);
        REQUIRE(out.output.size() == 256);
        // Memory beyond what the program touched reads as zero, in the model as in the EVM.
        CHECK(std::equal(out.output.begin(), out.output.end(), m.mem.begin()));
    }
}

#ifdef EVMONE_RV32_DISPATCH_TEST
namespace {

// Bytes that are not all zero, so that a precompile reading the wrong ones gives another result.
bytes pattern(size_t n, uint8_t seed) {
    bytes b(n, 0);
    for (size_t i = 0; i < n; ++i)
        b[i] = static_cast<uint8_t>(seed + 7 * i);
    return b;
}

// A MODEXP input: the lengths of base, exponent and modulus, then @p payload bytes.
bytes modexp_input(uint32_t base_len, uint32_t exp_len, uint32_t mod_len, size_t payload) {
    bytes in(96, 0);
    const uint32_t lens[] = {base_len, exp_len, mod_len};
    for (size_t k = 0; k < 3; ++k)
        for (size_t j = 0; j < 4; ++j)
            in[32 * k + 28 + j] = static_cast<uint8_t>(lens[k] >> (24 - 8 * j));
    const auto p = pattern(payload, 0x31);
    in.insert(in.end(), p.begin(), p.end());
    return in;
}

struct PrecompileCall {
    evmc_revision rev;
    uint16_t id;
    bytes setup;  // The first bytes of the input; zeros follow.
    uint64_t in_offset;
    uint64_t size;
    uint32_t gas;
};

address precompile_address(uint16_t id) {
    address a{};
    a.bytes[18] = static_cast<uint8_t>(id >> 8);
    a.bytes[19] = static_cast<uint8_t>(id);
    return a;
}

// Pays for 64 KiB of memory, copies the setup bytes from the code to the input and, with @p call,
// calls the precompile on the input. With @p results it returns the success flag as a word and the
// return data after it; without, it stops.
bytes precompile_program(const PrecompileCall& c, bool call, bool results) {
    const auto build = [&](uint64_t setup_at) {
        Asm a;
        a.mstore8(65535, 0);
        if (!c.setup.empty())
            a.copy(CODECOPY, c.in_offset, setup_at, c.setup.size());
        if (call) {
            a.push(0).push(0).push(c.size).push(c.in_offset).push(0);
            a.push_addr(precompile_address(c.id)).push4(c.gas).op(CALL);
            if (results)
                a.push(0).op(MSTORE).op(RETURNDATASIZE).push(0).push(32).op(RETURNDATACOPY)
                    .op(RETURNDATASIZE).push(32).op(ADD).push(0).op(RETURN);
            else
                a.op(POP);
        }
        return a.op(STOP);
    };
    auto a = build(0);
    a = build(a.code.size());
    a.code.insert(a.code.end(), c.setup.begin(), c.setup.end());
    return a.code;
}

}  // namespace

TEST_CASE("a precompile converts no more of its input than its gas pays for", "[word_layout]") {
    // A precompile called from the EVM gets its input converted from the caller's memory into byte
    // order. The memory is paid for once, and most precompiles cost the same for any input size:
    // converting bytes that they never read made each call as expensive as its input is long. The
    // bound is 11 bytes per gas unit of the call, above identity's 32 bytes per 3 gas. Each call
    // must also give the precompile's own status, gas and output on the bytes of its input.
    struct Kind {
        uint16_t id;
        uint64_t size;  // The input size the precompile is built around.
    };
    const Kind kinds[] = {{0x01, 128}, {0x02, 64}, {0x03, 64}, {0x04, 32}, {0x05, 96}, {0x06, 128},
        {0x07, 96}, {0x08, 192}, {0x09, 213}, {0x0a, 192}, {0x0b, 256}, {0x0c, 160}, {0x0d, 512},
        {0x0e, 288}, {0x0f, 384}, {0x10, 64}, {0x11, 128}, {0x100, 160}};
    std::vector<PrecompileCall> calls;
    for (const auto rev : {EVMC_PRAGUE, EVMC_OSAKA}) {
        for (const auto& k : kinds) {
            if (!evmone::state::is_precompile(rev, precompile_address(k.id)))
                continue;
            std::vector<bytes> setups{{}, pattern(k.size + 1, 0x5a)};
            if (k.id == 0x05) {
                // Short lengths, a long exponent with no modulus (the minimum price before Osaka),
                // and lengths that cost more than the call has.
                setups.push_back(modexp_input(1, 1, 1, 3));
                setups.push_back(modexp_input(0, 50000, 0, 64));
                setups.push_back(modexp_input(40, 40, 40, 120));
                setups.push_back(modexp_input(2, 300, 3, 305));
                setups.push_back(modexp_input(1024, 1, 1024, 64));
            }
            if (k.id == 0x09) {
                auto in = pattern(213, 0x11);
                in[0] = in[1] = in[2] = 0;
                in[3] = 12;  // Rounds.
                in[212] = 1;
                setups.push_back(in);
            }
            for (const auto& setup : setups) {
                std::vector<uint64_t> sizes{0, 1, k.size - 1, k.size, k.size + 1, 1000, 60000};
                if (!setup.empty()) {
                    sizes.push_back(setup.size() - 1);
                    sizes.push_back(setup.size());
                }
                for (const auto size : sizes)
                    for (const uint64_t in_offset : {uint64_t{0}, uint64_t{3}})
                        for (const uint32_t gas : {0u, 1000000u})
                            calls.push_back({rev, k.id, setup, in_offset, size, gas});
            }
        }
    }

    for (const auto& c : calls) {
        INFO("rev " << c.rev << " precompile " << c.id << " setup " << c.setup.size() << " size "
                    << c.size << " offset " << c.in_offset << " gas " << c.gas);
        const auto with = run(precompile_program(c, true, false), {}, echo_code(), c.rev);
        const auto without = run(precompile_program(c, false, false), {}, echo_code(), c.rev);
        const auto results = run(precompile_program(c, true, true), {}, echo_code(), c.rev);
        REQUIRE(with.status == EVMC_SUCCESS);
        REQUIRE(without.status == EVMC_SUCCESS);
        REQUIRE(results.status == EVMC_SUCCESS);

        bytes input(c.size, 0);
        std::copy_n(c.setup.begin(), std::min<size_t>(c.setup.size(), input.size()), input.begin());
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = c.gas;
        msg.depth = 1;
        msg.recipient = msg.code_address = precompile_address(c.id);
        msg.sender = kCaller;
        msg.input_data = input.data();
        msg.input_size = input.size();
        const auto expected = evmone::state::call_precompile(c.rev, msg);

        // CALL (warm) 100, seven pushes 21, POP 2, and what the precompile used.
        const auto call_gas = with.gas_used - without.gas_used;
        CHECK(call_gas == 123 + c.gas - expected.gas_left);
        bytes expected_output(32, 0);
        expected_output[31] = expected.status_code == EVMC_SUCCESS ? 1 : 0;
        if (expected.output_size != 0)
            expected_output.append(expected.output_data, expected.output_size);
        CHECK(results.output == expected_output);
        CHECK(with.converted <= 11 * static_cast<uint64_t>(call_gas));
    }
}

TEST_CASE("the precompile input buffer keeps its contents when it grows", "[word_layout]") {
    // MODEXP converts the first bytes of its input before the gas check and the rest after it, into
    // a buffer that may grow in between. The size is above any other use in the tests.
    auto* const small = evmone::wl::scratch<4>(16);
    for (uint8_t i = 0; i < 16; ++i)
        small[i] = static_cast<uint8_t>(i + 1);
    const auto* const grown = evmone::wl::scratch<4>(size_t{16} << 20);
    for (uint8_t i = 0; i < 16; ++i)
        CHECK(grown[i] == i + 1);
}
#endif
