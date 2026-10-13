// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs PUSH1 k SIGNEXTEND as one step (the immediate byte straight from the
// code), and SIGNEXTEND on the stack extends on 32-bit words. Both must give the result of the
// Yellow Paper definition and of the 64-bit word code they replace, which is copied here as
// base_signextend(). Each value test runs a program that leaves the extended word and a sentinel
// that sat under it, so a store past the word shows. Operands are crafted (zero, all ones, every
// single bit and its complement, 0x00, 0x7f, 0x80 and 0xff at every byte over three backgrounds)
// and random; the byte index is every value 0..40 and 63, 64, 127, 128, 254, 255 (fused), and
// for the stack form also indices with a high word set, whose low word is below 31 or not. The
// status and gas left of the fused form are compared with PUSH2 0 k SIGNEXTEND, which the
// dispatch does not fuse, and with the dispatch that has no fusion (cgoto off), at every gas limit
// from below the group to past it, with an empty stack, one item, a stack that the PUSH1 fills to
// 1024 and one that it overflows, and with the group cut by the code end. Built with
// -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build compiles the fused
// handler and the word code on the host; without it the checks against the definition still run
// against the 64-bit code.

#include <cstdint>
#include <initializer_list>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <intx/intx.hpp>

namespace {

using intx::uint256;
using bytes = std::vector<uint8_t>;

enum : uint8_t {
    STOP = 0x00, SIGNEXTEND = 0x0b, POP = 0x50, MSTORE = 0x52, JUMPDEST = 0x5b, PUSH1 = 0x60,
    PUSH2 = 0x61, PUSH32 = 0x7f, RETURN = 0xf3
};

// The Yellow Paper definition: bit 8e + 7 of x extended over the bits above it.
uint256 reference(const uint256& x, const uint256& ext) {
    if (ext >= 31)
        return x;
    const auto sign_bit = ext[0] * 8 + 7;
    const auto sign_mask = uint256{1} << sign_bit;
    const auto value_mask = sign_mask - 1;
    return (x & sign_mask) != 0 ? x | ~value_mask : x & value_mask;
}

// The 64-bit word code that the 32-bit word code replaced (evmone's instr::core::signextend).
uint256 base_signextend(uint256 x, const uint256& ext) {
    if (ext < 31) {
        const auto e = ext[0];
        const auto sign_word_index = static_cast<size_t>(e / sizeof(e));
        const auto sign_byte_index = e % sizeof(e);
        auto& sign_word = x[sign_word_index];
        const auto sign_byte_offset = sign_byte_index * 8;
        const auto sign_byte = sign_word >> sign_byte_offset;
        const auto sext_byte = static_cast<uint64_t>(int64_t{static_cast<int8_t>(sign_byte)});
        const auto sext = sext_byte << sign_byte_offset;
        const auto sign_mask = ~uint64_t{0} << sign_byte_offset;
        const auto value = sign_word & ~sign_mask;
        sign_word = sext | value;
        const auto sign_ex = static_cast<uint64_t>(static_cast<int64_t>(sext_byte) >> 8);
        for (size_t i = 3; i > sign_word_index; --i)
            x[i] = sign_ex;
    }
    return x;
}

bytes be32(const uint256& v) {
    bytes out(32);
    for (unsigned i = 0; i < 32; ++i)
        out[31 - i] = static_cast<uint8_t>(v[i / 8] >> (8 * (i % 8)));
    return out;
}

void push32(bytes& code, const uint256& v) {
    code.push_back(PUSH32);
    const auto w = be32(v);
    code.insert(code.end(), w.begin(), w.end());
}

// The sentinel under x: every byte differs, so a word written from the wrong place shows.
const uint256 kSentinel =
    (uint256{0x0102030405060708} << 192) | (uint256{0x1112131415161718} << 128) |
    (uint256{0x2122232425262728} << 64) | uint256{0x3132333435363738};

enum class Form { push1, push2, push32, jumpdest };

// PUSH32 sentinel, PUSH32 x, the byte index ext in the given form, SIGNEXTEND, then the extended
// word at memory 0 and the sentinel at 32 returned.
bytes value_program(const uint256& x, const uint256& ext, Form form) {
    bytes code;
    push32(code, kSentinel);
    push32(code, x);
    const auto k = static_cast<uint8_t>(ext[0]);
    switch (form) {
    case Form::push1: code.insert(code.end(), {PUSH1, k}); break;
    case Form::push2: code.insert(code.end(), {PUSH2, 0, k}); break;
    case Form::push32: push32(code, ext); break;
    case Form::jumpdest: code.insert(code.end(), {PUSH1, k, JUMPDEST}); break;
    }
    code.push_back(SIGNEXTEND);
    code.insert(code.end(),
        {PUSH1, 0, MSTORE, PUSH1, 32, MSTORE, PUSH1, 64, PUSH1, 0, RETURN});
    return code;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
    bool operator==(const Outcome&) const = default;
};

struct Runner {
    evmc::VM vm{evmc_create_evmone()};
    evmc::MockedHost host;

    explicit Runner(bool cgoto) {
        if (!cgoto)
            REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    }

    Outcome run(const bytes& code, int64_t gas, evmc_revision rev = EVMC_CANCUN) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        const auto r = vm.execute(host, rev, msg, code.data(), code.size());
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

// The operands: crafted and random.
std::vector<uint256> operands() {
    std::vector<uint256> v = {0, ~uint256{0}, 1, 0x80, 0x7f, 0xff, uint256{1} << 255};
    for (unsigned b = 0; b < 256; ++b) {
        v.push_back(uint256{1} << b);
        v.push_back(~(uint256{1} << b));
    }
    std::mt19937_64 rng{11};
    const uint256 backgrounds[] = {0, ~uint256{0}, uint256{rng(), rng(), rng(), rng()}};
    for (const auto& bg : backgrounds) {
        for (unsigned p = 0; p < 32; ++p) {
            for (const uint64_t byte : std::initializer_list<uint64_t>{0x00, 0x7f, 0x80, 0xff}) {
                const auto mask = uint256{0xff} << (8 * p);
                v.push_back((bg & ~mask) | (uint256{byte} << (8 * p)));
            }
        }
    }
    for (int i = 0; i < 700; ++i) {
        uint256 x{rng(), rng(), rng(), rng()};
        // Some with whole words zeroed or set, to put the sign bit at word edges.
        for (unsigned w = 0; w < 4; ++w) {
            const auto r = rng() % 5;
            if (r == 0)
                x[w] = 0;
            else if (r == 1)
                x[w] = ~uint64_t{0};
        }
        v.push_back(x);
    }
    return v;
}

// The byte indices that fit PUSH1.
std::vector<uint64_t> small_indices() {
    std::vector<uint64_t> v;
    for (uint64_t k = 0; k <= 40; ++k)
        v.push_back(k);
    for (const uint64_t k : std::initializer_list<uint64_t>{63, 64, 127, 128, 254, 255})
        v.push_back(k);
    return v;
}

// The byte indices for the stack form: small, plus ones with a high word set.
std::vector<uint256> stack_indices() {
    std::vector<uint256> v;
    for (const auto k : small_indices())
        v.emplace_back(k);
    v.push_back(uint256{1} << 32);
    v.push_back((uint256{1} << 32) | 5);
    v.push_back((uint256{1} << 64) | 2);
    v.push_back((uint256{1} << 128) | 1);
    v.push_back((uint256{1} << 224) | 3);
    v.push_back((uint256{1} << 255) | 2);
    v.push_back(uint256{1} << 255);
    v.push_back(~uint256{0});
    v.push_back(~uint256{0} - 25);  // all high words set, low word 0xffffffe6
    v.push_back(uint256{0x80000000});
    v.push_back(uint256{0xffffffff});
    v.push_back(uint256{0x100000005});
    return v;
}

}  // namespace

TEST_CASE("PUSH1 k SIGNEXTEND and SIGNEXTEND on words give the definition", "[signextend]") {
    const auto xs = operands();
    const auto ks = small_indices();
    const auto exts = stack_indices();
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t checks = 0;
        const auto check = [&](const uint256& x, const uint256& ext, Form form) {
            const auto want = reference(x, ext);
            // The test's own base copy agrees with the definition.
            REQUIRE(base_signextend(x, ext) == want);
            bytes expected = be32(want);
            const auto s = be32(kSentinel);
            expected.insert(expected.end(), s.begin(), s.end());
            const auto out = r.run(value_program(x, ext, form), 100000);
            if (out.status != EVMC_SUCCESS || out.output != expected) {
                FAIL("cgoto " << cgoto << " form " << static_cast<int>(form) << " x " << intx::hex(x)
                              << " ext " << intx::hex(ext) << " status " << out.status
                              << " got " << (out.output.size() >= 32 ? intx::hex(
                                     intx::be::unsafe::load<uint256>(out.output.data())) : "-")
                              << " want " << intx::hex(want));
            }
            ++checks;
        };
        for (const auto& x : xs) {
            for (const auto k : ks) {
                check(x, uint256{k}, Form::push1);    // fused with SIGNEXTEND on the rv32 dispatch
                check(x, uint256{k}, Form::push2);    // never fused
            }
            for (const auto& ext : exts)
                check(x, ext, Form::push32);
            for (const uint64_t k : std::initializer_list<uint64_t>{0, 3, 4, 7, 8, 15, 16, 23, 24, 29, 30, 31})
                check(x, uint256{k}, Form::jumpdest);  // a JUMPDEST between: not fused
        }
        REQUIRE(checks > 150000);
    }
}

TEST_CASE("PUSH1 k SIGNEXTEND on the stack path matches the 64-bit word code in place",
          "[signextend]") {
    // Every item of a stack of several, the extended one at each depth: the other items stay.
    Runner r{true};
    std::mt19937_64 rng{23};
    for (int i = 0; i < 300; ++i) {
        const uint256 above{rng(), rng(), rng(), rng()};
        const uint256 x{rng(), rng(), rng(), rng()};
        const uint256 below{rng(), rng(), rng(), rng()};
        for (uint64_t k = 0; k <= 32; ++k) {
            bytes code;
            push32(code, below);
            push32(code, x);
            code.insert(code.end(), {PUSH1, static_cast<uint8_t>(k), SIGNEXTEND});
            push32(code, above);  // pushed over the result, after the slot k was in
            code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, MSTORE, PUSH1, 64, MSTORE,
                                     PUSH1, 96, PUSH1, 0, RETURN});
            const auto out = r.run(code, 100000);
            REQUIRE(out.status == EVMC_SUCCESS);
            bytes expected = be32(above);
            for (const auto& w : {base_signextend(x, k), below}) {
                const auto b = be32(w);
                expected.insert(expected.end(), b.begin(), b.end());
            }
            REQUIRE(out.output == expected);
        }
    }
}

namespace {

// Runs code at every gas limit from lo to hi, and at four revisions: the three dispatches must
// agree on status, gas left and output. Returns the number of runs.
size_t compare_over_gas(Runner& fused, Runner& plain, const bytes& code, const bytes& ref_code,
    int64_t lo, int64_t hi, const char* what) {
    size_t n = 0;
    for (const auto rev : {EVMC_FRONTIER, EVMC_BYZANTIUM, EVMC_CANCUN, EVMC_LATEST_STABLE_REVISION}) {
        for (int64_t g = lo < 0 ? 0 : lo; g <= hi; ++g) {
            const auto f = fused.run(code, g, rev);
            const auto s = fused.run(ref_code, g, rev);
            const auto p = plain.run(code, g, rev);
            if (!(f == s) || !(f == p)) {
                FAIL(what << " gas " << g << " rev " << rev << ": fused status " << f.status
                          << " gas_left " << f.gas_left << ", PUSH2 status " << s.status
                          << " gas_left " << s.gas_left << ", no fusion status " << p.status
                          << " gas_left " << p.gas_left);
            }
            ++n;
        }
    }
    return n;
}

}  // namespace

TEST_CASE("PUSH1 k SIGNEXTEND checks in the order of the separate instructions", "[signextend]") {
    Runner fused{true};
    Runner plain{false};
    size_t checks = 0;
    // n items, PUSH1 k, SIGNEXTEND, then the result returned.
    for (const int n : {0, 1, 2, 1022, 1023, 1024}) {
        for (const uint8_t k : {uint8_t{0}, uint8_t{1}, uint8_t{30}, uint8_t{31}, uint8_t{80}}) {
            const auto build = [&](bool push2) {
                bytes code;
                for (int i = 0; i < n; ++i)
                    code.insert(code.end(), {PUSH1, 0x80});
                if (push2)
                    code.insert(code.end(), {PUSH2, 0, k});
                else
                    code.insert(code.end(), {PUSH1, k});
                code.push_back(SIGNEXTEND);
                code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
                return code;
            };
            const int64_t before = 3 * n;
            checks += compare_over_gas(fused, plain, build(false), build(true),
                before - 4, before + 40, "items");
        }
    }
    // The statuses themselves.
    const auto run = [&](const bytes& code, int64_t gas) { return fused.run(code, gas); };
    // Empty stack: the push passes, the value under it does not exist.
    for (const int64_t gas : {3, 4, 7, 8, 100})
        REQUIRE(run({PUSH1, 0, SIGNEXTEND}, gas).status == EVMC_STACK_UNDERFLOW);
    REQUIRE(run({PUSH1, 0, SIGNEXTEND}, 2).status == EVMC_OUT_OF_GAS);
    // One item: 3 for each push, 5 for SIGNEXTEND.
    REQUIRE(run({PUSH1, 1, PUSH1, 0, SIGNEXTEND}, 10).status == EVMC_OUT_OF_GAS);
    {
        const auto out = run({PUSH1, 1, PUSH1, 0, SIGNEXTEND}, 11);
        REQUIRE(out.status == EVMC_SUCCESS);
        REQUIRE(out.gas_left == 0);
    }
    // PUSH1 overflows the full stack before SIGNEXTEND is looked at; with 1023 items it fills
    // the stack and SIGNEXTEND pops one.
    {
        bytes code;
        for (int i = 0; i < 1024; ++i)
            code.insert(code.end(), {PUSH1, 0});
        code.insert(code.end(), {PUSH1, 5, SIGNEXTEND});
        REQUIRE(run(code, 1000000).status == EVMC_STACK_OVERFLOW);
    }
    {
        bytes code;
        for (int i = 0; i < 1023; ++i)
            code.insert(code.end(), {PUSH1, 0});
        code.insert(code.end(), {PUSH1, 5, SIGNEXTEND});
        REQUIRE(run(code, 1000000).status == EVMC_SUCCESS);
    }
    REQUIRE(checks > 5000);
}

TEST_CASE("PUSH1 k SIGNEXTEND cut by the code end or with the opcode as data", "[signextend]") {
    Runner fused{true};
    Runner plain{false};
    std::mt19937_64 rng{5};
    size_t checks = 0;
    for (int i = 0; i < 20; ++i) {
        const uint256 x{rng(), rng(), rng(), rng()};
        const auto prefix = [&] {
            bytes code;
            push32(code, x);
            return code;
        };
        // PUSH1 with its immediate missing or the code ending after it: no SIGNEXTEND follows.
        bytes a = prefix();
        a.push_back(PUSH1);
        bytes b = prefix();
        b.insert(b.end(), {PUSH1, SIGNEXTEND});         // the opcode byte is the immediate
        bytes c = prefix();
        c.insert(c.end(), {PUSH1, SIGNEXTEND, SIGNEXTEND});  // and then a SIGNEXTEND
        bytes d = prefix();
        d.insert(d.end(), {PUSH1, 0, SIGNEXTEND});      // the group ending the code
        for (const auto* code : {&a, &b, &c, &d}) {
            for (const auto rev : {EVMC_FRONTIER, EVMC_CANCUN}) {
                for (int64_t g = 0; g <= 20; ++g) {
                    const auto f = fused.run(*code, g, rev);
                    const auto p = plain.run(*code, g, rev);
                    REQUIRE(f == p);
                    ++checks;
                }
            }
        }
        // a: 3 + 3, STOP; b: 3 + 3, STOP; c: 3 + 3 + 5 reading the pushed byte as the index;
        // d: 3 + 3 + 5.
        REQUIRE(fused.run(a, 6).status == EVMC_SUCCESS);
        REQUIRE(fused.run(a, 5).status == EVMC_OUT_OF_GAS);
        REQUIRE(fused.run(b, 6).gas_left == 0);
        REQUIRE(fused.run(c, 11).gas_left == 0);
        REQUIRE(fused.run(c, 10).status == EVMC_OUT_OF_GAS);
        REQUIRE(fused.run(d, 11).gas_left == 0);
        REQUIRE(fused.run(d, 10).status == EVMC_OUT_OF_GAS);
    }
    REQUIRE(checks > 100);
}
