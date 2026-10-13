// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs SAR by moving 32-bit words: fused with a PUSH1 that gives the shift, and
// on its own when the shift comes from the stack. These programs run SAR in both forms on values
// whose words, signs and word boundaries each matter (0, 1, -1, 2^255, 2^255 - 1, single bits at
// each word's ends, alternating patterns, random values of both signs) for every shift from 0 to
// 255, shifts from the stack of 256 and beyond or with any high word set, and check the result
// against a SAR computed bit by bit. Gas left and status are checked at every gas limit around the
// SAR and at large ones (gas left stays exact far above the program's cost), with the stack too
// short, a full stack, and before Petersburg, where SAR is undefined and that test comes first.
// Built with -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build
// compiles these paths on the host; without it, instr::core::sar() runs, which the same checks
// cover. Every program also runs on the baseline without the computed-goto dispatch (the
// separate PUSH1 and SAR) and on the advanced interpreter (instr::core::sar()), the unchanged
// code to compare with.

#include <cstdint>
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
    SAR = 0x1d, POP = 0x50, MSTORE = 0x52, JUMPDEST = 0x5b, PUSH1 = 0x60, PUSH2 = 0x61,
    PUSH32 = 0x7f, DUP1 = 0x80, SWAP1 = 0x90, RETURN = 0xf3
};

// How the shift reaches SAR.
enum class Shape {
    push1,           // PUSH32 x, PUSH1 s, SAR: the fused form
    push1_jumpdest,  // PUSH32 x, PUSH1 s, JUMPDEST, SAR: s from the stack
    swap,            // PUSH1 s, PUSH32 x, SWAP1, SAR: s from the stack, through SWAP1's table
    push32,          // PUSH32 x, PUSH32 s, SAR: any 256-bit s, from the stack
};

constexpr Shape kSmallShapes[] = {Shape::push1, Shape::push1_jumpdest, Shape::swap};

// The gas each shape takes before the SAR, and after it: PUSH1 0, MSTORE (with one word of memory),
// PUSH1 32, PUSH1 0, RETURN.
int64_t gas_before(Shape s) {
    return s == Shape::swap ? 9 : s == Shape::push1_jumpdest ? 7 : 6;  // 3 + 3 (+ 3 SWAP1, 1 JUMPDEST)
}
constexpr int64_t kSarGas = 3;
constexpr int64_t kAfterGas = 3 + 3 + 3 + 3 + 3;

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

bytes program(Shape shape, const uint256& x, const uint256& s) {
    bytes code;
    switch (shape) {
    case Shape::push1:
        push32(code, x);
        code.insert(code.end(), {PUSH1, static_cast<uint8_t>(s[0]), SAR});
        break;
    case Shape::push1_jumpdest:
        push32(code, x);
        code.insert(code.end(), {PUSH1, static_cast<uint8_t>(s[0]), JUMPDEST, SAR});
        break;
    case Shape::swap:
        code.insert(code.end(), {PUSH1, static_cast<uint8_t>(s[0])});
        push32(code, x);
        code.insert(code.end(), {SWAP1, SAR});
        break;
    case Shape::push32:
        push32(code, x);
        push32(code, s);
        code.push_back(SAR);
        break;
    }
    code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
    return code;
}

// x >> s with the sign filling in, bit by bit from the words: bit i is bit i + s of x, or the sign
// when i + s is 256 or more.
uint256 sar_reference(const uint256& x, const uint256& s) {
    const auto bit = [&](unsigned i) { return (x[i / 64] >> (i % 64)) & 1; };
    const uint64_t sign = bit(255);
    const bool big = (s[1] | s[2] | s[3]) != 0 || s[0] >= 256;
    uint256 r;
    for (unsigned i = 0; i < 256; ++i) {
        const uint64_t b = (big || i + s[0] >= 256) ? sign : bit(i + static_cast<unsigned>(s[0]));
        r[i / 64] |= b << (i % 64);
    }
    return r;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
};

// The interpreters: the baseline with the computed-goto dispatch (the rv32 paths under
// EVMONE_RV32_DISPATCH), the baseline without it (stack SAR by words, no PUSH1 fusion), and the
// advanced interpreter, which runs instr::core::sar() and is the unchanged code to compare with.
enum class Mode { cgoto, baseline, advanced };
constexpr Mode kModes[] = {Mode::cgoto, Mode::baseline, Mode::advanced};

struct Runner {
    evmc::VM vm{evmc_create_evmone()};
    evmc::MockedHost host;
    // The advanced interpreter charges a basic block's gas up front, so when a program runs out of
    // gas it can fail with another status than the baseline's (which instruction fails differs);
    // only whether it fails and the gas left (0) are comparable.
    bool advanced = false;

    explicit Runner(Mode mode) : advanced(mode == Mode::advanced) {
        if (mode == Mode::baseline)
            REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
        else if (mode == Mode::advanced)
            REQUIRE(vm.set_option("advanced", "") == EVMC_SET_OPTION_SUCCESS);
    }

    Outcome run(const bytes& code, int64_t gas, evmc_revision rev) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        const auto r = vm.execute(host, rev, msg, code.data(), code.size());
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

std::string describe(Shape shape, const uint256& x, const uint256& s, int64_t gas,
                     evmc_revision rev) {
    return "shape " + std::to_string(static_cast<int>(shape)) + " x " + intx::hex(x) + " s " +
           intx::hex(s) + " gas " + std::to_string(gas) + " rev " +
           std::to_string(static_cast<int>(rev));
}

// Values whose words, signs and word boundaries each matter, and random ones of both signs.
std::vector<uint256> values() {
    const uint256 m255 = uint256{1} << 255;
    const uint256 minus1 = ~uint256{0};
    std::vector<uint256> v = {0, 1, minus1, m255, m255 - 1, m255 + 1, minus1 - 1,
        uint256{0x5555555555555555, 0x5555555555555555, 0x5555555555555555, 0x5555555555555555},
        uint256{0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa},
        uint256{0x0123456789abcdef, 0xfedcba9876543210, 0x0f1e2d3c4b5a6978, 0x8796a5b4c3d2e1f0},
        uint256{0x0123456789abcdef, 0xfedcba9876543210, 0x0f1e2d3c4b5a6978, 0x7796a5b4c3d2e1f0}};
    for (unsigned w = 0; w < 8; ++w) {
        v.push_back(uint256{1} << (32 * w));         // the low bit of word w
        v.push_back(uint256{1} << (32 * w + 31));    // its high bit
        v.push_back(minus1 << (32 * w));             // negative, zero below word w
        v.push_back(~(uint256{0xffffffff} << (32 * w)));  // word w zero, the rest ones
    }
    std::mt19937_64 rng{29};
    for (int i = 0; i < 12; ++i) {
        uint256 r{rng(), rng(), rng(), rng()};
        if (i % 2 == 0)
            r |= m255;
        else
            r &= m255 - 1;
        v.push_back(r);
    }
    return v;
}

// Shifts from the stack beyond a byte: 256 and more, and small low words with a high word set.
std::vector<uint256> big_shifts() {
    std::vector<uint256> v = {256, 257, 300, 511, 512, 0xffffffff, uint256{1} << 32,
        (uint256{1} << 32) + 1, uint256{1} << 64, uint256{1} << 128, uint256{1} << 255,
        ~uint256{0}};
    for (unsigned w = 1; w < 8; ++w) {
        v.push_back((uint256{1} << (32 * w)) | 1);
        v.push_back((uint256{0x80000000} << (32 * w)) | 255);
    }
    std::mt19937_64 rng{31};
    for (int i = 0; i < 4; ++i)
        v.push_back(uint256{rng(), rng(), rng(), rng()});
    return v;
}

void check_value(Runner& r, Shape shape, const uint256& x, const uint256& s) {
    const auto out = r.run(program(shape, x, s), 1000000, EVMC_CANCUN);
    if (out.status != EVMC_SUCCESS || out.output != be32(sar_reference(x, s))) {
        FAIL(describe(shape, x, s, 1000000, EVMC_CANCUN)
             << ": status " << out.status << " output size " << out.output.size());
    }
    const int64_t used = gas_before(shape) + kSarGas + kAfterGas;
    REQUIRE(out.gas_left == 1000000 - used);
}

// Gas at the SAR from 2^31 - 1 to 2^40 + 3: gas left must stay exact far above the cost of the program.
constexpr int64_t kLarge[] = {(int64_t{1} << 31) - 1, (int64_t{1} << 31) + 2,
    (int64_t{1} << 31) + 3, (int64_t{1} << 32) - 1, (int64_t{1} << 32), (int64_t{1} << 32) + 2,
    (int64_t{1} << 32) + 3, (int64_t{1} << 40) + 3};

// Status and gas left at every gas limit from 0 to past the program and at large ones, in a
// revision where SAR is undefined and in ones where it is defined.
void check_gas(Runner& r, Shape shape, const uint256& x, const uint256& s) {
    const auto code = program(shape, x, s);
    const int64_t before = gas_before(shape);
    const int64_t total = before + kSarGas + kAfterGas;
    std::vector<int64_t> limits;
    for (int64_t g = 0; g <= total + 2; ++g)
        limits.push_back(g);
    for (const auto large : kLarge)
        limits.push_back(before + large);
    for (const auto rev : {EVMC_BYZANTIUM, EVMC_PETERSBURG, EVMC_CANCUN}) {
        const bool defined = rev >= EVMC_PETERSBURG;
        for (const auto gas : limits) {
            const auto out = r.run(code, gas, rev);
            evmc_status_code want = EVMC_SUCCESS;
            if (gas < before)
                want = EVMC_OUT_OF_GAS;
            else if (!defined)
                want = EVMC_UNDEFINED_INSTRUCTION;  // before the SAR's gas test
            else if (gas < total)
                want = EVMC_OUT_OF_GAS;
            if (r.advanced && want != EVMC_SUCCESS)
                want = out.status == EVMC_SUCCESS ? EVMC_SUCCESS : out.status;  // Any failure.
            if (out.status != want || out.gas_left != (want == EVMC_SUCCESS ? gas - total : 0)) {
                FAIL(describe(shape, x, s, gas, rev) << ": status " << out.status << " (want "
                                                     << want << ") gas_left " << out.gas_left);
            }
            if (want == EVMC_SUCCESS)
                REQUIRE(out.output == be32(sar_reference(x, s)));
        }
    }
}

}  // namespace

TEST_CASE("SAR by an immediate or a stack shift below 256 matches a bitwise SAR", "[sar_words]") {
    const auto vals = values();
    for (const auto mode : kModes) {
        Runner r{mode};
        for (const auto shape : kSmallShapes)
            for (const auto& x : vals)
                for (unsigned s = 0; s < 256; ++s)
                    check_value(r, shape, x, s);
        for (const auto& x : vals)
            for (unsigned s = 0; s < 260; ++s)
                check_value(r, Shape::push32, x, s);
    }
}

TEST_CASE("SAR by a stack shift of 256 or more, or with a high word set, gives the sign",
          "[sar_words]") {
    const auto vals = values();
    for (const auto mode : kModes) {
        Runner r{mode};
        for (const auto& x : vals)
            for (const auto& s : big_shifts())
                check_value(r, Shape::push32, x, s);
    }
}

TEST_CASE("SAR status and gas left at every gas limit and revision", "[sar_words]") {
    const uint256 m255 = uint256{1} << 255;
    for (const auto mode : kModes) {
        Runner r{mode};
        for (const auto shape : kSmallShapes)
            for (const auto& x : {uint256{0x1234}, m255 | 0x1234})
                for (const unsigned s : {0u, 1u, 33u, 77u, 128u, 200u, 255u})
                    check_gas(r, shape, x, s);
        for (const auto& x : {uint256{0x1234}, m255 | 0x1234})
            for (const auto& s : {uint256{5}, uint256{256}, uint256{1} << 64})
                check_gas(r, Shape::push32, x, s);
    }
}

TEST_CASE("SAR with the stack too short or full", "[sar_words]") {
    for (const auto mode : kModes) {
        Runner r{mode};
        // PUSH1 s SAR with nothing under the shift: the PUSH1 runs, then SAR underflows before
        // its gas is tested; undefined comes first before Petersburg.
        // SAR alone, and PUSH32 s SAR, from the stack.
        const bytes shapes[] = {{PUSH1, 7, SAR}, {SAR}, {PUSH2, 0, 7, SAR}, {PUSH1, 7, JUMPDEST, SAR}};
        const int64_t before[] = {3, 0, 3, 4};
        for (size_t i = 0; i < std::size(shapes); ++i) {
            for (const auto rev : {EVMC_BYZANTIUM, EVMC_CANCUN}) {
                for (int64_t gas = 0; gas <= before[i] + kSarGas + 2; ++gas) {
                    const auto out = r.run(shapes[i], gas, rev);
                    evmc_status_code want = EVMC_STACK_UNDERFLOW;
                    if (gas < before[i])
                        want = EVMC_OUT_OF_GAS;
                    else if (rev < EVMC_PETERSBURG)
                        want = EVMC_UNDEFINED_INSTRUCTION;
                    if (r.advanced)
                        REQUIRE(out.status != EVMC_SUCCESS);
                    else
                        REQUIRE(out.status == want);
                    REQUIRE(out.gas_left == 0);
                }
            }
        }
        // 1024 items: the PUSH1 overflows before SAR is reached.
        bytes full;
        for (int i = 0; i < 1024; ++i)
            full.insert(full.end(), {PUSH1, static_cast<uint8_t>(i)});
        for (const auto rev : {EVMC_BYZANTIUM, EVMC_CANCUN}) {
            bytes code = full;
            code.insert(code.end(), {PUSH1, 7, SAR});
            REQUIRE(r.run(code, 1000000, rev).status == EVMC_STACK_OVERFLOW);
            // 1023 items: PUSH1 fills the stack, SAR takes two and leaves one; DUP1 and POP.
            code.assign(full.begin(), full.end() - 2);
            code.insert(code.end(), {PUSH1, 7, SAR, DUP1, POP, POP});
            const auto out = r.run(code, 1000000, rev);
            if (r.advanced && rev < EVMC_PETERSBURG)  // It may find the overflow first.
                REQUIRE(out.status != EVMC_SUCCESS);
            else
                REQUIRE(out.status ==
                        (rev < EVMC_PETERSBURG ? EVMC_UNDEFINED_INSTRUCTION : EVMC_SUCCESS));
        }
    }
}

TEST_CASE("SAR on random programs: status, gas left and output equal the unchanged code's",
          "[sar_words]") {
    // The computed-goto dispatch (PUSH1 SAR fused) is compared with the baseline without it, which
    // runs the separate PUSH1 and SAR through check_requirements(), so status and gas left must be
    // equal, and with the advanced interpreter, which runs instr::core::sar(): the output and gas
    // left when the program succeeds, and failure with no gas left otherwise (see Runner::advanced).
    // The programs run with gas around the total and in revisions on both sides of Petersburg, and
    // the outputs also meet the bitwise SAR.
    std::mt19937_64 rng{37};
    const auto word = [&]() -> uint64_t {
        switch (rng() % 8) {
        case 0: return 0;
        case 1: return ~uint64_t{0};
        case 2: return 0x8000000080000000;
        case 3: return 0x7fffffff7fffffff;
        case 4: return uint64_t{1} << (rng() % 64);
        default: return rng();
        }
    };
    const auto random_value = [&] { return uint256{word(), word(), word(), word()}; };
    const auto random_shift = [&](Shape shape) -> uint256 {
        if (shape != Shape::push32 || rng() % 4 != 0)
            return uint256{rng() % 256};
        switch (rng() % 3) {
        case 0: return uint256{256 + rng() % 1000};
        case 1:
            return uint256{rng() % 256} |
                   (uint256{1 + rng() % 0xffffffff} << (32 * (1 + rng() % 7)));
        default: return random_value();
        }
    };
    Runner fused{Mode::cgoto}, unfused{Mode::baseline}, advanced{Mode::advanced};
    constexpr evmc_revision revs[] = {EVMC_BYZANTIUM, EVMC_PETERSBURG, EVMC_CANCUN};
    for (int i = 0; i < 100000; ++i) {
        const auto shape = static_cast<Shape>(rng() % 4);
        const auto x = random_value();
        const auto s = random_shift(shape);
        const auto code = program(shape, x, s);
        const auto total = static_cast<uint64_t>(gas_before(shape) + kSarGas + kAfterGas);
        const auto gas = static_cast<int64_t>(rng() % 3 == 0 ? rng() % (total + 3) : total + rng() % 3);
        const auto rev = revs[rng() % 3];
        const auto base = unfused.run(code, gas, rev);
        const auto got = fused.run(code, gas, rev);
        const auto adv = advanced.run(code, gas, rev);
        const auto where = describe(shape, x, s, gas, rev);
        INFO(where);
        REQUIRE(got.status == base.status);
        REQUIRE(got.gas_left == base.gas_left);
        REQUIRE(got.output == base.output);
        if (base.status == EVMC_SUCCESS) {
            REQUIRE(adv.status == EVMC_SUCCESS);
            REQUIRE(adv.gas_left == base.gas_left);
            REQUIRE(adv.output == base.output);
            REQUIRE(base.output == be32(sar_reference(x, s)));
        } else {
            REQUIRE(adv.status != EVMC_SUCCESS);
            REQUIRE(adv.gas_left == 0);
        }
    }
}
