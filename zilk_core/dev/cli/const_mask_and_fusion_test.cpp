// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs three constant-mask ANDs as one step: PUSH20 0xff..ff AND, PUSH4 imm AND,
// and PUSH1 1 PUSH1 0xa0 SHL SUB AND on a top item of 1 (Solidity's address mask built by a shift).
// Each program is checked twice. Against a model of the separate instructions written here
// (undefined instruction, stack overflow, stack underflow and gas, in evmone's order, and the
// result from intx), and against the same program with the group written so that no fusion takes
// it (PUSH21 0x00 mask for PUSH20 mask, PUSH5 0x00 imm for PUSH4 imm, PUSH2 0x00 0x01 for the
// first PUSH1 of the shift), which runs the separate instructions at the same gas. Status, gas
// left and output must match at every gas limit from below the group to past the program's end
// and at large ones (where the one-test charge of the fused forms falls back), at the 4 code
// alignments, with no item, one item and a full stack under the group, a JUMPDEST between the
// push and the AND, the AND as the last byte, PUSH20 masks with one byte off at each position,
// truncated PUSH20s, several PUSH4 immediates, other shift operands and other top items, at
// Frontier, Byzantium (no SHL), Petersburg and Cancun, with cgoto and switch dispatch. Built
// with -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build compiles the
// fused handlers; without it both programs take the separate instructions, which the model still
// checks.

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
    SUB = 0x03, SHL = 0x1b, AND = 0x16, OR = 0x17, MSTORE = 0x52, JUMPDEST = 0x5b,
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH4 = 0x63, PUSH5 = 0x64, PUSH20 = 0x73, PUSH21 = 0x74,
    PUSH32 = 0x7f, RETURN = 0xf3
};

// One instruction of the model: the items it needs, the change of the stack height, its gas,
// and whether it is undefined before Constantinople.
struct Step {
    int required = 0;
    int change = 0;
    int64_t gas = 0;
    bool constantinople = false;
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
    bool operator==(const Outcome&) const = default;
};

bytes be32(const uint256& v) {
    bytes out(32);
    intx::be::unsafe::store(out.data(), v);
    return out;
}

// A program as code (fused form and reference form) and as model steps, with the value its
// RETURN outputs when it gets there.
struct Program {
    bytes code;
    bytes ref;
    std::vector<Step> steps;
    bool returns = false;
    uint256 result;

    void both(std::initializer_list<uint8_t> b) {
        code.insert(code.end(), b);
        ref.insert(ref.end(), b);
    }
    void push(const bytes& imm) {  // PUSHn imm, the same in both forms
        code.push_back(static_cast<uint8_t>(PUSH1 - 1 + imm.size()));
        code.insert(code.end(), imm.begin(), imm.end());
        ref.push_back(static_cast<uint8_t>(PUSH1 - 1 + imm.size()));
        ref.insert(ref.end(), imm.begin(), imm.end());
        steps.push_back({0, 1, 3});
    }
    // PUSHn imm in the fused form, PUSHn+1 0x00 imm in the reference: the same value and gas.
    void push_unfusable_in_ref(const bytes& imm) {
        code.push_back(static_cast<uint8_t>(PUSH1 - 1 + imm.size()));
        code.insert(code.end(), imm.begin(), imm.end());
        ref.push_back(static_cast<uint8_t>(PUSH1 + imm.size()));
        ref.push_back(0);
        ref.insert(ref.end(), imm.begin(), imm.end());
        steps.push_back({0, 1, 3});
    }
    void op(uint8_t o, Step s) {
        both({o});
        steps.push_back(s);
    }
    // Stores the top item at 0 and returns it: PUSH1 0 MSTORE (3 + 3 for the first word of
    // memory) PUSH1 32 PUSH1 0 RETURN.
    void return_top(const uint256& v) {
        push({0});
        op(MSTORE, {2, -2, 6});
        push({32});
        push({0});
        op(RETURN, {2, -2, 0});
        returns = true;
        result = v;
    }
    int64_t cost() const {
        int64_t g = 0;
        for (const auto& s : steps)
            g += s.gas;
        return g;
    }
};

Outcome model(const Program& p, int64_t gas, evmc_revision rev) {
    int depth = 0;
    for (const auto& s : p.steps) {
        if (s.constantinople && rev < EVMC_PETERSBURG)
            return {EVMC_UNDEFINED_INSTRUCTION, 0, {}};
        if (s.change > 0 && depth + s.change > 1024)
            return {EVMC_STACK_OVERFLOW, 0, {}};
        if (depth < s.required)
            return {EVMC_STACK_UNDERFLOW, 0, {}};
        if (gas < s.gas)
            return {EVMC_OUT_OF_GAS, 0, {}};
        gas -= s.gas;
        depth += s.change;
    }
    return {EVMC_SUCCESS, gas, p.returns ? be32(p.result) : bytes{}};
}

struct Runner {
    evmc::VM vm{evmc_create_evmone()};
    evmc::MockedHost host;

    explicit Runner(bool cgoto) {
        if (!cgoto)
            REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    }

    Outcome run(const bytes& code, int64_t gas, evmc_revision rev) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        const auto r = vm.execute(host, rev, msg, code.data(), code.size());
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

constexpr evmc_revision kRevs[] = {
    EVMC_FRONTIER, EVMC_BYZANTIUM, EVMC_PETERSBURG, EVMC_CANCUN};

// Gas left at the group from 2^31 - 1 to 2^32 + 7, where the one-test charge, which tests the
// low word alone, falls back although the gas suffices, or only just passes.
constexpr int64_t kLarge[] = {(int64_t{1} << 31) - 1, (int64_t{1} << 31) + 5,
    (int64_t{1} << 31) + 6, (int64_t{1} << 31) + 7, (int64_t{1} << 32) + 2,
    (int64_t{1} << 32) + 5, (int64_t{1} << 32) + 6, (int64_t{1} << 32) + 7, int64_t{1} << 40};

// Checks p, fused and as the reference, against the model at every gas limit from just below
// the group (which starts after `before` gas) to past the end, and at the large ones.
size_t check(Runner& r, const Program& p, int64_t before, const std::string& name) {
    std::vector<int64_t> limits;
    for (int64_t g = before > 3 ? before - 3 : 0; g <= p.cost() + 2; ++g)
        limits.push_back(g);
    for (const auto large : kLarge)
        limits.push_back(before + large);
    size_t checks = 0;
    for (const auto rev : kRevs) {
        for (const auto gas : limits) {
            const auto want = model(p, gas, rev);
            const auto fused = r.run(p.code, gas, rev);
            const auto separate = r.run(p.ref, gas, rev);
            if (!(fused == want) || !(separate == want)) {
                FAIL(name << " gas " << gas << " rev " << rev << ": want status " << want.status
                          << " gas_left " << want.gas_left << ", fused " << fused.status << " "
                          << fused.gas_left << ", separate " << separate.status << " "
                          << separate.gas_left);
            }
            ++checks;
        }
    }
    return checks;
}

// The code in front of a group: `pad` JUMPDESTs (so the group starts at every alignment), then
// `fill` items, then y when given. Returns the gas this takes.
int64_t prelude(Program& p, unsigned pad, int fill, const uint256* y) {
    for (unsigned i = 0; i < pad; ++i)
        p.op(JUMPDEST, {0, 0, 1});
    for (int i = 0; i < fill; ++i)
        p.push({static_cast<uint8_t>(i)});
    if (y != nullptr)
        p.push(be32(*y));
    return p.cost();
}

uint256 from_be(const bytes& b) {
    uint256 v = 0;
    for (const auto x : b)
        v = (v << 8) | x;
    return v;
}

std::vector<uint256> operands() {
    const uint256 ones = ~uint256{0};
    std::vector<uint256> v = {0, 1, ones, uint256{1} << 160, (uint256{1} << 160) - 1,
        ones << 160, uint256{0xffffffff}, ones << 32, uint256{1} << 255};
    std::mt19937_64 rng{11};
    for (int i = 0; i < 3; ++i)
        v.emplace_back(rng(), rng(), rng(), rng());
    return v;
}

}  // namespace

TEST_CASE("PUSH20 and PUSH4 AND fusions match the separate instructions", "[const_mask_and]") {
    std::mt19937_64 rng{5};
    const auto values = operands();
    std::vector<bytes> masks20 = {bytes(20, 0xff)};
    for (unsigned i = 0; i < 20; ++i) {  // one byte off at each position
        bytes m(20, 0xff);
        m[i] = static_cast<uint8_t>(i % 2 ? 0x7f : 0xfe);
        masks20.push_back(m);
    }
    bytes rnd(20);
    for (auto& b : rnd)
        b = static_cast<uint8_t>(rng());
    masks20.push_back(rnd);
    masks20.push_back(bytes(20, 0));
    const std::vector<bytes> imms4 = {{0xff, 0xff, 0xff, 0xff}, {0, 0, 0, 0},
        {0x00, 0xff, 0x00, 0xff}, {0x80, 0, 0, 0}, {0x12, 0x34, 0x56, 0x78}};
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t checks = 0;
        for (unsigned pad = 0; pad < 4; ++pad) {
            for (const bool four : {false, true}) {
                const auto& imms = four ? imms4 : masks20;
                for (const auto& imm : imms) {
                    const uint256 mask = from_be(imm);
                    // shape 0: plain; 1: a JUMPDEST between the push and the AND; 2: the AND
                    // ends the code; 3: OR instead of AND.
                    for (int shape = 0; shape < 4; ++shape) {
                        for (size_t vi = 0; vi < values.size(); ++vi) {
                            if (shape != 0 && vi > 1)
                                continue;
                            Program p;
                            const auto before = prelude(p, pad, 0, &values[vi]);
                            p.push_unfusable_in_ref(imm);
                            if (shape == 1)
                                p.op(JUMPDEST, {0, 0, 1});
                            p.op(shape == 3 ? OR : AND, {2, -1, 3});
                            if (shape != 2)
                                p.return_top(shape == 3 ? (values[vi] | mask) : (values[vi] & mask));
                            checks += check(r, p, before,
                                std::string(four ? "PUSH4 " : "PUSH20 ") + intx::hex(mask) +
                                    " pad " + std::to_string(pad) + " shape " +
                                    std::to_string(shape) + " x " + intx::hex(values[vi]));
                        }
                    }
                }
            }
        }
        REQUIRE(checks > 50000);
    }
}

TEST_CASE("PUSH20 and PUSH4 AND fusions with a short or full stack", "[const_mask_and]") {
    const uint256 y = uint256{0x1234} << 200 | 0xabcdef;
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const bool four : {false, true}) {
            const bytes imm = four ? bytes(4, 0xff) : bytes(20, 0xff);
            // Items under the push: none (AND underflows), y alone, 1022 then y (the push fills
            // the stack), 1023 then y (the push overflows).
            for (const int fill : {-1, 0, 1022, 1023}) {
                for (unsigned pad = 0; pad < 2; ++pad) {
                    Program p;
                    const auto before = prelude(p, pad, fill < 0 ? 0 : fill, fill < 0 ? nullptr : &y);
                    p.push_unfusable_in_ref(imm);
                    p.op(AND, {2, -1, 3});
                    if (fill < 1023)
                        p.return_top(y & from_be(imm));
                    check(r, p, before, "short/full " + std::to_string(fill));
                }
            }
        }
    }
}

TEST_CASE("PUSH20 and PUSH4 AND fusions: hand-computed status and gas", "[const_mask_and]") {
    // PUSH20 ff..ff AND (or PUSH4) alone, the AND the last byte: 6 gas, then STOP.
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const bool four : {false, true}) {
            bytes group{four ? PUSH4 : PUSH20};
            group.insert(group.end(), four ? 4 : 20, 0xff);
            group.push_back(AND);
            bytes with_item{PUSH1, 7};
            with_item.insert(with_item.end(), group.begin(), group.end());
            for (int64_t gas = 0; gas <= 10; ++gas) {
                // Empty stack: PUSH OOG below 3, then AND's underflow comes before its gas.
                const auto e = r.run(group, gas, EVMC_CANCUN);
                REQUIRE(e.status == (gas < 3 ? EVMC_OUT_OF_GAS : EVMC_STACK_UNDERFLOW));
                REQUIRE(e.gas_left == 0);
                // One item (PUSH1 7 takes 3): OOG below 3 + 6, else success with the rest.
                const auto w = r.run(with_item, 3 + gas, EVMC_CANCUN);
                if (gas < 6) {
                    REQUIRE(w.status == EVMC_OUT_OF_GAS);
                    REQUIRE(w.gas_left == 0);
                } else {
                    REQUIRE(w.status == EVMC_SUCCESS);
                    REQUIRE(w.gas_left == gas - 6);
                }
            }
        }
        // Truncated PUSH20 at the code end, k = 0..20 data bytes of 0xff: never an AND after it.
        for (unsigned k = 0; k <= 20; ++k) {
            bytes code{PUSH1, 7, PUSH20};
            code.insert(code.end(), k, 0xff);
            const auto o = r.run(code, 100, EVMC_CANCUN);
            REQUIRE(o.status == EVMC_SUCCESS);
            REQUIRE(o.gas_left == 94);
        }
    }
}

TEST_CASE("PUSH1 PUSH1 SHL SUB AND address mask matches the separate instructions",
          "[const_mask_and]") {
    struct Shift {
        uint8_t a, b;
    };
    // 1 << 160 is the fused one; 2 << 0x9f gives the same constant by another way.
    const Shift shifts[] = {{1, 0xa0}, {2, 0x9f}, {1, 0x80}, {1, 0xff}, {1, 0}, {0x80, 0xa0}};
    // Top items: 1 (the fused one), others, and 1 with one more bit in each higher word.
    std::vector<uint256> xs = {1, 0, 2, ~uint256{0}};
    for (unsigned w = 1; w < 8; ++w)
        xs.push_back(uint256{1} | (uint256{1} << (32 * w + 7 * (w % 4))));
    const auto values = operands();
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t checks = 0;
        for (unsigned pad = 0; pad < 4; ++pad) {
            for (const auto& s : shifts) {
                for (const auto& x : xs) {
                    for (const bool x_by_push1 : {false, true}) {
                        if (x_by_push1 && x > 0xff)
                            continue;
                        for (int shape = 0; shape < 3; ++shape) {  // plain, AND last, OR
                            for (size_t vi = 0; vi < values.size(); ++vi) {
                                // values[2] is all ones: the AND then returns the mask itself,
                                // so a top item mistaken for 1 shows in any word.
                                if ((shape != 0 || x != 1) && vi > 2)
                                    continue;
                                Program p;
                                const auto before = prelude(p, pad, 0, &values[vi]);
                                if (x_by_push1)
                                    p.push({static_cast<uint8_t>(x)});
                                else
                                    p.push(be32(x));
                                p.push_unfusable_in_ref({s.a});
                                p.push({s.b});
                                p.op(SHL, {2, -1, 3, true});
                                p.op(SUB, {2, -1, 3});
                                p.op(shape == 2 ? OR : AND, {2, -1, 3});
                                const uint256 c = (uint256{s.a} << s.b) - x;
                                if (shape != 1)
                                    p.return_top(shape == 2 ? (values[vi] | c) : (values[vi] & c));
                                checks += check(r, p, before,
                                    "shift a " + std::to_string(s.a) + " b " +
                                        std::to_string(s.b) + " x " + intx::hex(x) + " pad " +
                                        std::to_string(pad) + " shape " + std::to_string(shape) +
                                        " y " + intx::hex(values[vi]));
                            }
                        }
                    }
                }
            }
        }
        REQUIRE(checks > 50000);
    }
}

TEST_CASE("PUSH1 PUSH1 SHL SUB AND with a short or full stack", "[const_mask_and]") {
    const uint256 y = ~uint256{0} - 5;
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        // Items under x = 1: none (AND underflows), y alone, 1020 then y (PUSH1 0xa0 fills the
        // stack), 1021 then y (PUSH1 0xa0 overflows), 1022 then y (the PUSH1 1 after x
        // overflows), 1023 then y (pushing x overflows).
        for (const int fill : {-1, 0, 1020, 1021, 1022, 1023}) {
            Program p;
            const auto before =
                prelude(p, 0, fill < 0 ? 0 : fill, fill < 0 ? nullptr : &y);
            p.push({1});
            p.push_unfusable_in_ref({1});
            p.push({0xa0});
            p.op(SHL, {2, -1, 3, true});
            p.op(SUB, {2, -1, 3});
            p.op(AND, {2, -1, 3});
            if (fill <= 1020)
                p.return_top(y & ((uint256{1} << 160) - 1));
            check(r, p, before, "shift short/full " + std::to_string(fill));
        }
        // The six instructions alone on y: 18 gas.
        const bytes code{PUSH32, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, PUSH1, 1, PUSH1, 1, PUSH1, 0xa0, SHL, SUB, AND};
        for (int64_t gas = 15; gas <= 22; ++gas) {
            const auto o = r.run(code, 3 + gas, EVMC_CANCUN);
            REQUIRE(o.status == (gas < 18 ? EVMC_OUT_OF_GAS : EVMC_SUCCESS));
            REQUIRE(o.gas_left == (gas < 18 ? 0 : gas - 18));
            const auto f = r.run(code, 3 + gas, EVMC_BYZANTIUM);  // SHL is undefined there
            REQUIRE(f.status == (gas < 9 ? EVMC_OUT_OF_GAS : EVMC_UNDEFINED_INSTRUCTION));
        }
    }
}
