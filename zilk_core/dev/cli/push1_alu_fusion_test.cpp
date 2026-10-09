// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs PUSH1 followed by ADD, AND, NOT or SWAP1 as one step, on the immediate
// read from the code. Each program here runs three ways: as written (the fused step), with the
// immediate pushed by PUSH2 0x00 imm (same value and gas, a pair no fusion takes, so the separate
// instructions run), and as written on the baseline without the computed-goto dispatch (the
// separate PUSH1 and the operation). Status, gas left and output must be equal in all three at
// every gas limit around the programs (which covers an out-of-gas failure at the PUSH1, at the
// operation, and which of a stack underflow and an out-of-gas failure is reported when both
// hold), on operands whose carries run through each word boundary, with all-ones and zero words,
// with the stack empty, with one item, near the 1024-item limit and past it, and on random
// programs mixing the four pairs with the neighbours that change what follows them (SWAP1 followed
// by POP, JUMP, SWAP2 or DUP2, PUSH1 followed by the other fused successors). The output of the
// directed programs is also checked against the operation computed with intx. Built with
// -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build compiles the fused
// handlers on the host; without it, all three runs take the separate instructions, which the
// checks against intx still cover.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
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
    STOP = 0x00, ADD = 0x01, MUL = 0x02, SUB = 0x03, LT = 0x10, GT = 0x11, AND = 0x16, OR = 0x17,
    XOR = 0x18, NOT = 0x19, ISZERO = 0x15, SHL = 0x1b, SHR = 0x1c, POP = 0x50, MLOAD = 0x51,
    MSTORE = 0x52, JUMP = 0x56, JUMPI = 0x57, JUMPDEST = 0x5b, PUSH1 = 0x60, PUSH2 = 0x61,
    PUSH32 = 0x7f, DUP1 = 0x80, DUP2 = 0x81, SWAP1 = 0x90, SWAP2 = 0x91, RETURN = 0xf3
};

constexpr uint8_t kOps[] = {ADD, AND, NOT, SWAP1};

const char* name(uint8_t op) {
    switch (op) {
    case ADD: return "ADD";
    case AND: return "AND";
    case NOT: return "NOT";
    default: return "SWAP1";
    }
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

// PUSH1 imm, or PUSH2 0x00 imm for the reference (the same value for the same gas).
void push_imm(bytes& code, uint8_t imm, bool reference) {
    if (reference)
        code.insert(code.end(), {PUSH2, 0, imm});
    else
        code.insert(code.end(), {PUSH1, imm});
}

// Stores the top three items at 0x100, 0x120 and 0x140 and returns memory from 0 to 0x160, so the
// output shows the top three items and every earlier MSTORE.
void tail(bytes& code) {
    code.insert(code.end(), {PUSH2, 0x01, 0x00, MSTORE, PUSH2, 0x01, 0x20, MSTORE, PUSH2, 0x01,
                             0x40, MSTORE, PUSH2, 0x01, 0x60, PUSH1, 0, RETURN});
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

    Outcome run(const bytes& code, int64_t gas, evmc_revision rev) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        const auto r = vm.execute(host, rev, msg, code.data(), code.size());
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

// The three ways to run a program given as a function of "reference" (false: PUSH1, true: PUSH2).
struct Triple {
    Runner fused{true};
    Runner base{false};

    // Fused vs separate (same dispatch) vs the baseline without the dispatch, at one gas limit.
    // Returns the fused outcome.
    template <typename Build>
    Outcome check(const Build& build, int64_t gas, evmc_revision rev, const std::string& what) {
        const auto code = build(false);
        const auto ref = build(true);
        const auto f = fused.run(code, gas, rev);
        const auto s = fused.run(ref, gas, rev);
        const auto b = base.run(code, gas, rev);
        if (!(f == s) || !(f == b)) {
            FAIL(what << " gas " << gas << " rev " << static_cast<int>(rev) << ": fused status "
                      << f.status << " gas_left " << f.gas_left << " out " << f.output.size()
                      << ", separate status " << s.status << " gas_left " << s.gas_left << " out "
                      << s.output.size() << ", baseline status " << b.status << " gas_left "
                      << b.gas_left << " out " << b.output.size());
        }
        return f;
    }

    // At every gas limit from 0 to past the program's end, and at large ones.
    template <typename Build>
    size_t sweep(const Build& build, evmc_revision rev, const std::string& what) {
        const auto full = fused.run(build(true), int64_t{1} << 40, rev);
        const int64_t used = (int64_t{1} << 40) - full.gas_left;
        size_t n = 0;
        const int64_t top = full.status == EVMC_SUCCESS ? used + 3 : 80;
        for (int64_t g = 0; g <= top; ++g, ++n)
            check(build, g, rev, what);
        for (const int64_t g : {int64_t{1} << 31, (int64_t{1} << 32) + 7, int64_t{1} << 40}) {
            check(build, g, rev, what);
            ++n;
        }
        return n;
    }
};

constexpr evmc_revision kRevs[] = {EVMC_FRONTIER, EVMC_CANCUN};

// Values whose carries and masks cross every word boundary.
std::vector<uint256> operands() {
    const uint256 ones = ~uint256{0};
    std::vector<uint256> v = {0, 1, 2, 0x7f, 0x80, 0xff, 0x100, 0xffffffffu, uint256{1} << 32,
        uint256{1} << 255, (uint256{1} << 255) - 1, ones, ones - 1, ones - 0xfe, ones - 0xff,
        ones - 0x100, ones << 32, ones << 224, uint256{0x5a5a5a5a} << 224};
    std::mt19937_64 rng{11};
    for (unsigned k = 1; k <= 8; ++k) {
        const uint256 low_ones = k == 8 ? ones : (uint256{1} << (32 * k)) - 1;  // words 0..k-1
        const uint256 junk = k == 8 ? uint256{0} : uint256{rng(), rng(), rng(), rng()} << (32 * k);
        for (const unsigned m : {1u, 0x80u, 0xffu, 0x100u}) {
            const uint256 near_top = (k == 8 ? ones : low_ones) - (m - 1);  // 2^(32k) - m
            v.push_back(near_top);
            v.push_back(junk | near_top);
        }
        v.push_back(junk | low_ones);
        // words 0..k-1 all ones except the lowest, which sits just under the wrap
        v.push_back(junk | (low_ones & ~uint256{0xff}) | 0xf0);
    }
    for (int i = 0; i < 12; ++i)
        v.emplace_back(rng(), rng(), rng(), rng());
    return v;
}

constexpr uint8_t kImms[] = {0, 1, 2, 0x0f, 0x7f, 0x80, 0xf0, 0xfe, 0xff};

// Two sentinels, x, then PUSH1 imm OP, then the tail: the output is the top three items.
bytes directed(uint8_t op, const uint256& x, uint8_t imm, bool reference) {
    bytes code;
    push32(code, 0x5e5e5e5e5e5e5e5eULL);
    push32(code, 0xa1a1a1a1a1a1a1a1ULL);
    push32(code, x);
    push_imm(code, imm, reference);
    code.push_back(op);
    tail(code);
    return code;
}

bytes expected(uint8_t op, const uint256& x, uint8_t imm) {
    const uint256 s1 = 0x5e5e5e5e5e5e5e5eULL, s2 = 0xa1a1a1a1a1a1a1a1ULL;
    uint256 top, second, third;
    switch (op) {
    case ADD: top = x + imm; second = s2; third = s1; break;
    case AND: top = x & imm; second = s2; third = s1; break;
    case NOT: top = ~uint256{imm}; second = x; third = s2; break;
    default: top = x; second = imm; third = s2; break;
    }
    bytes out(0x160);
    const auto put = [&](size_t at, const uint256& v) {
        const auto w = be32(v);
        std::copy(w.begin(), w.end(), out.begin() + static_cast<std::ptrdiff_t>(at));
    };
    put(0x100, top);
    put(0x120, second);
    put(0x140, third);
    return out;
}

}  // namespace

TEST_CASE("PUSH1 ADD, AND, NOT and SWAP1 results", "[push1_alu]") {
    const auto xs = operands();
    Runner fused{true};
    Runner base{false};
    size_t adds_carrying = 0;
    for (const auto op : kOps) {
        for (const auto& x : xs) {
            for (unsigned imm = 0; imm < 256; ++imm) {
                const auto code = directed(op, x, static_cast<uint8_t>(imm), false);
                const auto want = expected(op, x, static_cast<uint8_t>(imm));
                for (auto* r : {&fused, &base}) {
                    const auto out = r->run(code, 1000000, EVMC_CANCUN);
                    if (out.status != EVMC_SUCCESS || out.output != want) {
                        FAIL(name(op) << " x " << intx::hex(x) << " imm " << imm << ": status "
                                      << out.status << (r == &base ? " (baseline)" : " (fused)"));
                    }
                }
                if (op == ADD && (x + imm) < x)
                    ++adds_carrying;
            }
        }
    }
    REQUIRE(adds_carrying > 0);
}

TEST_CASE("PUSH1 ADD, AND, NOT and SWAP1 status and gas at every gas limit", "[push1_alu]") {
    const auto xs = operands();
    Triple t;
    size_t checks = 0;
    for (const auto rev : kRevs) {
        for (const auto op : kOps) {
            for (const auto& x : xs) {
                for (const auto imm : kImms) {
                    checks += t.sweep([&](bool ref) { return directed(op, x, imm, ref); }, rev,
                        std::string(name(op)) + " x " + intx::hex(x) + " imm " + std::to_string(imm));
                }
            }
        }
    }
    REQUIRE(checks > 100000);
}

namespace {

// d items on the stack before the PUSH1 (the last one x), then PUSH1 imm OP and a tail that
// returns the top item only (it may not exist).
bytes at_depth(uint8_t op, unsigned d, const uint256& x, uint8_t imm, bool reference) {
    bytes code;
    for (unsigned i = 0; i + 1 < d; ++i)
        code.insert(code.end(), {PUSH1, static_cast<uint8_t>(i)});
    if (d > 0)
        push32(code, x);
    push_imm(code, imm, reference);
    code.push_back(op);
    code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
    return code;
}

}  // namespace

TEST_CASE("PUSH1 ADD, AND, NOT and SWAP1 on short and full stacks", "[push1_alu]") {
    Triple t;
    const uint256 x = ~uint256{0} - 0xf0;
    for (const auto rev : kRevs) {
        for (const auto op : kOps) {
            for (const unsigned d : {0u, 1u, 2u, 3u, 1021u, 1022u, 1023u, 1024u}) {
                for (const uint8_t imm : {uint8_t{0x10}, uint8_t{0xff}}) {
                    const auto build = [&](bool ref) { return at_depth(op, d, x, imm, ref); };
                    const auto what = std::string(name(op)) + " depth " + std::to_string(d);
                    t.sweep(build, rev, what);
                    // Which failure, with ample gas.
                    const auto out = t.check(build, 1000000, rev, what);
                    // The tail pushes once more, so 1022 and 1023 items may overflow there.
                    if (d == 1024)
                        REQUIRE(out.status == EVMC_STACK_OVERFLOW);
                    else if (op != NOT && d == 0)
                        REQUIRE(out.status == EVMC_STACK_UNDERFLOW);
                    else if (d == 1 || d == 2 || d == 3 || d == 1021)
                        REQUIRE(out.status == EVMC_SUCCESS);
                }
            }
        }
    }
}

TEST_CASE("PUSH1 ADD in a loop", "[push1_alu]") {
    // i = 2^256 - 0x400; do { i += 0xff } while (i > 0x100): the add wraps past 2^256 after four
    // rounds, carrying through all eight words.
    const auto build = [](bool ref) {
        bytes code;
        push32(code, 1);  // for the tail's three items
        push32(code, 2);
        push32(code, -uint256{0x400});
        code.push_back(JUMPDEST);  // at 99
        push_imm(code, 0xff, ref);
        code.insert(code.end(), {ADD, DUP1, PUSH2, 0x01, 0x00, LT, PUSH1, 99, JUMPI});
        tail(code);
        return code;
    };
    Triple t;
    for (const auto rev : kRevs) {
        const auto out = t.check(build, 100000, rev, "loop");
        REQUIRE(out.status == EVMC_SUCCESS);
        // Four rounds reach 2^256 - 4, the fifth wraps to 0xfb and ends the loop.
        REQUIRE(out.output.size() == 0x160);
        REQUIRE(out.output[0x100 + 31] == 0xfb);
        t.sweep(build, rev, "loop");
    }
}

namespace {

struct Ins {
    uint8_t op;      // an opcode, PUSH1, or PUSH32
    uint8_t imm;     // the PUSH1 immediate
    uint256 value;   // the PUSH32 value
};

uint8_t pick_imm(std::mt19937_64& rng) {
    constexpr uint8_t special[] = {0, 1, 2, 0x7f, 0x80, 0xfe, 0xff, 0x20, 0x40, 0xe0};
    if (rng() % 3 == 0)
        return static_cast<uint8_t>(rng());
    return special[rng() % std::size(special)];
}

uint256 pick_value(std::mt19937_64& rng) {
    const uint256 ones = ~uint256{0};
    switch (rng() % 9) {
    case 0: return 0;
    case 1: return ones;
    case 2: return ones - (rng() % 0x200);
    case 3: return ones << (32 * (rng() % 8));
    case 4: return (uint256{1} << (32 * (1 + rng() % 7))) - (1 + rng() % 0x100);
    case 5: return uint256{1} << (rng() % 256);
    case 6: return rng() % 0x300;
    default: return uint256{rng(), rng(), rng(), rng()};
    }
}

std::vector<Ins> random_program(std::mt19937_64& rng) {
    constexpr uint8_t plain[] = {ADD, AND, NOT, SWAP1, SWAP2, DUP1, DUP2, POP, OR, XOR, SUB, SHL,
        SHR, ISZERO, MSTORE, MLOAD, MUL, LT, GT};
    std::vector<Ins> p;
    const unsigned n = 2 + rng() % 24;
    for (unsigned i = 0; i < 2 + rng() % 3; ++i)  // a few values to work on
        p.push_back({PUSH32, 0, pick_value(rng)});
    for (unsigned i = 0; i < n; ++i) {
        switch (rng() % 10) {
        case 0: p.push_back({PUSH32, 0, pick_value(rng)}); break;
        case 1:
        case 2:
        case 3:
        case 4:  // PUSH1 and one of the fused successors
            p.push_back({PUSH1, pick_imm(rng), 0});
            p.push_back({kOps[rng() % 4], 0, 0});
            break;
        case 5:  // PUSH1 SWAP1 and a successor of SWAP1's own table
            p.push_back({PUSH1, pick_imm(rng), 0});
            p.push_back({SWAP1, 0, 0});
            p.push_back({std::array<uint8_t, 4>{POP, SWAP2, DUP2, ADD}[rng() % 4], 0, 0});
            break;
        case 6:  // PUSH1 and any other successor
            p.push_back({PUSH1, pick_imm(rng), 0});
            p.push_back({plain[rng() % std::size(plain)], 0, 0});
            break;
        default: p.push_back({plain[rng() % std::size(plain)], 0, 0}); break;
        }
    }
    return p;
}

bytes assemble(const std::vector<Ins>& p, bool reference) {
    bytes code;
    for (const auto& i : p) {
        if (i.op == PUSH1)
            push_imm(code, i.imm, reference);
        else if (i.op == PUSH32)
            push32(code, i.value);
        else
            code.push_back(i.op);
    }
    tail(code);
    return code;
}

}  // namespace

TEST_CASE("PUSH1 ADD, AND, NOT and SWAP1 in random programs", "[push1_alu]") {
    Triple t;
    std::mt19937_64 rng{2026};
    size_t succeeded = 0, failed = 0;
    for (unsigned n = 0; n < 60000; ++n) {
        const auto prog = random_program(rng);
        const auto rev = kRevs[rng() % 2];
        const auto build = [&](bool ref) { return assemble(prog, ref); };
        const auto full = t.check(build, 1000000, rev, "random #" + std::to_string(n));
        (full.status == EVMC_SUCCESS ? succeeded : failed) += 1;
        const int64_t used = 1000000 - full.gas_left;
        const int64_t limit = full.status == EVMC_SUCCESS ? used : 200;
        // Around the end of the program and at random points before it.
        for (int64_t g = limit > 6 ? limit - 6 : 0; g <= limit + 1; ++g)
            t.check(build, g, rev, "random #" + std::to_string(n));
        for (int k = 0; k < 3; ++k)
            t.check(build, static_cast<int64_t>(rng() % static_cast<uint64_t>(limit + 1)), rev,
                "random #" + std::to_string(n));
    }
    // The generator reaches both outcomes often enough to mean something.
    REQUIRE(succeeded > 5000);
    REQUIRE(failed > 5000);
}
