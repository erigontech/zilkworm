// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs LT, GT, SLT and SGT followed by PUSH2 JUMPI, or by ISZERO PUSH2 JUMPI, as
// one step. Each program here runs twice: as written, and with the jump destination pushed by
// PUSH3, which no fusion takes, so that the separate instructions run. Status, gas left and output
// must match at every gas limit from below the comparison to past the end of the group and at
// seven large ones (where the low-word charge falls back or only just passes), on operands that
// are equal, differ only in the low word, only in the high word or in the sign, or are random,
// with a valid destination and four invalid ones (a PUSH1, a 0x5b byte in push data, the code end
// and 0xffff), in 3 layouts (plain, a JUMPDEST at the fall-through, the group at the code end
// jumping back), with the stack too short, and with 1024 items. Built with
// -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build compiles the fused
// handlers on the host, where they compare words; the guest decides LT and GT by the BigInt SUB
// delegation in the PUSH2 JUMPI shape only (the ISZERO shape compares words there too). Without
// it, both runs take the separate instructions, which the checks against intx's comparisons still
// cover.

#include <cstdint>
#include <random>
#include <string>
#include <utility>
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
    STOP = 0x00, ADD = 0x01, LT = 0x10, GT = 0x11, SLT = 0x12, SGT = 0x13, ISZERO = 0x15,
    POP = 0x50, MSTORE = 0x52, JUMP = 0x56, JUMPI = 0x57, JUMPDEST = 0x5b, PUSH1 = 0x60,
    PUSH2 = 0x61, PUSH3 = 0x62, PUSH32 = 0x7f, RETURN = 0xf3
};

enum class Dest { valid, opcode, push_data, code_end, far };

struct Case {
    uint8_t op = LT;
    bool iszero = false;         // OP ISZERO PUSH2 JUMPI, else OP PUSH2 JUMPI
    bool fall_jumpdest = false;  // a JUMPDEST right after the JUMPI
    bool at_end = false;         // the group ends the code and jumps back
    Dest dest = Dest::valid;
    int items = 2;               // operands: 0, 1 or 2 (on a sentinel), or 1024 items in all
    uint256 a;                   // the top item
    uint256 b;                   // the item under it
};

constexpr uint64_t kSentinel = 0x5e5e5e5e;  // under the operands; the paths return it plus 1 or 2

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

// Returns the top item plus k, as 32 bytes.
void return_top_plus(bytes& code, uint8_t k) {
    code.insert(code.end(), {PUSH1, k, ADD, PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
}

// The program of c, the destination pushed by PUSH2, or by PUSH3 for the reference. The second
// member is the gas the instructions before the comparison take.
std::pair<bytes, int64_t> build(const Case& c, bool reference) {
    bytes code;
    int64_t before = 0;
    size_t skip_at = 0;  // the PUSH2 immediate that jumps over the target block (at_end)
    size_t target = 0, opcode_pos = 0, data_pos = 0;
    const auto tail_blocks = [&] {
        target = code.size();
        code.push_back(JUMPDEST);
        return_top_plus(code, 2);
        data_pos = code.size() + 5;  // 0x5b bytes inside PUSH32 data: never a destination
        push32(code, uint256{0x5b5b5b5b5b5b5b5b, 0x5b5b5b5b5b5b5b5b});
        code.push_back(POP);
        opcode_pos = code.size();  // a PUSH1, not a JUMPDEST
        code.insert(code.end(), {PUSH1, 7, POP});
    };
    if (c.at_end) {
        code.insert(code.end(), {PUSH2, 0, 0, JUMP});
        skip_at = 1;
        tail_blocks();
        const auto body = code.size();
        code[skip_at] = static_cast<uint8_t>(body >> 8);
        code[skip_at + 1] = static_cast<uint8_t>(body);
        code.push_back(JUMPDEST);
        before += 3 + 8 + 1;
    }
    if (c.items == 1024) {
        for (int i = 0; i < 1021; ++i)
            code.insert(code.end(), {PUSH1, static_cast<uint8_t>(i)});
        before += 3 * 1021;
    }
    if (c.items >= 2) {
        push32(code, kSentinel);
        push32(code, c.b);
        before += 6;
    }
    if (c.items >= 1) {
        push32(code, c.a);
        before += 3;
    }
    code.push_back(c.op);
    if (c.iszero)
        code.push_back(ISZERO);
    code.push_back(reference ? PUSH3 : PUSH2);
    const auto dst_at = code.size() + (reference ? 1 : 0);
    code.insert(code.end(), reference ? size_t{3} : size_t{2}, uint8_t{0});
    code.push_back(JUMPI);
    if (!c.at_end) {
        if (c.fall_jumpdest)
            code.push_back(JUMPDEST);
        return_top_plus(code, 1);
        tail_blocks();
    }
    size_t dst = 0;
    switch (c.dest) {
    case Dest::valid: dst = target; break;
    case Dest::opcode: dst = opcode_pos; break;
    case Dest::push_data: dst = data_pos; break;
    case Dest::code_end: dst = code.size(); break;
    case Dest::far: dst = 0xffff; break;
    }
    code[dst_at] = static_cast<uint8_t>(dst >> 8);
    code[dst_at + 1] = static_cast<uint8_t>(dst);
    return {code, before};
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

bool holds(uint8_t op, const uint256& a, const uint256& b) {
    switch (op) {
    case LT: return a < b;
    case GT: return b < a;
    case SLT: return intx::slt(a, b);
    default: return intx::slt(b, a);
    }
}

std::string describe(const Case& c, int64_t gas, evmc_revision rev) {
    return "op " + std::to_string(c.op) + (c.iszero ? " iszero" : "") +
           (c.fall_jumpdest ? " fall-jumpdest" : "") + (c.at_end ? " at-end" : "") + " dest " +
           std::to_string(static_cast<int>(c.dest)) + " items " + std::to_string(c.items) +
           " a " + intx::hex(c.a) + " b " + intx::hex(c.b) + " gas " + std::to_string(gas) +
           " rev " + std::to_string(static_cast<int>(rev));
}

// The operands (top, second): equal, apart only in word 0 or only in word 7 (with and without a
// sign change), across the sign boundary, and random.
std::vector<std::pair<uint256, uint256>> operand_pairs() {
    const uint256 m255 = uint256{1} << 255;
    const uint256 minus1 = ~uint256{0};
    const uint256 high = minus1 << 32;           // words 1-7 all ones: negative
    const uint256 mid = uint256{0x1234} << 100;  // a middle word
    std::vector<std::pair<uint256, uint256>> v = {
        {0, 0}, {5, 5}, {m255, m255}, {minus1, minus1},
        {5, 7}, {7, 5}, {high | 5, high | 7}, {high | 7, high | 5},
        {mid | 5, mid | 0xffffffff}, {mid | 0xffffffff, mid | 5},
        {uint256{1} << 224, uint256{2} << 224}, {uint256{2} << 224, uint256{1} << 224},
        {mid | (uint256{0x80000000} << 224), mid | (uint256{0x7fffffff} << 224)},
        {mid | (uint256{0x7fffffff} << 224), mid | (uint256{0x80000000} << 224)},
        {mid | (uint256{0xfffffffe} << 224), mid | (uint256{0xffffffff} << 224)},
        {m255, m255 - 1}, {m255 - 1, m255},
        {minus1, 0}, {0, minus1},
        {0, m255}, {m255, 0},
        {1, m255 + 1}, {minus1 - 1, minus1},
    };
    std::mt19937_64 rng{7};
    for (int i = 0; i < 6; ++i)
        v.emplace_back(uint256{rng(), rng(), rng(), rng()}, uint256{rng(), rng(), rng(), rng()});
    return v;
}

constexpr uint8_t kOps[] = {LT, GT, SLT, SGT};
constexpr Dest kDests[] = {Dest::valid, Dest::opcode, Dest::push_data, Dest::code_end, Dest::far};
constexpr evmc_revision kRevs[] = {EVMC_FRONTIER, EVMC_CANCUN};
// Gas left at the comparison from 2^31 - 1 to 2^40 + 3, where the low-word charge falls back or
// only just passes: it tests the low word alone, so it falls back although the gas suffices when
// that word is below the group's cost or 2^31 or more above it.
constexpr int64_t kLarge[] = {(int64_t{1} << 31) - 1, (int64_t{1} << 31) + 16,
    (int64_t{1} << 31) + 20, (int64_t{1} << 32) - 1, (int64_t{1} << 32) + 16,
    (int64_t{1} << 32) + 19, (int64_t{1} << 40) + 3};

// Runs c fused and as the reference at every gas limit from just below the comparison to past
// the group's end, and at a few large ones.
size_t check_case(Runner& r, const Case& c) {
    const auto [code, before] = build(c, false);
    const auto ref = build(c, true).first;
    size_t checks = 0;
    std::vector<int64_t> limits;
    for (int64_t g = before > 4 ? before - 4 : 0; g <= before + 56; ++g)
        limits.push_back(g);
    for (const auto large : kLarge)
        limits.push_back(before + large);
    for (const auto rev : kRevs) {
        for (const auto gas : limits) {
            const auto f = r.run(code, gas, rev);
            const auto e = r.run(ref, gas, rev);
            if (!(f == e)) {
                FAIL(describe(c, gas, rev) << ": fused status " << f.status << " gas_left "
                                           << f.gas_left << ", separate status " << e.status
                                           << " gas_left " << e.gas_left);
            }
            ++checks;
        }
    }
    return checks;
}

// What the separate instructions must do with ample gas, from the operands alone.
void check_semantics(Runner& r, const Case& c, size_t& taken, size_t& not_taken) {
    const auto [code, before] = build(c, false);
    const auto out = r.run(code, 1000000, EVMC_CANCUN);
    if (c.items < 2) {
        REQUIRE(out.status == EVMC_STACK_UNDERFLOW);
        return;
    }
    const bool jump = holds(c.op, c.a, c.b) != c.iszero;
    (jump ? taken : not_taken) += 1;
    if (jump && c.dest != Dest::valid) {
        REQUIRE(out.status == EVMC_BAD_JUMP_DESTINATION);
        REQUIRE(out.gas_left == 0);
    } else {
        REQUIRE(out.status == EVMC_SUCCESS);
        if (jump)
            REQUIRE(out.output == be32(kSentinel + 2));
        else if (!c.at_end)
            REQUIRE(out.output == be32(kSentinel + 1));
        else
            REQUIRE(out.output.empty());
    }
}

}  // namespace

TEST_CASE("comparison PUSH2 JUMPI fusions match the separate instructions", "[cmp_jumpi]") {
    const auto pairs = operand_pairs();
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t checks = 0;
        for (const auto op : kOps) {
            for (const bool iszero : {false, true}) {
                size_t taken = 0, not_taken = 0;
                for (const auto dest : kDests) {
                    for (const bool fall_jumpdest : {false, true}) {
                        for (const bool at_end : {false, true}) {
                            if (at_end && fall_jumpdest)
                                continue;
                            for (const auto& [a, b] : pairs) {
                                const Case c{op, iszero, fall_jumpdest, at_end, dest, 2, a, b};
                                checks += check_case(r, c);
                                check_semantics(r, c, taken, not_taken);
                            }
                        }
                    }
                }
                // Both outcomes of the jump occur for every comparison and shape.
                REQUIRE(taken > 0);
                REQUIRE(not_taken > 0);
            }
        }
        REQUIRE(checks > 100000);
    }
}

TEST_CASE("comparison PUSH2 JUMPI fusions with a short or full stack", "[cmp_jumpi]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const auto op : kOps) {
            for (const bool iszero : {false, true}) {
                for (const int items : {0, 1}) {
                    for (const auto dest : {Dest::valid, Dest::far}) {
                        const Case c{op, iszero, false, false, dest, items, 3, 4};
                        check_case(r, c);
                        size_t taken = 0, not_taken = 0;
                        check_semantics(r, c, taken, not_taken);
                    }
                }
                // 1024 items at the comparison: the PUSH2 refills the stack to the limit.
                for (const auto& [a, b] : {std::pair<uint256, uint256>{3, 4}, {4, 3}}) {
                    for (const auto dest : {Dest::valid, Dest::opcode}) {
                        const Case c{op, iszero, false, false, dest, 1024, a, b};
                        check_case(r, c);
                        size_t taken = 0, not_taken = 0;
                        check_semantics(r, c, taken, not_taken);
                    }
                }
            }
        }
    }
}

TEST_CASE("comparison PUSH2 JUMPI fusions do not match a group cut off by the code end",
          "[cmp_jumpi]") {
    // The code ends inside the group: the peeks read the zero padding, which is not JUMPI, and
    // the instructions run one by one, the PUSH2 immediate padded with zeros, up to the implicit
    // STOP.
    Runner r{true};
    for (const auto op : kOps) {
        for (const bool iszero : {false, true}) {
            for (int kept = 0; kept <= 3; ++kept) {
                bytes code;
                push32(code, 5);
                push32(code, 3);
                code.push_back(op);
                if (iszero)
                    code.push_back(ISZERO);
                const bytes group{PUSH2, 0x00, 0x4a};
                code.insert(code.end(), group.begin(), group.begin() + kept);
                const int64_t cost = 6 + 3 + (iszero ? 3 : 0) + (kept > 0 ? 3 : 0);
                for (int64_t gas = 0; gas <= cost + 2; ++gas) {
                    const auto out = r.run(code, gas, EVMC_CANCUN);
                    if (gas < cost) {
                        REQUIRE(out.status == EVMC_OUT_OF_GAS);
                    } else {
                        REQUIRE(out.status == EVMC_SUCCESS);
                        REQUIRE(out.gas_left == gas - cost);
                    }
                }
            }
        }
    }
}
