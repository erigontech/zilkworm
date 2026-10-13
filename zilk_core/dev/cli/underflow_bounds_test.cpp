// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch tests 2- and 3-operand stack underflow against stack_bottom + 1 and + 2
// computed once per frame, in check_requirements, in the comparison PUSH2 JUMPI fusions and in
// the SWAP1 successor entries. Every instruction runs here with one item too few and with exactly
// enough, reached from each kind of entry (the plain table, the PUSH1, SWAP1 and SWAP2 successor
// tables, DUP1, PUSH0 and CALLDATASIZE before it), in every revision and in both dispatchers; the
// fused groups run at every gas limit around the item they lack. Built with
// -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native build compiles those
// paths on the host.

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <evmone/instructions_traits.hpp>

namespace {

using bytes = std::vector<uint8_t>;

enum : uint8_t {
    STOP = 0x00, ADD = 0x01, LT = 0x10, GT = 0x11, SLT = 0x12, SGT = 0x13, EQ = 0x14,
    ISZERO = 0x15, CALLDATASIZE = 0x36, POP = 0x50, MSTORE8 = 0x53, JUMP = 0x56, JUMPI = 0x57,
    JUMPDEST = 0x5b, PUSH0 = 0x5f, PUSH1 = 0x60, PUSH2 = 0x61, DUP1 = 0x80, DUP2 = 0x81,
    SWAP1 = 0x90, SWAP2 = 0x91, RETURN = 0xf3
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
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

// The instruction before the one under test, which decides the dispatch entry it is reached by.
enum class Entry { plain, push1, push0, calldatasize, dup1, swap1, swap2 };
constexpr Entry kEntries[] = {Entry::plain, Entry::push1, Entry::push0, Entry::calldatasize,
    Entry::dup1, Entry::swap1, Entry::swap2};

// The items the entry instruction itself needs on the stack it is given.
int entry_needs(Entry e) {
    switch (e) {
    case Entry::dup1: return 1;
    case Entry::swap1: return 2;
    case Entry::swap2: return 3;
    default: return 0;
    }
}

// h items on the stack, the last step being the entry, then op and zero bytes (its immediate,
// if any, and STOP). Returns false if the entry cannot leave h items.
bool build(bytes& code, Entry e, int h, uint8_t op) {
    code.clear();
    const bool pushes = e == Entry::push1 || e == Entry::push0 || e == Entry::calldatasize;
    const int before = pushes ? h - 1 : e == Entry::dup1 ? h - 1 : h;
    if (before < 0 || before < entry_needs(e))
        return false;
    // Small values: an instruction given exactly enough items must not fail for its operands'
    // sake in a way that could hide an underflow (memory offsets stay small).
    for (int i = 0; i < before; ++i)
        code.insert(code.end(), {PUSH2, 0, static_cast<uint8_t>(1 + i % 3)});
    switch (e) {
    case Entry::plain: break;
    case Entry::push1: code.insert(code.end(), {PUSH1, 2}); break;
    case Entry::push0: code.push_back(PUSH0); break;
    case Entry::calldatasize: code.push_back(CALLDATASIZE); break;
    case Entry::dup1: code.push_back(DUP1); break;
    case Entry::swap1: code.push_back(SWAP1); break;
    case Entry::swap2: code.push_back(SWAP2); break;
    }
    code.push_back(op);
    code.insert(code.end(), 34, uint8_t{0});
    return true;
}

std::string describe(uint8_t op, Entry e, int h, evmc_revision rev, bool cgoto) {
    return "op " + std::to_string(op) + " entry " + std::to_string(static_cast<int>(e)) +
           " items " + std::to_string(h) + " rev " + std::to_string(static_cast<int>(rev)) +
           (cgoto ? " cgoto" : " switch");
}

// The comparison PUSH2 JUMPI groups and the SWAP1 / SWAP2 successor pairs, with the gas and the
// stack items each instruction needs, in order (none of them changes the height before the last).
// Jump groups have a PUSH2 whose immediate is patched to the target.
struct Group {
    const char* name;
    bytes body;
    std::vector<int64_t> gas;  // per instruction, PUSH2 and its immediate as one
    std::vector<int> needs;    // per instruction
    bool jumps;
};

const std::vector<Group>& groups() {
    static const std::vector<Group> g = {
        {"EQ PUSH2 JUMPI", {EQ, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {2, 0, 2}, true},
        {"ISZERO PUSH2 JUMPI", {ISZERO, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {1, 0, 2}, true},
        {"LT PUSH2 JUMPI", {LT, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {2, 0, 2}, true},
        {"GT PUSH2 JUMPI", {GT, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {2, 0, 2}, true},
        {"SLT PUSH2 JUMPI", {SLT, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {2, 0, 2}, true},
        {"SGT PUSH2 JUMPI", {SGT, PUSH2, 0, 0, JUMPI}, {3, 3, 10}, {2, 0, 2}, true},
        {"LT ISZERO PUSH2 JUMPI", {LT, ISZERO, PUSH2, 0, 0, JUMPI}, {3, 3, 3, 10}, {2, 1, 0, 2},
            true},
        {"GT ISZERO PUSH2 JUMPI", {GT, ISZERO, PUSH2, 0, 0, JUMPI}, {3, 3, 3, 10}, {2, 1, 0, 2},
            true},
        {"SLT ISZERO PUSH2 JUMPI", {SLT, ISZERO, PUSH2, 0, 0, JUMPI}, {3, 3, 3, 10},
            {2, 1, 0, 2}, true},
        {"SGT ISZERO PUSH2 JUMPI", {SGT, ISZERO, PUSH2, 0, 0, JUMPI}, {3, 3, 3, 10},
            {2, 1, 0, 2}, true},
        {"SWAP1 SWAP2", {SWAP1, SWAP2}, {3, 3}, {2, 3}, false},
        {"SWAP1 DUP2", {SWAP1, DUP2}, {3, 3}, {2, 2}, false},
        {"SWAP1 POP", {SWAP1, POP}, {3, 2}, {2, 1}, false},
        {"SWAP1 JUMP", {SWAP1, JUMP}, {3, 8}, {2, 1}, true},
        {"SWAP2 SWAP1", {SWAP2, SWAP1}, {3, 3}, {3, 2}, false},
        {"SWAP2 POP", {SWAP2, POP}, {3, 2}, {3, 1}, false},
        {"SWAP2 ADD", {SWAP2, ADD}, {3, 3}, {3, 2}, false},
    };
    return g;
}

// The items the whole group needs: the first instruction's (the comparison pops before the
// PUSH2), or the most any of the swap pairs' instructions needs.
int group_items(const Group& g) {
    return g.jumps && g.body[0] != SWAP1 ? g.needs[0] : std::max(g.needs[0], g.needs[1]);
}

// k items, each pushed by PUSH1 (3 gas), that decide a jump group's jump with `taken` (SWAP1
// JUMP gets the target second from the top), then the group, a fall-through that returns 0x11
// and a JUMPDEST that returns 0x22.
bytes build_group(const Group& g, int k, bool taken) {
    const uint8_t op = g.body[0];
    std::vector<uint8_t> top_first;  // the items from the top down
    if (op == ISZERO)
        top_first = {static_cast<uint8_t>(taken ? 0 : 9)};
    else if (op == EQ)
        top_first = {5, static_cast<uint8_t>(taken ? 5 : 7)};
    else if (op >= LT && op <= SGT) {
        // The top a = 5 and the second b: a < b holds for b = 7 and a > b for b = 3. ISZERO
        // inverts the jump.
        const bool lt = op == LT || op == SLT;
        const bool holds = taken != (g.body[1] == ISZERO);
        top_first = {5, static_cast<uint8_t>(holds == lt ? 7 : 3)};
    } else
        top_first = {4, 5, 6};
    const bool swap_jump = op == SWAP1 && g.body[1] == JUMP;
    bytes code;
    size_t target_at = 0;
    for (int i = k - 1; i >= 0; --i) {
        const uint8_t v = i < static_cast<int>(top_first.size()) ? top_first[size_t(i)] : 1;
        code.insert(code.end(), {PUSH1, v});
        if (swap_jump && i == 1)
            target_at = code.size() - 1;
    }
    const size_t body_at = code.size();
    code.insert(code.end(), g.body.begin(), g.body.end());
    code.insert(code.end(), {PUSH1, 0x11, PUSH1, 0, MSTORE8, PUSH1, 1, PUSH1, 0, RETURN});
    const size_t dest = code.size();
    code.insert(code.end(), {JUMPDEST, PUSH1, 0x22, PUSH1, 0, MSTORE8, PUSH1, 1, PUSH1, 0, RETURN});
    if (target_at != 0)
        code[target_at] = static_cast<uint8_t>(dest);
    for (size_t i = body_at; i < body_at + g.body.size(); ++i) {
        if (code[i] == PUSH2) {
            code[i + 1] = static_cast<uint8_t>(dest >> 8);
            code[i + 2] = static_cast<uint8_t>(dest);
            i += 2;
        }
    }
    return code;
}

}  // namespace

TEST_CASE("every instruction underflows one item short and not with exactly enough",
          "[underflow_bounds]") {
    using namespace evmone;
    bytes code;
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t short_runs = 0, enough_runs = 0;
        for (size_t rev = EVMC_FRONTIER; rev <= EVMC_LATEST_STABLE_REVISION; ++rev) {
            const auto revision = static_cast<evmc_revision>(rev);
            for (size_t op = 0; op < 256; ++op) {
                const int required = instr::traits[op].stack_height_required;
                if (required == 0 || !instr::traits[op].since.has_value())
                    continue;
                const bool defined = instr::gas_costs[rev][op] != instr::undefined;
                for (const auto e : kEntries) {
                    if (e == Entry::push0 && instr::gas_costs[rev][PUSH0] == instr::undefined)
                        continue;
                    const auto op8 = static_cast<uint8_t>(op);
                    if (build(code, e, required - 1, op8)) {
                        const auto out = r.run(code, 1000000, revision);
                        // The undefined-instruction test comes first, then the underflow test.
                        const auto expected =
                            defined ? EVMC_STACK_UNDERFLOW : EVMC_UNDEFINED_INSTRUCTION;
                        if (out.status != expected || out.gas_left != 0)
                            FAIL(describe(op8, e, required - 1, revision, cgoto)
                                 << ": status " << out.status << " gas_left " << out.gas_left);
                        ++short_runs;
                    }
                    if (defined && build(code, e, required, op8)) {
                        const auto out = r.run(code, 1000000, revision);
                        if (out.status == EVMC_STACK_UNDERFLOW ||
                            out.status == EVMC_UNDEFINED_INSTRUCTION)
                            FAIL(describe(op8, e, required, revision, cgoto)
                                 << ": status " << out.status);
                        ++enough_runs;
                    }
                }
            }
        }
        REQUIRE(short_runs > 5000);
        REQUIRE(enough_runs > 5000);
    }
}

TEST_CASE("fused groups underflow at the instruction that lacks an item, at every gas limit",
          "[underflow_bounds]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const auto rev : {EVMC_FRONTIER, EVMC_PETERSBURG, EVMC_CANCUN}) {
            for (const auto& g : groups()) {
                const int items = group_items(g);
                for (int k = 0; k < items; ++k) {
                    const auto code = build_group(g, k, true);
                    // Each PUSH1 and each instruction before the short one charges its gas; the
                    // short one fails on the stack before it charges any.
                    int64_t before = 3 * k;
                    size_t i = 0;
                    while (k >= g.needs[i])
                        before += g.gas[i++];
                    for (int64_t gas = 0; gas <= before + 30; ++gas) {
                        const auto out = r.run(code, gas, rev);
                        const auto expected =
                            gas < before ? EVMC_OUT_OF_GAS : EVMC_STACK_UNDERFLOW;
                        if (out.status != expected || out.gas_left != 0)
                            FAIL(g.name << " items " << k << " gas " << gas << " rev " << rev
                                        << (cgoto ? " cgoto" : " switch") << ": status "
                                        << out.status << " gas_left " << out.gas_left);
                    }
                    // Gas limits where the fused handlers' single charge falls back.
                    for (const int64_t large : {int64_t{1} << 31, (int64_t{1} << 32) + 5}) {
                        const auto out = r.run(code, before + large, rev);
                        REQUIRE(out.status == EVMC_STACK_UNDERFLOW);
                    }
                }
                // Exactly enough items: the group completes, both ways for a conditional jump.
                for (const bool taken : {true, false}) {
                    if (!taken && (!g.jumps || g.body[1] == JUMP))
                        continue;
                    const auto code = build_group(g, items, taken);
                    for (const int64_t gas : {int64_t{100000}, (int64_t{1} << 32) + 5}) {
                        const auto out = r.run(code, gas, rev);
                        if (out.status != EVMC_SUCCESS)
                            FAIL(g.name << " taken " << taken << " rev " << rev
                                        << (cgoto ? " cgoto" : " switch") << ": status "
                                        << out.status);
                        const uint8_t marker = taken && g.jumps ? 0x22 : 0x11;
                        REQUIRE(out.output == bytes{marker});
                    }
                }
            }
        }
    }
}
