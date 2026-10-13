// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// A taken jump on the rv32 dispatch paths tests one bound, the scanned prefix of the code, with the
// JUMPDEST map and the code start held by the interpreter loop (CodeAnalysis::check_jumpdest_in()
// and the landing address of the fused PUSH2 JUMP/JUMPI, compare, selector, SWAP1 JUMP and plain
// JUMP handlers). This test covers it at two levels. The native build sets
// -DEVMONE_RV32_DISPATCH_TEST, which compiles the byte map, the lazy scan and those handlers on the
// host.
//
// Analysis: check_jumpdest_in() against a reference scan, interleaved at random with
// check_jumpdest() on one analysis (they share the scan bound, as the frames of one contract do),
// on codes around the cases a single bound can get wrong: a JUMPDEST in the last byte, a PUSH cut
// off by the code end (the scan overshoots the end, and the bound is clamped), targets at and past
// the end, 2^31 and 2^32 - 1.
//
// Execution: every jump form runs at every gas limit up to past its landing, for the target
// positions a jump can get wrong (a valid JUMPDEST, a PUSH opcode, a 0x5b in push data, the code
// end and positions up to 40 past it, 0xffff, 2^31, 2^32 - 1, and a valid low word under a nonzero
// high word), laid out with the jump first (a cold scan) or last (the scan done by an earlier jump
// over the whole code, then a warm check), with and without a PUSH cut off by the code end, and
// with the jump back to position 0. The outcome (status, gas left, output) comes from a model of
// the separate instructions: JUMP's check follows its charge, and the landing JUMPDEST's charge
// follows the check. With the environment variable JUMPDEST_SINGLE_BOUND_DIGEST set, the
// execution tests print a digest of every outcome, to compare two builds of the interpreter.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/baseline.hpp>
#include <evmone/evmone.h>
#include <intx/intx.hpp>

namespace {

using intx::uint256;
using bytes = std::vector<uint8_t>;

constexpr uint8_t kJumpdest = 0x5b;
constexpr uint8_t kPush1 = 0x60;
constexpr uint8_t kPush32 = 0x7f;

// ---- Analysis ----------------------------------------------------------------------------------

#if EVMONE_JUMPDEST_BYTEMAP

std::vector<bool> reference_jumpdests(const bytes& code) {
    std::vector<bool> valid(code.size(), false);
    for (size_t i = 0; i < code.size(); ++i) {
        const uint8_t op = code[i];
        if (op == kJumpdest)
            valid[i] = true;
        else if (op >= kPush1 && op <= kPush32)
            i += static_cast<size_t>(op - kPush1) + 1;
    }
    return valid;
}

bool expected(const std::vector<bool>& valid, uint64_t position) {
    return position < valid.size() && valid[position];
}

// Queries the positions in the given order on a fresh analysis, each by check_jumpdest() or by
// check_jumpdest_in(), then the targets at and beyond the code end.
void check_order(const bytes& code, const std::vector<bool>& valid,
                 const std::vector<uint32_t>& order, std::mt19937_64& rng) {
    const auto analysis =
        evmone::baseline::analyze(evmc::bytes_view{code.data(), code.size()});
    const auto map = analysis.jumpdest_map();
    for (const auto position : order) {
        const bool got = (rng() & 1) ? analysis.check_jumpdest_in(map, position)
                                     : analysis.check_jumpdest(position);
        REQUIRE(got == expected(valid, position));
    }
    const auto size = static_cast<uint32_t>(code.size());
    std::vector<uint32_t> beyond;
    for (uint32_t k = 0; k <= 40; ++k)
        beyond.push_back(size + k);
    beyond.insert(beyond.end(), {0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu});
    for (const auto position : beyond) {
        REQUIRE_FALSE(analysis.check_jumpdest_in(map, position));
        REQUIRE_FALSE(analysis.check_jumpdest(position));
    }
}

void check_code(const bytes& code, std::mt19937_64& rng) {
    const auto valid = reference_jumpdests(code);
    std::vector<uint32_t> order(code.size());
    std::iota(order.begin(), order.end(), uint32_t{0});
    check_order(code, valid, order, rng);  // Ascending: each query lands at the scan bound.
    std::reverse(order.begin(), order.end());
    check_order(code, valid, order, rng);  // Descending: the first query scans everything.
    std::shuffle(order.begin(), order.end(), rng);
    check_order(code, valid, order, rng);
    if (!code.empty()) {
        const auto last = static_cast<uint32_t>(code.size() - 1);
        // Far, then back below the bound, then above what is classified, then the end again.
        check_order(code, valid, {last, 0, last / 2, last, 0}, rng);
        check_order(code, valid, {0, last / 4, last / 2, last}, rng);
    }
}

TEST_CASE("jumpdest check_jumpdest_in: fixed codes", "[jumpdest_in]") {
    std::mt19937_64 rng{11};
    check_code({}, rng);
    check_code({kJumpdest}, rng);
    check_code({0x00}, rng);
    check_code({kJumpdest, kJumpdest, kJumpdest}, rng);
    check_code({kPush1, kJumpdest, kJumpdest}, rng);
    check_code({kPush32, kJumpdest, kJumpdest}, rng);
    // A PUSH cut off by the code end, after a JUMPDEST: the scan runs past the end by up to 32.
    for (unsigned op = kPush1; op <= kPush32; ++op) {
        for (size_t have = 0; have <= static_cast<size_t>(op - kPush1) + 1; ++have) {
            for (const size_t lead : {size_t{0}, size_t{1}, size_t{7}, size_t{8}, size_t{9}}) {
                bytes code(lead + 1 + have, kJumpdest);
                code[lead] = static_cast<uint8_t>(op);
                check_code(code, rng);
            }
        }
    }
}

TEST_CASE("jumpdest check_jumpdest_in: every length around the scan step", "[jumpdest_in]") {
    std::mt19937_64 rng{12};
    for (size_t size = 1; size <= 72; ++size) {
        check_code(bytes(size, kJumpdest), rng);
        bytes last_only(size, 0x01);
        last_only.back() = kJumpdest;
        check_code(last_only, rng);
        // A truncated PUSH32 at the end of dense JUMPDESTs, then of plain opcodes.
        for (const uint8_t fill : {kJumpdest, uint8_t{0x01}}) {
            bytes code(size, fill);
            code.back() = kPush32;
            check_code(code, rng);
        }
    }
}

TEST_CASE("jumpdest check_jumpdest_in: random codes", "[jumpdest_in]") {
    std::mt19937_64 rng{13};
    const uint8_t pool[] = {kJumpdest, kJumpdest, kPush1, kPush1 + 1, kPush1 + 3, kPush32, 0x00,
        0x01, 0x56, 0x57, 0x80, 0xff, 0x5a, 0x5c};
    for (int round = 0; round < 3000; ++round) {
        bytes code(rng() % 300);
        for (auto& b : code)
            b = (rng() % 4) ? pool[rng() % std::size(pool)] : static_cast<uint8_t>(rng());
        // Half of the codes end in a PUSH cut off by the code end.
        if (!code.empty() && (rng() & 1))
            code.back() = static_cast<uint8_t>(kPush1 + rng() % 32);
        check_code(code, rng);
    }
}

#endif  // EVMONE_JUMPDEST_BYTEMAP

// ---- Execution ---------------------------------------------------------------------------------

enum : uint8_t {
    STOP = 0x00, ADD = 0x01, LT = 0x10, GT = 0x11, SLT = 0x12, SGT = 0x13, EQ = 0x14, ISZERO = 0x15,
    GAS = 0x5a, POP = 0x50, MSTORE = 0x52, JUMP = 0x56, JUMPI = 0x57, JUMPDEST = 0x5b,
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH3 = 0x62, PUSH4 = 0x63, PUSH5 = 0x64, PUSH32 = 0x7f,
    DUP1 = 0x80, SWAP1 = 0x90, RETURN = 0xf3
};

constexpr uint64_t kFallthrough = 0xbb;  // returned by the block the jump falls through to
constexpr uint64_t kLanded = 0xaa;       // returned by the block a valid jump lands on

constexpr uint64_t kDigestStart = 1469598103934665603ull;
uint64_t digest = kDigestStart;  // FNV-1a over every outcome of a test case

void mix(uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        digest ^= (v >> (8 * i)) & 0xff;
        digest *= 1099511628211ull;
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

void put(bytes& code, std::initializer_list<uint8_t> ops) { code.insert(code.end(), ops); }

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
        Outcome out{r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
        mix(static_cast<uint64_t>(out.status));
        mix(static_cast<uint64_t>(out.gas_left));
        mix(out.output.size());
        for (const auto b : out.output)
            mix(b);
        return out;
    }
};

// Returns the top item plus nothing: MSTORE it at 0 and RETURN 32 bytes; 18 gas with the memory.
constexpr int64_t kReturnCost = 3 + 3 + 3 + 3 + 3 + 3;  // PUSH1 v PUSH1 0 MSTORE PUSH1 32 PUSH1 0
void return_value(bytes& code, uint64_t v) {
    put(code, {PUSH1, static_cast<uint8_t>(v), PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
}

bytes word(uint64_t v) {
    bytes out(32, 0);
    out[31] = static_cast<uint8_t>(v);
    return out;
}

// The instructions of one jump form with a placeholder destination.
struct Group {
    bytes code;
    int64_t cost = 0;     // gas of its instructions up to and including the jump
    size_t dst_at = 0;    // where the destination's bytes start
    size_t width = 0;     // how many bytes it has (2 for PUSH2, 3, 4, 32)
    bool taken = true;    // the jump is made (always for JUMP, depends on the condition for JUMPI)
    bool jump = false;    // the form has JUMP, not JUMPI: no condition, a jump never falls through
};

enum class Form {
    push2_jump, push2_jumpi, push2_jumpi_wide_cond, lt, gt, slt, sgt, eq, iszero, lt_iszero,
    gt_iszero, slt_iszero, sgt_iszero, selector, push3_jump, push4_jump, push32_jump,
    push3_jumpi, swap1_jump3, swap1_jump32, swap1_jumpi
};

constexpr Form kForms[] = {Form::push2_jump, Form::push2_jumpi, Form::push2_jumpi_wide_cond,
    Form::lt, Form::gt, Form::slt, Form::sgt, Form::eq, Form::iszero, Form::lt_iszero,
    Form::gt_iszero, Form::slt_iszero, Form::sgt_iszero, Form::selector, Form::push3_jump,
    Form::push4_jump, Form::push32_jump, Form::push3_jumpi, Form::swap1_jump3,
    Form::swap1_jump32, Form::swap1_jumpi};

bool is_jump_only(Form f) {
    return f == Form::push2_jump || f == Form::push3_jump || f == Form::push4_jump ||
           f == Form::push32_jump || f == Form::swap1_jump3 || f == Form::swap1_jump32;
}

// The operands (top a, second b) of the comparison op and whether it holds.
std::pair<uint256, uint256> operands(uint8_t op, bool holds) {
    const uint256 minus1 = ~uint256{0};
    switch (op) {
    case LT: return holds ? std::pair{uint256{1}, uint256{2}} : std::pair{uint256{2}, uint256{1}};
    case GT: return holds ? std::pair{uint256{2}, uint256{1}} : std::pair{uint256{1}, uint256{2}};
    case SLT: return holds ? std::pair{minus1, uint256{1}} : std::pair{uint256{1}, minus1};
    default: return holds ? std::pair{uint256{1}, minus1} : std::pair{minus1, uint256{1}};
    }
}

// The group of form f; for a conditional form, taken says whether the condition is true.
Group make_group(Form f, bool taken) {
    Group g;
    g.taken = taken;
    g.jump = is_jump_only(f);
    if (g.jump)
        g.taken = true;
    const auto dst = [&](uint8_t push_op, size_t width) {
        g.code.push_back(push_op);
        g.dst_at = g.code.size();
        g.width = width;
        g.code.insert(g.code.end(), width, uint8_t{0});
    };
    const auto cmp = [&](uint8_t op, bool zero) {
        const auto [a, b] = operands(op, zero ? !taken : taken);
        push32(g.code, b);
        push32(g.code, a);
        g.code.push_back(op);
        if (zero)
            g.code.push_back(ISZERO);
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 3 + (zero ? 3 : 0) + 3 + 10;
    };
    switch (f) {
    case Form::push2_jump: dst(PUSH2, 2); g.code.push_back(JUMP); g.cost = 3 + 8; break;
    case Form::push2_jumpi:
        put(g.code, {PUSH1, static_cast<uint8_t>(taken ? 1 : 0)});
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 10;
        break;
    case Form::push2_jumpi_wide_cond:  // the condition is nonzero in its top word only
        push32(g.code, taken ? uint256{1} << 255 : uint256{0});
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 10;
        break;
    case Form::lt: cmp(LT, false); break;
    case Form::gt: cmp(GT, false); break;
    case Form::slt: cmp(SLT, false); break;
    case Form::sgt: cmp(SGT, false); break;
    case Form::lt_iszero: cmp(LT, true); break;
    case Form::gt_iszero: cmp(GT, true); break;
    case Form::slt_iszero: cmp(SLT, true); break;
    case Form::sgt_iszero: cmp(SGT, true); break;
    case Form::eq:
        push32(g.code, uint256{5});
        push32(g.code, taken ? uint256{5} : uint256{6});
        g.code.push_back(EQ);
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 3 + 3 + 10;
        break;
    case Form::iszero:
        push32(g.code, taken ? uint256{0} : uint256{9});
        g.code.push_back(ISZERO);
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 3 + 10;
        break;
    case Form::selector:  // PUSH4 sel, then DUP1 PUSH4 sel EQ PUSH2 dst JUMPI
        put(g.code, {PUSH4, 0xa9, 0x05, 0x9c, 0xbb, DUP1, PUSH4, 0xa9, 0x05, 0x9c,
            static_cast<uint8_t>(taken ? 0xbb : 0xbc), EQ});
        dst(PUSH2, 2);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 3 + 3 + 3 + 10;
        break;
    case Form::push3_jump: dst(PUSH3, 3); g.code.push_back(JUMP); g.cost = 3 + 8; break;
    case Form::push4_jump: dst(PUSH4, 4); g.code.push_back(JUMP); g.cost = 3 + 8; break;
    case Form::push32_jump: dst(PUSH32, 32); g.code.push_back(JUMP); g.cost = 3 + 8; break;
    case Form::push3_jumpi:
        put(g.code, {PUSH1, static_cast<uint8_t>(taken ? 1 : 0)});
        dst(PUSH3, 3);
        g.code.push_back(JUMPI);
        g.cost = 3 + 3 + 10;
        break;
    case Form::swap1_jump3:  // dst, then 7 on top: SWAP1 brings dst to the top
        dst(PUSH3, 3);
        put(g.code, {PUSH1, 7, SWAP1, JUMP});
        g.cost = 3 + 3 + 3 + 8;
        break;
    case Form::swap1_jump32:
        dst(PUSH32, 32);
        put(g.code, {PUSH1, 7, SWAP1, JUMP});
        g.cost = 3 + 3 + 3 + 8;
        break;
    case Form::swap1_jumpi:
        dst(PUSH32, 32);
        put(g.code, {PUSH1, static_cast<uint8_t>(taken ? 1 : 0), SWAP1, JUMPI});
        g.cost = 3 + 3 + 3 + 10;
        break;
    }
    return g;
}

// The cut-off PUSH the code can end with: none, or opcode op with have data bytes.
struct Tail {
    int op = 0;  // 0: none
    size_t have = 0;
};

struct Program {
    bytes code;
    Group group;
    bool at_end = false;  // the group is last and jumps back to the block above it
    Tail tail;
    int64_t pre = 0;      // gas of what runs before the group
    size_t target = 0;    // the JUMPDEST the block that returns kLanded starts with
    size_t opcode_pos = 0, data_pos = 0;
    size_t last_jumpdest = 0;  // a JUMPDEST just before the cut-off PUSH; 0: none
};

constexpr int64_t kLandedCost = 1 + kReturnCost;  // JUMPDEST, then the return block

// Layout, with the group at the front (a cold scan from 0) or at the end (jumped to by a jump over
// the whole code first, so the scan bound is the code end when the group runs).
Program build(Form f, bool taken, bool at_end, Tail tail) {
    Program p;
    p.group = make_group(f, taken);
    p.at_end = at_end;
    p.tail = tail;
    auto& c = p.code;
    size_t skip_at = 0;
    if (at_end) {
        put(c, {PUSH2, 0, 0, JUMP});
        skip_at = 1;
        p.pre = 3 + 8 + 1;
    } else {
        p.group.dst_at += c.size();
        c.insert(c.end(), p.group.code.begin(), p.group.code.end());
        // The fall-through block.
        return_value(c, kFallthrough);
    }
    p.target = c.size();
    c.push_back(JUMPDEST);
    return_value(c, kLanded);
    // 0x5b bytes inside PUSH32 data: never a destination.
    p.data_pos = c.size() + 5;
    push32(c, uint256{0x5b5b5b5b5b5b5b5b, 0x5b5b5b5b5b5b5b5b, 0x5b5b5b5b5b5b5b5b,
                      0x5b5b5b5b5b5b5b5b});
    c.push_back(POP);
    p.opcode_pos = c.size();  // a PUSH1, not a JUMPDEST
    put(c, {PUSH1, 7, POP});
    if (at_end) {
        const auto body = c.size();
        c[skip_at] = static_cast<uint8_t>(body >> 8);
        c[skip_at + 1] = static_cast<uint8_t>(body);
        c.push_back(JUMPDEST);
        p.group.dst_at += c.size();
        c.insert(c.end(), p.group.code.begin(), p.group.code.end());
    } else if (tail.op != 0) {
        p.last_jumpdest = c.size();
        c.push_back(JUMPDEST);
    }
    if (tail.op != 0) {
        c.push_back(static_cast<uint8_t>(tail.op));
        c.insert(c.end(), tail.have, kJumpdest);
    }
    return p;
}

void set_dst(Program& p, const uint256& v) {
    const auto w = be32(v);
    std::copy(w.end() - static_cast<std::ptrdiff_t>(p.group.width), w.end(),
              p.code.begin() + static_cast<std::ptrdiff_t>(p.group.dst_at));
}

bool fits(const Program& p, const uint256& v) {
    return p.group.width == 32 || (v >> (8 * p.group.width)) == 0;
}

// The destinations to try, by name for failure messages.
std::vector<std::pair<std::string, uint256>> destinations(const Program& p) {
    const auto size = static_cast<uint64_t>(p.code.size());
    std::vector<std::pair<std::string, uint256>> v = {
        {"target", p.target}, {"opcode", p.opcode_pos}, {"push data", p.data_pos},
        {"size", size}, {"size+1", size + 1}, {"size+7", size + 7}, {"size+8", size + 8},
        {"size+31", size + 31}, {"size+32", size + 32}, {"size+33", size + 33},
        {"size+40", size + 40}, {"0xffff", 0xffff}, {"0x10000", 0x10000}, {"0xffffff", 0xffffff},
        {"2^24", uint64_t{1} << 24}, {"2^31-1", 0x7fffffff}, {"2^31", uint64_t{1} << 31},
        {"2^32-1", 0xffffffff}, {"2^32", uint64_t{1} << 32},
        {"2^32+target", (uint256{1} << 32) | p.target},
        {"2^64+target", (uint256{1} << 64) | p.target},
        {"2^255+target", (uint256{1} << 255) | p.target}, {"2^256-1", ~uint256{0}},
        {"0", 0}, {"1", 1},
    };
    if (p.last_jumpdest != 0)
        v.emplace_back("last jumpdest", p.last_jumpdest);
    return v;
}

// What the instructions do under gas limit g.
Outcome model(const Program& p, const uint256& dst, int64_t g) {
    const auto oog = Outcome{EVMC_OUT_OF_GAS, 0, {}};
    const int64_t head = p.pre + p.group.cost;
    if (g < head)
        return oog;
    int64_t tail_cost;
    bytes output;
    if (p.group.taken) {
        if (dst == uint256{p.target}) {
            tail_cost = kLandedCost;
            output = word(kLanded);
        } else if (p.last_jumpdest != 0 && dst == uint256{p.last_jumpdest}) {
            tail_cost = 1 + (p.tail.op != 0 ? 3 : 0);  // JUMPDEST, then the cut-off PUSH
        } else {
            return {EVMC_BAD_JUMP_DESTINATION, 0, {}};
        }
    } else if (p.at_end) {
        tail_cost = p.tail.op != 0 ? 3 : 0;
    } else {
        tail_cost = kReturnCost;
        output = word(kFallthrough);
    }
    if (g < head + tail_cost)
        return oog;
    return {EVMC_SUCCESS, g - head - tail_cost, output};
}

constexpr evmc_revision kRevs[] = {EVMC_CANCUN, EVMC_FRONTIER};

size_t check_program(Runner& r, Program p, Form f, const std::vector<evmc_revision>& revs) {
    size_t checks = 0;
    for (const auto& [name, dst] : destinations(p)) {
        if (!fits(p, dst))
            continue;
        set_dst(p, dst);
        for (const auto rev : revs) {
            for (int64_t g = 0; g <= p.pre + p.group.cost + kLandedCost + 4; ++g) {
                const auto got = r.run(p.code, g, rev);
                const auto want = model(p, dst, g);
                if (!(got == want)) {
                    FAIL("form " << static_cast<int>(f) << (p.group.taken ? " taken" : " not taken")
                                 << (p.at_end ? " at-end" : " first") << " tail op " << p.tail.op
                                 << "/" << p.tail.have << " dst " << name << " gas " << g
                                 << ": status " << got.status << " gas_left " << got.gas_left
                                 << " output " << got.output.size() << ", model status "
                                 << want.status << " gas_left " << want.gas_left << " output "
                                 << want.output.size());
                }
                ++checks;
            }
        }
    }
    return checks;
}

void print_digest(const char* what) {
    if (std::getenv("JUMPDEST_SINGLE_BOUND_DIGEST") != nullptr)
        std::fprintf(stderr, "jumpdest_single_bound digest %s %016llx\n", what,
            static_cast<unsigned long long>(digest));
}

}  // namespace

TEST_CASE("jumps check one scanned bound: every form, target and gas limit", "[jumpdest_in]") {
    digest = kDigestStart;
    const Tail tails[] = {{0, 0}, {PUSH32, 0}, {PUSH32, 31}, {PUSH3, 1}, {PUSH5, 4}};
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        size_t checks = 0;
        for (const auto f : kForms) {
            for (const bool taken : {true, false}) {
                if (is_jump_only(f) && !taken)
                    continue;
                for (const bool at_end : {false, true}) {
                    for (const auto& tail : tails) {
                        // The second revision only on the plain layouts: gas costs of these
                        // instructions do not change across revisions.
                        const auto revs = tail.op == 0 ? std::vector<evmc_revision>{kRevs[0], kRevs[1]}
                                                       : std::vector<evmc_revision>{kRevs[0]};
                        checks += check_program(r, build(f, taken, at_end, tail), f, revs);
                    }
                }
            }
        }
        REQUIRE(checks > 300000);
    }
    print_digest("forms");
}

namespace {

// Jumps back to 0, where the code starts with a JUMPDEST: the loop runs while GAS is above 256.
// Back is the way the loop jumps back. Returns the code and the gas of one iteration besides the
// back jump; the exit block returns kFallthrough.
enum class Back { cmp_jumpi, push2_jump, push3_jump, swap1_jump, plain_jumpi };

bytes loop_code(Back back) {
    bytes c;
    c.push_back(JUMPDEST);
    put(c, {PUSH2, 0x01, 0x00, GAS, GT});
    switch (back) {
    case Back::cmp_jumpi:  // GT PUSH2 0 JUMPI, fused with the compare
        put(c, {PUSH2, 0, 0, JUMPI});
        break;
    case Back::plain_jumpi:  // PUSH3 0 JUMPI is not fused
        put(c, {PUSH3, 0, 0, 0, JUMPI});
        break;
    default: {
        // Leave the loop when GAS is not above 256: GT ISZERO PUSH2 exit JUMPI, then jump back.
        put(c, {ISZERO, PUSH2, 0, 0, JUMPI});
        const auto exit_at = c.size() - 3;
        if (back == Back::push2_jump)
            put(c, {PUSH2, 0, 0, JUMP});
        else if (back == Back::push3_jump)
            put(c, {PUSH3, 0, 0, 0, JUMP});
        else
            put(c, {PUSH3, 0, 0, 0, PUSH1, 7, SWAP1, JUMP});
        const auto exit = c.size();
        c[exit_at] = static_cast<uint8_t>(exit >> 8);
        c[exit_at + 1] = static_cast<uint8_t>(exit);
        c.push_back(JUMPDEST);
        return_value(c, kFallthrough);
        return c;
    }
    }
    return_value(c, kFallthrough);
    return c;
}

// The outcome of loop_code(back) under gas limit g, by the separate instructions.
Outcome loop_model(Back back, int64_t g) {
    const auto oog = Outcome{EVMC_OUT_OF_GAS, 0, {}};
    const bool cmp_exit = back == Back::cmp_jumpi || back == Back::plain_jumpi;
    int64_t left = g;
    const auto spend = [&](int64_t n) {
        left -= n;
        return left >= 0;
    };
    for (;;) {
        if (!spend(1 + 3 + 2))  // JUMPDEST, PUSH2, GAS
            return oog;
        const int64_t seen = left;  // GAS pushes what is left after its own charge
        if (!spend(3))  // GT
            return oog;
        bool again;
        if (cmp_exit) {
            if (!spend(3 + 10))  // PUSH2 or PUSH3, JUMPI
                return oog;
            again = seen > 256;
        } else {
            if (!spend(3 + 3 + 10))  // ISZERO, PUSH2, JUMPI
                return oog;
            const bool exit = !(seen > 256);
            if (exit) {
                if (!spend(1 + kReturnCost))  // JUMPDEST and the return block
                    return oog;
                return {EVMC_SUCCESS, left, word(kFallthrough)};
            }
            again = true;
            const int64_t back_cost = back == Back::swap1_jump ? 3 + 3 + 3 + 8 : 3 + 8;
            if (!spend(back_cost))
                return oog;
        }
        if (!again) {
            if (!spend(kReturnCost))
                return oog;
            return {EVMC_SUCCESS, left, word(kFallthrough)};
        }
        // The jump lands on JUMPDEST at 0, which the next round charges.
    }
}

}  // namespace

TEST_CASE("jumps back to position 0 run the loop the model runs", "[jumpdest_in]") {
    digest = kDigestStart;
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const auto back : {Back::cmp_jumpi, Back::push2_jump, Back::push3_jump,
                 Back::swap1_jump, Back::plain_jumpi}) {
            const auto code = loop_code(back);
            std::vector<int64_t> limits;
            for (int64_t g = 0; g <= 400; ++g)
                limits.push_back(g);
            // Up to 30000 gas: the SWAP1 loop leaves an item per round, so 1024 rounds overflow.
            for (const int64_t g : {1000, 1001, 4093, 5000, 20000, 30000})
                limits.push_back(g);
            for (const auto g : limits) {
                const auto got = r.run(code, g, EVMC_CANCUN);
                const auto want = loop_model(back, g);
                if (!(got == want)) {
                    FAIL("loop " << static_cast<int>(back) << " gas " << g << ": status "
                                 << got.status << " gas_left " << got.gas_left << ", model status "
                                 << want.status << " gas_left " << want.gas_left);
                }
            }
        }
    }
    print_digest("loops");
}
