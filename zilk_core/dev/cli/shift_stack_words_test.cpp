// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The rv32 dispatch runs SHL and SHR with both operands on the stack on 32-bit words: a shift of
// 256 or more, in any of the 8 words of the shift operand, gives 0, and a smaller one selects an
// unrolled body by its word shift. The shift operands here are pushed by PUSH2 or PUSH32, never
// PUSH1, which takes the PUSH1 fusion (a few cases cross-check the two). Results are compared with
// a bit-by-bit model for every shift from 0 to 511, for shifts 2^k - 1, 2^k and 2^k + 1 at every
// bit k, for shift operands with exactly one non-zero word at each position and a low word below,
// at and above 256, and for random operands (values of mixed word density, shifts of mixed
// length). A sentinel under the operands must survive, which pins the stack height after the
// shift; the gas used, the underflow, out-of-gas and undefined-before-Constantinople outcomes must
// not change. Built with -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the native
// build compiles the word handlers on the host; without it the generic intx shift runs and the
// same checks hold.

#include <array>
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
    SHL = 0x1b, SHR = 0x1c, MSTORE = 0x52, PUSH1 = 0x60, PUSH2 = 0x61, PUSH32 = 0x7f, RETURN = 0xf3
};

constexpr uint64_t kSentinel = 0x5e5e5e5e5e5e5e5e;

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

// Pushes the shift: PUSH2 when it fits, else PUSH32. Never PUSH1.
void push_shift(bytes& code, const uint256& s) {
    if (s <= 0xffff) {
        code.insert(code.end(),
            {PUSH2, static_cast<uint8_t>(static_cast<uint64_t>(s) >> 8), static_cast<uint8_t>(s)});
    } else {
        push32(code, s);
    }
}

// sentinel, x, shift, OP; then the result to memory 0 and the sentinel to memory 32, returned.
bytes program(uint8_t op, const uint256& x, const uint256& s) {
    bytes code;
    push32(code, kSentinel);
    push32(code, x);
    push_shift(code, s);
    code.push_back(op);
    code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, MSTORE, PUSH1, 64, PUSH1, 0, RETURN});
    return code;
}

// The result of x op s from the bits, with s read as a full 256-bit number: bit i of the result
// is bit i - s of x for SHL and bit i + s for SHR, and 0 outside.
uint256 model(uint8_t op, const uint256& x, const uint256& s) {
    if (s >= 256)
        return 0;
    const auto n = static_cast<int>(static_cast<uint64_t>(s));
    uint256 r = 0;
    for (int i = 0; i < 256; ++i) {
        const int from = op == SHL ? i - n : i + n;
        if (from < 0 || from > 255)
            continue;
        const auto f = static_cast<unsigned>(from), t = static_cast<unsigned>(i);
        if ((x[f / 64] >> (f % 64)) & 1)
            r[t / 64] |= uint64_t{1} << (t % 64);
    }
    return r;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
};

struct Runner {
    evmc::VM vm{evmc_create_evmone()};
    evmc::MockedHost host;
    size_t runs = 0;

    explicit Runner(bool cgoto) {
        if (!cgoto)
            REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    }

    Outcome run(const bytes& code, int64_t gas, evmc_revision rev = EVMC_CANCUN) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        const auto r = vm.execute(host, rev, msg, code.data(), code.size());
        ++runs;
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }

    // One shift, checked against the model and the sentinel.
    void check(uint8_t op, const uint256& x, const uint256& s) {
        const auto out = run(program(op, x, s), 1000000);
        const auto want = model(op, x, s);
        INFO("op " << (op == SHL ? "SHL" : "SHR") << " x " << intx::hex(x) << " shift "
                   << intx::hex(s));
        REQUIRE(out.status == EVMC_SUCCESS);
        REQUIRE(out.output.size() == 64);
        bytes result(out.output.begin(), out.output.begin() + 32);
        bytes sentinel(out.output.begin() + 32, out.output.end());
        REQUIRE(result == be32(want));
        REQUIRE(sentinel == be32(kSentinel));
    }
};

// Values of mixed density: x is all zero, a single bit, all ones, or random words, some of them
// zeroed or set to ones.
std::vector<uint256> values() {
    const uint256 minus1 = ~uint256{0};
    std::vector<uint256> v = {1, 2, uint256{1} << 255, minus1, minus1 - 1,
        uint256{0xdeadbeef} << 100, uint256{0x0123456789abcdef, 0xfedcba9876543210,
            0x0f0f0f0f0f0f0f0f, 0xf0f0f0f0f0f0f0f0},
        // each 32-bit word marked differently, so a misplaced word shows
        uint256{0x0000000200000001, 0x0000000400000003, 0x0000000600000005, 0x0000000800000007}};
    std::mt19937_64 rng{11};
    for (int i = 0; i < 4; ++i)
        v.emplace_back(rng(), rng(), rng(), rng());
    return v;
}

// A full-width random value with some words zero or all ones.
uint256 mixed(std::mt19937_64& rng) {
    uint256 v;
    for (size_t i = 0; i < 4; ++i) {
        switch (rng() % 4) {
        case 0: v[i] = 0; break;
        case 1: v[i] = ~uint64_t{0}; break;
        default: v[i] = rng(); break;
        }
    }
    return v;
}

}  // namespace

TEST_CASE("SHL and SHR of a stack operand: every shift from 0 to 511", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const auto x : values()) {
            for (const uint8_t op : {SHL, SHR}) {
                for (unsigned s = 0; s < 512; ++s)
                    r.check(op, x, s);
            }
        }
        REQUIRE(r.runs > 10000);
    }
}

TEST_CASE("SHL and SHR of a stack operand: shifts 2^k - 1, 2^k and 2^k + 1", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        const auto xs = values();
        for (unsigned k = 0; k < 256; ++k) {
            const uint256 p = uint256{1} << k;
            for (const uint256 s : {p - 1, p, p + 1, ~uint256{0} - p, ~p, p | 255, p | 256}) {
                for (const uint8_t op : {SHL, SHR}) {
                    for (size_t i : {size_t{0}, size_t{3}, size_t{6}, size_t{7}, size_t{8}})
                        r.check(op, xs[i], s);
                }
            }
        }
    }
}

TEST_CASE("SHL and SHR of a stack operand: one non-zero word in the shift", "[shift_stack]") {
    // Any word above word 0 non-zero is a shift of 2^32 or more: the result is 0, whatever the
    // low word, and a mutation that leaves one word out of the test shifts by the low word.
    const std::array<uint64_t, 5> pieces = {
        1, 0x80000000, 0xffffffff, 0x100000000, 0x7654321012345678};
    const std::array<uint32_t, 8> lows = {0, 1, 31, 32, 255, 256, 0x7fffffff, 0xffffffff};
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        const auto xs = values();
        for (unsigned word = 0; word < 8; ++word) {
            for (const auto piece : pieces) {
                // The 32-bit word at `word` set, so words 1-7 each are tested alone; a piece of
                // 2^32 or more spills into the next word, so that case is a pair.
                for (const auto low : lows) {
                    if (word == 0 && low != lows[0])
                        continue;  // the low word is the piece itself, so one pass covers it
                    uint256 s = low;
                    if (word == 0)
                        s = piece;  // the low word alone (up to 64 bits: words 0 and 1)
                    else
                        s = s | (uint256{piece} << (32 * word));
                    for (const uint8_t op : {SHL, SHR}) {
                        for (size_t i : {size_t{0}, size_t{3}, size_t{7}, size_t{8}})
                            r.check(op, xs[i], s);
                    }
                }
            }
        }
        // The low word alone at and around 256, and 2^32 - 1 (the largest with no high word).
        for (const uint32_t s : {255u, 256u, 257u, 0x1ffu, 0x100u << 8, 0x7fffffffu, 0x80000000u,
                 0xfffffeffu, 0xffffffffu}) {
            for (const uint8_t op : {SHL, SHR}) {
                for (const auto& x : xs)
                    r.check(op, x, s);
            }
        }
    }
}

TEST_CASE("SHL and SHR of a stack operand: random operands", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        std::mt19937_64 rng{cgoto ? 21u : 22u};
        for (int i = 0; i < 6000; ++i) {
            const uint256 x = mixed(rng);
            uint256 s;
            switch (rng() % 5) {
            case 0: s = rng() % 300; break;                       // around the word shifts
            case 1: s = mixed(rng); break;                        // mostly 256 or more
            case 2: s = rng() & 0xffffffff; break;                // a low word only
            case 3: s = uint256{0, 0, 0, 0} | (rng() % 256); break;
            default:
                s = uint256{rng() % 300, 0, 0, 0} | (uint256{rng() % 2} << (rng() % 256));
                break;
            }
            r.check(SHL, x, s);
            r.check(SHR, x, s);
        }
    }
}

TEST_CASE("SHL and SHR of a stack operand agree with the PUSH1 fusion and intx", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        std::mt19937_64 rng{31};
        for (unsigned s = 0; s < 256; ++s) {
            const uint256 x = mixed(rng);
            for (const uint8_t op : {SHL, SHR}) {
                bytes fused;
                push32(fused, kSentinel);
                push32(fused, x);
                fused.insert(fused.end(), {PUSH1, static_cast<uint8_t>(s), op, PUSH1, 0, MSTORE,
                                              PUSH1, 32, MSTORE, PUSH1, 64, PUSH1, 0, RETURN});
                const auto a = r.run(fused, 1000000);
                const auto b = r.run(program(op, x, s), 1000000);
                REQUIRE(a.status == EVMC_SUCCESS);
                REQUIRE(a.output == b.output);
                REQUIRE(a.gas_left == b.gas_left);  // PUSH2 and PUSH1 both cost 3
                const uint256 want = op == SHL ? x << uint256{s} : x >> uint256{s};
                REQUIRE(bytes(b.output.begin(), b.output.begin() + 32) == be32(want));
            }
        }
    }
}

TEST_CASE("SHL and SHR of a stack operand: gas and failures", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const uint8_t op : {SHL, SHR}) {
            // PUSH32 PUSH32 OP: 3 + 3 + 3 gas, then the implicit STOP.
            bytes two;
            push32(two, 0x1234);
            push32(two, 5);
            two.push_back(op);
            for (const auto rev : {EVMC_PETERSBURG, EVMC_ISTANBUL, EVMC_CANCUN,
                     EVMC_PRAGUE}) {
                for (int64_t gas = 0; gas <= 12; ++gas) {
                    const auto out = r.run(two, gas, rev);
                    if (gas < 9) {
                        REQUIRE(out.status == EVMC_OUT_OF_GAS);
                        REQUIRE(out.gas_left == 0);
                    } else {
                        REQUIRE(out.status == EVMC_SUCCESS);
                        REQUIRE(out.gas_left == gas - 9);
                    }
                }
                // A shift of 256 or more costs the same.
                bytes big;
                push32(big, 0x1234);
                push32(big, uint256{1} << 200);
                big.push_back(op);
                REQUIRE(r.run(big, 8, rev).status == EVMC_OUT_OF_GAS);
                const auto ok = r.run(big, 9, rev);
                REQUIRE(ok.status == EVMC_SUCCESS);
                REQUIRE(ok.gas_left == 0);
                // Large gas limits.
                for (const int64_t gas :
                    {int64_t{1} << 31, (int64_t{1} << 32) + 9, int64_t{1} << 50}) {
                    const auto out = r.run(two, gas, rev);
                    REQUIRE(out.status == EVMC_SUCCESS);
                    REQUIRE(out.gas_left == gas - 9);
                }
            }
            // Stack underflow with no item and with one: the operands are pushed by PUSH32, so no
            // fusion is involved; the shift fails before it reads or writes a slot.
            const bytes none{op};
            bytes one;
            push32(one, 7);
            one.push_back(op);
            for (const auto rev : {EVMC_PETERSBURG, EVMC_CANCUN}) {
                const auto a = r.run(none, 1000, rev);
                REQUIRE(a.status == EVMC_STACK_UNDERFLOW);
                REQUIRE(a.gas_left == 0);
                const auto b = r.run(one, 1000, rev);
                REQUIRE(b.status == EVMC_STACK_UNDERFLOW);
                REQUIRE(b.gas_left == 0);
            }
            // Before Constantinople the opcode does not exist, with the operands there or not.
            for (const auto rev : {EVMC_FRONTIER, EVMC_HOMESTEAD, EVMC_TANGERINE_WHISTLE,
                     EVMC_SPURIOUS_DRAGON, EVMC_BYZANTIUM}) {
                for (const auto& code : {none, one, two}) {
                    const auto out = r.run(code, 1000, rev);
                    REQUIRE(out.status == EVMC_UNDEFINED_INSTRUCTION);
                    REQUIRE(out.gas_left == 0);
                }
            }
        }
    }
}

TEST_CASE("SHL and SHR of a stack operand: a full stack and a chain", "[shift_stack]") {
    for (const bool cgoto : {true, false}) {
        Runner r{cgoto};
        for (const uint8_t op : {SHL, SHR}) {
            // 1022 items, then the operands pushed on top reach 1024 and the shift leaves 1023.
            bytes code;
            for (int i = 0; i < 1022; ++i)
                code.insert(code.end(), {PUSH1, static_cast<uint8_t>(i)});
            push32(code, 0x8000000000000001);
            push_shift(code, 100);
            code.push_back(op);
            code.insert(code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, PUSH1, 0, RETURN});
            const auto out = r.run(code, 1000000);
            REQUIRE(out.status == EVMC_SUCCESS);
            REQUIRE(out.output.size() == 32);
            const uint256 x = 0x8000000000000001;
            const uint256 want = op == SHL ? x << uint256{100} : x >> uint256{100};
            REQUIRE(out.output == be32(want));
        }
        // A chain of shifts through the same slot: (((x << a) >> b) << c) >> d.
        std::mt19937_64 rng{41};
        for (int i = 0; i < 300; ++i) {
            const uint256 x = mixed(rng);
            const uint256 sh[4] = {rng() % 300, rng() % 300, rng() % 300, mixed(rng)};
            bytes code;
            push32(code, kSentinel);
            push32(code, x);
            uint256 want = x;
            const uint8_t ops[4] = {SHL, SHR, SHL, SHR};
            for (int k = 0; k < 4; ++k) {
                push_shift(code, sh[k]);
                code.push_back(ops[k]);
                want = model(ops[k], want, sh[k]);
            }
            code.insert(
                code.end(), {PUSH1, 0, MSTORE, PUSH1, 32, MSTORE, PUSH1, 64, PUSH1, 0, RETURN});
            const auto out = r.run(code, 1000000);
            REQUIRE(out.status == EVMC_SUCCESS);
            REQUIRE(bytes(out.output.begin(), out.output.begin() + 32) == be32(want));
            REQUIRE(bytes(out.output.begin() + 32, out.output.end()) == be32(kSentinel));
        }
    }
}
