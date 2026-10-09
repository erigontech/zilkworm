// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// MLOAD, MSTORE, MSTORE8, CALLDATALOAD and KECCAK256 against a model of the Yellow Paper rules, at
// the boundaries of the memory and the calldata. The rv32 dispatch tests the memory with one
// compare against a limit kept next to its size (Memory::limit32()) and the calldata against one
// kept next to its size (ExecutionState::cd_lim), and hashes 64 bytes inside the memory without
// the general path. Built with -DEVMONE_RV32_DISPATCH_TEST (the rv32 test configuration), the
// native build compiles those paths on the host; without it the tests still hold, on the general
// code.
//
// The model is a small interpreter of the opcodes the programs use (PUSH, POP, MSIZE, MLOAD,
// MSTORE, MSTORE8, CALLDATALOAD, KECCAK256, RETURN, STOP) with the gas of Cancun: stack checks
// first, then the base cost, then the memory and word costs. It is written from the rules alone
// (offsets and sizes as 256-bit numbers, the expansion cost from the word count), so an access at
// an offset near 2^32 that a 32-bit sum would wrap, a size or offset above 32 bits, a limit that
// disagrees with the size and a gas charged twice or not at all show as a different status, gas
// left or output. Programs are directed (every boundary of each opcode, at memory sizes from 0 to
// 0x120 and calldata of 0 to 65 bytes) and random (the offsets drawn around the live size of the
// memory and the calldata). Each runs on one VM in a row, so that its per-depth state is reused
// by a program of another memory and calldata size, at the exact gas of the model, one below it,
// and at random lower values, and a CALL test reuses the state of depth 1 between callees.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/advanced_analysis.hpp>
#include <evmone/evmone.h>
#include <evmone/execution_state.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <intx/intx.hpp>

namespace {

using intx::uint256;
using bytes = std::vector<uint8_t>;

enum : uint8_t {
    STOP = 0x00, SUB = 0x03, SWAP1 = 0x90, KECCAK256 = 0x20, CALLDATALOAD = 0x35, POP = 0x50, MLOAD = 0x51,
    MSTORE = 0x52, MSTORE8 = 0x53, MSIZE = 0x59, GAS = 0x5a, PUSH1 = 0x60, PUSH32 = 0x7f,
    CALL = 0xf1, RETURN = 0xf3
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
    bool operator==(const Outcome&) const = default;
};

constexpr int64_t kAmple = 10'000'000;

// ---------------------------------------------------------------- assembler

bytes be_bytes(const uint256& v, unsigned n) {
    bytes out(n);
    for (unsigned i = 0; i < n; ++i)
        out[n - 1 - i] = static_cast<uint8_t>(v[i / 8] >> (8 * (i % 8)));
    return out;
}

unsigned min_width(const uint256& v) {
    unsigned n = 1;
    for (unsigned i = 1; i < 32; ++i)
        if (v >> (8 * i) != 0)
            n = i + 1;
    return n;
}

struct Asm {
    bytes code;
    // Pushes v in its shortest form, or (full) as PUSH32.
    Asm& push(const uint256& v, bool full = false) {
        const unsigned n = full ? 32 : min_width(v);
        code.push_back(static_cast<uint8_t>(PUSH1 + n - 1));
        const auto b = be_bytes(v, n);
        code.insert(code.end(), b.begin(), b.end());
        return *this;
    }
    Asm& op(uint8_t o) {
        code.push_back(o);
        return *this;
    }
};

// ------------------------------------------------------------------- model

struct Model {
    static constexpr uint64_t kHuge = uint64_t{1} << 36;  // an end past this costs more than any gas

    bytes mem;
    std::vector<uint256> stack;
    int64_t gas;
    bytes calldata;
    Outcome out;

    static uint64_t mem_cost(uint64_t words) { return 3 * words + words * words / 512; }

    // Charges the expansion for size bytes at offset; false when it cannot be paid.
    bool expand(const uint256& offset, const uint256& size) {
        if (size == 0)
            return true;
        if (offset > kHuge || size > kHuge)
            return false;
        const uint64_t end = static_cast<uint64_t>(offset) + static_cast<uint64_t>(size);
        if (end > kHuge)
            return false;
        const uint64_t words = (end + 31) / 32;
        const uint64_t have = mem.size() / 32;
        if (words > have) {
            const uint64_t cost = mem_cost(words) - mem_cost(have);
            if (cost > static_cast<uint64_t>(gas))
                return false;
            gas -= static_cast<int64_t>(cost);
            mem.resize(words * 32, 0);
        }
        return true;
    }

    bool charge(int64_t cost) {
        gas -= cost;
        return gas >= 0;
    }

    void fail(evmc_status_code s) {
        out = {s, 0, {}};
    }

    Outcome run(const bytes& code, int64_t gas_in, const bytes& input) {
        mem.clear();
        stack.clear();
        gas = gas_in;
        calldata = input;
        const auto pop = [&] {
            const auto v = stack.back();
            stack.pop_back();
            return v;
        };
        size_t pc = 0;
        while (pc < code.size()) {
            const uint8_t o = code[pc];
            size_t need = 0;
            int64_t cost = 3;
            switch (o) {
            case STOP: out = {EVMC_SUCCESS, gas, {}}; return out;
            case POP: need = 1; cost = 2; break;
            case MSIZE: cost = 2; break;
            case MLOAD: case CALLDATALOAD: need = 1; break;
            case MSTORE: case MSTORE8: need = 2; break;
            case KECCAK256: need = 2; cost = 30; break;
            case RETURN: need = 2; cost = 0; break;
            default:
                REQUIRE(o >= PUSH1);
                REQUIRE(o <= PUSH32);
                break;
            }
            if (stack.size() < need) {
                fail(EVMC_STACK_UNDERFLOW);
                return out;
            }
            if (!charge(cost)) {
                fail(EVMC_OUT_OF_GAS);
                return out;
            }
            ++pc;
            switch (o) {
            case POP: pop(); break;
            case MSIZE: stack.push_back(mem.size()); break;
            case MLOAD: {
                const auto off = pop();
                if (!expand(off, 32)) { fail(EVMC_OUT_OF_GAS); return out; }
                stack.push_back(intx::be::unsafe::load<uint256>(&mem[static_cast<size_t>(off)]));
                break;
            }
            case MSTORE: {
                const auto off = pop();
                const auto v = pop();
                if (!expand(off, 32)) { fail(EVMC_OUT_OF_GAS); return out; }
                const auto b = be_bytes(v, 32);
                std::memcpy(&mem[static_cast<size_t>(off)], b.data(), 32);
                break;
            }
            case MSTORE8: {
                const auto off = pop();
                const auto v = pop();
                if (!expand(off, 1)) { fail(EVMC_OUT_OF_GAS); return out; }
                mem[static_cast<size_t>(off)] = static_cast<uint8_t>(v[0]);
                break;
            }
            case CALLDATALOAD: {
                const auto off = pop();
                bytes w(32, 0);
                if (off < calldata.size())
                    for (size_t i = 0; i < 32 && static_cast<size_t>(off) + i < calldata.size(); ++i)
                        w[i] = calldata[static_cast<size_t>(off) + i];
                stack.push_back(intx::be::unsafe::load<uint256>(w.data()));
                break;
            }
            case KECCAK256: {
                const auto off = pop();
                const auto size = pop();
                if (!expand(off, size)) { fail(EVMC_OUT_OF_GAS); return out; }
                if (!charge(6 * static_cast<int64_t>((static_cast<uint64_t>(size) + 31) / 32))) {
                    fail(EVMC_OUT_OF_GAS);
                    return out;
                }
                const auto h = ethash::keccak256(
                    size == 0 ? nullptr : &mem[static_cast<size_t>(off)], static_cast<size_t>(size));
                stack.push_back(intx::be::load<uint256>(h));
                break;
            }
            case RETURN: {
                const auto off = pop();
                const auto size = pop();
                if (!expand(off, size)) { fail(EVMC_OUT_OF_GAS); return out; }
                out = {EVMC_SUCCESS, gas, {}};
                if (size != 0)
                    out.output.assign(mem.begin() + static_cast<std::ptrdiff_t>(static_cast<size_t>(off)),
                        mem.begin() + static_cast<std::ptrdiff_t>(static_cast<size_t>(off) + static_cast<size_t>(size)));
                return out;
            }
            default: {
                const size_t n = o - PUSH1 + 1;
                bytes w(32, 0);
                std::copy_n(code.begin() + static_cast<std::ptrdiff_t>(pc), n,
                    w.begin() + static_cast<std::ptrdiff_t>(32 - n));
                pc += n;
                stack.push_back(intx::be::unsafe::load<uint256>(w.data()));
                break;
            }
            }
        }
        out = {EVMC_SUCCESS, gas, {}};
        return out;
    }
};

// ------------------------------------------------------------------ engine

struct Engine {
    evmc::VM vm{evmc_create_evmone()};
    evmc::MockedHost host;

    Engine(bool cgoto, bool advanced) {
        if (advanced)
            REQUIRE(vm.set_option("advanced", "") == EVMC_SET_OPTION_SUCCESS);
        else if (!cgoto)
            REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    }

    Outcome run(const bytes& code, int64_t gas, const bytes& input) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        msg.input_data = input.data();
        msg.input_size = input.size();
        const auto r = vm.execute(host, EVMC_CANCUN, msg, code.data(), code.size());
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

std::string hexs(const bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (const auto x : b) {
        s += d[x >> 4];
        s += d[x & 15];
    }
    return s;
}

// A digest of every outcome the engine gave, printed at exit when MEMCHECK_DIGEST is set: the
// programs and gas values are fixed by seeds, so the digests of two builds are equal exactly when
// the builds gave one outcome to each program (this is how a change is compared with the code it
// replaces, which has no model of its own to be checked against: the base run passes the same
// tests).
struct Digest {
    uint64_t h = 1469598103934665603ull;
    size_t runs = 0;
    void add(uint64_t x) {
        for (int i = 0; i < 8; ++i) {
            h ^= (x >> (8 * i)) & 0xff;
            h *= 1099511628211ull;
        }
    }
    ~Digest() {
        if (std::getenv("MEMCHECK_DIGEST") != nullptr)
            std::fprintf(stderr, "memcheck digest %016llx over %zu runs\n",
                static_cast<unsigned long long>(h), runs);
    }
} g_digest;

// One program at the model's exact gas, one below it, and a few other values: the engine must give
// the model's status, gas left and output. Returns the number of runs.
size_t check(Engine& e, Model& m, const bytes& code, const bytes& input, std::mt19937_64& rng,
    int64_t extra_gas = -1) {
    const auto ample = m.run(code, kAmple, input);
    std::vector<int64_t> gases = {kAmple};
    if (ample.status == EVMC_SUCCESS) {
        const int64_t used = kAmple - ample.gas_left;
        gases.push_back(used);
        gases.push_back(used - 1);
        gases.push_back(used + 1);
        if (used > 3) {
            gases.push_back(static_cast<int64_t>(rng() % static_cast<uint64_t>(used)));
            gases.push_back(used - 1 - static_cast<int64_t>(rng() % 12));
        }
    } else {
        // A failure: find where by lowering the gas a little below what is enough for the prefix.
        gases.push_back(static_cast<int64_t>(rng() % 200));
    }
    if (extra_gas >= 0)
        gases.push_back(extra_gas);
    for (auto g : gases) {
        if (g < 0)
            continue;
        const auto expected = m.run(code, g, input);
        const auto got = e.run(code, g, input);
        g_digest.add(static_cast<uint64_t>(got.status));
        g_digest.add(static_cast<uint64_t>(got.gas_left));
        for (const auto x : got.output)
            g_digest.add(x);
        ++g_digest.runs;
        if (!(got == expected)) {
            FAIL("code " << hexs(code) << " calldata " << input.size() << " bytes, gas " << g
                         << ": got status " << got.status << " gas_left " << got.gas_left
                         << " output " << hexs(got.output) << ", model status " << expected.status
                         << " gas_left " << expected.gas_left << " output " << hexs(expected.output));
        }
    }
    return gases.size();
}

bytes pattern(size_t n, uint8_t seed) {
    bytes b(n);
    for (size_t i = 0; i < n; ++i)
        b[i] = static_cast<uint8_t>(seed + 7 * i + (i >> 3));
    return b;
}

// Memory of exactly `size` bytes (a multiple of 32), filled with a pattern: one MSTORE at size-32,
// and, below it, MSTOREs of pattern words.
Asm grow_to(size_t size, uint8_t seed) {
    Asm a;
    for (size_t at = 0; at < size; at += 32) {
        // Words of distinct bytes so that a read at a wrong offset shows.
        a.push(intx::be::unsafe::load<uint256>(pattern(32, static_cast<uint8_t>(seed + at)).data()), true);
        a.push(at);
        a.op(MSTORE);
    }
    return a;
}

// RETURN of the first 64 bytes of the memory (grows it to 64 when smaller).
Asm& finish(Asm& a) {
    return a.push(64).push(0).op(RETURN);
}

const uint256 kTop = ~uint256{0};

// Offsets and sizes around a boundary b (the live size or the calldata size) and the 32-bit edge.
std::vector<uint256> edge_values(size_t b) {
    std::vector<uint256> v;
    for (int64_t d = -66; d <= 66; ++d) {
        const int64_t x = static_cast<int64_t>(b) + d;
        if (x >= 0)
            v.emplace_back(x);
    }
    for (uint64_t base : {uint64_t{1} << 32, uint64_t{1} << 31, uint64_t{0xffffff00}, uint64_t{1} << 16})
        for (int d = -66; d <= 66; ++d)
            v.emplace_back(base + static_cast<uint64_t>(static_cast<int64_t>(d)));
    for (const uint64_t x : {uint64_t{255}, uint64_t{256}, uint64_t{257}, uint64_t{0xffffffff}, uint64_t{0xffffffffff},
             uint64_t{1} << 40, uint64_t{1} << 63, ~uint64_t{0}})
        v.emplace_back(x);
    // Each high word on its own (a test of one word less than all seven is a bug the others hide).
    for (unsigned k = 1; k < 8; ++k)
        v.push_back(uint256{1} << (32 * k));
    v.push_back(uint256{1} << 255);
    v.push_back(kTop);
    v.push_back(kTop - 31);
    return v;
}

}  // namespace

TEST_CASE("MLOAD, MSTORE and MSTORE8 at the edges of the memory", "[memcheck]") {
    std::mt19937_64 rng{11};
    for (const auto config : {0, 1, 2}) {
        Engine e{config != 1, config == 2};
        Model m;
        size_t runs = 0;
        for (const size_t msize : {size_t{0}, size_t{32}, size_t{64}, size_t{96}, size_t{0x100}, size_t{0x120}}) {
            const auto vals = edge_values(msize);
            for (const uint8_t op : {MLOAD, MSTORE, MSTORE8}) {
                for (const auto& off : vals) {
                    // The offset in its shortest form (PUSH1 offsets are the fused form) and as PUSH32.
                    for (const bool full : {false, true}) {
                        auto a = grow_to(msize, 1);
                        if (op == MLOAD) {
                            a.push(off, full).op(MLOAD);
                            a.push(0).op(MSTORE);
                        } else {
                            a.push(uint256{0x1122334455667788, 0x99aabbccddeeff00, 0x0123456789abcdef, 0xfedcba9876543210}, true);
                            a.push(off, full).op(op);
                        }
                        finish(a);
                        runs += check(e, m, a.code, {}, rng);
                    }
                }
            }
        }
        REQUIRE(runs > 20000);
    }
}

TEST_CASE("PUSH1 MLOAD and PUSH1 MSTORE at the edges of a memory of 0x100 and 0x120", "[memcheck]") {
    std::mt19937_64 rng{12};
    Engine e{true, false};
    Model m;
    for (const size_t msize : {size_t{0x100}, size_t{0x120}, size_t{0xe0}, size_t{0x20}, size_t{0}}) {
        for (unsigned off = 0; off < 0x100; ++off) {
            for (const uint8_t op : {MLOAD, MSTORE}) {
                auto a = grow_to(msize, 3);
                if (op == MLOAD)
                    a.push(off).op(MLOAD).push(0).op(MSTORE);
                else
                    a.push(0xcafe, true).push(off).op(MSTORE);
                // The memory afterwards, whole, to see a store outside the checked memory.
                a.op(MSIZE).push(0).op(MSTORE).push(0x140).push(0).op(RETURN);
                check(e, m, a.code, {}, rng);
            }
        }
    }
}

TEST_CASE("CALLDATALOAD at the edges of the calldata", "[memcheck]") {
    std::mt19937_64 rng{13};
    for (const auto config : {0, 1, 2}) {
        Engine e{config != 1, config == 2};
        Model m;
        size_t runs = 0;
        // Calldata sizes in a row of every kind: the state is reused with a limit from the
        // previous size.
        for (const size_t n : {size_t{100}, size_t{0}, size_t{31}, size_t{32}, size_t{33}, size_t{64}, size_t{65},
                 size_t{0}, size_t{1}, size_t{63}, size_t{200}, size_t{4}}) {
            const auto input = pattern(n, 0x40);
            for (const auto& off : edge_values(n)) {
                for (const bool full : {false, true}) {
                    Asm a;
                    a.push(off, full).op(CALLDATALOAD).push(0).op(MSTORE);
                    finish(a);
                    runs += check(e, m, a.code, input, rng);
                }
            }
        }
        REQUIRE(runs > 5000);
    }
}

TEST_CASE("KECCAK256 at the edges of the memory, sizes and indexes", "[memcheck]") {
    std::mt19937_64 rng{14};
    for (const auto config : {0, 1, 2}) {
        Engine e{config != 1, config == 2};
        Model m;
        size_t runs = 0;
        for (const size_t msize : {size_t{0}, size_t{32}, size_t{64}, size_t{96}, size_t{128}, size_t{0x100}}) {
            const auto idx = edge_values(msize);
            std::vector<uint256> sizes = {0, 1, 31, 32, 33, 63, 64, 65, 96, 127, 128, 129, 0x100, 0x101};
            for (const uint256& s : {uint256{1} << 32, (uint256{1} << 32) - 64, uint256{1} << 33, uint256{1} << 64,
                     uint256{1} << 128, uint256{1} << 224, uint256{1} << 255,
                     kTop, kTop - 63, uint256{0xffffffc0}, uint256{0xffffffe0}, uint256{0xffffffff}})
                sizes.push_back(s);
            // 64 plus a single high word, one word at a time: the low word alone is the fast path's.
            for (unsigned k = 1; k < 8; ++k)
                sizes.push_back((uint256{1} << (32 * k)) + 64);
            // Size 64 at every index, the other sizes at the indexes near the memory only.
            for (const auto& s : sizes) {
                for (const auto& i : idx) {
                    if (s != 64 && !(i < msize + 70 || i >= (uint256{1} << 32) - 70))
                        continue;
                    for (const bool full : {false, s != 64 ? false : true}) {
                        auto a = grow_to(msize, 5);
                        a.push(s, full).push(i, full).op(KECCAK256).push(0).op(MSTORE);
                        finish(a);
                        runs += check(e, m, a.code, {}, rng);
                    }
                }
            }
        }
        REQUIRE(runs > 20000);
    }
}

TEST_CASE("KECCAK256 of 64 bytes costs 42 gas inside the memory, once, at any alignment", "[memcheck]") {
    // Against fixed numbers, not the model: the program's whole bill is 98 gas, 42 of it the
    // hash's (30 + 2 words x 6), and 97 gas is out of gas.
    for (const bool cgoto : {true, false}) {
        Engine e{cgoto, false};
        for (unsigned at = 0; at <= 8; ++at) {
            auto a = grow_to(128, 9);
            a.push(64).push(at).op(KECCAK256).op(POP);
            // 4 x (PUSH32 + PUSH1 + MSTORE) = 36, the memory of 4 words = 12, then PUSH1, PUSH1, the
            // hash and POP.
            const int64_t used = 36 + 12 + 3 + 3 + 30 + 12 + 2;
            const auto got = e.run(a.code, used, {});
            CHECK(got.status == EVMC_SUCCESS);
            CHECK(got.gas_left == 0);
            const auto less = e.run(a.code, used - 1, {});
            CHECK(less.status == EVMC_OUT_OF_GAS);
            // The hash itself, as 32 bytes through MSTORE: the digest of the bytes at `at`.
            auto b = grow_to(128, 9);
            b.push(64).push(at).op(KECCAK256).push(0).op(MSTORE).push(32).push(0).op(RETURN);
            Model m;
            const auto expected = m.run(b.code, kAmple, {});
            REQUIRE(expected.status == EVMC_SUCCESS);
            const auto r = e.run(b.code, kAmple, {});
            CHECK(r == expected);
            // The model's memory is the Yellow Paper's: the digest is of the 64 bytes at `at`.
            bytes mem;
            for (size_t w = 0; w < 128; w += 32) {
                const auto p = pattern(32, static_cast<uint8_t>(9 + w));
                mem.insert(mem.end(), p.begin(), p.end());
            }
            const auto h = ethash::keccak256(&mem[at], 64);
            CHECK(r.output == bytes(h.bytes, h.bytes + 32));
        }
    }
}

TEST_CASE("KECCAK256, memory and calldata accesses in random programs", "[memcheck]") {
    for (const auto config : {0, 1, 2}) {
        std::mt19937_64 rng{100 + static_cast<uint64_t>(config)};
        Engine e{config != 1, config == 2};
        Model m;
        size_t runs = 0;
        const size_t programs = 12000;
        for (size_t p = 0; p < programs; ++p) {
            // The calldata of this program (any size from 0 to 130, mostly the edge sizes).
            static constexpr size_t kSizes[] = {0, 1, 31, 32, 33, 63, 64, 65, 96, 100, 129};
            const size_t n = rng() % 3 == 0 ? rng() % 131 : kSizes[rng() % std::size(kSizes)];
            const auto input = pattern(n, static_cast<uint8_t>(rng()));

            Asm a;
            size_t msize = 0;  // the size the memory has if every access so far succeeded
            size_t depth = 0;  // stack items
            // Keeps msize for the offsets drawn around it: a guess, the model is the oracle.
            const auto touch = [&](const uint256& off, size_t len) {
                if (off < (uint256{1} << 20))
                    msize = std::max(msize, (static_cast<size_t>(off) + len + 31) / 32 * 32);
            };
            const auto draw = [&](size_t boundary) -> uint256 {
                const auto pick = rng() % 10;
                if (pick < 6) {
                    // Near the boundary, or near 0 or the 32-bit edge.
                    const auto vals = edge_values(boundary);
                    return vals[rng() % vals.size()];
                }
                if (pick < 8)
                    return uint256{rng() % (msize + 200)};
                if (pick == 8)
                    return uint256{rng() % 0x1000};
                return uint256{rng()} << (rng() % 4 == 0 ? 32 * (rng() % 8) : 0);
            };
            const auto push_val = [&](const uint256& v) {
                a.push(v, rng() % 4 == 0);
                ++depth;
            };
            const size_t len = 2 + rng() % 8;
            for (size_t i = 0; i < len; ++i) {
                const auto kind = rng() % 9;
                if (kind <= 1) {
                    // MSTORE: value, offset
                    push_val(uint256{rng(), rng(), rng(), rng()});
                    const auto off = draw(msize);
                    push_val(off);
                    a.op(MSTORE);
                    depth -= 2;
                    touch(off, 32);
                } else if (kind == 2) {
                    const auto off = draw(msize);
                    push_val(off);
                    a.op(MLOAD);
                    touch(off, 32);
                } else if (kind == 3) {
                    push_val(draw(n));
                    a.op(CALLDATALOAD);
                } else if (kind <= 5) {
                    // KECCAK256: size, offset; size 64 for most.
                    const auto size = rng() % 3 == 0 ? draw(msize) : uint256{64};
                    const auto off = draw(msize);
                    push_val(size);
                    push_val(off);
                    a.op(KECCAK256);
                    --depth;
                    if (size < 4096)
                        touch(off, static_cast<size_t>(size));
                } else if (kind == 6) {
                    push_val(uint256{rng()});
                    const auto off = draw(msize);
                    push_val(off);
                    a.op(MSTORE8);
                    depth -= 2;
                    touch(off, 1);
                } else if (kind == 7) {
                    a.op(MSIZE);
                    ++depth;
                } else if (depth > 0) {
                    a.op(POP);
                    --depth;
                }
            }
            if (rng() % 8 != 0 && depth > 0) {
                a.push(0).op(MSTORE);
                --depth;
            }
            finish(a);
            runs += check(e, m, a.code, input, rng);
        }
        REQUIRE(runs > programs * 2);
    }
}

namespace {

constexpr evmc::address kCaller{{0xaa, 1}};
constexpr evmc::address kCallee{{0xbb, 2}};
constexpr evmc::address kCallee2{{0xcc, 3}};
constexpr evmc::address kSender{{0x5e, 4}};

struct EmptyView final : evmone::state::StateView {
    std::optional<Account> get_account(const evmc::address&) const noexcept override { return std::nullopt; }
    evmc::bytes_view get_account_code(const evmc::address&) const noexcept override { return {}; }
    evmc::bytes32 get_storage(const evmc::address&, const evmc::bytes32&) const noexcept override { return {}; }
};

struct NoHashes final : evmone::state::BlockHashes {
    evmc::bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// The caller at kCaller runs `code`; kCallee and kCallee2 run the two given programs.
Outcome run_calls(const bytes& code, const bytes& callee, const bytes& callee2) {
    EmptyView view;
    NoHashes hashes;
    evmone::state::State state{view};
    const auto add = [&state](const evmc::address& a, const bytes& c) {
        evmone::state::Account acc;
        acc.code = evmc::bytes(c.data(), c.size());
        std::memcpy(acc.code_hash.bytes, ethash::keccak256(c.data(), c.size()).bytes, 32);
        acc.balance = 1000000;
        state.insert(a, std::move(acc));
    };
    add(kCaller, code);
    add(kCallee, callee);
    add(kCallee2, callee2);
    evmone::state::Account sender;
    sender.balance = 1000000;
    state.insert(kSender, std::move(sender));

    evmc::VM vm{new evmone::VM{}};
    evmone::state::BlockInfo block;
    block.gas_limit = 30000000;
    block.number = 1;
    block.timestamp = 1;
    evmone::state::Transaction tx;
    evmone::state::Host host{EVMC_PRAGUE, vm, state, block, hashes, tx};

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 10000000;
    msg.recipient = kCaller;
    msg.code_address = kCaller;
    msg.sender = kSender;
    const auto r = host.call(msg);
    return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
}

// CALL(gas, to, 0, in, in_size, out, 64): the callee's output, up to 64 bytes, copied to out.
Asm& call(Asm& a, const evmc::address& to, uint64_t in, uint64_t in_size, uint64_t out) {
    a.push(64).push(out).push(in_size).push(in).push(0);
    a.push(intx::be::load<uint256>(to)).push(1000000).op(CALL).op(POP);
    return a;
}

}  // namespace

TEST_CASE("the state of one depth is reused by calls of other memory and calldata sizes", "[memcheck]") {
    // The caller's memory is all 0xff (so that a calldata limit left over from a longer calldata
    // reads its bytes where the zero padding of a short one is due).
    Asm filler;
    for (unsigned w = 0; w < 8; ++w)
        filler.push(~uint256{0}, true).push(32 * w).op(MSTORE);

    // Callee 1: grows its memory to 1 KiB and returns CALLDATALOAD(64).
    const auto callee1 = Asm{}.push(1).push(0x3e0).op(MSTORE).push(64).op(CALLDATALOAD).push(0).op(MSTORE)
                             .push(32).push(0).op(RETURN).code;
    // Callee 2: returns the first word of its calldata and, after it, the gas between two GAS
    // readings around PUSH1 0 MLOAD POP: 13 when the frame's memory starts empty (the MLOAD pays 3
    // for the expansion to 32 bytes), 10 when a limit left over from callee 1 says it holds 1 KiB.
    const auto callee2 = Asm{}.op(GAS).push(0).op(MLOAD).op(POP).op(GAS).op(SWAP1).op(SUB)
                             .push(0x20).op(MSTORE).push(0).op(CALLDATALOAD).push(0).op(MSTORE)
                             .push(64).push(0).op(RETURN).code;
    // The same, run first as the only frame under the caller (the reference), at depth 1.
    const auto reference = [&](uint64_t in_size) {
        Asm c;
        c.code = filler.code;
        call(c, kCallee2, 0, in_size, 0x100);
        c.push(0x40).push(0x100).op(RETURN);
        return run_calls(c.code, callee1, callee2);
    };
    for (const uint64_t first : {uint64_t{100}, uint64_t{64}, uint64_t{33}}) {
        for (const uint64_t second : {uint64_t{0}, uint64_t{4}, uint64_t{31}, uint64_t{32}}) {
            Asm c;
            c.code = filler.code;
            call(c, kCallee, 0, first, 0x200);   // depth 1: a calldata of `first` bytes, a memory of 1 KiB
            call(c, kCallee2, 0, second, 0x100); // depth 1 again: `second` bytes, an empty memory
            c.push(0x40).push(0x100).op(RETURN);
            const auto got = run_calls(c.code, callee1, callee2);
            const auto expected = reference(second);
            REQUIRE(got.status == EVMC_SUCCESS);
            REQUIRE(expected.status == EVMC_SUCCESS);
            REQUIRE(got.output.size() == 64);
            CHECK(got.output == expected.output);
            // The calldata word is zero-padded after the `second` bytes (0xff before them).
            for (size_t i = 0; i < 32; ++i)
                CHECK(got.output[i] == (i < second ? 0xff : 0x00));
            CHECK(got.output[63] == 13);
        }
    }
}

TEST_CASE("the memory limit follows the size through growth and clear", "[memcheck]") {
    // limit32() is the size minus 31 (0 while empty) after every change of the size, and the new
    // extent is zero even when the bytes under it were written before a clear. Release builds
    // drop the asserts inside Memory, so this reads the limit itself.
    std::mt19937_64 rng{21};
    evmone::Memory mem;
    const auto expected = [](size_t size) { return size != 0 ? size - 31 : size_t{0}; };
    REQUIRE(mem.size() == 0);
    REQUIRE(mem.limit32() == 0);
    for (int round = 0; round < 400; ++round) {
        if (rng() % 7 == 0) {
            for (size_t i = 0; i < mem.size(); ++i)
                mem[i] = 0xff;
            mem.clear();
            REQUIRE(mem.size() == 0);
            REQUIRE(mem.limit32() == 0);
        }
        const size_t old = mem.size();
        // The two fused writers of the MSTORE fast path take their limits as constants: a store
        // at the end of the memory (any size, 0 included, within the capacity) and the store at
        // 0x40 of the empty memory.
        const auto pick = rng() % 4;
        if (pick == 0 && old + 32 <= mem.capacity()) {
            // The bytes past the size are dirty (a frame's buffer is reused). A store that starts
            // below the end leaves the new word zero for the part it does not cover; one that
            // starts at the end covers it whole.
            for (size_t i = old; i < old + 32; ++i)
                mem[i] = 0xff;
            const size_t offset = old - (old != 0 && rng() % 2 == 0 ? rng() % 32 : 0);
            mem.grow_word_for_store(offset);
            if (offset != old)
                for (size_t i = old; i < old + 32; ++i)
                    REQUIRE(mem[i] == 0);
            REQUIRE(mem.size() == old + 32);
            REQUIRE(mem.limit32() == expected(old + 32));
            REQUIRE(mem.limit32() == old + 1);
            for (size_t i = old; i < old + 32; i += 5)
                mem[i] = static_cast<uint8_t>(i | 1);
            continue;
        }
        if (pick == 1 && old == 0) {
            mem.grow_empty_for_store_at_64();
            REQUIRE(mem.size() == 96);
            REQUIRE(mem.limit32() == expected(96));
            REQUIRE(mem.limit32() == 65);
            for (size_t i = 0; i < 64; ++i)
                REQUIRE(mem[i] == 0);
            continue;
        }
        // One word, a few words, a page or more (the capacity grows).
        static constexpr size_t kSteps[] = {1, 1, 1, 2, 3, 7, 64, 129, 1100};
        const size_t size = mem.size() + 32 * kSteps[rng() % std::size(kSteps)];
        mem.grow(size);
        REQUIRE(mem.size() == size);
        REQUIRE(mem.limit32() == expected(size));
        for (size_t i = old; i < size; ++i)
            REQUIRE(mem[i] == 0);
        for (size_t i = old; i < size; i += 5)
            mem[i] = static_cast<uint8_t>(i | 1);
    }
}

TEST_CASE("the calldata limit follows the message of every kind of state", "[memcheck]") {
    const auto expected = [](size_t size) { return size >= 32 ? size - 31 : size_t{0}; };
    const evmc_host_interface host_interface{};
    const uint8_t code[]{0x00};
    const evmc::bytes_view code_view{code, std::size(code)};
    static constexpr size_t kSizes[] = {0, 1, 31, 32, 33, 63, 64, 65, 100, 0xffff, 0x7fffffff, 0xffffffff};

    // The default state is safe: the empty memory and no calldata limit send every access down the
    // checks that read the sizes.
    const evmone::ExecutionState fresh;
    CHECK(fresh.cd_lim == 0);
    CHECK(fresh.memory.limit32() == 0);

    evmone::ExecutionState reused;
    for (const size_t n : kSizes) {
        evmc_message msg{};
        msg.input_size = n;
        const evmone::ExecutionState constructed{msg, EVMC_CANCUN, host_interface, nullptr, code_view};
        CHECK(constructed.cd_lim == expected(n));
        const evmone::advanced::AdvancedExecutionState advanced{msg, EVMC_CANCUN, host_interface, nullptr, code_view};
        CHECK(advanced.cd_lim == expected(n));
        // The state of a depth reused after another message: grown memory, a longer calldata.
        reused.memory.grow(reused.memory.size() + 64);
        reused.reset(msg, EVMC_CANCUN, host_interface, nullptr, code_view);
        CHECK(reused.cd_lim == expected(n));
        CHECK(reused.memory.size() == 0);
        CHECK(reused.memory.limit32() == 0);
    }
}
