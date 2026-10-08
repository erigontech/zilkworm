// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// evmone runs legacy code where it lies, without the padded copy, when the code is inside the
// region the host registered (set_in_place_code_region()) and the 33 bytes after it read zero.
// The first case pins down when it does: a nonzero byte anywhere in those 33 bytes, at every
// alignment of the code's end, makes it copy, and bytes just before or past them do not matter.
// The second runs codes both ways, status, gas left, refund, output, logs and storage compared:
// codes cut off inside each PUSH, without a final STOP, with a JUMPDEST in the last byte and
// jumps to it and past it, cut off inside the PUSH4 of a selector test, every one-byte code, a
// 24576-byte code and random ones. In place, the 33 zero bytes are followed by opcodes that
// would change the outcome if the interpreter read them. Built with -DEVMONE_RV32_DISPATCH_TEST
// (the native test build), the in-place path, the lazy byte-map scan and the rv32 dispatch with
// its fusions run on the host; without it, there is no in-place path to test.

#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/baseline.hpp>
#include <evmone/evmone.h>

#if EVMONE_IN_PLACE_CODE

namespace {

using bytes = std::vector<uint8_t>;
using evmone::baseline::set_in_place_code_region;

constexpr size_t kPadding = 33;

/// No case leaves a region behind.
struct RegionGuard {
    RegionGuard() { set_in_place_code_region(nullptr, nullptr); }
    ~RegionGuard() { set_in_place_code_region(nullptr, nullptr); }
};

bool analyzed_in_place(const uint8_t* code, size_t size) {
    const evmc::bytes_view view{code, size};
    return evmone::baseline::analyze(view).code().data() == view.data();
}

/// A code placed at a chosen alignment, followed by kPadding zero bytes and then by `after`.
struct Placed {
    bytes buf;
    size_t at;
    size_t size;

    Placed(const bytes& code, size_t misalign, const bytes& after) : size{code.size()} {
        at = 8 + misalign;
        buf.assign(at + code.size() + kPadding + after.size() + 8, 0);
        std::memcpy(buf.data() + at, code.data(), code.size());
        std::memcpy(buf.data() + at + code.size() + kPadding, after.data(), after.size());
    }
    const uint8_t* code() const { return buf.data() + at; }
    void register_region() const { set_in_place_code_region(code(), code() + size); }
};

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    int64_t gas_refund = 0;
    bytes output;
    std::vector<evmc::MockedHost::log_record> logs;
    std::map<evmc::bytes32, evmc::bytes32> storage;
    size_t calls = 0;
    bool operator==(const Outcome&) const = default;
};

constexpr evmc::address kSelf{0x5e};

Outcome run(const uint8_t* code, size_t size, evmc_revision rev, bool cgoto) {
    evmc::VM vm{evmc_create_evmone()};
    if (!cgoto)
        REQUIRE(vm.set_option("cgoto", "no") == EVMC_SET_OPTION_SUCCESS);
    evmc::MockedHost host;
    static constexpr uint8_t kInput[36] = {0xa9, 0x05, 0x9c, 0xbb, 1, 2, 3};
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 300'000;
    msg.recipient = kSelf;
    msg.input_data = kInput;
    msg.input_size = sizeof(kInput);
    const auto r = vm.execute(host, rev, msg, code, size);
    Outcome o{r.status_code, r.gas_left, r.gas_refund,
        bytes(r.output_data, r.output_data + r.output_size), host.recorded_logs, {},
        host.recorded_calls.size()};
    if (const auto it = host.accounts.find(kSelf); it != host.accounts.end())
        for (const auto& [key, value] : it->second.storage)
            o.storage[key] = value.current;
    return o;
}

/// Runs the code in place, followed by kPadding zeros and then `after`, and as a copy.
void check_same(const bytes& code, const bytes& after, size_t misalign = 0) {
    RegionGuard guard;
    const Placed p{code, misalign, after};
    for (const auto rev : {EVMC_FRONTIER, EVMC_CANCUN})
    {
        for (const bool cgoto : {true, false})
        {
            p.register_region();
            REQUIRE(analyzed_in_place(p.code(), p.size));
            const auto in_place = run(p.code(), p.size, rev, cgoto);
            set_in_place_code_region(nullptr, nullptr);
            REQUIRE_FALSE(analyzed_in_place(p.code(), p.size));
            const auto copied = run(p.code(), p.size, rev, cgoto);
            INFO("size " << code.size() << " rev " << rev << " cgoto " << cgoto);
            CHECK(in_place == copied);
        }
    }
}

// Opcodes past the padding that would show if read: a JUMPDEST for a jump past the end, PUSHes
// and LOGs and INVALID for an opcode walk.
const bytes kAfter{0x5b, 0xa0, 0x5b, 0x60, 0xfe, 0x5b, 0x7f, 0x01, 0x5b, 0xff, 0x5b, 0xfe};

enum : uint8_t {
    STOP = 0x00, ADD = 0x01, EQ = 0x14, ISZERO = 0x15, SHR = 0x1c, CALLDATALOAD = 0x35,
    CODESIZE = 0x38, CODECOPY = 0x39, POP = 0x50, MLOAD = 0x51, MSTORE = 0x52, SLOAD = 0x54,
    SSTORE = 0x55, JUMP = 0x56, JUMPI = 0x57, PC = 0x58, GAS = 0x5a, JUMPDEST = 0x5b,
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH4 = 0x63, PUSH32 = 0x7f, DUP1 = 0x80, SWAP1 = 0x90,
    LOG1 = 0xa1, RETURN = 0xf3, REVERT = 0xfd, INVALID = 0xfe
};

/// Stores the top item, the gas left and the code size, so that the run shows where it ended.
bytes observe() {
    return {PUSH1, 0, SSTORE, GAS, PUSH1, 1, SSTORE, CODESIZE, PUSH1, 2, SSTORE};
}

bytes random_code(std::mt19937_64& rng, size_t size) {
    static constexpr uint8_t kPlain[] = {ADD, 0x02, 0x03, 0x10, 0x11, EQ, ISZERO, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, SHR, 0x1d, CALLDATALOAD, CODESIZE, POP, PC, GAS, DUP1, 0x81,
        0x82, 0x83, SWAP1, 0x91, 0x92, 0x5f, 0x30, 0x32, 0x33, 0x34, 0x36};
    bytes code;
    auto u = [&](uint64_t n) { return static_cast<size_t>(rng() % n); };
    while (code.size() < size)
    {
        switch (u(16))
        {
        case 0:
        case 1:
        case 2:
        {
            const auto n = u(32) + 1;
            code.push_back(static_cast<uint8_t>(PUSH1 + n - 1));
            for (size_t i = 0; i < n; ++i)
                code.push_back(u(4) == 0 ? uint8_t{JUMPDEST} : static_cast<uint8_t>(rng()));
            break;
        }
        case 3:
            code.push_back(JUMPDEST);
            break;
        case 4:
        case 5:
        {
            // A jump to any position up to past the end.
            const auto dst = u(size + 40);
            if (dst < 256)
                code.insert(code.end(), {PUSH1, static_cast<uint8_t>(dst)});
            else
                code.insert(code.end(),
                    {PUSH2, static_cast<uint8_t>(dst >> 8), static_cast<uint8_t>(dst)});
            code.push_back(u(2) == 0 ? JUMP : JUMPI);
            break;
        }
        case 6:
            code.insert(code.end(), {PUSH1, static_cast<uint8_t>(u(64)), u(2) == 0 ? MSTORE : MLOAD});
            break;
        case 7:
            code.insert(code.end(), {PUSH1, static_cast<uint8_t>(u(4)), u(2) == 0 ? SSTORE : SLOAD});
            break;
        case 8:
            code.insert(code.end(), {PUSH1, 64, PUSH1, 0, PUSH1, 0, CODECOPY});
            break;
        case 9:
            code.insert(code.end(), {PUSH1, 32, PUSH1, 0, LOG1});
            break;
        case 10:
        {
            // A selector test: DUP1 PUSH4 EQ PUSH2 JUMPI, a fused group in the rv32 dispatch.
            const auto dst = u(size + 8);
            code.insert(code.end(), {PUSH1, 0, CALLDATALOAD, PUSH1, 0xe0, SHR, DUP1, PUSH4, 0xa9,
                0x05, 0x9c, static_cast<uint8_t>(u(2) == 0 ? 0xbb : 0xbc), EQ, PUSH2,
                static_cast<uint8_t>(dst >> 8), static_cast<uint8_t>(dst), JUMPI});
            break;
        }
        case 11:
            code.push_back(u(8) == 0 ? (u(2) == 0 ? RETURN : REVERT) : STOP);
            break;
        case 12:
            code.push_back(static_cast<uint8_t>(rng()));
            break;
        default:
            code.push_back(kPlain[u(sizeof(kPlain))]);
            break;
        }
    }
    code.resize(size);  // Often inside a PUSH.
    return code;
}

}  // namespace

TEST_CASE("in-place code: analyzed in place exactly when the 33 bytes after it read zero",
    "[evmone][in_place_code]") {
    RegionGuard guard;
    for (size_t misalign = 0; misalign < 4; ++misalign)
    {
        for (const size_t size : std::initializer_list<size_t>{0, 1, 2, 3, 4, 5, 7, 8, 9, 31, 32, 33, 64, 65})
        {
            // JUMPDESTs: the code's own bytes are nonzero up to its end.
            Placed p{bytes(size, JUMPDEST), misalign, bytes(8, 0xff)};
            uint8_t* const code = p.buf.data() + p.at;
            uint8_t* const end = code + size;
            INFO("misalign " << misalign << " size " << size);

            p.register_region();
            CHECK(analyzed_in_place(code, size));
            // A nonzero byte from 3 before the end to 35 past it: only the 33 after it count.
            for (ptrdiff_t q = -3; q < 36; ++q)
            {
                uint8_t* const b = end + q;
                const uint8_t saved = *b;
                *b = 0x5b;
                INFO("byte at end + " << q);
                CHECK(analyzed_in_place(code, size) == !(q >= 0 && q < 33));
                *b = saved;
            }

            // The region must hold the whole code: its end may be the code's end.
            set_in_place_code_region(code + 1, end);
            CHECK_FALSE(analyzed_in_place(code, size));
            if (size > 0)
            {
                set_in_place_code_region(code, end - 1);
                CHECK_FALSE(analyzed_in_place(code, size));
            }
            set_in_place_code_region(code - 8, end + 8);
            CHECK(analyzed_in_place(code, size));
            set_in_place_code_region(nullptr, nullptr);
            CHECK_FALSE(analyzed_in_place(code, size));
        }
    }
    // An empty view of no code is never in place, whatever the region.
    set_in_place_code_region(reinterpret_cast<const uint8_t*>(uintptr_t{8}),
        reinterpret_cast<const uint8_t*>(UINTPTR_MAX - 64));
    CHECK_FALSE(analyzed_in_place(nullptr, 0));
}

TEST_CASE("in-place code: JUMPDESTs as in the copy", "[evmone][in_place_code]") {
    RegionGuard guard;
    std::mt19937_64 rng{7};
    for (int i = 0; i < 400; ++i)
    {
        const auto code = random_code(rng, 1 + rng() % 200);
        const Placed p{code, static_cast<size_t>(i % 4), kAfter};
        p.register_region();
        const auto in_place = evmone::baseline::analyze({p.code(), p.size});
        REQUIRE(in_place.code().data() == p.code());
        set_in_place_code_region(nullptr, nullptr);
        const auto copied = evmone::baseline::analyze({p.code(), p.size});
        REQUIRE(copied.code().data() != p.code());
        // Descending: the first query scans the whole code, up to its end.
        for (size_t pos = code.size() + 40; pos-- > 0;)
            CHECK(in_place.check_jumpdest(pos) == copied.check_jumpdest(pos));
    }
}

TEST_CASE("in-place code: execution as in the copy", "[evmone][in_place_code]") {
    // Cut off inside a PUSH of every size, after an observation of the state.
    for (size_t n = 1; n <= 32; ++n)
    {
        for (size_t k = 0; k < n; ++k)
        {
            bytes code = observe();
            code.reserve(code.size() + 1 + n);
            code.push_back(static_cast<uint8_t>(PUSH1 + n - 1));
            code.insert(code.end(), k, JUMPDEST);
            check_same(code, kAfter, (n + k) % 4);
        }
    }
    // No final STOP, or a code of one opcode: every byte value.
    check_same({PUSH1, 1, PUSH1, 2, ADD}, kAfter);
    for (unsigned op = 0; op < 256; ++op)
        check_same({static_cast<uint8_t>(op)}, kAfter, op % 4);
    // A JUMPDEST in the last byte, jumped to by JUMP and JUMPI, and jumps to the end and past it,
    // where the bytes in place are padding and then a JUMPDEST.
    for (size_t pad = 0; pad < 8; ++pad)
    {
        for (const uint8_t jump : {JUMP, JUMPI})
        {
            for (size_t past = 0; past < 3 + kPadding; ++past)
            {
                bytes code = {PUSH1, 1, PUSH1, 0};
                code.reserve(code.size() + pad + 3);
                code.insert(code.end(), pad, JUMPDEST);
                const size_t last = code.size() + 2;  // past the jump and the STOP
                code[3] = static_cast<uint8_t>(last + past);
                code.push_back(jump);
                code.push_back(STOP);
                code.push_back(JUMPDEST);
                check_same(code, kAfter, pad % 4);
                bytes tail = code;
                tail.pop_back();
                tail.push_back(PUSH1);  // the jump target is a PUSH cut off by the end
                check_same(tail, kAfter, pad % 4);
            }
        }
    }
    // A selector test cut off at every point: DUP1 PUSH4 ... reaches up to 10 bytes ahead.
    {
        const bytes full{PUSH1, 0, CALLDATALOAD, PUSH1, 0xe0, SHR, DUP1, PUSH4, 0xa9, 0x05, 0x9c,
            0xbb, EQ, PUSH2, 0, 19, JUMPI, STOP, STOP, JUMPDEST, PUSH1, 7, PUSH1, 0, SSTORE};
        for (size_t cut = 1; cut <= full.size(); ++cut)
            check_same(bytes(full.begin(), full.begin() + static_cast<ptrdiff_t>(cut)), kAfter, cut % 4);
    }
    std::mt19937_64 rng{11};
    // The largest code a contract can deploy.
    check_same(random_code(rng, 24576), kAfter, 1);
    for (int i = 0; i < 600; ++i)
        check_same(random_code(rng, 1 + rng() % 300), kAfter, static_cast<size_t>(i % 4));
}

#endif
