// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// JUMP and JUMPI validity (CodeAnalysis::check_jumpdest) against a reference scan, on codes built
// around the cases a JUMPDEST map can get wrong: a JUMPDEST in the last byte, a PUSH cut off by the
// end of the code, 0x5b inside push data, and lengths on every side of the 8-opcode scan step. The
// native build sets -DEVMONE_RV32_DISPATCH_TEST, which compiles the byte map and its 8-wide lazy
// scan on the host.

#include <algorithm>
#include <cstdint>
#include <numeric>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/baseline.hpp>

namespace {

evmone::baseline::CodeAnalysis analyze(const std::vector<uint8_t>& code) {
    return evmone::baseline::analyze(evmc::bytes_view{code.data(), code.size()});
}

constexpr uint8_t kJumpdest = 0x5b;
constexpr uint8_t kPush1 = 0x60;
constexpr uint8_t kPush32 = 0x7f;

// Positions that are a JUMPDEST opcode and not push data.
std::vector<bool> reference_jumpdests(const std::vector<uint8_t>& code) {
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

// Queries every position in the given order on a fresh analysis, then the positions beyond the end.
void check_order(const std::vector<uint8_t>& code, const std::vector<bool>& valid,
                 const std::vector<uint64_t>& order) {
    const auto analysis = analyze(code);
    for (const auto position : order)
        REQUIRE(analysis.check_jumpdest(position) == expected(valid, position));
    for (const uint64_t position : {code.size() + 0, code.size() + 7, code.size() + 8,
             uint64_t{0xffffffff}})
        REQUIRE(analysis.check_jumpdest(position) == false);
}

void check_code(const std::vector<uint8_t>& code, std::mt19937_64& rng) {
    const auto valid = reference_jumpdests(code);
    std::vector<uint64_t> order(code.size());
    std::iota(order.begin(), order.end(), uint64_t{0});

    check_order(code, valid, order);  // Ascending: each query scans a little further.
    std::reverse(order.begin(), order.end());
    check_order(code, valid, order);  // Descending: the first query scans everything.
    std::shuffle(order.begin(), order.end(), rng);
    check_order(code, valid, order);
    // A high target first, then low ones, which the first scan already classified.
    if (!code.empty()) {
        std::vector<uint64_t> high_then_low{code.size() - 1, code.size() / 2, 0, code.size() - 1};
        check_order(code, valid, high_then_low);
    }
}

}  // namespace

TEST_CASE("jumpdest map: fixed codes", "[jumpdest]") {
    std::mt19937_64 rng{1};
    check_code({}, rng);
    check_code({kJumpdest}, rng);
    check_code({0x00}, rng);
    check_code({kJumpdest, kJumpdest, kJumpdest}, rng);
    // 0x5b as push data is not a destination; the one after the data is.
    check_code({kPush1, kJumpdest, kJumpdest}, rng);
    check_code({kPush1 + 1, kJumpdest, kJumpdest, kJumpdest}, rng);
    check_code({kPush32, kJumpdest, kJumpdest}, rng);
    // A PUSH whose data runs off the end: the missing bytes are padding, not code.
    for (unsigned op = kPush1; op <= kPush32; ++op) {
        for (size_t have = 0; have <= op - kPush1 + 1; ++have) {
            std::vector<uint8_t> code(2 + have, kJumpdest);
            code[1] = static_cast<uint8_t>(op);
            check_code(code, rng);
        }
    }
}

TEST_CASE("jumpdest map: every length around the scan step", "[jumpdest]") {
    std::mt19937_64 rng{2};
    for (size_t size = 1; size <= 80; ++size) {
        // All JUMPDESTs, with the last byte one.
        check_code(std::vector<uint8_t>(size, kJumpdest), rng);
        // A JUMPDEST at the last byte only, then at every position only.
        std::vector<uint8_t> code(size, 0x01);
        code.back() = kJumpdest;
        check_code(code, rng);
        for (size_t at = 0; at < size; ++at) {
            std::vector<uint8_t> single(size, 0x01);
            single[at] = kJumpdest;
            check_code(single, rng);
        }
        // A PUSH1 at every position with a JUMPDEST as its data and one after.
        for (size_t at = 0; at + 1 < size; ++at) {
            std::vector<uint8_t> pushed(size, kJumpdest);
            pushed[at] = kPush1;
            check_code(pushed, rng);
        }
    }
    for (const size_t size : {size_t{24575}, size_t{24576}}) {
        std::vector<uint8_t> code(size, kJumpdest);
        check_code(code, rng);
        code.back() = kPush32;
        check_code(code, rng);
    }
}

TEST_CASE("jumpdest map: random codes", "[jumpdest]") {
    std::mt19937_64 rng{3};
    for (int round = 0; round < 3000; ++round) {
        const size_t size = rng() % 300;
        // Few distinct opcodes so that PUSH data, JUMPDEST and plain opcodes meet often.
        const uint8_t pool[] = {kJumpdest, kJumpdest, kPush1, kPush1 + 1, kPush1 + 3, kPush32,
            0x00, 0x01, 0x56, 0x57, 0x80, 0xff, 0x5a, 0x5c};
        std::vector<uint8_t> code(size);
        for (auto& b : code)
            b = (rng() % 4) ? pool[rng() % std::size(pool)] : static_cast<uint8_t>(rng());
        check_code(code, rng);
    }
    // A code that is mostly distinct maps in a row: stale marks from one analysis must not show in
    // the next.
    for (int round = 0; round < 200; ++round) {
        std::vector<uint8_t> dense(1 + rng() % 200, kJumpdest);
        const auto a = analyze(dense);
        for (size_t i = 0; i < dense.size(); ++i)
            REQUIRE(a.check_jumpdest(i));
        std::vector<uint8_t> sparse(dense.size(), 0x01);
        const auto b = analyze(sparse);
        for (size_t i = 0; i < sparse.size(); ++i)
            REQUIRE_FALSE(b.check_jumpdest(i));
    }
}
