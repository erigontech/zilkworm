// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// MSTORE memory growth against a model of the gas and the memory, through the state Host. The
// rv32 dispatch grows the memory by one word for MSTORE without grow_memory(), leaving the new
// word unzeroed when the store covers it whole, and grows the empty memory of a frame to 3 words
// for PUSH1 0x40 MSTORE (Solidity's prologue). The native build sets -DEVMONE_RV32_DISPATCH_TEST,
// which compiles both paths on the host. A frame's memory buffer is reused at its depth, so each
// program runs after one that left nonzero bytes in it: any byte the growth fails to zero shows
// in the output. The programs store at every offset around the end of the memory (overlap,
// append, gap), at the capacity's boundaries (the fast path does not reallocate), around 2 MB
// (65536 words, where the square of the word count leaves 32 bits) and with the gas exactly
// enough, one short, and with large values. The model does not depend on either path, so the
// test holds on a build without them.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/instructions.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>
#include <evmone_precompiles/keccak.hpp>

namespace {

using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using namespace evmc::literals;

constexpr address kDirty = 0xd100000000000000000000000000000000000001_address;
constexpr address kTest = 0x7e00000000000000000000000000000000000002_address;
constexpr address kCaller = 0xaa00000000000000000000000000000000000003_address;
constexpr address kSender = 0x5e00000000000000000000000000000000000004_address;

enum : uint8_t {
    STOP = 0x00, SUB = 0x03, OR = 0x17, RETURNDATASIZE = 0x3d, RETURNDATACOPY = 0x3e,
    CODECOPY = 0x39, POP = 0x50, MLOAD = 0x51, MSTORE = 0x52, MSTORE8 = 0x53, MSIZE = 0x59,
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH3 = 0x62, PUSH20 = 0x73, PUSH32 = 0x7f, SWAP1 = 0x90,
    CALL = 0xf1, RETURN = 0xf3
};

struct Asm {
    bytes code;
    Asm& op(uint8_t o) { code.push_back(o); return *this; }
    Asm& push1(uint8_t v) { code.insert(code.end(), {PUSH1, v}); return *this; }
    // Offsets go through PUSH3, which no fusion takes: the plain MSTORE and its check_memory().
    Asm& push3(uint64_t v) {
        code.insert(code.end(), {PUSH3, static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8),
                                    static_cast<uint8_t>(v)});
        return *this;
    }
    Asm& push_word(const bytes32& w) {
        code.push_back(PUSH32);
        code.insert(code.end(), w.bytes, w.bytes + 32);
        return *this;
    }
    Asm& push_addr(const address& a) {
        code.push_back(PUSH20);
        code.insert(code.end(), a.bytes, a.bytes + 20);
        return *this;
    }
    // Returns the memory from lo to its end (MSIZE - lo bytes): 14 gas, no growth.
    Asm& return_tail(uint64_t lo) { return op(MSIZE).push3(lo).op(SWAP1).op(SUB).push3(lo).op(RETURN); }
};

constexpr int64_t kReturnTailGas = 2 + 3 + 3 + 3 + 3;

// The memory cost of w words.
int64_t memory_cost(uint64_t w) { return static_cast<int64_t>(3 * w + w * w / 512); }

uint64_t words(uint64_t size) { return (size + 31) / 32; }

bytes32 word_of(uint8_t seed) {
    bytes32 w;
    for (unsigned i = 0; i < 32; ++i)
        w.bytes[i] = static_cast<uint8_t>(0x80 | ((seed + 13 * i) & 0x7f));  // never zero
    return w;
}

// Fills the first `size` bytes of its frame's memory with nonzero bytes (CODECOPY of its tail).
bytes dirty_code(uint64_t size) {
    Asm a;
    a.push3(size).push3(0).push3(0).op(CODECOPY).op(STOP);
    const auto prefix = a.code.size();
    a.code[5] = static_cast<uint8_t>(prefix >> 16);  // the source offset: the tail
    a.code[6] = static_cast<uint8_t>(prefix >> 8);
    a.code[7] = static_cast<uint8_t>(prefix);
    for (uint64_t i = 0; i < size; ++i)
        a.code.push_back(static_cast<uint8_t>(i % 251 + 1));
    return a.code;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = 0;
    bytes output;
};

struct EmptyView final : evmone::state::StateView {
    std::optional<Account> get_account(const address&) const noexcept override {
        return std::nullopt;
    }
    evmc::bytes_view get_account_code(const address&) const noexcept override { return {}; }
    bytes32 get_storage(const address&, const bytes32&) const noexcept override { return {}; }
};

struct NoHashes final : evmone::state::BlockHashes {
    bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// One VM, so the frames at a depth share one memory buffer, whose capacity only grows: a fresh
// Env starts at the initial 4 KiB page.
struct Env {
    EmptyView view;
    NoHashes hashes;
    evmone::state::State state{view};
    evmc::VM vm{new evmone::VM{}};
    evmone::state::BlockInfo block;
    evmone::state::Transaction tx;
    evmone::state::Host host{EVMC_PRAGUE, vm, state, block, hashes, tx};

    Env() {
        block.gas_limit = 30000000;
        block.number = 1;
        block.timestamp = 1;
        evmone::state::Account sender;
        sender.balance = 1000000;
        state.insert(kSender, std::move(sender));
    }

    static evmone::state::Account account(const bytes& code) {
        evmone::state::Account acc;
        acc.code = code;
        std::memcpy(acc.code_hash.bytes, ethash::keccak256(code.data(), code.size()).bytes, 32);
        acc.balance = 1000000;
        return acc;
    }

    void set_code(const address& a, const bytes& code) { state.insert(a, account(code)); }

    // kDirty with dirty_code(size), whose account is made once per size.
    void set_dirty(uint64_t size) {
        static std::vector<std::pair<uint64_t, evmone::state::Account>> made;
        auto it = std::find_if(made.begin(), made.end(), [&](const auto& m) { return m.first == size; });
        if (it == made.end())
            it = made.insert(made.end(), {size, account(dirty_code(size))});
        state.insert(kDirty, evmone::state::Account{it->second});
    }

    Outcome run(const address& to, int64_t gas) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = gas;
        msg.recipient = to;
        msg.code_address = to;
        msg.sender = kSender;
        const auto r = host.call(msg);
        return {r.status_code, r.gas_left, bytes(r.output_data, r.output_data + r.output_size)};
    }
};

// Runs kDirty, which leaves `dirty` nonzero bytes in the depth-0 buffer (and its capacity at least
// that), then the program, at depth 0 too.
Outcome run_after_dirty(const bytes& program, uint64_t dirty, int64_t gas) {
    Env env;
    env.set_code(kTest, program);
    if (dirty != 0) {
        env.set_dirty(dirty);
        const auto d = env.run(kDirty, 30000000);
        REQUIRE(d.status == EVMC_SUCCESS);
    }
    return env.run(kTest, gas);
}

// Gas limits around `total` (the gas the program takes in all): enough, one short and a few below
// it, and large ones, with the low word at and around the costs (on rv32 the PUSH1 path charges
// the low word alone and falls back when it is short).
std::vector<int64_t> gas_limits(int64_t total, int64_t first_fail) {
    std::vector<int64_t> v;
    for (int64_t g = std::max<int64_t>(0, first_fail - 2); g <= first_fail + 1; ++g)
        v.push_back(g);
    for (int64_t g = total - 2; g <= total + 1; ++g)
        v.push_back(g);
    for (const int64_t base : {int64_t{1} << 31, int64_t{1} << 32, int64_t{7} << 32})
        for (const int64_t d : {-1, 0, 1, 5, 20})
            v.push_back(base + total + d - 20);
    v.push_back(int64_t{1} << 40);
    return v;
}

// The program: grow the memory to `size` (MSTORE8 at size - 1, then a nonzero word below the end),
// MSTORE a nonzero word at `offset`, return the memory from `lo` to its end. Checks the outcome at
// every gas limit of gas_limits(), or with `few` at the three limits around the costs, against the
// model.
void check_store(uint64_t size, uint64_t offset, uint64_t dirty, size_t& runs, bool few = false) {
    const bytes32 below = word_of(1), value = word_of(2);
    Asm a;
    int64_t setup = 0;
    if (size != 0) {
        a.push1(0x77).push3(size - 1).op(MSTORE8);
        a.push_word(below).push3(size - 32).op(MSTORE);
        setup = 9 + memory_cost(size / 32) + 9;
    }
    a.push_word(value).push3(offset).op(MSTORE);
    const auto store_end = a.code.size();
    const uint64_t lo = size > 96 ? size - 96 : 0;
    a.return_tail(lo);

    const uint64_t new_size = std::max(size, 32 * words(offset + 32));
    const int64_t expansion = memory_cost(new_size / 32) - memory_cost(size / 32);
    const int64_t at_store = setup + 9 + expansion;  // through the MSTORE
    const int64_t total = at_store + kReturnTailGas;

    std::vector<uint8_t> model(new_size + 32, 0);
    if (size != 0)
        std::memcpy(&model[size - 32], below.bytes, 32);
    std::memcpy(&model[offset], value.bytes, 32);
    const bytes expected(model.begin() + static_cast<std::ptrdiff_t>(lo),
        model.begin() + static_cast<std::ptrdiff_t>(new_size));

    const auto limits = few ? std::vector<int64_t>{at_store - 1, total - 1, total}
                            : gas_limits(total, at_store - 1);
    for (const auto gas : limits) {
        const auto out = run_after_dirty(a.code, dirty, gas);
        ++runs;
        INFO("size " << size << " offset " << offset << " dirty " << dirty << " gas " << gas
                     << " total " << total);
        if (gas < total) {
            REQUIRE(out.status == EVMC_OUT_OF_GAS);
            REQUIRE(out.gas_left == 0);
        } else {
            REQUIRE(out.status == EVMC_SUCCESS);
            REQUIRE(out.gas_left == gas - total);
            REQUIRE(out.output == expected);
        }
    }

    // The program cut after the MSTORE: the gas runs out exactly at the expansion, or the store
    // leaves exactly 0.
    const bytes cut(a.code.begin(), a.code.begin() + static_cast<std::ptrdiff_t>(store_end));
    for (const auto gas : {at_store - 1, at_store}) {
        const auto out = run_after_dirty(cut, dirty, gas);
        ++runs;
        INFO("cut: size " << size << " offset " << offset << " gas " << gas);
        REQUIRE(out.status == (gas < at_store ? EVMC_OUT_OF_GAS : EVMC_SUCCESS));
        REQUIRE(out.gas_left == 0);
    }
}

}  // namespace

TEST_CASE("MSTORE growth around the end of the memory", "[mstore_grow]") {
    // Capacities of 4, 8 and 16 KiB (a dirty frame of that size leaves the buffer at exactly
    // that), sizes from empty to the capacity, offsets from 70 below the end to 100 above it.
    size_t runs = 0;
    for (const uint64_t cap : {4096u, 8192u, 16384u}) {
        for (const uint64_t size : {uint64_t{0}, uint64_t{32}, uint64_t{64}, uint64_t{96}, cap / 2,
                 cap - 64, cap - 32, cap}) {
            for (uint64_t offset = size > 70 ? size - 70 : 0; offset <= size + 100; ++offset)
                check_store(size, offset, cap, runs);
        }
    }
    REQUIRE(runs > 50000);
}

TEST_CASE("MSTORE growth around 2 MB of memory", "[mstore_grow]") {
    // A dirty frame of 2^21 bytes leaves the capacity at 65536 words: from 65535 words the
    // growth fills it, from 65536 it reallocates. The one-word cost is exact at every size (the
    // low 9 bits of the wrapped square), where (n + 1)^2 in 32 bits wraps from n = 65536.
    size_t runs = 0;
    for (uint64_t w = 65533; w <= 65537; ++w) {
        const uint64_t size = 32 * w;
        for (const uint64_t offset : {size - 31, size - 1, size, size + 1, size + 32})
            check_store(size, offset, uint64_t{1} << 21, runs, true);
    }
    REQUIRE(runs > 0);
}

TEST_CASE("MSTORE offsets above 32 bits run out of gas", "[mstore_grow]") {
    for (unsigned bit = 32; bit < 256; bit += 7) {
        for (const uint64_t low : {uint64_t{0}, uint64_t{32}, uint64_t{0xffffffe0}}) {
            bytes32 off{};
            off.bytes[31 - bit / 8] = static_cast<uint8_t>(1u << (bit % 8));
            for (unsigned i = 0; i < 4; ++i)
                off.bytes[31 - i] |= static_cast<uint8_t>(low >> (8 * i));
            Asm a;
            a.push1(0x77).push3(31).op(MSTORE8);  // 32 bytes of memory: a store at 32 appends
            a.push_word(word_of(3)).push_word(off).op(MSTORE).op(STOP);
            const auto out = run_after_dirty(a.code, 4096, 10000000);
            REQUIRE(out.status == EVMC_OUT_OF_GAS);
        }
    }
    // Offsets at the end of the 32-bit range: the store's end needs 33 bits.
    for (const uint64_t offset : {uint64_t{0xffffffe0}, uint64_t{0xffffffe1}, uint64_t{0xffffffff}}) {
        Asm a;
        a.push_word(word_of(3));
        bytes32 off{};
        for (unsigned i = 0; i < 4; ++i)
            off.bytes[31 - i] = static_cast<uint8_t>(offset >> (8 * i));
        a.push_word(off).op(MSTORE).op(STOP);
        const auto out = run_after_dirty(a.code, 4096, int64_t{1} << 40);
        REQUIRE(out.status == EVMC_OUT_OF_GAS);
    }
}

TEST_CASE("PUSH1 MSTORE growth, Solidity's prologue among it", "[mstore_grow]") {
    // PUSH1 0x80 PUSH1 imm MSTORE, the first access at 0x40 being the prologue: the 0x40 bytes
    // below the store read as zeros in a reused buffer.
    const bytes32 value = word_of(4);
    for (const uint64_t size : {0u, 32u, 64u, 96u, 128u}) {
        for (const unsigned imm : {0x00u, 0x01u, 0x20u, 0x3fu, 0x40u, 0x41u, 0x60u, 0xa0u, 0xffu}) {
            Asm a;
            int64_t setup = 0;
            if (size != 0) {
                a.push1(0x77).push3(size - 1).op(MSTORE8);
                setup = 9 + memory_cost(size / 32);
            }
            a.push_word(value).push1(static_cast<uint8_t>(imm)).op(MSTORE);
            a.return_tail(0);
            const uint64_t new_size = std::max<uint64_t>(size, 32 * words(imm + 32));
            const int64_t at_store =
                setup + 9 + memory_cost(new_size / 32) - memory_cost(size / 32);
            const int64_t total = at_store + kReturnTailGas;
            bytes expected(new_size, 0);
            if (size != 0)
                expected[size - 1] = 0x77;
            std::memcpy(&expected[imm], value.bytes, 32);
            for (const auto gas : gas_limits(total, at_store - 1)) {
                const auto out = run_after_dirty(a.code, 4096, gas);
                INFO("size " << size << " imm " << imm << " gas " << gas << " total " << total);
                if (gas < total) {
                    REQUIRE(out.status == EVMC_OUT_OF_GAS);
                } else {
                    REQUIRE(out.status == EVMC_SUCCESS);
                    REQUIRE(out.gas_left == gas - total);
                    REQUIRE(out.output == expected);
                }
            }
        }
    }
}

TEST_CASE("PUSH1 0x80 PUSH1 0x40 MSTORE as a frame's first memory access", "[mstore_grow]") {
    // The prologue exactly: 3 + 3 + 3 + 9 gas. Then MSIZE, and MLOAD 0x00, 0x20, 0x40 (fused
    // with PUSH1) stored at 0x60, 0x80, 0xa0, MSIZE at 0xc0, and those 4 words returned.
    Asm a;
    a.push1(0x80).push1(0x40).op(MSTORE).op(MSIZE);
    a.push1(0x00).op(MLOAD).push1(0x60).op(MSTORE);
    a.push1(0x20).op(MLOAD).push1(0x80).op(MSTORE);
    a.push1(0x40).op(MLOAD).push1(0xa0).op(MSTORE);
    a.push1(0xc0).op(MSTORE);
    a.push3(0x80).push3(0x60).op(RETURN);
    const int64_t prologue = 3 + 3 + 3 + 9;
    const int64_t total =
        prologue + 2 + 3 * (3 + 3 + 3 + 3) + (3 + 3) + memory_cost(7) - memory_cost(3) + (3 + 3);
    bytes expected(0x80, 0);
    expected[0x5f] = 0x80;  // MLOAD 0x40
    expected[0x7f] = 0x60;  // MSIZE after the prologue
    for (const uint64_t dirty : {0u, 4096u}) {
        for (int64_t gas = prologue - 3; gas <= total + 2; ++gas) {
            const auto out = run_after_dirty(a.code, dirty, gas);
            INFO("dirty " << dirty << " gas " << gas);
            if (gas < total) {
                REQUIRE(out.status == EVMC_OUT_OF_GAS);
            } else {
                REQUIRE(out.status == EVMC_SUCCESS);
                REQUIRE(out.gas_left == gas - total);
                REQUIRE(out.output == expected);
            }
        }
    }
    // The prologue alone, the gas running out exactly at its expansion or ending at 0.
    const bytes alone{PUSH1, 0x80, PUSH1, 0x40, MSTORE};
    for (const uint64_t dirty : {0u, 4096u}) {
        const auto short_by_one = run_after_dirty(alone, dirty, prologue - 1);
        REQUIRE(short_by_one.status == EVMC_OUT_OF_GAS);
        const auto exact = run_after_dirty(alone, dirty, prologue);
        REQUIRE(exact.status == EVMC_SUCCESS);
        REQUIRE(exact.gas_left == 0);
    }
    // Without the value under the offset: underflow ahead of MSTORE's gas, once PUSH1 has its 3.
    const bytes underflow{PUSH1, 0x40, MSTORE};
    for (const int64_t gas : {2, 3, 5, 6, 100})
        REQUIRE(run_after_dirty(underflow, 4096, gas).status ==
                (gas < 3 ? EVMC_OUT_OF_GAS : EVMC_STACK_UNDERFLOW));
}

TEST_CASE("MSTORE growth in a frame after a sibling call at the same depth", "[mstore_grow]") {
    // Two calls from one frame: the first leaves nonzero bytes in the depth-1 buffer, the second
    // reuses it, grows its memory by one word with a store at 1 (the word above holds 31 bytes
    // the store does not cover) and runs the prologue in a third call; the caller returns their
    // return data.
    const bytes32 value = word_of(5);
    Asm overlap;
    overlap.push_word(word_of(6)).push3(0).op(MSTORE);   // append: 0 to 32 bytes
    overlap.push_word(value).push3(1).op(MSTORE);        // overlap: 32 to 64 bytes
    overlap.push3(64).push3(0).op(RETURN);
    Asm prologue;
    prologue.push1(0x80).push1(0x40).op(MSTORE).push3(0x60).push3(0).op(RETURN);

    for (const bool use_prologue : {false, true}) {
        const auto call = [](Asm& a, const address& to) {
            a.push3(0).push3(0).push3(0).push3(0).push3(0).push_addr(to).push3(1000000).op(CALL).op(POP);
        };
        Asm caller;
        call(caller, kDirty);
        call(caller, kTest);
        caller.op(RETURNDATASIZE).push3(0).push3(0).op(RETURNDATACOPY);
        caller.op(RETURNDATASIZE).push3(0).op(RETURN);

        Env env;
        env.set_dirty(4096);
        env.set_code(kTest, use_prologue ? prologue.code : overlap.code);
        env.set_code(kCaller, caller.code);
        const auto out = env.run(kCaller, 10000000);
        REQUIRE(out.status == EVMC_SUCCESS);
        if (use_prologue) {
            bytes expected(0x60, 0);
            expected[0x5f] = 0x80;
            CHECK(out.output == expected);
        } else {
            bytes expected(64, 0);
            std::memcpy(&expected[0], word_of(6).bytes, 32);
            std::memcpy(&expected[1], value.bytes, 32);
            CHECK(out.output == expected);
        }
    }
}

#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
namespace {

using evmone::Memory;

// A memory of `size` bytes in a buffer of at least `capacity` that held nonzero bytes: the
// window around the end gets bytes from `seed` (content below the size, garbage above it), so
// the two copies of a pair are identical and a byte the growth leaves unzeroed shows.
Memory make_memory(size_t capacity, size_t size, uint64_t seed) {
    std::mt19937_64 r(seed);
    Memory m;
    if (capacity > m.capacity())
        m.grow(capacity);
    const size_t lo = size > 256 ? size - 256 : 0;
    const size_t hi = std::min(m.capacity(), size + 512);
    for (size_t i = lo; i < hi; ++i)
        m[i] = static_cast<uint8_t>(r());
    m.clear();
    if (size != 0)
        m.grow(size);
    for (size_t i = lo; i < size; ++i)
        m[i] = static_cast<uint8_t>(r());
    return m;
}

// The offset with one bit set in the 32-bit word `hi_word` (1 to 7) above the low one.
evmone::uint256 offset_with_high_bit(uint32_t low, unsigned hi_word, unsigned bit) {
    evmone::uint256 x = low;
    const uint32_t v = uint32_t{1} << bit;
    std::memcpy(reinterpret_cast<char*>(&x) + 4 * hi_word, &v, 4);  // not a typed access
    return x;
}

// MSTORE's check and the 32-byte store through the fast path and through check_memory(), which
// the host build and the generic dispatch use: the same verdict, gas, size and bytes.
void compare_mstore(size_t capacity, size_t size, const evmone::uint256& offset, int64_t gas,
    std::mt19937_64& rng, size_t& fast) {
    const uint64_t seed = rng();
    Memory ref = make_memory(capacity, size, seed);
    Memory fastm = make_memory(capacity, size, seed);
    REQUIRE(ref.size() == fastm.size());
    REQUIRE(ref.capacity() == fastm.capacity());
    uint8_t value[32];
    for (auto& v : value)
        v = static_cast<uint8_t>(rng());

    int64_t gas_ref = gas, gas_fast = gas;
    const bool ok_ref = evmone::check_memory(gas_ref, ref, offset, 32);
    size_t at = 0;
    const bool ok_fast = evmone::check_memory_for_mstore(gas_fast, fastm, offset, at);
    if (ok_ref)
        std::memcpy(&ref[static_cast<size_t>(offset)], value, 32);
    if (ok_fast)
        std::memcpy(&fastm[static_cast<size_t>(offset)], value, 32);
    fast += offset <= size && !(offset + 32 <= size);

    INFO("capacity " << capacity << " size " << size << " offset " << static_cast<uint64_t>(offset)
                     << " gas " << gas);
    REQUIRE(ok_fast == ok_ref);
    REQUIRE(gas_fast == gas_ref);
    REQUIRE(fastm.size() == ref.size());
    REQUIRE(fastm.limit32() == ref.limit32());
    if (ok_fast)
        REQUIRE(at == static_cast<size_t>(offset));  // the checked offset the store goes on with
    if (ok_ref) {
        const size_t lo = size > 256 ? size - 256 : 0;
        REQUIRE(std::memcmp(&fastm[lo], &ref[lo], ref.size() - lo) == 0);
    }
}

}  // namespace

TEST_CASE("MSTORE fast path against check_memory(), the memory it leaves and the gas",
    "[mstore_grow]") {
    // The cost of growing from n to n + 1 words, from the formula in 64 bits.
    const auto cost1 = [](uint64_t n) {
        const auto c = [](uint64_t w) { return 3 * w + w * w / 512; };
        return static_cast<int64_t>(c(n + 1) - c(n));
    };
    // The inline cost, exact for every word count up to 2^22 and for random ones up to 2^27 (a
    // 4 GiB memory).
    size_t wrong = 0;
    const auto inline_cost = [](uint64_t n) {
        const auto m = static_cast<uint32_t>(n);
        return 3 + ((((m * m) & 511) + 2 * m + 1) >> 9);
    };
    for (uint64_t n = 0; n < (uint64_t{1} << 22); ++n)
        wrong += inline_cost(n) != cost1(n);
    std::mt19937_64 rng(20261008);
    for (int i = 0; i < 200000; ++i) {
        const uint64_t n = rng() % (uint64_t{1} << 27);
        wrong += inline_cost(n) != cost1(n);
    }
    REQUIRE(wrong == 0);

    size_t fast = 0, checks = 0;
    for (const size_t capacity : {size_t{4096}, size_t{8192}, size_t{65536}}) {
        std::vector<size_t> sizes = {0, 32, 64, 96, capacity - 64, capacity - 32, capacity};
        for (int k = 0; k < 4; ++k)
            sizes.push_back(32 * (rng() % (capacity / 32 + 1)));
        for (const size_t size : sizes) {
            const int64_t c1 = cost1(size / 32);
            for (int64_t d = -70; d <= 100; ++d) {
                const auto offset = static_cast<uint64_t>(static_cast<int64_t>(size) + d);
                if (static_cast<int64_t>(size) + d < 0)
                    continue;
                // Gas around the one-word cost and the gap growths', and values whose low word
                // is at the sign and wrap boundaries.
                for (const int64_t gas : {c1 - 1, c1, c1 + 1, int64_t{0}, 2 * c1, int64_t{1000000},
                         (int64_t{1} << 32) + c1 - 1, (int64_t{1} << 32) + 2,
                         (int64_t{1} << 31) + 1, (int64_t{1} << 31) - 1, (int64_t{1} << 32) - 1,
                         static_cast<int64_t>(rng() % 100000000)}) {
                    compare_mstore(capacity, size, evmone::uint256{offset}, gas, rng, fast);
                    ++checks;
                }
            }
            // Offsets at the end of the 32-bit range, and with any one high bit set.
            for (const uint32_t o : {0xffffffe0u, 0xffffffffu, 0xffffffc0u, 0x80000000u, 0x7fffffe0u})
                compare_mstore(capacity, size, evmone::uint256{o}, int64_t{1} << 40, rng, fast);
            for (unsigned hi_word = 1; hi_word < 8; ++hi_word)
                for (unsigned bit = 0; bit < 32; bit += 5)
                    compare_mstore(capacity, size,
                        offset_with_high_bit(static_cast<uint32_t>(size), hi_word, bit),
                        int64_t{1} << 40, rng, fast);
        }
    }
    // Random states.
    for (int i = 0; i < 50000; ++i) {
        const size_t capacity = size_t{4096} << (rng() % 4);
        const size_t size = 32 * (rng() % (capacity / 32 + 1));
        const int64_t offset = std::max<int64_t>(
            0, static_cast<int64_t>(size) + static_cast<int64_t>(rng() % 200) - 100);
        const int64_t gas = rng() % 4 == 0
            ? cost1(size / 32) - 1 + static_cast<int64_t>(rng() % 3)
            : static_cast<int64_t>(rng() % 3000);
        compare_mstore(capacity, size, evmone::uint256{static_cast<uint64_t>(offset)}, gas, rng, fast);
        ++checks;
    }
    // Most of the stores above start at or below the end of the memory with room in the buffer,
    // where the fast path runs.
    REQUIRE(checks > 100000);
    REQUIRE(fast > 10000);
}

TEST_CASE("Growing the empty memory to 3 words matches grow_memory() with a store at 0x40",
    "[mstore_grow]") {
    // Memory::grow_empty_for_store_at_64() and the store of 32 bytes at 0x40, against
    // grow_memory(.., 0x60) and the same store: the same bytes in the 0x60 bytes, whatever the
    // buffer held before.
    std::mt19937_64 rng(7);
    for (int i = 0; i < 2000; ++i) {
        const uint64_t seed = rng();
        Memory ref = make_memory(4096, 0, seed);
        Memory fastm = make_memory(4096, 0, seed);
        uint8_t value[32];
        for (auto& v : value)
            v = static_cast<uint8_t>(rng());
        const int64_t gas = 100;
        REQUIRE(evmone::grow_memory(gas, ref, 0x60) == gas - 9);
        fastm.grow_empty_for_store_at_64();
        std::memcpy(&ref[0x40], value, 32);
        std::memcpy(&fastm[0x40], value, 32);
        REQUIRE(fastm.size() == 0x60);
        REQUIRE(ref.size() == 0x60);
        REQUIRE(fastm.limit32() == ref.limit32());  // the limit the next access compares with
        REQUIRE(std::memcmp(&fastm[0], &ref[0], 0x60) == 0);
    }
}
#endif
