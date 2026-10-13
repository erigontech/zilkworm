// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The VM's code cache, which the rv32 guest keeps without LRU eviction, the analyses held by value
// in a node-based map (evmone/vm.hpp, EVMONE_LEAN_CODE_CACHE). The native build sets
// -DEVMONE_RV32_DISPATCH_TEST, which compiles that variant on the host; without it the bounded LRU
// cache is tested instead, by the checks that hold for both.
//
// The cache is tested directly, against a model of the LRU cache it replaces, on random streams of
// hashes that hit and miss, on hashes that differ in one byte only, in the last word only, or not
// in the last word (the guest's std::hash reads the last word alone, so equality must compare all
// 32 bytes), and with the analyses held across 20000 inserts (a frame keeps its analysis while a
// nested call inserts and rehashes). Then through the state Host, whose CALL, DELEGATECALL,
// STATICCALL and CALLCODE reach the cache with the code address: a loop that runs while it makes
// thousands of nested calls to distinct, repeated and colliding hashes, and a call chain 100 deep,
// each against the same program run through the uncached path, and against a model of the result.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>
#include <evmone/vm.hpp>

namespace {

using evmc::address;
using evmc::bytes;
using evmc::bytes32;
using namespace evmc::literals;
using evmone::baseline::CodeAnalysis;
using Code = std::vector<uint8_t>;

#ifdef EVMONE_RV32_DISPATCH_TEST
static_assert(EVMONE_LEAN_CODE_CACHE, "the native rv32 test build must compile the lean code cache");
#endif

struct Rng {
    uint64_t s;
    uint64_t next() {
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        uint64_t x = s;
        x ^= x >> 33;
        x *= 0xff51afd7ed558ccdull;
        x ^= x >> 33;
        return x;
    }
    uint64_t below(uint64_t n) { return next() % n; }
};

// A hash of id. Modes: 0 random; 1 the same last word; 2 the same first 28 bytes; 3 the same but
// for one byte (255 * 32 distinct ids).
enum Mode { kRandom = 0, kSameLastWord = 1, kSameFirstBytes = 2, kOneByte = 3 };

bytes32 hash_of(uint64_t id, int mode) {
    bytes32 h;
    Rng rng{id * 0x9e3779b97f4a7c15ull + 1};
    for (auto& b : h.bytes)
        b = static_cast<uint8_t>(rng.next());
    switch (mode) {
    case kSameLastWord:
        std::memcpy(&h.bytes[28], "\xde\xad\xbe\xef", 4);
        break;
    case kSameFirstBytes:
        std::memset(h.bytes, 0xa5, 28);
        std::memcpy(&h.bytes[28], &id, 4);
        break;
    case kOneByte: {
        std::memset(h.bytes, 0xa5, 32);
        auto v = static_cast<uint8_t>(id % 255);
        if (v >= 0xa5)
            ++v;
        h.bytes[(id / 255) % 32] = v;
        break;
    }
    default:
        break;
    }
    return h;
}

// The code of id: distinct per id (its first bytes), 0x5b bytes in and out of push data, a PUSH
// cut off by the code end now and then.
Code code_of(uint64_t id) {
    Rng rng{id + 77};
    const size_t len = 8 + rng.below(190);
    Code code(len);
    for (auto& b : code) {
        const auto r = rng.below(8);
        b = r < 3 ? 0x5b : r < 5 ? static_cast<uint8_t>(0x60 + rng.below(32)) : static_cast<uint8_t>(rng.next());
    }
    code[0] = 0x60;  // PUSH1 id's low byte, then the next 3 bytes of id: distinct codes
    code[1] = static_cast<uint8_t>(id);
    code[2] = static_cast<uint8_t>(id >> 8);
    code[3] = static_cast<uint8_t>(id >> 16);
    if (id % 7 == 0)
        code.back() = 0x7f;  // a PUSH32 at the end
    return code;
}

// Positions that are a JUMPDEST and not push data.
std::vector<bool> reference_jumpdests(const Code& code) {
    std::vector<bool> valid(code.size(), false);
    for (size_t i = 0; i < code.size(); ++i) {
        const uint8_t op = code[i];
        if (op == 0x5b)
            valid[i] = true;
        else if (op >= 0x60 && op <= 0x7f)
            i += static_cast<size_t>(op - 0x60) + 1;
    }
    return valid;
}

CodeAnalysis analyze(const Code& code) {
    return evmone::baseline::analyze(evmc::bytes_view{code.data(), code.size()});
}

bool same_code(const CodeAnalysis& a, const Code& code) {
    const auto view = a.code();
    return view.size() == code.size() && std::equal(code.begin(), code.end(), view.begin());
}

// All positions of a, last first (the lazy scan then covers the whole code at the first query),
// against the reference.
void check_all_jumpdests(const CodeAnalysis& a, const Code& code) {
    const auto valid = reference_jumpdests(code);
    for (size_t i = code.size(); i-- > 0;)
        REQUIRE(a.check_jumpdest(i) == valid[i]);
    REQUIRE_FALSE(a.check_jumpdest(code.size()));
    REQUIRE_FALSE(a.check_jumpdest(0xffffffff));
}

// The bounded LRU cache of the host build, which the lean cache replaces (a model of vm.cpp's).
class ModelLru {
    using Entry = std::pair<bytes32, std::shared_ptr<CodeAnalysis>>;
    size_t cap_;
    std::list<Entry> list_;
    std::unordered_map<bytes32, std::list<Entry>::iterator> map_;

public:
    explicit ModelLru(size_t cap) : cap_{cap} {}

    template <typename F>
    std::shared_ptr<CodeAnalysis> get_or_analyze(const bytes32& h, F&& make) {
        const auto it = map_.find(h);
        if (it != map_.end()) {
            list_.splice(list_.begin(), list_, it->second);
            return it->second->second;
        }
        auto p = std::make_shared<CodeAnalysis>(make());
        list_.emplace_front(h, p);
        map_[h] = list_.begin();
        if (list_.size() > cap_) {
            map_.erase(list_.back().first);
            list_.pop_back();
        }
        return p;
    }
};

}  // namespace

TEST_CASE("the code cache returns the analysis of each hash's own code", "[lean_code_cache]") {
    for (const int mode : {kRandom, kSameLastWord, kSameFirstBytes, kOneByte}) {
        evmone::CodeCache cache;
        ModelLru model{100};
        Rng rng{1234u + static_cast<uint64_t>(mode)};
        constexpr uint64_t kPool = 2500;
        std::unordered_set<uint64_t> seen;
        size_t analyzed = 0;
        for (int step = 0; step < 20000; ++step) {
            // Half of the accesses on a hot set of 50, the rest over the pool.
            const uint64_t id = rng.below(2) ? rng.below(50) : rng.below(kPool);
            const auto h = hash_of(id, mode);
            const auto code = code_of(id);
            seen.insert(id);
            const auto make = [&] {
                ++analyzed;
                return analyze(code);
            };
            const auto& a = *cache.get_or_analyze(h, make);
            const auto ref = model.get_or_analyze(h, [&] { return analyze(code); });
            REQUIRE(same_code(a, code));
            REQUIRE(same_code(a, std::vector<uint8_t>(ref->code().begin(), ref->code().end())));
            // A few positions, in no order (the lazy scan runs up to the highest one asked).
            const auto valid = reference_jumpdests(code);
            for (int q = 0; q < 6; ++q) {
                const auto pos = rng.below(code.size() + 3);
                REQUIRE(a.check_jumpdest(pos) == (pos < valid.size() && valid[pos]));
                REQUIRE(a.check_jumpdest(pos) == ref->check_jumpdest(pos));
            }
        }
#if EVMONE_LEAN_CODE_CACHE
        // Only the misses analyze: the LRU cache of the model analyzes more often than this.
        REQUIRE(analyzed == seen.size());
#endif
        // Every analysis on the whole code, a fresh query order each.
        for (const auto id : seen) {
            const auto code = code_of(id);
            const auto& a = *cache.get_or_analyze(hash_of(id, mode), [&] {
                ++analyzed;
                return analyze(code);
            });
            check_all_jumpdests(a, code);
        }
#if EVMONE_LEAN_CODE_CACHE
        REQUIRE(analyzed == seen.size());
#endif
    }
}

TEST_CASE("a hit does not analyze and a miss analyzes once", "[lean_code_cache]") {
    evmone::CodeCache cache;
    int analyzed = 0;
    const auto make = [&](uint64_t id) {
        return [&analyzed, id] {
            ++analyzed;
            return analyze(code_of(id));
        };
    };
    const auto* first = &*cache.get_or_analyze(hash_of(1, kRandom), make(1));
    REQUIRE(analyzed == 1);
    for (int i = 0; i < 5; ++i) {
        const auto& again = *cache.get_or_analyze(hash_of(1, kRandom), make(1));
        REQUIRE(&again == first);
    }
    REQUIRE(analyzed == 1);
    // The make of a hit must not be called, whatever it would return.
    const auto& hit = *cache.get_or_analyze(hash_of(1, kRandom), [&]() -> CodeAnalysis {
        FAIL("analyzed on a hit");
        return analyze(Code{0});
    });
    REQUIRE(&hit == first);
    cache.get_or_analyze(hash_of(2, kRandom), make(2));
    REQUIRE(analyzed == 2);
    // The zero and all-ones hashes are keys like any other, and the empty code can be analyzed.
    const bytes32 zero{};
    bytes32 ones;
    std::memset(ones.bytes, 0xff, 32);
    const auto& z = *cache.get_or_analyze(zero, make(10));
    const auto& o = *cache.get_or_analyze(ones, make(11));
    REQUIRE(same_code(z, code_of(10)));
    REQUIRE(same_code(o, code_of(11)));
    REQUIRE(&z != &o);
    REQUIRE(analyzed == 4);
    const Code empty;
    const auto& e = *cache.get_or_analyze(hash_of(12, kRandom), [&] { return analyze(empty); });
    REQUIRE(e.code().empty());
    REQUIRE_FALSE(e.check_jumpdest(0));
}

#if EVMONE_LEAN_CODE_CACHE
TEST_CASE("an analysis stays where it is across inserts and rehashes", "[lean_code_cache]") {
    for (const int mode : {kRandom, kSameLastWord, kSameFirstBytes}) {
        evmone::CodeCache cache;
        constexpr uint64_t kHeld = 64;
        std::vector<const CodeAnalysis*> held;
        for (uint64_t id = 0; id < kHeld; ++id)
            held.push_back(cache.get_or_analyze(hash_of(id, mode), [&] { return analyze(code_of(id)); }));
        // The frames' views: queried halfway so some have scanned and some have not.
        for (uint64_t id = 0; id < kHeld; id += 2)
            REQUIRE_FALSE(held[id]->check_jumpdest(1));
        for (uint64_t id = kHeld; id < kHeld + 20000; ++id)
            cache.get_or_analyze(hash_of(id, mode), [&] { return analyze(code_of(id)); });
        for (uint64_t id = 0; id < kHeld; ++id) {
            const auto code = code_of(id);
            REQUIRE(same_code(*held[id], code));
            check_all_jumpdests(*held[id], code);
            // The same entry again, not a second one.
            const auto* again = cache.get_or_analyze(hash_of(id, mode), [&]() -> CodeAnalysis {
                FAIL("analyzed on a hit");
                return analyze(code);
            });
            REQUIRE(again == held[id]);
        }
    }
}
#endif

TEST_CASE("hashes that differ in one byte or in all but the last word are different keys",
          "[lean_code_cache]") {
    // The guest's std::hash is the last word alone: these keys share a bucket there. Equality has
    // to compare the 32 bytes, or one hash gets the analysis of another.
    for (const int mode : {kSameLastWord, kOneByte}) {
        evmone::CodeCache cache;
        constexpr uint64_t kCount = 600;
        std::vector<const CodeAnalysis*> first(kCount);
        for (uint64_t id = 0; id < kCount; ++id)
            first[id] = &*cache.get_or_analyze(hash_of(id, mode), [&] { return analyze(code_of(id)); });
        for (uint64_t id = 0; id < kCount; ++id) {
            const auto code = code_of(id);
            const auto& a = *cache.get_or_analyze(hash_of(id, mode), [&]() -> CodeAnalysis {
                FAIL("analyzed on a hit");
                return analyze(code);
            });
            REQUIRE(same_code(a, code));
#if EVMONE_LEAN_CODE_CACHE
            REQUIRE(&a == first[id]);
#endif
        }
    }
    // Mode 2: the last word is the id's low 32 bits and the rest equal: all share the first 28.
    evmone::CodeCache cache;
    for (uint64_t id = 0; id < 300; ++id)
        REQUIRE(same_code(*cache.get_or_analyze(hash_of(id, kSameFirstBytes), [&] { return analyze(code_of(id)); }),
                          code_of(id)));
}

// ---------------------------------------------------------------------------------------------
// Through the state Host.

namespace {

constexpr address kSender = 0x5e00000000000000000000000000000000000004_address;
constexpr address kOuter = 0xaa00000000000000000000000000000000000001_address;
constexpr uint32_t kLoopBase = 0xc00000;   // the loop's callees: address kLoopBase + i
constexpr uint32_t kChainBase = 0xd00000;  // the chain's contracts: address kChainBase + d

enum : uint8_t {
    ADD = 0x01, LT = 0x10, GAS = 0x5a, MLOAD = 0x51, MSTORE = 0x52, JUMP = 0x56, JUMPI = 0x57,
    JUMPDEST = 0x5b, POP = 0x50, PUSH1 = 0x60, PUSH2 = 0x61, PUSH3 = 0x62, DUP2 = 0x81,
    DUP6 = 0x85, DUP7 = 0x86, CALL = 0xf1, CALLCODE = 0xf2, RETURN = 0xf3, DELEGATECALL = 0xf4,
    STATICCALL = 0xfa
};

address addr_of(uint32_t n) {
    address a{};
    a.bytes[17] = static_cast<uint8_t>(n >> 16);
    a.bytes[18] = static_cast<uint8_t>(n >> 8);
    a.bytes[19] = static_cast<uint8_t>(n);
    return a;
}

struct Asm {
    Code code;
    Asm& op(uint8_t o) { code.push_back(o); return *this; }
    Asm& push1(uint8_t v) { code.push_back(PUSH1); code.push_back(v); return *this; }
    Asm& push2(uint16_t v) {
        code.insert(code.end(), {PUSH2, static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)});
        return *this;
    }
    Asm& push3(uint32_t v) {
        code.insert(code.end(), {PUSH3, static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8),
                                 static_cast<uint8_t>(v)});
        return *this;
    }
    size_t size() const { return code.size(); }
};

// The loop's callee of class k: returns 1000 + k through a JUMP over a PUSH2 with 0x5b data, or,
// for k % 5 == 0, jumps into that push data and fails (an invalid jump, which burns the call's gas).
Code callee_code(uint64_t k) {
    Asm a;
    a.push2(static_cast<uint16_t>(1000 + k));  // 0
    const size_t dest_at = a.size();
    a.push2(0);                                // 3: patched
    a.op(JUMP);                                // 6
    a.code.insert(a.code.end(), {PUSH2, 0x5b, 0x5b});  // 7: 8 and 9 are push data
    for (uint64_t i = 0; i < k % 7; ++i)       // varies the length and the destination
        a.code.insert(a.code.end(), {PUSH1, 0x5b});
    const size_t dest = a.size();
    a.op(JUMPDEST).push1(0).op(MSTORE).push1(32).push1(0).op(RETURN);
    const size_t target = k % 5 == 0 ? 8 : dest;
    a.code[dest_at + 1] = static_cast<uint8_t>(target >> 8);
    a.code[dest_at + 2] = static_cast<uint8_t>(target);
    return a.code;
}

uint64_t callee_value(uint64_t k) { return k % 5 == 0 ? 0 : 1 + 1000 + k; }  // ok + returned word

// The outer loop: for c in 0..n-1 { mem[0] = 0; ok = KIND(addr kLoopBase + c); acc += ok + mem[0] }.
// Returns acc. KIND is one of CALL, CALLCODE, DELEGATECALL and STATICCALL (the last two without
// the value).
Code loop_code(uint16_t n, uint8_t kind) {
    const bool has_value = kind == CALL || kind == CALLCODE;
    Asm a;
    a.push1(0);  // c
    const size_t loop = a.size();
    a.op(JUMPDEST).push1(0).push1(0).op(MSTORE);
    a.push1(32).push1(0).push1(0).push1(0);  // outsize outoff insize inoff
    if (has_value)
        a.push1(0);
    a.push3(kLoopBase).op(has_value ? DUP7 : DUP6).op(ADD);  // address; DUP reaches c
    a.push2(20000).op(kind);
    a.push1(0).op(MLOAD).op(ADD);
    a.push1(64).op(MLOAD).op(ADD).push1(64).op(MSTORE);
    a.push1(1).op(ADD);
    a.push2(n).op(DUP2).op(LT).push2(static_cast<uint16_t>(loop)).op(JUMPI);
    a.op(POP).push1(32).push1(64).op(RETURN);
    return a.code;
}

// The chain's contract d: calls d + 1 with all gas, jumps over push data after the call, and
// returns the callee's word plus 1 (the last one returns 0): its result is depth - d.
Code chain_code(uint32_t d, uint32_t depth) {
    Asm a;
    if (d == depth) {
        a.push1(0).push1(0).op(MSTORE).push1(32).push1(0).op(RETURN);
        return a.code;
    }
    a.push1(32).push1(0).push1(0).push1(0).push1(0).push3(kChainBase + d + 1).op(GAS).op(CALL);
    const size_t dest_at = a.size();
    a.push1(0).op(JUMP);
    a.code.insert(a.code.end(), {PUSH2, 0x5b, 0x5b});
    a.code[dest_at + 1] = static_cast<uint8_t>(a.size());
    a.op(JUMPDEST);
    // [ok]: add the returned word, return it plus the ok flag (1)
    a.push1(0).op(MLOAD).op(ADD).push1(0).op(MSTORE).push1(32).push1(0).op(RETURN);
    return a.code;
}

struct Outcome {
    evmc_status_code status = EVMC_INTERNAL_ERROR;
    int64_t gas_left = -1;
    int64_t gas_refund = -1;
    bytes output;
    bool operator==(const Outcome& o) const {
        return status == o.status && gas_left == o.gas_left && gas_refund == o.gas_refund &&
               output == o.output;
    }
};

uint64_t word_of(const bytes& out) {
    if (out.size() != 32)
        return ~0ull;
    uint64_t v = 0;
    for (size_t i = 24; i < 32; ++i)
        v = v << 8 | out[i];
    return v;
}

struct EmptyView final : evmone::state::StateView {
    std::optional<Account> get_account(const address&) const noexcept override { return std::nullopt; }
    evmc::bytes_view get_account_code(const address&) const noexcept override { return {}; }
    bytes32 get_storage(const address&, const bytes32&) const noexcept override { return {}; }
};

struct NoHashes final : evmone::state::BlockHashes {
    bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// The Baseline interpreter without the cache: the same function as the VM's, behind a pointer the
// VM does not take for its cached one, so the Host analyzes every message's code afresh.
evmc_result uncached_execute(evmc_vm* vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept {
    return evmone::baseline::execute(vm, host, ctx, rev, msg, code, code_size);
}

struct World {
    // address, code, code hash
    struct Contract { address addr; Code code; bytes32 hash; };
    std::vector<Contract> contracts;
};

// Runs entry on the VM: a fresh state of the contracts, the cache of the VM as it is.
Outcome run(evmc::VM& vm, const World& world, const address& entry) {
    EmptyView view;
    NoHashes hashes;
    evmone::state::State state{view};
    for (const auto& c : world.contracts) {
        evmone::state::Account acc;
        acc.code = bytes{c.code.data(), c.code.size()};
        acc.code_hash = c.hash;
        acc.balance = 1000000;
        state.insert(c.addr, std::move(acc));
    }
    evmone::state::Account sender;
    sender.balance = 1000000;
    state.insert(kSender, std::move(sender));

    evmone::state::BlockInfo block;
    block.gas_limit = 2000000000;
    block.number = 1;
    block.timestamp = 1;
    evmone::state::Transaction tx;
    evmone::state::Host host{EVMC_PRAGUE, vm, state, block, hashes, tx};

    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 1000000000;
    msg.recipient = entry;
    msg.code_address = entry;
    msg.sender = kSender;
    const auto r = host.call(msg);
    Outcome o;
    o.status = r.status_code;
    o.gas_left = r.gas_left;
    o.gas_refund = r.gas_refund;
    o.output.assign(r.output_data, r.output_size);
    return o;
}

// The loop of n calls to classes 0..k-1 round robin (so n - k hits), under hash mode.
World loop_world(uint16_t n, uint16_t k, int mode, uint8_t kind) {
    World w;
    w.contracts.push_back({kOuter, loop_code(n, kind), hash_of(1u << 20, mode)});
    for (uint32_t i = 0; i < n; ++i)
        w.contracts.push_back({addr_of(kLoopBase + i), callee_code(i % k), hash_of(i % k, mode)});
    return w;
}

uint64_t loop_expected(uint16_t n, uint16_t k) {
    uint64_t acc = 0;
    for (uint32_t i = 0; i < n; ++i)
        acc += callee_value(i % k);
    return acc;
}

}  // namespace

TEST_CASE("nested calls to many distinct, repeated and colliding hashes, against the uncached path",
          "[lean_code_cache]") {
    struct Shape { uint16_t n, k; };
    const Shape shapes[] = {{1, 1}, {5, 5}, {40, 7}, {700, 700}, {1500, 60}, {3000, 2999}, {3000, 3000}};
    for (const int mode : {kRandom, kSameLastWord, kSameFirstBytes}) {
        for (const uint8_t kind : {CALL, DELEGATECALL, STATICCALL, CALLCODE}) {
            for (const auto& s : shapes) {
                if (kind != CALL && s.n > 700)
                    continue;  // the larger loops only with CALL, for the run time
                const auto world = loop_world(s.n, s.k, mode, kind);

                evmc::VM cached{new evmone::VM{}};
                REQUIRE(static_cast<evmone::VM*>(cached.get_raw_pointer())->has_cached_execution());
                evmc::VM plain{new evmone::VM{}};
                plain.get_raw_pointer()->execute = uncached_execute;
                REQUIRE_FALSE(static_cast<evmone::VM*>(plain.get_raw_pointer())->has_cached_execution());

                const auto ref = run(plain, world, kOuter);
                REQUIRE(ref.status == EVMC_SUCCESS);
                REQUIRE(word_of(ref.output) == loop_expected(s.n, s.k));
                // Twice on the VM that keeps its cache (the second run is all hits), once on the
                // other (its cache is empty): the same status, gas, refund and output.
                const auto first = run(cached, world, kOuter);
                REQUIRE(first == ref);
                const auto second = run(cached, world, kOuter);
                REQUIRE(second == ref);
            }
        }
    }
}

TEST_CASE("a call chain 100 deep returns through the analyses it inserted under", "[lean_code_cache]") {
    constexpr uint32_t kDepth = 100;
    World w;
    for (uint32_t d = 0; d <= kDepth; ++d)
        w.contracts.push_back({addr_of(kChainBase + d), chain_code(d, kDepth), hash_of(d, kRandom)});
    evmc::VM cached{new evmone::VM{}};
    evmc::VM plain{new evmone::VM{}};
    plain.get_raw_pointer()->execute = uncached_execute;
    const auto ref = run(plain, w, addr_of(kChainBase));
    REQUIRE(ref.status == EVMC_SUCCESS);
    REQUIRE(word_of(ref.output) == kDepth);  // each level adds the ok flag of its call
    REQUIRE(run(cached, w, addr_of(kChainBase)) == ref);
    REQUIRE(run(cached, w, addr_of(kChainBase)) == ref);
    // Entered from the middle: the cache holds the deeper contracts already.
    const auto mid_ref = run(plain, w, addr_of(kChainBase + 40));
    REQUIRE(word_of(mid_ref.output) == kDepth - 40);
    REQUIRE(run(cached, w, addr_of(kChainBase + 40)) == mid_ref);
}

TEST_CASE("the cache serves the code of the code address, not of the recipient", "[lean_code_cache]") {
    // DELEGATECALL, CALLCODE: the proxy is the recipient, kLoopBase + 0 the code address. The loop
    // test covers these in bulk; this one has two classes that return different words.
    World w;
    w.contracts.push_back({kOuter, loop_code(2, DELEGATECALL), hash_of(1u << 20, kRandom)});
    w.contracts.push_back({addr_of(kLoopBase + 0), callee_code(1), hash_of(1, kRandom)});
    w.contracts.push_back({addr_of(kLoopBase + 1), callee_code(2), hash_of(2, kRandom)});
    evmc::VM cached{new evmone::VM{}};
    const auto r = run(cached, w, kOuter);
    REQUIRE(r.status == EVMC_SUCCESS);
    REQUIRE(word_of(r.output) == callee_value(1) + callee_value(2));
}
