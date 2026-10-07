// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The fused SLOAD and SSTORE host calls (evmone::state::Host::sload and ::sstore) against the
// sequences they replace, access_storage() + get_storage() and access_storage() + set_storage().
// The orderings they must keep are not covered by any fixture: a cold SLOAD that runs out of gas
// reads nothing, because a stateless witness may omit a slot that the reference client never
// read; and a revert of a cold SSTORE must erase a fresh slot only after the value change that
// points at it has been undone.

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/host.hpp>
#include <evmone/test/state/state.hpp>

namespace {

using evmc::address;
using evmc::bytes32;
using namespace evmc::literals;
using evmone::state::StorageValue;

constexpr address kContract = 0xcccccccccccccccccccccccccccccccccccccc01_address;

bytes32 word(uint8_t v) {
    bytes32 r{};
    r.bytes[31] = v;
    return r;
}

// The pre-state value of a slot is its key's last byte plus one, so that every initial value is
// non-zero and tells which slot was read. Counts the reads.
class CountingView final : public evmone::state::StateView {
public:
    mutable uint32_t storage_reads = 0;

    std::optional<Account> get_account(const address&) const noexcept override { return Account{}; }
    evmc::bytes_view get_account_code(const address&) const noexcept override { return {}; }
    bytes32 get_storage(const address&, const bytes32& key) const noexcept override {
        ++storage_reads;
        return word(static_cast<uint8_t>(key.bytes[31] + 1));
    }
};

class NoBlockHashes final : public evmone::state::BlockHashes {
public:
    bytes32 get_block_hash(int64_t) const noexcept override { return {}; }
};

// One State, Host and view; the host is used through evmc::Host, as the interpreter does.
struct Fixture {
    CountingView view;
    evmone::state::State state{view};
    evmc::VM vm;
    evmone::state::BlockInfo block;
    NoBlockHashes block_hashes;
    evmone::state::Transaction tx;
    evmone::state::Host host{EVMC_CANCUN, vm, state, block, block_hashes, tx};

    Fixture() { state.insert(kContract); }

    evmc::Host& h() { return host; }
    const StorageValue* slot(const bytes32& key) {
        auto& storage = state.get(kContract).storage;
        const auto it = storage.find(key);
        return it == storage.end() ? nullptr : &it->second;
    }
};

}  // namespace

TEST_CASE("cold SLOAD out of gas reads no slot", "[storage_host]") {
    Fixture f;
    const auto key = word(5);
    int64_t gas = 1999;
    evmc_bytes32 buffer{};
    CHECK(f.h().sload(kContract, key, 2000, gas, buffer) == nullptr);
    CHECK(gas == -1);
    // Nothing was fetched, but the slot stays warm: the access is not undone by the failure.
    CHECK(f.view.storage_reads == 0);
    REQUIRE(f.slot(key) != nullptr);
    CHECK(f.slot(key)->access_status == EVMC_ACCESS_WARM);
    CHECK_FALSE(f.slot(key)->loaded);

    // The next access is warm and fetches, once.
    gas = 0;
    const auto* value = f.h().sload(kContract, key, 2000, gas, buffer);
    REQUIRE(value != nullptr);
    CHECK(bytes32{*value} == word(6));
    CHECK(gas == 0);
    CHECK(f.view.storage_reads == 1);
    f.h().sload(kContract, key, 2000, gas, buffer);
    CHECK(f.view.storage_reads == 1);
}

TEST_CASE("cold SLOAD with exactly the surcharge succeeds", "[storage_host]") {
    Fixture f;
    int64_t gas = 2000;
    evmc_bytes32 buffer{};
    const auto* value = f.h().sload(kContract, word(9), 2000, gas, buffer);
    REQUIRE(value != nullptr);
    CHECK(bytes32{*value} == word(10));
    CHECK(gas == 0);
    CHECK(f.view.storage_reads == 1);
}

TEST_CASE("SLOAD and SSTORE equal the sequences they replace", "[storage_host]") {
    Fixture fused;
    Fixture twin;
    const std::array<bytes32, 4> keys{word(0), word(1), word(2), word(3)};
    uint32_t rng = 12345;
    const auto next = [&rng] {
        rng = rng * 1664525u + 1013904223u;
        return rng >> 16;
    };

    std::vector<size_t> checkpoints_fused, checkpoints_twin;
    for (int i = 0; i < 20000; ++i) {
        const auto& key = keys[next() % keys.size()];
        switch (next() % 7) {
        case 0:
        case 1: {
            int64_t gas_a = static_cast<int64_t>(next() % 4) * 1000;
            int64_t gas_b = gas_a;
            evmc_bytes32 buffer{};
            const auto* a = fused.h().sload(kContract, key, 2000, gas_a, buffer);
            const bool cold = twin.h().access_storage(kContract, key) == EVMC_ACCESS_COLD;
            const bool oog = cold && (gas_b -= 2000) < 0;
            REQUIRE((a == nullptr) == oog);
            REQUIRE(gas_a == gas_b);
            if (!oog)
                REQUIRE(bytes32{*a} == twin.h().get_storage(kContract, key));
            break;
        }
        case 2:
        case 3:
        case 4: {
            const auto value = word(static_cast<uint8_t>(next() % 3));
            evmc_access_status access{};
            const auto a = fused.h().sstore(kContract, key, value, access);
            const auto expected_access = twin.h().access_storage(kContract, key);
            const auto b = twin.h().set_storage(kContract, key, value);
            REQUIRE(a == b);
            REQUIRE(access == expected_access);
            break;
        }
        case 5:
            checkpoints_fused.push_back(fused.state.checkpoint());
            checkpoints_twin.push_back(twin.state.checkpoint());
            break;
        default:
            if (!checkpoints_fused.empty()) {
                fused.state.rollback(checkpoints_fused.back());
                twin.state.rollback(checkpoints_twin.back());
                checkpoints_fused.pop_back();
                checkpoints_twin.pop_back();
            }
            break;
        }

        // The slots, including the access-only ones, are the same after every step.
        auto& sa = fused.state.get(kContract).storage;
        auto& sb = twin.state.get(kContract).storage;
        REQUIRE(sa.size() == sb.size());
        for (const auto& [k, va] : sa) {
            const auto it = sb.find(k);
            REQUIRE(it != sb.end());
            REQUIRE(va.current == it->second.current);
            REQUIRE(va.original == it->second.original);
            REQUIRE(va.access_status == it->second.access_status);
            REQUIRE(va.loaded == it->second.loaded);
        }
        REQUIRE(fused.view.storage_reads == twin.view.storage_reads);
    }
}

TEST_CASE("reverting a cold SSTORE of a fresh slot erases it", "[storage_host]") {
    Fixture f;
    const auto key = word(4);
    const auto cp = f.state.checkpoint();
    evmc_access_status access{};
    CHECK(f.h().sstore(kContract, key, word(0), access) == EVMC_STORAGE_DELETED);
    CHECK(access == EVMC_ACCESS_COLD);
    REQUIRE(f.slot(key) != nullptr);
    f.state.rollback(cp);
    CHECK(f.slot(key) == nullptr);

    // Warm and loaded: a revert restores the value and the warm flag of the entry that stays.
    CHECK(f.h().sstore(kContract, key, word(7), access) == EVMC_STORAGE_MODIFIED);
    const auto cp2 = f.state.checkpoint();
    CHECK(f.h().sstore(kContract, key, word(8), access) == EVMC_STORAGE_ASSIGNED);
    CHECK(access == EVMC_ACCESS_WARM);
    f.state.rollback(cp2);
    REQUIRE(f.slot(key) != nullptr);
    CHECK(f.slot(key)->current == word(7));
}
