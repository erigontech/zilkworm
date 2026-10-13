// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// DirectStateView::get_account hands the evmone State a handle to its record of the account, and
// get_storage_at, get_account_code_at and apply_state_diff use it instead of looking the address
// up again. The handle must be that record, so every read through it equals the plain read and
// the diff it carries lands where the lookup would have put it.

#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone/test/state/bal.hpp>
#include <evmone/test/state/state_diff.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>

using namespace zilkworm;
using namespace zilkworm::test_util;
using silkworm::Bytes;

namespace {

using evmc::bytes32;
using evmone::state::BalBuilder;
using evmone::state::BalStateView;
using evmone::state::StateDiff;
using namespace evmc::literals;

constexpr evmc::address kNoStorage = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01_address;
constexpr evmc::address kOneSlot = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02_address;
constexpr evmc::address kSlotIndex = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03_address;
constexpr evmc::address kRandom = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa04_address;
constexpr evmc::address kAbsent = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa05_address;
constexpr evmc::address kDoomed = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa06_address;
constexpr evmc::address kBorn = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa07_address;

constexpr unsigned kManySlots = 40;

const Bytes kCode{0x60, 0x01, 0x60, 0x00, 0x55, 0x00};

uint64_t next_rand(uint64_t& s) {
    s = s * 6364136223846793005ull + 1442695040888963407ull;
    return s >> 17;
}

bytes32 index_key(uint64_t i) {
    bytes32 k{};
    for (int b = 0; b < 8; ++b) k.bytes[31 - b] = static_cast<uint8_t>(i >> (8 * b));
    return k;
}

bytes32 random_key(uint64_t& s) {
    bytes32 k{};
    for (auto& b : k.bytes) b = static_cast<uint8_t>(next_rand(s));
    return k;
}

using Slots = std::vector<std::pair<bytes32, bytes32>>;

Slots index_slots() {
    Slots out;
    for (unsigned i = 0; i < kManySlots; ++i) out.emplace_back(index_key(i), index_key(1000 + i));
    return out;
}

Slots random_slots() {
    Slots out;
    uint64_t s = 7;
    for (unsigned i = 0; i < kManySlots; ++i) out.emplace_back(random_key(s), index_key(2000 + i));
    return out;
}

struct Fixture {
    Prestate pre;
    std::unique_ptr<DirectState> state;

    Fixture()
        : pre{build_prestate({
              {kNoStorage, 1, 100, kCode, {}},
              {kOneSlot, 2, 200, {}, {{index_key(5), index_key(55)}}},
              {kSlotIndex, 3, 300, kCode, index_slots()},
              {kRandom, 4, 400, {}, random_slots()},
              {kDoomed, 5, 500, {}, {{index_key(1), index_key(11)}}},
          })},
          state{std::make_unique<DirectState>(std::span<uint8_t>{pre.blob},
                                              std::span<uint8_t>{pre.nodestore})} {
        REQUIRE(state->sanitize());
    }
};

std::vector<bytes32> probe_keys(const Slots& present) {
    std::vector<bytes32> keys;
    for (const auto& [k, _] : present) keys.push_back(k);
    uint64_t s = 99;
    for (unsigned i = 0; i < 20; ++i) keys.push_back(random_key(s));
    for (unsigned i = 0; i < kManySlots + 5; ++i) keys.push_back(index_key(i));
    keys.push_back(bytes32{});
    return keys;
}

}  // namespace

TEST_CASE("the account handle is the DirectState record", "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};
    for (const auto& addr : {kNoStorage, kOneSlot, kSlotIndex, kRandom}) {
        const auto acc = view.get_account(addr);
        REQUIRE(acc.has_value());
        CHECK(acc->handle == f.state->read_account(addr));
        CHECK(acc->handle != nullptr);
    }
}

TEST_CASE("reads through the handle equal the plain reads", "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};
    const std::pair<evmc::address, Slots> accounts[] = {
        {kNoStorage, {}},
        {kOneSlot, {{index_key(5), index_key(55)}}},
        {kSlotIndex, index_slots()},
        {kRandom, random_slots()},
    };
    for (const auto& [addr, slots] : accounts) {
        const auto acc = view.get_account(addr);
        REQUIRE(acc.has_value());
        CHECK(acc->has_storage == !slots.empty());
        const auto code = view.get_account_code(addr);
        const auto code_at = view.get_account_code_at(acc->handle, addr);
        CHECK(code_at.data() == code.data());
        CHECK(code_at.size() == code.size());
        for (const auto& key : probe_keys(slots)) {
            CHECK(view.get_storage_at(acc->handle, addr, key) == view.get_storage(addr, key));
        }
        for (const auto& [k, v] : slots) CHECK(view.get_storage_at(acc->handle, addr, k) == v);
    }
}

TEST_CASE("a null handle takes the lookup", "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};
    CHECK(view.get_storage_at(nullptr, kOneSlot, index_key(5)) == index_key(55));
    CHECK(view.get_account_code_at(nullptr, kNoStorage).size() == kCode.size());
}

TEST_CASE("absent and deleted accounts carry no handle", "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};
    CHECK_FALSE(view.get_account(kAbsent).has_value());

    StateDiff diff;
    diff.deleted_accounts.push_back(kDoomed);
    f.state->apply_state_diff(diff);
    CHECK_FALSE(view.get_account(kDoomed).has_value());
}

TEST_CASE("a handle to a created account survives a rehash of created_accounts_",
          "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};

    StateDiff diff;
    auto& e = diff.modified_accounts.emplace_back();
    e.addr = kBorn;
    e.nonce = 1;
    e.balance = 10;
    e.modified_storage = {{index_key(3), index_key(33)}};
    f.state->apply_state_diff(diff);

    const auto acc = view.get_account(kBorn);
    REQUIRE(acc.has_value());
    REQUIRE(acc->handle == f.state->read_account(kBorn));

    // Materializing absent addresses inserts into the map: far more than its bucket count.
    for (uint64_t i = 0; i < 600; ++i) {
        evmc::address a{};
        for (int b = 0; b < 8; ++b) a.bytes[19 - b] = static_cast<uint8_t>((i + 1) >> (8 * b));
        a.bytes[0] = 0xcc;
        CHECK_FALSE(view.get_account(a).has_value());
    }
    CHECK(f.state->created_accounts().size() > 600);

    CHECK(acc->handle == f.state->read_account(kBorn));
    CHECK(view.get_storage_at(acc->handle, kBorn, index_key(3)) == index_key(33));
    CHECK(view.get_storage_at(acc->handle, kBorn, index_key(4)) == bytes32{});
}

TEST_CASE("apply_state_diff gives the same root with and without handles", "[state_zz][handle]") {
    Fixture with;
    Fixture without;
    DirectStateView view{*with.state};

    auto entry_for = [&](StateDiff& diff, const evmc::address& addr, bool use_handle) {
        auto& e = diff.modified_accounts.emplace_back();
        e.addr = addr;
        e.nonce = 9;
        e.balance = 999;
        e.modified_storage = {{index_key(2), index_key(77)}, {index_key(5), bytes32{}},
                              {index_key(1000), index_key(78)}};
        if (use_handle) e.view_handle = view.get_account(addr)->handle;
    };

    StateDiff d1, d2;
    for (const auto& addr : {kNoStorage, kOneSlot, kSlotIndex, kRandom}) {
        entry_for(d1, addr, true);
        entry_for(d2, addr, false);
    }
    // A new account has no record to hand over: the handle stays null.
    for (auto* d : {&d1, &d2}) {
        auto& e = d->modified_accounts.emplace_back();
        e.addr = kBorn;
        e.nonce = 1;
        e.balance = 5;
    }
    with.state->apply_state_diff(d1);
    without.state->apply_state_diff(d2);

    const MirrorRoot a = mirror_check_root(*with.state, with.pre.prev_root);
    const MirrorRoot b = mirror_check_root(*without.state, without.pre.prev_root);
    CHECK(a.missing == b.missing);
    CHECK(a.root == b.root);
    CHECK(with.state->read_storage(kSlotIndex, index_key(2)) == index_key(77));
    CHECK(with.state->read_storage(kSlotIndex, index_key(1000)) == index_key(78));
}

TEST_CASE("BalStateView records storage reads made through a handle", "[state_zz][handle]") {
    Fixture f;
    DirectStateView view{*f.state};
    BalBuilder builder;
    BalStateView bal{view, builder};

    const auto acc = bal.get_account(kOneSlot);
    REQUIRE(acc.has_value());
    CHECK(bal.get_storage_at(acc->handle, kOneSlot, index_key(5)) == index_key(55));

    const auto list = builder.build();
    REQUIRE(list.accounts.size() == 1);
    CHECK(list.accounts[0].addr == kOneSlot);
    REQUIRE(list.accounts[0].storage_reads.size() == 1);
    CHECK(list.accounts[0].storage_reads[0] == index_key(5));
}
