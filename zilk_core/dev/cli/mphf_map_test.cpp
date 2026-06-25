// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Standalone MphfBuilder tests (no gtest plumbing); returns failure count as exit code.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <print>
#include <ranges>
#include <source_location>
#include <span>
#include <unordered_map>
#include <vector>

#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using zilkworm::MphfBuilder;
using zilkworm::MphfMapHeader;
using zilkworm::MphfMap;
using zilkworm::addr_key8;
using zilkworm::kMphfMapVersion;
using silkworm::ByteView;

namespace {

inline constexpr uint32_t kTestMphfMagic = 0x54534554u;  // 'TEST'

int g_failures = 0;
int g_tests = 0;
const char* g_current_test = "<none>";

inline void expect_true(bool cond,
                        std::source_location loc = std::source_location::current()) {
    if (!cond) {
        std::println(stderr, "[FAIL {}] {}:{} expect_true",
                     g_current_test, loc.file_name(), loc.line());
        ++g_failures;
    }
}

inline void expect_false(bool cond,
                         std::source_location loc = std::source_location::current()) {
    if (cond) {
        std::println(stderr, "[FAIL {}] {}:{} expect_false",
                     g_current_test, loc.file_name(), loc.line());
        ++g_failures;
    }
}

template <class A, class B>
void expect_eq(const A& a, const B& b,
               std::source_location loc = std::source_location::current()) {
    if (!(a == b)) {
        std::println(stderr, "[FAIL {}] {}:{} expect_eq: {} != {}",
                     g_current_test, loc.file_name(), loc.line(), a, b);
        ++g_failures;
    }
}

#define RUN_TEST(name)                                                                     \
    do {                                                                                   \
        g_current_test = #name;                                                            \
        ++g_tests;                                                                         \
        const int before = g_failures;                                                     \
        name();                                                                            \
        const int after = g_failures;                                                      \
        std::println("{} {}", (after == before ? "PASS" : "FAIL"), #name);                 \
    } while (0)

struct AddrBody {
    std::array<uint8_t, 20> addr{};
    std::vector<uint8_t> body;
};

// Singleton-slot lookup by uint64_t key (mirrors DirectState's primary path).
[[nodiscard]] inline std::span<const uint8_t> singleton_lookup(const MphfMapHeader* m, uint64_t k8) noexcept {
    if (m->n_keys == 0) return {};
    const uint32_t idx = m->index_lookup(k8);
    if (idx >= m->n_keys) [[unlikely]] return {};
    const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
        reinterpret_cast<const uint8_t*>(m) + m->slot_offsets_offset);
    const uint32_t off = slot_offsets[idx];
    if (off == 0) return {};
    const uint8_t* data = reinterpret_cast<const uint8_t*>(m) + m->data_offset;
    uint64_t body_len;
    std::memcpy(&body_len, data + off, 8);
    return std::span<const uint8_t>{data + off + 8, static_cast<size_t>(body_len)};
}

AddrBody make_addr_body(uint64_t tag, uint8_t seed_byte) {
    AddrBody ab;
    std::memcpy(ab.addr.data(), &tag, 8);
    ab.addr[19] = static_cast<uint8_t>((tag >> 8) ^ seed_byte);
    ab.body.resize(60);
    std::memcpy(ab.body.data(), ab.addr.data(), 20);
    std::memcpy(ab.body.data() + 20, &tag, 8);
    // pad
    std::memset(ab.body.data() + 28, 0xAB, 32);
    return ab;
}

// ----------------------------------------------------------------------------
// Test 1: clean key set with default retry budget — finalize() returns a
// valid blob and every key resolves via the primary path. Establishes that
// the graceful-fallback code path doesn't break the clean case.
// ----------------------------------------------------------------------------
void CleanBuild_AllPrimary() {
    const uint32_t N = 64;
    std::vector<AddrBody> entries;
    entries.reserve(N);
    MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
    for (uint32_t i = 0; i < N; ++i) {
        auto ab = make_addr_body(0x10000ULL + i, 0);
        b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*ab.addr.data())),
              ByteView{ab.body.data(), ab.body.size()});
        entries.push_back(std::move(ab));
    }
    auto blob = std::move(b).finalize();
    expect_false(blob.empty());
    if (blob.empty()) return;

    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());
    expect_true(m->n_keys > 0);

    for (const auto& e : entries) {
        uint64_t k8;
        std::memcpy(&k8, e.addr.data(), 8);
        k8 = (k8 & 0x00FFFFFFFFFFFFFFull) | (uint64_t(e.addr[19]) << 56);
        auto body = singleton_lookup(m, k8);
        if (body.empty()) {
            MphfMap mm{m};
            if (auto found = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()))) body = *found;
        }
        expect_false(body.empty());
        if (body.empty()) continue;
        expect_eq(body.size(), e.body.size());
        expect_eq(std::memcmp(body.data(), e.body.data(), e.body.size()), 0);
    }
}

void ExhaustionForcedByMockRetries_Spills() {
    bool spilled_at_least_once = false;
    std::vector<AddrBody> entries;
    std::vector<uint8_t> blob;
    for (uint32_t N : {16u, 32u, 64u, 128u, 256u, 512u}) {
        entries.clear();
        entries.reserve(N);
        MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
        b.set_max_retries_for_test(2);
        b.set_max_displacement_for_test(1);
        const uint8_t seed_byte = static_cast<uint8_t>(N & 0xFFu);
        for (uint32_t i = 0; i < N; ++i) {
            auto ab = make_addr_body(0x20000ULL + i, seed_byte);
            b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*ab.addr.data())),
                  ByteView{ab.body.data(), ab.body.size()});
            entries.push_back(std::move(ab));
        }
        blob = std::move(b).finalize();
        if (blob.empty()) continue;
        const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data());
        if (m->collisions_size > 0) {
            spilled_at_least_once = true;
            break;
        }
    }

    expect_true(spilled_at_least_once);
    expect_false(blob.empty());
    if (blob.empty() || !spilled_at_least_once) return;

    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());
    expect_true(m->collisions_size > 0);

    uint32_t reached = 0;
    for (const auto& e : entries) {
        uint64_t k8;
        std::memcpy(&k8, e.addr.data(), 8);
        k8 = (k8 & 0x00FFFFFFFFFFFFFFull) | (uint64_t(e.addr[19]) << 56);
        auto body = singleton_lookup(m, k8);
        if (body.empty() || std::memcmp(body.data(), e.addr.data(), 20) != 0) {
            MphfMap mm{m};
            if (auto found = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()))) body = *found; else body = {};
        }
        if (!body.empty() && body.size() == e.body.size() &&
            std::memcmp(body.data(), e.body.data(), e.body.size()) == 0) {
            ++reached;
        }
    }
    expect_eq(reached, static_cast<uint32_t>(entries.size()));
}

void Walkers_VisitEachEntryOnce() {
    std::vector<AddrBody> entries;
    std::vector<uint8_t> blob;
    for (uint32_t N : {32u, 64u, 128u, 256u}) {
        entries.clear();
        entries.reserve(N);
        MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
        b.set_max_retries_for_test(2);
        b.set_max_displacement_for_test(1);
        for (uint32_t i = 0; i < N; ++i) {
            auto ab = make_addr_body(0x30000ULL + i, static_cast<uint8_t>(N & 0xFFu));
            b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*ab.addr.data())),
                  ByteView{ab.body.data(), ab.body.size()});
            entries.push_back(std::move(ab));
        }
        blob = std::move(b).finalize();
        if (blob.empty()) continue;
        const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data());
        if (m->collisions_size > 0) break;
    }
    expect_false(blob.empty());
    if (blob.empty()) return;

    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());

    std::vector<std::array<uint8_t, 20>> visited;
    visited.reserve(entries.size());
    MphfMap mm{m};
    expect_true(mm.for_each<20>([&](const uint8_t* key_ptr, std::span<uint8_t> /*body*/) {
        std::array<uint8_t, 20> a{};
        std::memcpy(a.data(), key_ptr, 20);
        visited.push_back(a);
    }));

    expect_eq(visited.size(), entries.size());

    uint32_t found = 0;
    for (const auto& e : entries) {
        if (std::ranges::contains(visited, e.addr)) ++found;
    }
    expect_eq(found, static_cast<uint32_t>(entries.size()));
}

void SpilledSlotsReuseCollisionMarker() {
    std::vector<uint8_t> blob;
    for (uint32_t N : {64u, 128u, 256u, 512u}) {
        MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
        b.set_max_retries_for_test(2);
        b.set_max_displacement_for_test(1);
        for (uint32_t i = 0; i < N; ++i) {
            auto ab = make_addr_body(0x40000ULL + i, static_cast<uint8_t>(N & 0xFFu));
            b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*ab.addr.data())),
                  ByteView{ab.body.data(), ab.body.size()});
        }
        blob = std::move(b).finalize();
        if (blob.empty()) continue;
        const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data());
        if (m->collisions_size > 0) break;
    }
    expect_false(blob.empty());
    if (blob.empty()) return;

    const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data());
    const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
        blob.data() + m->slot_offsets_offset);

    uint32_t n_legacy_sentinels = 0;
    uint32_t n_zero_slots = 0;
    for (uint32_t i = 0; i < m->n_keys; ++i) {
        if (slot_offsets[i] == 0xFFFFFFFFu) ++n_legacy_sentinels;
        if (slot_offsets[i] == 0u) ++n_zero_slots;
    }
    std::println("[INFO SpilledSlotsReuseCollisionMarker] n_zero_slots={}, "
                 "n_legacy_sentinels={}, collisions_size={}",
                 n_zero_slots, n_legacy_sentinels, m->collisions_size);
    expect_eq(n_legacy_sentinels, 0u);
    expect_true(m->collisions_size > 0);
}

// Test 5: a CHD-spilled unique-fingerprint address must stay reachable on the
// EVM read path. build_blob_from_accounts feeds every address into the addr
// MPHF, but find_pre_account_unchecked only checks the singleton slot + the
// AddrCollisionEntry table (fingerprint groups of size > 1 only) — never the
// MPHF-internal sidecar. A spilled singleton lands in the sidecar but not the
// table, so the read path can't see it.

struct CollEntry {  // mirrors AddrCollisionEntry
    std::array<uint8_t, 20> addr;
    uint32_t entry_offset;
};

// AddrCollisionEntry table as built by build_blob_from_accounts: fingerprint
// groups of size > 1 only, sorted by full address.
std::vector<CollEntry> build_addr_collision_table(const std::vector<AddrBody>& entries,
                                                  const MphfMapHeader* m) {
    const auto* slot_offsets =
        reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(m) + m->slot_offsets_offset);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(m) + m->data_offset;

    auto entry_offset_for_addr = [&](const uint8_t addr20[20]) -> uint32_t {
        const uint64_t k8 = addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*addr20));
        const uint32_t off = slot_offsets[m->index_lookup(k8)];
        if (off != 0 && std::memcmp(data + off + 8u, addr20, 20) == 0) return off;
        if (m->collisions_size == 0) return 0u;
        const auto* ce = reinterpret_cast<const zilkworm::MphfCollisionEntry*>(
            reinterpret_cast<const uint8_t*>(m) + m->collisions_offset);
        const uint32_t n_c = m->collisions_size / static_cast<uint32_t>(sizeof(zilkworm::MphfCollisionEntry));
        auto it = std::lower_bound(
            ce, ce + n_c, k8,
            [](const zilkworm::MphfCollisionEntry& e, uint64_t kk) noexcept { return e.key < kk; });
        for (; it != ce + n_c && it->key == k8; ++it) {
            if (std::memcmp(data + it->offset + 8u, addr20, 20) == 0) return it->offset;
        }
        return 0u;
    };

    std::unordered_map<uint64_t, std::vector<uint32_t>> by_key;
    for (uint32_t i = 0; i < entries.size(); ++i)
        by_key[addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*entries[i].addr.data()))].push_back(i);

    std::vector<CollEntry> table;
    for (const auto& [k, group] : by_key) {
        if (group.size() <= 1) continue;
        for (uint32_t gi : group)
            table.push_back({entries[gi].addr, entry_offset_for_addr(entries[gi].addr.data())});
    }
    std::ranges::sort(table,
                      [](const CollEntry& a, const CollEntry& b) { return std::memcmp(a.addr.data(), b.addr.data(), 20) < 0; });
    return table;
}

// Reproduces find_pre_account_unchecked (minus cache / deleted-set).
const uint8_t* evm_read_path_find(MphfMapHeader* m, const std::vector<CollEntry>& /*table*/, const uint8_t addr[20]) {
    const auto* slot_offsets =
        reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(m) + m->slot_offsets_offset);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(m) + m->data_offset;

    const uint64_t k8 = addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*addr));
    const uint32_t off = slot_offsets[m->index_lookup(k8)];
    if (off != 0 && std::memcmp(data + off + 8u, addr, 20) == 0) return data + off + 8u;

    MphfMap mm{m};
    if (auto b = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*addr))) return b->data();
    return nullptr;
}

void EvmReadPath_MissesSpilledSingleton() {
    // Two addresses (distinct fingerprints) that collide into one bucket and
    // spill under a 1-seed / 1-displacement CHD budget.
    std::vector<AddrBody> entries{make_addr_body(0x516000, 0), make_addr_body(0x516001, 0)};

    MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
    b.set_max_retries_for_test(1);
    b.set_max_displacement_for_test(1);
    for (const auto& e : entries)
        b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data())), ByteView{e.body.data(), e.body.size()});
    auto blob = std::move(b).finalize();

    expect_false(blob.empty());
    if (blob.empty()) return;
    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());
    expect_true(m->collisions_size > 0);  // confirm the pair spilled

    const auto table = build_addr_collision_table(entries, m);

    const auto& e = entries[0];
    // Spilled singleton: present in the sidecar, absent from the collision table.
    MphfMap mm{m};
    auto stored = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()));
    expect_false(!stored.has_value());
    expect_eq(table.size(), 0u);
    // Expected behaviour: the EVM read path finds the account. (Currently fails.)
    expect_true(evm_read_path_find(m, table, e.addr.data()) != nullptr);
}

}  // namespace

int main() {
    RUN_TEST(CleanBuild_AllPrimary);
    RUN_TEST(ExhaustionForcedByMockRetries_Spills);
    RUN_TEST(Walkers_VisitEachEntryOnce);
    RUN_TEST(SpilledSlotsReuseCollisionMarker);
    RUN_TEST(EvmReadPath_MissesSpilledSingleton);
    std::println("\n{} test(s), {} failure(s)", g_tests, g_failures);
    return g_failures == 0 ? 0 : 1;
}
