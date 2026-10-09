// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// MphfBuilder / MphfMap unit tests (zilkworm.tests target).
//
// Why these sit alongside the account-read soundness tests: `DirectState`'s account and
// code lookups route through this minimal perfect hash map, so the account-read argument
// depends on `find()` never turning a genuinely-present key into a false miss. The map
// gives each distinct key one index and stores its body there; keys the builder cannot
// place that way go into a side list, the collision sidecar. `MphfMap::find` consults the
// sidecar ONLY when the slot it lands on is empty — an occupied slot whose embedded key
// fails the byte comparison is a definitive miss, with no sidecar scan. So the builder owes
// the lookup one invariant: a key whose body lives in the sidecar must land on an empty
// slot. `chd_solve` upholds it with an explicit occupancy map, co-spilling any placed key
// that shares an index with a spilled one (see mphf_builder.cpp). The four spill-invariant
// cases below were added for that work.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <span>
#include <unordered_map>
#include <vector>

#include <catch2/catch_test_macros.hpp>

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

[[nodiscard]] inline uint64_t key8_of(const AddrBody& e) noexcept {
    return addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()));
}

[[nodiscard]] inline const uint32_t* slot_offsets_of(const MphfMapHeader* m) noexcept {
    return reinterpret_cast<const uint32_t*>(
        reinterpret_cast<const uint8_t*>(m) + m->slot_offsets_offset);
}

[[nodiscard]] inline const zilkworm::MphfCollisionEntry* collisions_of(const MphfMapHeader* m) noexcept {
    return reinterpret_cast<const zilkworm::MphfCollisionEntry*>(
        reinterpret_cast<const uint8_t*>(m) + m->collisions_offset);
}

[[nodiscard]] inline uint32_t n_collisions_of(const MphfMapHeader* m) noexcept {
    return m->collisions_size / static_cast<uint32_t>(sizeof(zilkworm::MphfCollisionEntry));
}

// A map over n sequential tagged addresses. A 0 budget override means "use the
// production default"; small overrides force CHD to exhaust and spill.
struct BuiltMap {
    std::vector<uint8_t> blob;
    std::vector<AddrBody> entries;
    [[nodiscard]] MphfMapHeader* header() noexcept {
        return reinterpret_cast<MphfMapHeader*>(blob.data());
    }
};

[[nodiscard]] BuiltMap build_map(uint32_t max_retries, uint32_t max_displacement, uint32_t n,
                                 uint64_t tag_base) {
    BuiltMap out;
    out.entries.reserve(n);
    MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
    b.set_max_retries_for_test(max_retries);
    b.set_max_displacement_for_test(max_displacement);
    for (uint32_t i = 0; i < n; ++i) {
        auto ab = make_addr_body(tag_base + i, 0);
        b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*ab.addr.data())),
              ByteView{ab.body.data(), ab.body.size()});
        out.entries.push_back(std::move(ab));
    }
    out.blob = std::move(b).finalize();
    return out;
}

// The production read path; empty span when the key is absent.
[[nodiscard]] std::span<uint8_t> find_body(MphfMapHeader* m,
                                           const std::array<uint8_t, 20>& addr) noexcept {
    MphfMap mm{m};
    if (auto found = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*addr.data())))
        return *found;
    return {};
}

}  // namespace

// Clean key set with default retry budget: finalize() returns a valid blob
// and every key resolves via the primary path. Establishes that the
// graceful-fallback code path doesn't break the clean case.
TEST_CASE("MphfBuilder clean build resolves all keys via primary path", "[mphf]") {
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
    REQUIRE_FALSE(blob.empty());

    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());
    CHECK(m->n_keys > 0);

    for (const auto& e : entries) {
        uint64_t k8;
        std::memcpy(&k8, e.addr.data(), 8);
        k8 = (k8 & 0x00FFFFFFFFFFFFFFull) | (uint64_t(e.addr[19]) << 56);
        auto body = singleton_lookup(m, k8);
        if (body.empty()) {
            MphfMap mm{m};
            if (auto found = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()))) body = *found;
        }
        REQUIRE_FALSE(body.empty());
        CHECK(body.size() == e.body.size());
        CHECK(std::memcmp(body.data(), e.body.data(), e.body.size()) == 0);
    }
}

// A CHD bucket that exhausts its displacement budget spills its keys into the
// collision sidecar and keeps displacement factor 0, so those keys probe the
// index index_lookup() reproduces at runtime. find() treats an occupied slot
// whose embedded key fails memcmp as a definitive miss and consults the sidecar
// only from an empty slot, so a placed key owning that index made the spilled
// key unreachable. The builder must therefore leave every sidecar key's index
// empty. Guard: every added key resolves, spill or no spill.
TEST_CASE("MphfBuilder keeps every key findable when buckets spill", "[mphf]") {
    struct Recipe {
        uint32_t max_retries;
        uint32_t max_displacement;
        uint32_t n;
        bool expect_spill;
    };
    const Recipe recipes[] = {
        {1, 1, 5, true},
        {1, 1, 12, true},
        {2, 1, 32, true},
        {2, 1, 512, true},
        {0, 0, 1000, false},  // production budget: places every key
    };

    uint64_t tag_base = 0x600000ULL;
    for (const auto& r : recipes) {
        auto built = build_map(r.max_retries, r.max_displacement, r.n, tag_base);
        tag_base += 0x100000ULL;
        REQUIRE_FALSE(built.blob.empty());
        auto* m = built.header();
        CAPTURE(r.max_retries, r.max_displacement, r.n, m->n_keys, m->collisions_size);
        REQUIRE(m->n_keys == r.n);
        // The recipe must exercise the branch it claims to, or the case is vacuous.
        if (r.expect_spill) {
            REQUIRE(m->collisions_size > 0);
        } else {
            REQUIRE(m->collisions_size == 0);
        }

        uint32_t unreachable = 0;
        uint32_t wrong_body = 0;
        for (const auto& e : built.entries) {
            const auto body = find_body(m, e.addr);
            if (body.empty()) {
                ++unreachable;
                continue;
            }
            if (body.size() != e.body.size() ||
                std::memcmp(body.data(), e.body.data(), e.body.size()) != 0 ||
                std::memcmp(body.data(), e.addr.data(), 20) != 0) {
                ++wrong_body;
            }
        }
        CHECK(unreachable == 0u);
        CHECK(wrong_body == 0u);
    }
}

// The invariant find() rests on: slot_offsets[index_lookup(key)] == 0 for every
// key whose body lives in the sidecar, so slot == 0 unambiguously means
// "consult the sidecar".
TEST_CASE("MphfBuilder sidecar keys always probe an empty slot", "[mphf]") {
    struct Recipe {
        uint32_t max_retries;
        uint32_t max_displacement;
        uint32_t n;
    };
    const Recipe recipes[] = {{1, 1, 5}, {1, 1, 12}, {2, 1, 32}, {2, 1, 512}};

    uint64_t tag_base = 0x6A0000ULL;
    uint32_t sidecar_entries_checked = 0;
    for (const auto& r : recipes) {
        auto built = build_map(r.max_retries, r.max_displacement, r.n, tag_base);
        tag_base += 0x100000ULL;
        REQUIRE_FALSE(built.blob.empty());
        auto* m = built.header();
        const uint32_t n_coll = n_collisions_of(m);
        CAPTURE(r.max_retries, r.max_displacement, r.n, n_coll);
        REQUIRE(n_coll > 0);

        const auto* slots = slot_offsets_of(m);
        const auto* coll = collisions_of(m);
        uint32_t violations = 0;
        for (uint32_t i = 0; i < n_coll; ++i) {
            if (slots[m->index_lookup(coll[i].key)] != 0u) ++violations;
        }
        CHECK(violations == 0u);
        sidecar_entries_checked += n_coll;
    }
    CHECK(sidecar_entries_checked > 0u);
}

// find() misses two ways: an occupied slot whose embedded key fails memcmp
// (definitive, no sidecar scan) and an empty slot that scans the sidecar in
// vain. Both must report absence, and both must actually be reached — a
// spilled map is the only way empty slots exist in an otherwise minimal table.
TEST_CASE("MphfMap absent keys miss from both occupied and empty slots", "[mphf]") {
    auto built = build_map(2, 1, 512, 0x700000ULL);
    REQUIRE_FALSE(built.blob.empty());
    auto* m = built.header();
    REQUIRE(m->collisions_size > 0);
    const auto* slots = slot_offsets_of(m);

    uint32_t from_occupied = 0;
    uint32_t from_empty = 0;
    uint32_t false_hits = 0;
    for (uint32_t i = 0; i < 512; ++i) {
        // 0x7F0000.. is disjoint from the 0x700000..0x7001FF keys built above.
        const auto absent = make_addr_body(0x7F0000ULL + i, 0);
        const uint32_t idx = m->index_lookup(key8_of(absent));
        REQUIRE(idx < m->n_keys);
        if (!find_body(m, absent.addr).empty()) ++false_hits;
        if (slots[idx] != 0u) {
            ++from_occupied;
        } else {
            ++from_empty;
        }
    }
    CAPTURE(from_occupied, from_empty, false_hits);
    CHECK(false_hits == 0u);
    CHECK(from_occupied > 0u);  // definitive miss: memcmp against a foreign body
    CHECK(from_empty > 0u);     // sidecar scanned, still a miss
}

// Sweep sizes under a reduced CHD budget. This used to stop at the first size
// that produced a sidecar (16, which happens to have no unreachable key), which
// is how the spill bug survived; no early exit now.
TEST_CASE("MphfBuilder exhaustion sweep keeps every size findable", "[mphf]") {
    uint32_t sizes_with_sidecar = 0;
    uint32_t broken_sizes = 0;

    auto check_size = [&](uint32_t n) {
        auto built = build_map(2, 1, n, 0x800000ULL + (static_cast<uint64_t>(n) << 16));
        REQUIRE_FALSE(built.blob.empty());
        auto* m = built.header();
        const uint32_t n_coll = n_collisions_of(m);
        if (n_coll > 0) ++sizes_with_sidecar;

        uint32_t unreachable = 0;
        for (const auto& e : built.entries) {
            const auto body = find_body(m, e.addr);
            if (body.empty() || body.size() != e.body.size() ||
                std::memcmp(body.data(), e.body.data(), e.body.size()) != 0) {
                ++unreachable;
            }
        }

        const auto* slots = slot_offsets_of(m);
        const auto* coll = collisions_of(m);
        uint32_t violations = 0;
        for (uint32_t i = 0; i < n_coll; ++i) {
            if (slots[m->index_lookup(coll[i].key)] != 0u) ++violations;
        }

        CAPTURE(n, n_coll, unreachable, violations);
        CHECK(unreachable == 0u);
        CHECK(violations == 0u);
        if (unreachable != 0u || violations != 0u) ++broken_sizes;
    };

    for (uint32_t n = 4; n <= 64; ++n) check_size(n);
    for (uint32_t n : {128u, 256u, 512u, 1024u}) check_size(n);

    CAPTURE(sizes_with_sidecar, broken_sizes);
    CHECK(sizes_with_sidecar > 0u);  // the sweep must reach the spill path
    CHECK(broken_sizes == 0u);
}

TEST_CASE("MphfMap walkers visit each entry once", "[mphf]") {
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
        const auto* mh = reinterpret_cast<const MphfMapHeader*>(blob.data());
        if (mh->collisions_size > 0) break;
    }
    REQUIRE_FALSE(blob.empty());

    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());

    std::vector<std::array<uint8_t, 20>> visited;
    visited.reserve(entries.size());
    MphfMap mm{m};
    mm.for_each<20>([&](const uint8_t* key_ptr, std::span<uint8_t> /*body*/) {
        std::array<uint8_t, 20> a{};
        std::memcpy(a.data(), key_ptr, 20);
        visited.push_back(a);
    });

    CHECK(visited.size() == entries.size());

    uint32_t found = 0;
    for (const auto& e : entries) {
        if (std::ranges::contains(visited, e.addr)) ++found;
    }
    CHECK(found == static_cast<uint32_t>(entries.size()));
}

TEST_CASE("MphfBuilder spilled slots reuse the collision marker", "[mphf]") {
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
        const auto* mh = reinterpret_cast<const MphfMapHeader*>(blob.data());
        if (mh->collisions_size > 0) break;
    }
    REQUIRE_FALSE(blob.empty());

    const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data());
    const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
        blob.data() + m->slot_offsets_offset);

    uint32_t n_legacy_sentinels = 0;
    uint32_t n_zero_slots = 0;
    for (uint32_t i = 0; i < m->n_keys; ++i) {
        if (slot_offsets[i] == 0xFFFFFFFFu) ++n_legacy_sentinels;
        if (slot_offsets[i] == 0u) ++n_zero_slots;
    }
    CAPTURE(n_zero_slots, n_legacy_sentinels, m->collisions_size);
    CHECK(n_legacy_sentinels == 0u);
    CHECK(m->collisions_size > 0);
}

namespace {

// A CHD-spilled unique-fingerprint address must stay reachable on the EVM
// read path. A spilled singleton lands in the MPHF-internal sidecar but not
// in the AddrCollisionEntry table (fingerprint groups of size > 1 only), so
// the read path must fall back to the sidecar (MphfMap::find) after the
// singleton-slot miss. Historically it didn't; regression guard below.

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
            if (std::memcmp(data + it->offset + 8u, addr20, 20) == 0)
                return static_cast<uint32_t>(it->offset);
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

}  // namespace

TEST_CASE("EVM read path finds a spilled singleton", "[mphf]") {
    // Two addresses (distinct fingerprints) that collide into one bucket and
    // spill under a 1-seed / 1-displacement CHD budget.
    std::vector<AddrBody> entries{make_addr_body(0x516000, 0), make_addr_body(0x516001, 0)};

    MphfBuilder<20> b{kTestMphfMagic, kMphfMapVersion};
    b.set_max_retries_for_test(1);
    b.set_max_displacement_for_test(1);
    for (const auto& e : entries)
        b.add(addr_key8(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data())), ByteView{e.body.data(), e.body.size()});
    auto blob = std::move(b).finalize();

    REQUIRE_FALSE(blob.empty());
    auto* m = reinterpret_cast<MphfMapHeader*>(blob.data());
    REQUIRE(m->collisions_size > 0);  // confirm the pair spilled

    const auto table = build_addr_collision_table(entries, m);

    const auto& e = entries[0];
    // Spilled singleton: present in the sidecar, absent from the collision table.
    MphfMap mm{m};
    auto stored = mm.find<20, 0, &addr_key8>(reinterpret_cast<const uint8_t(&)[20]>(*e.addr.data()));
    REQUIRE(stored.has_value());
    REQUIRE(table.empty());
    CHECK(evm_read_path_find(m, table, e.addr.data()) != nullptr);
}

TEST_CASE("MphfMap collision entries are {u64 key, u64 offset}, 8-aligned, and offsets cannot wrap", "[mphf]") {
    using zilkworm::MphfCollisionEntry;
    CHECK(sizeof(MphfCollisionEntry) == 16u);
    CHECK(alignof(MphfCollisionEntry) == 8u);
    CHECK(sizeof(MphfCollisionEntry{}.key) == 8u);
    CHECK(sizeof(MphfCollisionEntry{}.offset) == 8u);

    auto built = build_map(2, 1, 512, 0x900000ULL);
    REQUIRE_FALSE(built.blob.empty());
    auto* m = built.header();
    REQUIRE(reinterpret_cast<uintptr_t>(m) % 8u == 0u);
    REQUIRE(m->collisions_size > 0);
    REQUIRE(m->collisions_size % 16u == 0u);
    REQUIRE(m->collisions_offset % 8u == 0u);
    const uint32_t n_coll = n_collisions_of(m);
    const auto* coll = collisions_of(m);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(m) + m->data_offset;
    const auto size = static_cast<uint32_t>(built.blob.size());
    REQUIRE(zilkworm::validate_mphf<20>(std::span<const uint8_t>{built.blob}, 0, size, kTestMphfMagic));

    SECTION("every entry is 8-aligned and resolves through find()") {
        for (uint32_t i = 0; i < n_coll; ++i) {
            CAPTURE(i, n_coll);
            REQUIRE(reinterpret_cast<uintptr_t>(coll + i) % 8u == 0u);
            REQUIRE(coll[i].offset < m->data_size);
            uint64_t body_len = 0;
            std::memcpy(&body_len, data + coll[i].offset, 8);
            const uint8_t* body = data + coll[i].offset + 8u;
            std::array<uint8_t, 20> addr{};
            std::memcpy(addr.data(), body, 20);
            const auto found = find_body(m, addr);
            REQUIRE_FALSE(found.empty());
            CHECK(found.data() == body);
            CHECK(found.size() == body_len);
        }
    }

    SECTION("validate_mphf rejects a collisions_offset that is not 8-aligned") {
        auto forged = built.blob;
        auto* fh = reinterpret_cast<MphfMapHeader*>(forged.data());
        fh->collisions_offset += 4u;
        CHECK_FALSE(zilkworm::validate_mphf<20>(std::span<const uint8_t>{forged}, 0, size, kTestMphfMagic));
    }

    SECTION("validate_mphf rejects a data_offset that is not 8-aligned") {
        auto forged = built.blob;
        auto* fh = reinterpret_cast<MphfMapHeader*>(forged.data());
        fh->data_offset += 4u;
        CHECK_FALSE(zilkworm::validate_mphf<20>(std::span<const uint8_t>{forged}, 0, size, kTestMphfMagic));
    }

    // The soundness condition in validate_mphf's comment: data[] past every table.
    SECTION("validate_mphf rejects a data section that overlaps the sidecar") {
        auto forged = built.blob;
        auto* fh = reinterpret_cast<MphfMapHeader*>(forged.data());
        fh->data_offset = fh->collisions_offset;  // 8-aligned and still inside the region
        CHECK_FALSE(zilkworm::validate_mphf<20>(std::span<const uint8_t>{forged}, 0, size, kTestMphfMagic));
    }

    auto check_rejected = [&](const std::vector<uint8_t>& forged) {
        CHECK_FALSE(zilkworm::validate_mphf<20>(std::span<const uint8_t>{forged}, 0, size, kTestMphfMagic));
    };

    const uint32_t victim = n_coll / 2u;
    const uint64_t honest_off = coll[victim].offset;
    auto forge_offset = [&](uint64_t lie) {
        auto forged = built.blob;
        std::memcpy(forged.data() + m->collisions_offset + 16u * victim + 8u, &lie, 8);
        return forged;
    };

    SECTION("an offset with a set high half is rejected, not truncated to its low half") {
        check_rejected(forge_offset((uint64_t{1} << 32) | honest_off));
    }

    SECTION("an offset whose +8 would wrap past zero is rejected") {
        check_rejected(forge_offset(0xFFFF'FFFF'FFFF'FFF8ull));
    }

    SECTION("a sidecar entry whose body runs past data_size is rejected") {
        auto forged = built.blob;
        const uint64_t lie = m->data_size;  // header says the body fills the arena and more
        std::memcpy(forged.data() + m->data_offset + honest_off, &lie, 8);
        check_rejected(forged);
    }

    SECTION("a slot-routed entry is bounded the same way as a sidecar entry") {
        const auto* slots = slot_offsets_of(m);
        uint32_t slot_off = 0;
        for (uint32_t i = 0; i < m->n_keys && slot_off == 0; ++i) slot_off = slots[i];
        REQUIRE(slot_off != 0);
        auto forged = built.blob;
        const uint64_t lie = m->data_size;
        std::memcpy(forged.data() + m->data_offset + slot_off, &lie, 8);
        check_rejected(forged);
        auto undersized = built.blob;
        const uint64_t short_len = 19;  // one byte short of the 20-byte key
        std::memcpy(undersized.data() + m->data_offset + slot_off, &short_len, 8);
        check_rejected(undersized);
    }
}

// The two tilings in validate_mphf's comment, one forgery per way of breaking them.
TEST_CASE("validate_mphf requires sections and entries to tile with no overlap and no gap", "[mphf]") {
    auto built = build_map(0, 0, 64, 0xA00000ULL);
    REQUIRE_FALSE(built.blob.empty());
    const auto validate = [](const std::vector<uint8_t>& b) {
        return zilkworm::validate_mphf<20>(std::span<const uint8_t>{b}, 0,
                                           static_cast<uint32_t>(b.size()), kTestMphfMagic);
    };
    REQUIRE(validate(built.blob));
    const auto hdr = [](std::vector<uint8_t>& b) { return reinterpret_cast<MphfMapHeader*>(b.data()); };
    const auto slots = [&](std::vector<uint8_t>& b) {
        return reinterpret_cast<uint32_t*>(b.data() + hdr(b)->slot_offsets_offset);
    };
    // Two distinct slot-routed entries.
    uint32_t idx_a = UINT32_MAX, idx_b = UINT32_MAX;
    for (uint32_t i = 0; i < built.header()->n_keys && idx_b == UINT32_MAX; ++i) {
        if (slot_offsets_of(built.header())[i] == 0) continue;
        (idx_a == UINT32_MAX ? idx_a : idx_b) = i;
    }
    REQUIRE(idx_b != UINT32_MAX);

    SECTION("an entry nested inside another entry's body is rejected") {
        auto forged = built.blob;
        uint8_t* data = forged.data() + hdr(forged)->data_offset;
        const uint32_t off_a = slots(forged)[idx_a];
        const uint32_t off_b = slots(forged)[idx_b];
        // A's body is 60 bytes at off_a+8. Plant B's [len=20][key] at off_a+32, past A's key.
        const uint64_t len_b = 20;
        std::array<uint8_t, 20> key_b{};
        std::memcpy(key_b.data(), data + off_b + 8u, 20);
        std::memcpy(data + off_a + 32u, &len_b, 8);
        std::memcpy(data + off_a + 40u, key_b.data(), 20);
        slots(forged)[idx_b] = off_a + 32u;
        CHECK_FALSE(validate(forged));
    }

    SECTION("two slots claiming the same entry are rejected") {
        auto forged = built.blob;
        slots(forged)[idx_b] = slots(forged)[idx_a];
        CHECK_FALSE(validate(forged));
    }

    SECTION("an entry that no slot or sidecar row owns is rejected") {
        auto forged = built.blob;
        slots(forged)[idx_a] = 0;
        CHECK_FALSE(validate(forged));
    }

    SECTION("a shrunk entry that leaves a gap before the next one is rejected") {
        auto forged = built.blob;
        const uint64_t shorter = 60 - 16;  // still >= the 20-byte key, but align8(8 + len) drops by 16
        std::memcpy(forged.data() + hdr(forged)->data_offset + 8u, &shorter, 8);
        CHECK_FALSE(validate(forged));
    }

    SECTION("spare bytes after data[] are rejected") {
        auto forged = built.blob;
        forged.resize(forged.size() + 8u);
        CHECK_FALSE(validate(forged));
    }

    SECTION("a gap between the tables and data[] is rejected") {
        auto forged = built.blob;
        forged.insert(forged.begin() + hdr(forged)->data_offset, 8, uint8_t{0});
        hdr(forged)->data_offset += 8u;
        CHECK_FALSE(validate(forged));
    }

    SECTION("tables laid over each other are rejected") {
        auto forged = built.blob;
        hdr(forged)->slot_offsets_offset = hdr(forged)->displacement_offset;
        CHECK_FALSE(validate(forged));
    }
}

// The blob-level tiling in validate_prestate_layout: a code store placed under an
// account body would have its checked slot_offsets[] rewritten by an ordinary SSTORE.
TEST_CASE("validate_direct_state_layout keeps the code store out of the addr map", "[mphf]") {
    using zilkworm::DirectState;
    using zilkworm::PreStateMeta;
    using zilkworm::validate_direct_state_layout;

    std::vector<uint8_t> kv(32 + 5, 0x5B);  // [hash:32][code]; layout checks do not hash
    kv[0] = 0xC0;
    MphfBuilder<32> cb{zilkworm::kMphfCodeStoreMagic, kMphfMapVersion};
    cb.add(zilkworm::hash_key8(reinterpret_cast<const uint8_t(&)[32]>(*kv.data())),
           ByteView{kv.data(), kv.size()});
    const std::vector<uint8_t> code_store = std::move(cb).finalize();
    REQUIRE_FALSE(code_store.empty());

    DirectState::AccountInfo ai{};
    ai.addr.bytes[0] = 0x11;
    ai.addr.bytes[19] = 0x22;
    std::memcpy(ai.account.code_hash, silkworm::kEmptyHash.bytes, 32);
    std::memcpy(ai.account.storage_root, silkworm::kEmptyRoot.bytes, 32);
    evmc::bytes32 k1{}, k2{};
    k1.bytes[31] = 1;
    k2.bytes[31] = 2;
    ai.storage = {{k1, k1}, {k2, k2}};  // two inline slots: room to hide a small map in the body

    const auto accepts = [](const std::vector<uint8_t>& b) {
        return validate_direct_state_layout(std::span<const uint8_t>{b}, {});
    };

    SECTION("the honest layouts, with and without a code store, are accepted") {
        CHECK(accepts(DirectState::build_blob_from_accounts({ai}, {}, {})));
        CHECK(accepts(DirectState::build_blob_from_accounts({ai}, {}, code_store)));
        CHECK(accepts(DirectState::build_blob_from_accounts({}, {}, {})));
    }

    SECTION("a code store nested inside an account body is rejected") {
        auto forged = DirectState::build_blob_from_accounts({ai}, {}, {});
        auto* meta = reinterpret_cast<PreStateMeta*>(forged.data());
        const auto* mh = reinterpret_cast<const MphfMapHeader*>(forged.data() + meta->prestate_offset);
        uint32_t off = 0;
        for (uint32_t i = 0; i < mh->n_keys && off == 0; ++i) off = slot_offsets_of(mh)[i];
        REQUIRE(off != 0);
        // First inline Slot of the account: 8-aligned and inside the addr map's data[].
        const uint32_t nest = meta->prestate_offset + mh->data_offset + off + 8u +
                              static_cast<uint32_t>(sizeof(zilkworm::Account));
        REQUIRE(nest + code_store.size() <= forged.size());
        std::memcpy(forged.data() + nest, code_store.data(), code_store.size());
        meta->code_store_offset = nest;
        meta->code_store_size = static_cast<uint32_t>(code_store.size());
        CHECK_FALSE(accepts(forged));
    }

    SECTION("a code store that does not end the blob is rejected") {
        auto forged = DirectState::build_blob_from_accounts({ai}, {}, code_store);
        forged.resize(forged.size() + 8u);
        CHECK_FALSE(accepts(forged));
    }

    SECTION("an addr map that does not start right after the meta is rejected") {
        auto forged = DirectState::build_blob_from_accounts({ai}, {}, code_store);
        forged.insert(forged.begin() + 72, 8, uint8_t{0});
        auto* meta = reinterpret_cast<PreStateMeta*>(forged.data());
        meta->prestate_offset += 8u;
        meta->addr_hashes_offset += 8u;
        meta->block_hashes_offset += 8u;
        meta->code_store_offset += 8u;
        CHECK_FALSE(accepts(forged));
    }
}
