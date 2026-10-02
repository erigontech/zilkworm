// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/print.hpp>

namespace zilkworm {
using ::silkworm::ByteView;
using ::silkworm::Bytes;

// MphfMapHeader: u64 -> bytes minimal perfect hash with collision sidecar.
// Header layout: displacement_factors[n_buckets]:u64, slot_offsets[n_keys]:u32
// (0 == collision), collisions:[key:u64][data_offset:u64]*,
// data:[len:u64][body]*.
// Caller verifies membership via key bytes embedded in body.
// MphfMap reads unchecked: see validate_mphf below for the layout contract.
inline constexpr uint64_t kMphfGoldenRatio = 0x9E3779B97F4A7C15ull;
inline constexpr uint32_t kMphfMapVersion = 3u;

// SplitMix64-stage1 mixer.
[[gnu::always_inline]] inline uint64_t mix64_body(uint64_t z) noexcept {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    return z ^ (z >> 31);
}

// Lemire fast mod: x in [0,n) with one mul + shift.
[[gnu::always_inline]] inline uint32_t fast_mod_u32(uint32_t x, uint32_t n) noexcept {
    return static_cast<uint32_t>((static_cast<uint64_t>(x) * n) >> 32);
}

[[gnu::always_inline]] inline constexpr uint32_t mphf_align8(uint32_t v) noexcept {
    return (v + 7u) & ~uint32_t{7u};
}
[[gnu::always_inline]] inline constexpr uint32_t mphf_align4(uint32_t v) noexcept {
    return (v + 3u) & ~uint32_t{3u};
}

struct alignas(8) MphfMapHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t n_keys;
    uint32_t n_buckets;
    uint64_t seed;
    uint64_t seed_factor;
    uint32_t collisions_offset;
    uint32_t collisions_size;
    uint32_t displacement_offset;
    uint32_t slot_offsets_offset;
    uint32_t data_offset;
    uint32_t data_size;

    // Lookup the [0, n_keys) index for a key
    [[gnu::always_inline]] uint32_t index_lookup(uint64_t key) const noexcept {
        const uint64_t z1 = key + seed_factor;
        const uint64_t h1 = mix64_body(z1);
        const uint32_t b  = fast_mod_u32(static_cast<uint32_t>(h1), n_buckets);
        const auto* dfac_base = reinterpret_cast<const uint64_t*>(
            reinterpret_cast<const uint8_t*>(this) + displacement_offset);
        const uint64_t df = dfac_base[b];
        const uint64_t h2 = mix64_body(z1 + df);
        return fast_mod_u32(static_cast<uint32_t>(h2), n_keys);
    }
};

struct MphfCollisionEntry {
    uint64_t key;
    uint64_t offset;
    // No length here on purpose. The entry's length lives in the data-section header
    // ([len:u64] before the body), which is the range sanitize() hashes; a second copy
    // could disagree with it and would be trusted for the span handed to the EVM.
};

static_assert(sizeof(MphfMapHeader) == 56);
static_assert(alignof(MphfMapHeader) == 8);
static_assert(sizeof(MphfCollisionEntry) == 16);
static_assert(alignof(MphfCollisionEntry) == 8);
static_assert(std::is_trivially_copyable_v<MphfMapHeader>);
static_assert(std::is_trivially_copyable_v<MphfCollisionEntry>);

class MphfMap {
  public:
    MphfMap() = default;
    explicit MphfMap(MphfMapHeader* h) noexcept { reset(h); }

    void reset(MphfMapHeader* h) noexcept {
        h_ = h;
        if (h == nullptr) {
            slot_offsets_ = nullptr; data_ = nullptr; collisions_ = nullptr; displacement_ = nullptr;
            n_keys_ = n_buckets_ = n_collisions_ = 0; seed_factor_ = 0;
            return;
        }
        const auto* base = reinterpret_cast<const uint8_t*>(h);
        slot_offsets_ = reinterpret_cast<const uint32_t*>(base + h->slot_offsets_offset);
        data_         = reinterpret_cast<uint8_t*>(h) + h->data_offset;
        collisions_   = reinterpret_cast<const MphfCollisionEntry*>(base + h->collisions_offset);
        displacement_ = reinterpret_cast<const uint64_t*>(base + h->displacement_offset);
        n_keys_       = h->n_keys;
        n_buckets_    = h->n_buckets;
        n_collisions_ = h->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
        seed_factor_  = h->seed_factor;
    }

    bool valid() const noexcept { return h_ != nullptr; }
    uint32_t n_keys() const noexcept { return n_keys_; }
    uint8_t* data() const noexcept { return data_; }
    const MphfMapHeader* header() const noexcept { return h_; }

    [[gnu::always_inline]] uint32_t index_lookup(uint64_t key) const noexcept {
        const uint64_t z1 = key + seed_factor_;
        const uint64_t h1 = mix64_body(z1);
        const uint32_t b  = fast_mod_u32(static_cast<uint32_t>(h1), n_buckets_);
        const uint64_t df = displacement_[b];
        const uint64_t h2 = mix64_body(z1 + df);
        return fast_mod_u32(static_cast<uint32_t>(h2), n_keys_);
    }

    template <std::size_t KeySize, std::size_t KeyOffset,
              uint64_t (*shorten_key)(const uint8_t (&)[KeySize])>
    [[gnu::always_inline]] std::optional<std::span<uint8_t>>
    find(const uint8_t (&key)[KeySize]) const noexcept {
        if (h_ == nullptr || n_keys_ == 0) return std::nullopt;
        const uint64_t k8 = shorten_key(key);
        const uint32_t idx = index_lookup(k8);
        const uint32_t off = slot_offsets_[idx];
        if (off != 0) [[likely]] {
            uint8_t* body = data_ + off + 8u;
            if (std::memcmp(body + KeyOffset, key, KeySize) == 0) [[likely]] {
                uint64_t len; std::memcpy(&len, data_ + off, 8);
                return std::span<uint8_t>{body, static_cast<size_t>(len)};
            }
        } else if (n_collisions_ > 0) [[unlikely]] {
            const std::span<uint8_t> b = resolve_collision<KeySize, KeyOffset>(k8, key);
            if (!b.empty()) return b;
        }
        return std::nullopt;
    }

    // Visits every singleton slot (skipping the 0 sentinels) and then every sidecar entry.
    template <std::size_t KeySize = 32, std::size_t KeyOffset = 0, typename Cb>
    void for_each(Cb&& cb) const noexcept {
        if (h_ == nullptr || n_keys_ == 0) return;
        auto apply_cb = [&](uint64_t off) noexcept {
            uint64_t body_len; std::memcpy(&body_len, data_ + off, 8);
            uint8_t* body = data_ + off + 8u;
            cb(body + KeyOffset, std::span<uint8_t>{body, static_cast<size_t>(body_len)});
        };
        for (uint32_t i = 0; i < n_keys_; ++i) {
            const uint32_t off = slot_offsets_[i];
            if (off != 0) apply_cb(off);
        }
        for (uint32_t i = 0; i < n_collisions_; ++i)
            apply_cb(collisions_[i].offset);
    }

  private:
    template <std::size_t KeySize, std::size_t KeyOffset = 0>
    [[gnu::always_inline]] std::span<uint8_t>
    resolve_collision(uint64_t k8, const uint8_t (&key)[KeySize]) const noexcept {
        if (n_collisions_ == 0) return {};
        auto it = std::lower_bound(collisions_, collisions_ + n_collisions_, k8,
            [](const MphfCollisionEntry& e, uint64_t kk) noexcept { return e.key < kk; });
        for (; it != collisions_ + n_collisions_ && it->key == k8; ++it) {
            uint8_t* body = data_ + it->offset + 8u;
            if (std::memcmp(body + KeyOffset, key, KeySize) == 0) {
                uint64_t len; std::memcpy(&len, data_ + it->offset, 8);
                return std::span<uint8_t>{body, static_cast<size_t>(len)};
            }
        }
        return {};
    }

    const MphfMapHeader*      h_{nullptr};
    const uint32_t*           slot_offsets_{nullptr};
    uint8_t*                  data_{nullptr};
    const MphfCollisionEntry* collisions_{nullptr};
    const uint64_t*           displacement_{nullptr};
    uint32_t n_keys_{0}, n_buckets_{0}, n_collisions_{0};
    uint64_t seed_factor_{0};
};

// The one layout check for an MphfMap region. Every map passes it before an MphfMap
// is built over it (validate_direct_state_layout, for the addr map, code store and
// node store), so find() and for_each() read without re-checking.
//
// It requires the one layout MphfBuilder and mfbd.rs emit, as two tilings with no
// overlap and no gap:
//   - sections: header | displacement | slot_offsets | collisions | data, each
//     starting where the previous one ends (8-byte padding only), data[] ending
//     the region;
//   - entries: [len:u64][body] back to back over data[8, data_size), 8-aligned,
//     body_len >= KeyOffset + KeySize (the bytes find<KeySize, KeyOffset>()
//     memcmps), each owned by exactly one slot or sidecar row.
//
// Checking once is sound because the only bytes written afterwards are entry bodies
// (Account scratch, EVM state). A body shares no byte with a table, with another
// entry's len header, or with another body, so no write can change a checked value.
template <size_t KeySize, size_t KeyOffset = 0>
[[nodiscard]] bool validate_mphf(std::span<const uint8_t> base,
                                 uint32_t region_off,
                                 uint32_t region_size,
                                 uint32_t expected_magic) noexcept {
    if (region_size == 0) return true;

    if (static_cast<uint64_t>(region_off) + region_size > base.size()) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: region out of base");
        return false;
    }
    if (region_size < sizeof(MphfMapHeader)) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: region smaller than MphfMapHeader");
        return false;
    }
    if ((region_off % alignof(MphfMapHeader)) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: region offset misaligned for MphfMapHeader");
        return false;
    }

    const auto* m = reinterpret_cast<const MphfMapHeader*>(base.data() + region_off);

    if (expected_magic != 0 && m->magic != expected_magic) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: bad magic");
        return false;
    }
    if (m->version != kMphfMapVersion) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: bad version");
        return false;
    }

    if (m->n_keys == 0) {
        return true;
    }
    if (m->n_buckets == 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: n_buckets == 0 with n_keys > 0");
        return false;
    }
    if ((m->collisions_size % sizeof(MphfCollisionEntry)) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: collisions_size not a MphfCollisionEntry multiple");
        return false;
    }
    if (m->data_size < 8u || (m->data_size % 8u) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: data_size not an 8-multiple >= 8");
        return false;
    }

    // Section tiling. One equality chain gives bounds, alignment, mutual exclusion
    // and gaplessness together.
    auto a8 = [](uint64_t v) noexcept { return (v + 7u) & ~uint64_t{7u}; };
    const uint64_t disp_lo  = a8(sizeof(MphfMapHeader));
    const uint64_t slots_lo = disp_lo + uint64_t{m->n_buckets} * 8u;
    const uint64_t coll_lo  = slots_lo + a8(uint64_t{m->n_keys} * 4u);
    const uint64_t data_lo  = coll_lo + uint64_t{m->collisions_size};
    const uint64_t region_hi = data_lo + uint64_t{m->data_size};
    if (m->displacement_offset != disp_lo || m->slot_offsets_offset != slots_lo ||
        m->collisions_offset != coll_lo || m->data_offset != data_lo ||
        region_hi != region_size) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: sections do not tile the region canonically");
        return false;
    }

    const uint8_t* mbase = base.data() + region_off;
    const auto* slot_offsets = reinterpret_cast<const uint32_t*>(mbase + m->slot_offsets_offset);
    const auto* collisions = reinterpret_cast<const MphfCollisionEntry*>(mbase + m->collisions_offset);
    const uint32_t n_collisions = m->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
    const uint8_t* data = mbase + m->data_offset;
    const uint64_t data_size = m->data_size;

    // Entry tiling, pass 1: walk the arena from offset 8 and mark every entry start.
    // It never follows a slot or sidecar offset.
    std::vector<uint64_t> starts((data_size / 8u + 63u) / 64u, 0u);
    uint64_t n_entries = 0;
    for (uint64_t pos = 8u; pos != data_size;) {
        // pos and data_size are 8-multiples with pos < data_size, so 8 header bytes fit.
        uint64_t body_len; std::memcpy(&body_len, data + pos, 8);
        if (body_len > data_size - pos - 8u) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry body out of data region");
            return false;
        }
        if (body_len < KeyOffset + KeySize) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry body shorter than its key");
            return false;
        }
        starts[(pos / 8u) / 64u] |= uint64_t{1} << ((pos / 8u) % 64u);
        ++n_entries;
        pos += a8(8u + body_len);  // <= data_size: both sides of the bound above are 8-multiples
    }
    // Pass 2: every slot and sidecar offset claims one marked start, once. off is
    // u64 (sidecar) or u32 (slot); compare before indexing so the high half counts.
    uint64_t n_claimed = 0;
    auto claim = [&](uint64_t off) -> bool {
        if (off >= data_size || (off % 8u) != 0) [[unlikely]] return false;
        uint64_t& word = starts[(off / 8u) / 64u];
        const uint64_t bit = uint64_t{1} << ((off / 8u) % 64u);
        if ((word & bit) == 0) [[unlikely]] return false;  // not an entry start, or already claimed
        word &= ~bit;
        ++n_claimed;
        return true;
    };
    for (uint32_t i = 0; i < m->n_keys; ++i) {
        const uint32_t off = slot_offsets[i];
        if (off != 0 && !claim(off)) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: slot offset is not a distinct entry start");
            return false;
        }
    }
    for (uint32_t i = 0; i < n_collisions; ++i) {
        if (!claim(collisions[i].offset)) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: sidecar offset is not a distinct entry start");
            return false;
        }
    }
    if (n_claimed != n_entries) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: data[] holds an entry no slot or sidecar row owns");
        return false;
    }
    return true;
}

}  // namespace zilkworm
