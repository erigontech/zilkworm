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
// (0 == collision), collisions:[data_offset:u32]*, data:[len:u64][body]*.
// Caller verifies membership via key bytes embedded in body.
inline constexpr uint64_t kMphfGoldenRatio = 0x9E3779B97F4A7C15ull;
inline constexpr uint32_t kMphfMapVersion = 2u;

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

struct alignas(8) MphfCollisionEntry {
    uint64_t key;
    uint32_t offset;
    uint32_t len;
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
            n_keys_ = n_buckets_ = data_size_ = n_collisions_ = 0; seed_factor_ = 0;
            return;
        }
        const auto* base = reinterpret_cast<const uint8_t*>(h);
        slot_offsets_ = reinterpret_cast<const uint32_t*>(base + h->slot_offsets_offset);
        data_         = reinterpret_cast<uint8_t*>(h) + h->data_offset;
        collisions_   = reinterpret_cast<const MphfCollisionEntry*>(base + h->collisions_offset);
        displacement_ = reinterpret_cast<const uint64_t*>(base + h->displacement_offset);
        n_keys_       = h->n_keys;
        n_buckets_    = h->n_buckets;
        data_size_    = h->data_size;
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
        }
        if (n_collisions_ > 0) [[unlikely]] {
            const std::span<uint8_t> b = resolve_collision<KeySize, KeyOffset>(k8, key);
            if (!b.empty()) return b;
        }
        return std::nullopt;
    }

    template <std::size_t KeySize = 32, std::size_t KeyOffset = 0, typename Cb>
    bool for_each(Cb&& cb) const noexcept {
        if (h_ == nullptr || n_keys_ == 0) return true;
        auto emit = [&](uint32_t off) noexcept -> bool {
            const uint64_t hdr_end = static_cast<uint64_t>(off) + 8u;
            uint64_t body_len = 0;
            if (hdr_end <= data_size_) std::memcpy(&body_len, data_ + off, 8);
            const bool bad = hdr_end + body_len > data_size_ || body_len < KeyOffset + KeySize;
            if (bad) [[unlikely]] {
                sys_println("MphfMap: for_each: entry out of range or undersized");
                return false;
            }
            uint8_t* body = data_ + off + 8u;
            cb(body + KeyOffset, std::span<uint8_t>{body, static_cast<size_t>(body_len)});
            return true;
        };
        for (uint32_t i = 0; i < n_keys_; ++i) {
            const uint32_t off = slot_offsets_[i];
            if (off == 0) continue;
            if (!emit(off)) return false;
        }
        for (uint32_t i = 0; i < n_collisions_; ++i)
            if (!emit(collisions_[i].offset)) return false;
        return true;
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
            if (std::memcmp(body + KeyOffset, key, KeySize) == 0)
                return std::span<uint8_t>{body, static_cast<size_t>(it->len)};
        }
        return {};
    }

    const MphfMapHeader*      h_{nullptr};
    const uint32_t*           slot_offsets_{nullptr};
    uint8_t*                  data_{nullptr};
    const MphfCollisionEntry* collisions_{nullptr};
    const uint64_t*           displacement_{nullptr};
    uint32_t n_keys_{0}, n_buckets_{0}, data_size_{0}, n_collisions_{0};
    uint64_t seed_factor_{0};
};

template <size_t KeySize>
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

    auto bounds_within_region = [&](uint64_t off, uint64_t size, const char* msg) -> bool {
        if (off > region_size || size > region_size || off + size > region_size) [[unlikely]] {
            sys_println(msg);
            return false;
        }
        return true;
    };

    if (m->n_keys == 0) {
        return true;
    }

    bool ok = true;

    if ((m->displacement_offset % alignof(uint64_t)) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: displacement_offset misaligned");
        ok = false;
    }
    if (m->n_buckets == 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: n_buckets == 0 with n_keys > 0");
        ok = false;
    }
    ok &= bounds_within_region(m->displacement_offset,
                               static_cast<uint64_t>(m->n_buckets) * 8u,
                               "MphfMapHeader: validate_mphf: displacement table out of range");

    if ((m->slot_offsets_offset % alignof(uint32_t)) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: slot_offsets misaligned");
        ok = false;
    }
    ok &= bounds_within_region(m->slot_offsets_offset,
                               static_cast<uint64_t>(m->n_keys) * 4u,
                               "MphfMapHeader: validate_mphf: slot_offsets out of range");

    if (m->collisions_size > 0) {
        if ((m->collisions_size % sizeof(MphfCollisionEntry)) != 0) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: collisions_size not a MphfCollisionEntry multiple");
            ok = false;
        }
        ok &= bounds_within_region(m->collisions_offset, m->collisions_size,
                                   "MphfMapHeader: validate_mphf: collisions out of range");
    }

    if (m->data_size > 0) {
        ok &= bounds_within_region(m->data_offset, m->data_size,
                                   "MphfMapHeader: validate_mphf: data region out of range");
    }

    return ok;
}

}  // namespace zilkworm
