// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <array>
#include <bit>
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

/// a[0..N) == b[0..N); word-aligned operands compare inline (memcmp is a call under strict alignment).
template <size_t N>
[[gnu::always_inline]] inline bool bytes_equal(const uint8_t* a, const uint8_t* b) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    if constexpr (N % 4 == 0) {
        if (((reinterpret_cast<uintptr_t>(a) | reinterpret_cast<uintptr_t>(b)) & 3) == 0) {
            typedef uint32_t __attribute__((may_alias)) w32;
            const w32* const wa = reinterpret_cast<const w32*>(a);
            const w32* const wb = reinterpret_cast<const w32*>(b);
            for (size_t i = 0; i < N / 4; ++i)
                if (wa[i] != wb[i]) return false;
            return true;
        }
    }
#endif
    return std::memcmp(a, b, N) == 0;
}

#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
/// a[0..n) == b[0..n) at any alignments; every load stays inside the two ranges.
[[gnu::noinline]] inline bool bytes_equal_any(const uint8_t* a, const uint8_t* b, size_t n) noexcept {
    static_assert(std::endian::native == std::endian::little, "assembles b's bytes little-endian");
    typedef uint32_t __attribute__((may_alias)) w32;
    if (n < 12) {
#pragma GCC unroll 1
        for (size_t i = 0; i < n; ++i)
            if (a[i] != b[i]) return false;
        return true;
    }
    const unsigned h = static_cast<unsigned>(-reinterpret_cast<uintptr_t>(a)) & 3;
    switch (h) {
        case 3: if (a[2] != b[2]) return false; [[fallthrough]];
        case 2: if (a[1] != b[1]) return false; [[fallthrough]];
        case 1: if (a[0] != b[0]) return false; [[fallthrough]];
        default: break;
    }
    a += h; b += h; n -= h;
    const w32* const wa = reinterpret_cast<const w32*>(a);
    const unsigned s = reinterpret_cast<uintptr_t>(b) & 3;
    size_t k;
    if (s == 0) {
        const w32* const wb = reinterpret_cast<const w32*>(b);
        k = n / 4;
#pragma GCC unroll 4
        for (size_t i = 0; i < k; ++i)
            if (wa[i] != wb[i]) return false;
    } else {
        uint32_t cur;
        switch (s) {
            case 1: cur = b[0] | uint32_t{b[1]} << 8 | uint32_t{b[2]} << 16; break;
            case 2: cur = b[0] | uint32_t{b[1]} << 8; break;
            default: cur = b[0];
        }
        const unsigned rs = 8 * s, ls = 32 - rs;
        const w32* const wb = reinterpret_cast<const w32*>(b + 4 - s);
        // a-word i takes from wb[i], which ends at b + 4i + 8 - s: inside b while that is <= n.
        k = (n + s - 4) / 4;
#pragma GCC unroll 4
        for (size_t i = 0; i < k; ++i) {
            const uint32_t hi = wb[i];
            if (wa[i] != (cur | (hi << ls))) return false;
            cur = hi >> rs;
        }
    }
    a += 4 * k; b += 4 * k;
    // n - 4k is at most 3 when b is co-aligned and 4 - s + ((n + s) mod 4), at most 6, otherwise.
    switch (n - 4 * k) {
        case 6: if (a[5] != b[5]) return false; [[fallthrough]];
        case 5: if (a[4] != b[4]) return false; [[fallthrough]];
        case 4: if (a[3] != b[3]) return false; [[fallthrough]];
        case 3: if (a[2] != b[2]) return false; [[fallthrough]];
        case 2: if (a[1] != b[1]) return false; [[fallthrough]];
        case 1: if (a[0] != b[0]) return false; [[fallthrough]];
        case 0: return true;
        default: return std::memcmp(a, b, n - 4 * k) == 0;
    }
}
#endif

/// Little-endian u64 at p (the builder 8-aligns every entry); two word loads under strict alignment.
[[gnu::always_inline]] inline uint64_t load_u64_le(const uint8_t* p) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    if ((reinterpret_cast<uintptr_t>(p) & 3) == 0) [[likely]] {
        typedef uint32_t __attribute__((may_alias)) w32;
        const w32* const w = reinterpret_cast<const w32*>(p);
        return w[0] | (uint64_t{w[1]} << 32);
    }
#endif
    uint64_t v; std::memcpy(&v, p, 8);
    return v;
}
using ::silkworm::ByteView;
using ::silkworm::Bytes;

// Layout: displacement_factors[n_buckets]:u64, slot_offsets[n_keys]:u32 (0 = collision), collisions:[key:u64][offset:u64]*, data:[len:u64][body]*; reads are unchecked (see validate_mphf).
inline constexpr uint64_t kMphfGoldenRatio = 0x9E3779B97F4A7C15ull;
inline constexpr uint32_t kMphfMapVersion = 3u;

[[gnu::always_inline]] inline uint64_t mix64_body(uint64_t z) noexcept {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    return z ^ (z >> 31);
}

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
    // No length here: the data-section [len:u64] header is what sanitize() hashes, and a copy could disagree with it.
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
    /// The data section: every entry's body lies at an 8-aligned offset from here.
    const uint8_t* data_base() const noexcept { return data_; }
    uint32_t data_size() const noexcept { return h_ != nullptr ? h_->data_size : 0u; }
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
            if (bytes_equal<KeySize>(body + KeyOffset, key)) [[likely]] {
                const uint64_t len = load_u64_le(data_ + off);
                return std::span<uint8_t>{body, static_cast<size_t>(len)};
            }
        } else if (n_collisions_ > 0) [[unlikely]] {
            const std::span<uint8_t> b = resolve_collision<KeySize, KeyOffset>(k8, key);
            if (!b.empty()) return b;
        }
        return std::nullopt;
    }

    template <typename Cb>
    void for_each_offset(Cb&& cb) const noexcept {
        if (h_ == nullptr || n_keys_ == 0) return;
        for (uint32_t i = 0; i < n_keys_; ++i) {
            const uint32_t off = slot_offsets_[i];
            if (off != 0) cb(uint64_t{off});
        }
        for (uint32_t i = 0; i < n_collisions_; ++i)
            cb(collisions_[i].offset);
    }

    template <std::size_t KeySize = 32, std::size_t KeyOffset = 0, typename Cb>
    void for_each(Cb&& cb) const noexcept {
        for_each_offset([&](uint64_t off) noexcept {
            uint64_t body_len; std::memcpy(&body_len, data_ + off, 8);
            uint8_t* body = data_ + off + 8u;
            cb(body + KeyOffset, std::span<uint8_t>{body, static_cast<size_t>(body_len)});
        });
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
            if (bytes_equal<KeySize>(body + KeyOffset, key)) {
                const uint64_t len = load_u64_le(data_ + it->offset);
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

// The one layout check for an MphfMap region, run before construction so find() and for_each() read unchecked; sound because only data[] is written afterwards and it starts past every table.
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
        if ((m->collisions_offset % alignof(MphfCollisionEntry)) != 0) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: collisions_offset misaligned");
            ok = false;
        }
        if ((m->collisions_size % sizeof(MphfCollisionEntry)) != 0) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: collisions_size not a MphfCollisionEntry multiple");
            ok = false;
        }
        ok &= bounds_within_region(m->collisions_offset, m->collisions_size,
                                   "MphfMapHeader: validate_mphf: collisions out of range");
    }

    if ((m->data_offset % alignof(uint64_t)) != 0) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: data_offset misaligned");
        ok = false;
    }
    ok &= bounds_within_region(m->data_offset, m->data_size,
                               "MphfMapHeader: validate_mphf: data region out of range");
    const uint64_t data_lo = m->data_offset;
    if (data_lo < sizeof(MphfMapHeader) ||
        data_lo < uint64_t{m->displacement_offset} + uint64_t{m->n_buckets} * 8u ||
        data_lo < uint64_t{m->slot_offsets_offset} + uint64_t{m->n_keys} * 4u ||
        (m->collisions_size > 0 &&
         data_lo < uint64_t{m->collisions_offset} + m->collisions_size)) [[unlikely]] {
        sys_println("MphfMapHeader: validate_mphf: data section overlaps a preceding section");
        ok = false;
    }
    if (!ok) [[unlikely]] return false;

    const uint8_t* mbase = base.data() + region_off;
    const auto* slot_offsets = reinterpret_cast<const uint32_t*>(mbase + m->slot_offsets_offset);
    const auto* collisions = reinterpret_cast<const MphfCollisionEntry*>(mbase + m->collisions_offset);
    const uint32_t n_collisions = m->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
    const uint8_t* data = mbase + m->data_offset;
    const uint32_t data_size = m->data_size;

    // Compare before adding: off is u64 and off + 8 can wrap.
    auto entry_within_data = [&](uint64_t off) -> bool {
        // Entries are 8-aligned (find_node_rlp keeps one verified bit per body offset / 8).
        if ((off & 7u) != 0) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry offset not 8-aligned");
            return false;
        }
        if (off > data_size || data_size - off < 8u) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry header out of data region");
            return false;
        }
        const uint64_t body_len = load_u64_le(data + off);
        if (body_len > data_size - off - 8u) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry body out of data region");
            return false;
        }
        if (body_len < KeyOffset + KeySize) [[unlikely]] {
            sys_println("MphfMapHeader: validate_mphf: entry body shorter than its key");
            return false;
        }
        return true;
    };
    for (uint32_t i = 0; i < m->n_keys; ++i) {
        const uint32_t off = slot_offsets[i];
        if (off != 0 && !entry_within_data(off)) [[unlikely]] return false;
    }
    for (uint32_t i = 0; i < n_collisions; ++i) {
        if (!entry_within_data(collisions[i].offset)) [[unlikely]] return false;
    }
    return true;
}

}  // namespace zilkworm
