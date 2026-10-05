// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>

namespace zilkworm {

// HashIndex: the HashState backend's open-addressed key -> u32-offset index.
// See docs/hashstate.md, "Hash index".
template <std::size_t KeySize, uint64_t (*Key8)(const uint8_t (&)[KeySize])>
class HashIndex {
  public:
    static_assert(KeySize > 0, "HashIndex needs a non-empty key");

    // offset 0 is reserved as the empty-bucket sentinel; real entries carry offset != 0.
    static constexpr uint32_t kEmptyOffset = 0u;
    // Smallest table: keeps at least one free bucket present even for a tiny entry set.
    static constexpr uint32_t kMinCapacity = 8u;

    // Size the table for `expected_entries` at load factor ~= 0.5: capacity is the
    // power of two at or above 2x the count (never below kMinCapacity).
    explicit HashIndex(uint32_t expected_entries) noexcept {
        const uint32_t want = expected_entries != 0u ? expected_entries * 2u : 1u;
        capacity_ = std::max<uint32_t>(kMinCapacity, std::bit_ceil(want));
        mask_ = capacity_ - 1u;
        buckets_.resize(capacity_);  // value-initialized: every bucket empty (offset 0)
    }

    // Home bucket for a derived key8 (also the probe start). Exposed for tests that
    // craft forced collisions / wraparound.
    [[gnu::always_inline]] uint32_t index_of(uint64_t k8) const noexcept {
        return static_cast<uint32_t>(mix64_body(k8) & mask_);
    }

    // Place key -> offset. Overwrites the offset if `key` is already present. Rejects
    // offset 0 (the empty sentinel) and returns false if the table is unexpectedly
    // full (cannot happen at load factor <= 0.5). Returns true on insert/update.
    [[gnu::always_inline]] bool insert(const uint8_t (&key)[KeySize], uint32_t offset) noexcept {
        if (offset == kEmptyOffset) [[unlikely]] return false;
        // Grow before the load factor can exceed 0.5; the ctor size is only a hint.
        // See docs/hashstate.md, "Growth past the size hint".
        if ((static_cast<uint64_t>(size_) + 1u) * 2u > capacity_) [[unlikely]] grow_();
        uint32_t i = index_of(Key8(key));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            Bucket& b = buckets_[i];
            if (b.offset == kEmptyOffset) {  // empty bucket: claim it
                std::memcpy(b.key, key, KeySize);
                b.offset = offset;
                ++size_;
                return true;
            }
            if (std::memcmp(b.key, key, KeySize) == 0) {  // same key: update offset
                b.offset = offset;
                return true;
            }
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return false;  // table full — sizing should have prevented this
    }

    // Look up `key`. Probing stops at the empty sentinel (definitive miss) or on a
    // full-key match (hit). An occupied bucket whose full key differs is skipped, never
    // returned — the collision safety gate.
    [[gnu::always_inline]] std::optional<uint32_t> find(const uint8_t (&key)[KeySize]) const noexcept {
        uint32_t i = index_of(Key8(key));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            const Bucket& b = buckets_[i];
            if (b.offset == kEmptyOffset) return std::nullopt;              // empty sentinel: stop
            if (std::memcmp(b.key, key, KeySize) == 0) return b.offset;     // full-key gate: hit
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return std::nullopt;
    }

    uint32_t capacity() const noexcept { return capacity_; }
    uint32_t size() const noexcept { return size_; }

  private:
    struct Bucket {
        uint8_t key[KeySize];   // full key bytes, compared on every hit
        uint32_t offset{kEmptyOffset};  // 0 == empty
    };

    // Double the table and rehash every occupied bucket into it. Offsets are arena byte
    // indices, unaffected by the reshuffle (only the bucket a key HOMES to changes), so
    // callers' stored offsets stay valid. size_ is preserved. Cold: fires only when a
    // witness outgrows the ctor hint. Not always_inline (out of the hot insert path).
    void grow_() noexcept {
        std::vector<Bucket> old = std::move(buckets_);
        capacity_ <<= 1u;             // power-of-two invariant preserved
        mask_ = capacity_ - 1u;
        buckets_.assign(capacity_, Bucket{});  // all empty (offset 0)
        for (const Bucket& b : old) {
            if (b.offset == kEmptyOffset) continue;
            uint32_t i = index_of(Key8(b.key));
            while (buckets_[i].offset != kEmptyOffset) i = (i + 1u) & mask_;
            std::memcpy(buckets_[i].key, b.key, KeySize);
            buckets_[i].offset = b.offset;
        }
    }

    std::vector<Bucket> buckets_;
    uint32_t capacity_{0};
    uint32_t mask_{0};
    uint32_t size_{0};
};

}  // namespace zilkworm
