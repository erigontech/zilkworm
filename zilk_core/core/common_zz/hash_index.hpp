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

// HashIndex: the HashState backend's in-guest key -> u32-offset index. It replaces
// the minimal perfect hash (MphfMap) on the SSZ input path with a plain
// open-addressed hash table built in the guest, so no displacement/collision
// sidecar has to be serialized ahead of time.
//
// The 64-bit index key is the SAME key8 derivation the MPHF path uses: the caller
// supplies it as the `Key8` template parameter (`hash_key8` for 32-byte hashes,
// `addr_key8` for 20-byte addresses), exactly as `MphfMap::find` takes `shorten_key`.
// Passing it in keeps this header free of a state_zz dependency (hash_key8 /
// addr_key8 live beside DirectState, which already includes mphf_map.hpp).
//
// Buckets are `mix64_body(key8) & (capacity-1)` with capacity a power of two, so the
// mask replaces a modulo. Probing is linear and wraps at the table end. Capacity is
// sized to ~2x the expected entry count (load factor ~= 0.5), which keeps probe runs
// short and guarantees a free bucket exists so lookups terminate on the empty
// sentinel.
//
// Safety gate: two distinct keys can share a key8 (and thus a home bucket), so every
// occupied bucket a probe visits is confirmed with a FULL-KEY memcmp before it counts
// as a hit. A collision therefore can never return the wrong key's value — the same
// invariant MphfMap::find upholds with its embedded-key memcmp (see mphf_map.hpp:137).
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

    std::vector<Bucket> buckets_;
    uint32_t capacity_{0};
    uint32_t mask_{0};
    uint32_t size_{0};
};

}  // namespace zilkworm
