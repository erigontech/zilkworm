// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>  // std::max
#include <bit>
#include <cstdint>
#include <cstring>
#include <memory>  // std::assume_aligned
#include <optional>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>

namespace zilkworm {

// HashIndex: the HashState backend's open-addressed key -> value index. The value is a u32
// arena offset by default, or any small trivially-copyable type that compares with ==.
// A value-initialized Value marks an empty bucket, so a real entry's value never equals it.
// See docs/hashstate.md, "Hash index".
template <std::size_t KeySize, uint64_t (*Key8)(const uint8_t*), class Value = uint32_t>
class HashIndex {
  public:
    static_assert(KeySize > 0, "HashIndex needs a non-empty key");

    // The empty-bucket sentinel: real entries carry a value != kEmpty.
    static constexpr Value kEmpty{};
    // Smallest table: keeps at least one free bucket present even for a tiny entry set.
    static constexpr uint32_t kMinCapacity = 8u;

    // 2^31 clamp: the doubling must not wrap.
    static uint32_t capacity_for(uint32_t entries) noexcept {
        const uint64_t want = std::bit_ceil<uint64_t>(std::max<uint64_t>(kMinCapacity, 2ull * entries));
        return static_cast<uint32_t>(std::min<uint64_t>(want, 1ull << 31));
    }

    // Size the table for `expected_entries` at load factor ~= 0.5: capacity is the
    // power of two at or above 2x the count (never below kMinCapacity).
    explicit HashIndex(uint32_t expected_entries) noexcept {
        capacity_ = capacity_for(expected_entries);
        mask_ = capacity_ - 1u;
        buckets_.resize(capacity_);  // value-initialized: every bucket empty
    }

    void reserve(uint32_t expected) noexcept {
        if (size_ != 0u) return;
        const uint32_t want = capacity_for(expected);
        if (want <= capacity_) return;
        capacity_ = want;
        mask_ = want - 1u;
        buckets_.clear();
        buckets_.resize(capacity_);  // value-initialized: every bucket empty
    }

    // Home bucket for a derived key8 (also the probe start): mix64_body(k8) % capacity_.
    // Written as a mask, which equals the modulo because capacity_ is a power of two; the
    // compiler cannot prove that of a runtime value and would emit a division (remu on
    // RV64IM). Exposed for tests that craft forced collisions / wraparound.
    [[gnu::always_inline]] uint32_t index_of(uint64_t k8) const noexcept {
        return static_cast<uint32_t>(mix64_body(k8) & mask_);
    }

    // Place key -> value. Overwrites the value if `key` is already present. Rejects
    // kEmpty (the empty sentinel) and returns false if the table is unexpectedly
    // full (cannot happen at load factor <= 0.5). Returns true on insert/update.
    [[gnu::always_inline]] bool insert(const uint8_t (&key)[KeySize], Value value) noexcept {
        if (value == kEmpty) [[unlikely]] return false;
        // Grow before the load factor can exceed 0.5; the ctor size is only a hint.
        // See docs/hashstate.md, "Growth past the size hint".
        if ((static_cast<uint64_t>(size_) + 1u) * 2u > capacity_) [[unlikely]] grow_();
        uint32_t i = index_of(Key8(key));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            Bucket& b = buckets_[i];
            if (b.value == kEmpty) {  // empty bucket: claim it
                claim_(b, key, value);
                ++size_;
                return true;
            }
            if (key_eq_(b.key, key)) {
                b.value = value;
                return true;
            }
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return false;  // table full — sizing should have prevented this
    }

    // kFull also covers a rejected sentinel value.
    enum class Insert : uint8_t { kInserted, kExisted, kFull };

    // First wins, unlike insert's overwrite.
    [[gnu::always_inline]] Insert try_insert(const uint8_t (&key)[KeySize], Value value) noexcept {
        if (value == kEmpty) [[unlikely]] return Insert::kFull;
        if ((static_cast<uint64_t>(size_) + 1u) * 2u > capacity_) [[unlikely]] grow_();
        uint32_t i = index_of(Key8(key));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            Bucket& b = buckets_[i];
            if (b.value == kEmpty) {
                claim_(b, key, value);
                ++size_;
                return Insert::kInserted;
            }
            if (key_eq_(b.key, key)) return Insert::kExisted;
            i = (i + 1u) & mask_;
        }
        return Insert::kFull;
    }

    // Caller guarantees KeySize readable bytes; any alignment.
    [[gnu::always_inline]] std::optional<Value> find_ptr(const uint8_t* key) const noexcept {
        uint32_t i = index_of(Key8(key));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            const Bucket& b = buckets_[i];
            if (b.value == kEmpty) return std::nullopt;  // empty sentinel: stop
            if (key_eq_(b.key, key)) return b.value;
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return std::nullopt;
    }

    [[gnu::always_inline]] std::optional<Value> find(const uint8_t (&key)[KeySize]) const noexcept {
        return find_ptr(key);
    }

    void clear() noexcept {
        if (size_ == 0u) return;
        std::fill(buckets_.begin(), buckets_.end(), Bucket{});
        size_ = 0u;
    }

    uint32_t capacity() const noexcept { return capacity_; }
    uint32_t size() const noexcept { return size_; }
    // Padded bucket size, for tests.
    static constexpr std::size_t bucket_bytes() noexcept { return sizeof(Bucket); }

  private:
    // alignas(8): key_eq_ and claim_ use whole words.
    struct alignas(8) Bucket {
        uint8_t key[KeySize];  // full key bytes, compared on every hit
        Value value{};         // kEmpty == empty
    };
    static_assert(alignof(Bucket) == 8, "bucket keys must start 8-aligned for key_eq_");
    static_assert(sizeof(Bucket) % 8 == 0, "bucket stride must keep every key 8-aligned");

    // Inline: memcmp is a guest byte loop.
    [[gnu::always_inline]] static bool key_eq_(const uint8_t* bucket_key,
                                               const uint8_t* probe) noexcept {
        if constexpr (KeySize % 8 == 0) {
            const uint8_t* bk = std::assume_aligned<8>(bucket_key);
            uint64_t a;
            uint64_t b;
            std::memcpy(&a, bk, 8);
            std::memcpy(&b, probe, 8);
            if (a != b) return false;
            uint64_t acc = 0;
            for (std::size_t i = 8; i < KeySize; i += 8) {
                std::memcpy(&a, bk + i, 8);
                std::memcpy(&b, probe + i, 8);
                acc |= a ^ b;
            }
            return acc == 0;
        } else {
            return std::memcmp(bucket_key, probe, KeySize) == 0;
        }
    }

    // memcpy here would be a guest call.
    [[gnu::always_inline]] static void claim_(Bucket& b, const uint8_t* key, Value value) noexcept {
        Bucket* const bp = std::assume_aligned<8>(&b);
        if constexpr (KeySize % 8 == 0) {
            for (std::size_t o = 0; o < KeySize; o += 8) {
                uint64_t w;
                std::memcpy(&w, key + o, 8);
                std::memcpy(bp->key + o, &w, 8);
            }
        } else {
            std::memcpy(bp->key, key, KeySize);
        }
        bp->value = value;
    }

    // Double the table and rehash every occupied bucket into it. Values move with their
    // keys unchanged (only the bucket a key HOMES to changes), so callers' stored offsets or
    // pointers stay valid. size_ is preserved. Cold: fires only when a witness outgrows the
    // ctor hint. Not always_inline (out of the hot insert path).
    void grow_() noexcept {
        std::vector<Bucket> old = std::move(buckets_);
        capacity_ <<= 1u;             // power-of-two invariant preserved
        mask_ = capacity_ - 1u;
        buckets_.assign(capacity_, Bucket{});  // all empty
        for (const Bucket& b : old) {
            if (b.value == kEmpty) continue;
            uint32_t i = index_of(Key8(b.key));
            while (!(buckets_[i].value == kEmpty)) i = (i + 1u) & mask_;
            claim_(buckets_[i], b.key, b.value);
        }
    }

    std::vector<Bucket> buckets_;
    uint32_t capacity_{0};
    uint32_t mask_{0};
    uint32_t size_{0};
};

}  // namespace zilkworm
