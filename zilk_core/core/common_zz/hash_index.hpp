// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

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
template <std::size_t KeySize, uint64_t (*Key8)(const uint8_t (&)[KeySize]),
          class Value = uint32_t>
class HashIndex {
  public:
    static_assert(KeySize > 0, "HashIndex needs a non-empty key");

    // The empty-bucket sentinel: real entries carry a value != kEmpty.
    static constexpr Value kEmpty{};
    // Smallest table: keeps at least one free bucket present even for a tiny entry set.
    static constexpr uint32_t kMinCapacity = 8u;

    // Size the table for `expected_entries` at load factor ~= 0.5: capacity is the
    // power of two at or above 2x the count (never below kMinCapacity).
    explicit HashIndex(uint32_t expected_entries) noexcept {
        const uint32_t want = expected_entries != 0u ? expected_entries * 2u : 1u;
        capacity_ = std::max<uint32_t>(kMinCapacity, std::bit_ceil(want));
        mask_ = capacity_ - 1u;
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
                std::memcpy(b.key, key, KeySize);
                b.value = value;
                ++size_;
                return true;
            }
            if (key_eq_(b.key, key)) {  // same key: update value
                b.value = value;
                return true;
            }
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return false;  // table full — sizing should have prevented this
    }

    // Look up the KeySize bytes at `key`, read in place: the caller guarantees KeySize
    // readable bytes there, at any alignment (the HashState sweep and confirmation walk
    // probe straight from a child hash ref inside a node's RLP, with no copy into a
    // stack key). Probing stops at the empty sentinel (definitive miss) or on a full-key
    // match (hit). An occupied bucket whose full key differs is skipped, never returned —
    // the collision safety gate.
    [[gnu::always_inline]] std::optional<Value> find_ptr(const uint8_t* key) const noexcept {
        // Key8 only reads through memcpy (and byte indexing), so handing it the bytes
        // behind an unaligned pointer as the array reference it takes is fine.
        uint32_t i = index_of(Key8(*reinterpret_cast<const uint8_t (*)[KeySize]>(key)));
        for (uint32_t probes = 0; probes < capacity_; ++probes) {
            const Bucket& b = buckets_[i];
            if (b.value == kEmpty) return std::nullopt;   // empty sentinel: stop
            if (key_eq_(b.key, key)) return b.value;       // full-key gate: hit
            i = (i + 1u) & mask_;  // linear probe, wraps at the table end
        }
        return std::nullopt;
    }

    // Look up `key` given as a whole array; the same probe as find_ptr.
    [[gnu::always_inline]] std::optional<Value> find(const uint8_t (&key)[KeySize]) const noexcept {
        return find_ptr(key);
    }

    uint32_t capacity() const noexcept { return capacity_; }
    uint32_t size() const noexcept { return size_; }
    // Bytes per bucket (key + value, padded to the 8-byte bucket alignment). For tests.
    static constexpr std::size_t bucket_bytes() noexcept { return sizeof(Bucket); }

  private:
    // alignas(8): every bucket, and so every bucket's key, starts 8-aligned (the vector's
    // storage is at least that aligned and sizeof(Bucket) is padded to a multiple of 8), so
    // key_eq_ can read the stored key as whole aligned words. 40 bytes for a 32-byte key
    // with a u32 value, 72 for a 64-byte key, 48 (unchanged) for a 32-byte key with a
    // 16-byte view value.
    struct alignas(8) Bucket {
        uint8_t key[KeySize];  // full key bytes, compared on every hit
        Value value{};         // kEmpty == empty
    };
    static_assert(alignof(Bucket) == 8, "bucket keys must start 8-aligned for key_eq_");
    static_assert(sizeof(Bucket) % 8 == 0, "bucket stride must keep every key 8-aligned");

    // Full-key equality of a stored bucket key against the probe key, inline: no library
    // memcmp call (whose byte loop costs ~6 instructions per byte in the guest) and no
    // dependence on the probe's alignment. Word by word: the bucket side is 8-aligned
    // (Bucket's alignas) and loads as whole words; the probe side goes through memcpy-8
    // into a local, which the strict-alignment guest target (rv64im, where a misaligned
    // ld traps) compiles to byte loads and the host to one load — never a library call.
    // The leading word decides most misses (keys that share a home bucket differ in it
    // unless they share a key8), so it is tested first; the rest are folded with XOR/OR so
    // a hit is reported only on equality of EVERY word. The bucket's first word is NOT
    // compared against the key8: that identity holds for hash_key8 only (storage_key8 and
    // addr_key8 fold more than the leading bytes), and the gate must be the full key.
    // A key size that is not a multiple of 8 (none of HashState's) keeps memcmp.
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
            std::memcpy(buckets_[i].key, b.key, KeySize);
            buckets_[i].value = b.value;
        }
    }

    std::vector<Bucket> buckets_;
    uint32_t capacity_{0};
    uint32_t mask_{0};
    uint32_t size_{0};
};

}  // namespace zilkworm
