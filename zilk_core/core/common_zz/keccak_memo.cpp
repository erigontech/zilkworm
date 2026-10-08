// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "keccak_memo.hpp"

#include <array>
#include <bit>
#include <cstring>
#include <memory>

namespace zilkworm {

namespace {

    static_assert(std::endian::native == std::endian::little);

    struct KeccakSlot {
        uint64_t size;  // 0 marks an empty slot
        uint8_t data[32];
        uint8_t hash[32];
    };
    static_assert(sizeof(KeccakSlot) == 72);
    static_assert(alignof(KeccakSlot) == 8);

    inline constexpr size_t kKeccakMemoSlots{8192};
    static_assert(std::has_single_bit(kKeccakMemoSlots));
    // Table index = top log2(slots) bits of the mixed key.
    inline constexpr unsigned kKeccakMemoShift{64 - std::countr_zero(kKeccakMemoSlots)};

#if defined(NO_THREAD_LOCAL) || defined(SP1) || defined(QEMU_DEBUG)
    // Single-threaded guest: thread_local would emit an emutls call per access.
    constinit std::array<KeccakSlot, kKeccakMemoSlots> keccak_memo_{};
#else
    thread_local constinit std::array<KeccakSlot, kKeccakMemoSlots> keccak_memo_{};
#endif

    // u64 load from 8-aligned p.
    inline uint64_t ld8_a8(const uint8_t* p) noexcept {
        uint64_t v;
        std::memcpy(&v, std::assume_aligned<8>(p), sizeof v);
        return v;
    }

    // u32 load from 4-aligned p.
    inline uint32_t ld4_a4(const uint8_t* p) noexcept {
        uint32_t v;
        std::memcpy(&v, std::assume_aligned<4>(p), sizeof v);
        return v;
    }

    // Keeps the hit path frameless; caller has already stored size + data words.
    [[gnu::noinline]] ethash::hash256 keccak_memo_fill(const uint8_t* data, size_t size,
                                                       KeccakSlot& slot) noexcept {
        const ethash::hash256 out{ethash::keccak256(data, size)};
        std::memcpy(slot.hash, out.bytes, 32);
        return out;
    }

}  // namespace

ethash::hash256 keccak256_memo(const uint8_t* data, size_t size) noexcept {
    uint64_t w0, w1, w2, w3;
    const auto pa{reinterpret_cast<uintptr_t>(data)};
    if (size == 32) [[likely]] {
        if ((pa % 8) == 0) [[likely]] {
            w0 = ld8_a8(data);
            w1 = ld8_a8(data + 8);
            w2 = ld8_a8(data + 16);
            w3 = ld8_a8(data + 24);
        } else {
            alignas(8) uint8_t buf[32];
            std::memcpy(buf, data, 32);
            w0 = ld8_a8(buf);
            w1 = ld8_a8(buf + 8);
            w2 = ld8_a8(buf + 16);
            w3 = ld8_a8(buf + 24);
        }
    } else if (size == 20) [[likely]] {
        if ((pa & 7) == 0) [[likely]] {
            w0 = ld8_a8(data);
            w1 = ld8_a8(data + 8);
            w2 = ld4_a4(data + 16);
        } else {
            alignas(8) uint8_t buf[24];
            std::memcpy(buf, data, 20);
            w0 = ld8_a8(buf);
            w1 = ld8_a8(buf + 8);
            w2 = ld4_a4(buf + 16);
        }
        w3 = 0;
    } else {
        alignas(8) uint8_t buf[32]{};
        std::memcpy(buf, data, size);
        w0 = ld8_a8(buf);
        w1 = ld8_a8(buf + 8);
        w2 = ld8_a8(buf + 16);
        w3 = ld8_a8(buf + 24);
    }
    const uint64_t mix{(w0 ^ w1 ^ w2 ^ w3) * 0x9E3779B97F4A7C15};
    KeccakSlot& slot{keccak_memo_[mix >> kKeccakMemoShift]};
    const uint8_t* d{slot.data};
    // Early-exit compare: SP1 costs executed instructions.
    if (slot.size == size && ld8_a8(d) == w0 && ld8_a8(d + 8) == w1 && ld8_a8(d + 16) == w2 &&
        ld8_a8(d + 24) == w3) [[likely]] {
        ethash::hash256 out;
        std::memcpy(out.bytes, slot.hash, 32);
        return out;
    }
    slot.size = size;
    std::memcpy(slot.data, &w0, 8);
    std::memcpy(slot.data + 8, &w1, 8);
    std::memcpy(slot.data + 16, &w2, 8);
    std::memcpy(slot.data + 24, &w3, 8);
    return keccak_memo_fill(data, size, slot);
}

}  // namespace zilkworm
