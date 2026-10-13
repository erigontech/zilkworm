// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstdlib>
#include <memory>

// Padding the code store's payloads where they lie, for the EVM to run witness code without a copy.
//
// evmone copies every code it analyzes to append 33 zero bytes (a STOP after the last opcode and
// the data of a PUSH32 cut off by the end): 2.8 MB a block on mainnet, about 80M cycles over the
// 200-block corpus. In the code store's data section, entries [len:u64][key:32][payload][zeros to 8
// bytes] follow one another, so the 33 bytes after a payload are its padding and the next entry's
// length and key. Once every payload is hashed and every account is bound to its entry, nothing
// reads those again (code_for() takes the account's offset and length), and DirectState::sanitize()
// zeroes them. That pads the payload of every entry but the last in place, and evmone runs such code
// where it lies (evmone::baseline::set_in_place_code_region(), which checks the 33 bytes itself).
//
// Only payload bytes are hashed, and a zeroed byte must lie in none that an account uses. That
// holds for the dense layout MphfBuilder writes: entries that tile the data section from the 8-byte
// sentinel to its end, each at the 8-aligned end of the one before, every entry the map refers to
// being one of them. Anything else keeps the copy.

namespace zilkworm::code_store_seal {

/// The entry starts of a code-store data section (data_size bytes at data, 8-aligned), if its
/// entries tile it.
class DenseLayout {
  public:
    DenseLayout(const uint8_t* data, uint32_t data_size) noexcept;

    /// Whether the entries tile the section. The other members hold only then.
    bool dense() const noexcept { return starts_ != nullptr; }
    /// Whether an entry starts at off.
    bool is_entry(uint64_t off) const noexcept {
        return (off & 7) == 0 && (off >> 3) < n_bits_ &&
               ((starts_[off >> 8] >> ((off >> 3) & 31)) & 1) != 0;
    }
    /// The offset of the last entry, whose tail adjoins whatever follows the section.
    uint32_t last() const noexcept { return last_; }

  private:
    struct FreeDeleter {
        void operator()(uint32_t* p) const noexcept { std::free(p); }
    };
    /// One bit per 8 bytes, set at an entry start. calloc: the guest's heap is fresh memory, zero
    /// already, where a vector would clear it word by word.
    std::unique_ptr<uint32_t[], FreeDeleter> starts_;
    uint32_t n_bits_{0};
    uint32_t last_{0};
};

inline DenseLayout::DenseLayout(const uint8_t* data, uint32_t data_size) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    // The rounding of an entry's end to 8 bytes must not wrap.
    if (data_size <= 8 || data_size > UINT32_MAX - 8) return;
    std::unique_ptr<uint32_t[], FreeDeleter> starts{
        static_cast<uint32_t*>(std::calloc(data_size / 256 + 1, sizeof(uint32_t)))};
    if (starts == nullptr) return;
    uint32_t off = 8, last = 0;
    while (off < data_size) {
        if (data_size - off < 40) return;
        // [len:u64] as two aligned words; len covers the key and the payload, inside the section.
        const w32* const len = reinterpret_cast<const w32*>(data + off);
        if (len[1] != 0 || len[0] < 32 || len[0] > data_size - off - 8) return;
        starts[off >> 8] |= uint32_t{1} << ((off >> 3) & 31);
        last = off;
        off = (off + 8 + len[0] + 7) & ~uint32_t{7};
    }
    if (off != data_size) return;
    starts_ = std::move(starts);
    n_bits_ = data_size / 8;
    last_ = last;
}

/// Zeroes [end, align4(end) + 36) after the payload of every entry of a dense section (data
/// 8-aligned) but the last: at most 39 bytes, the payload's padding and then the next entry's
/// length and up to 28 bytes of its key, which ends 4 bytes or more before the next payload. That
/// leaves 36 zero bytes after the payload at least, where evmone needs 33.
inline void zero_tails(uint8_t* data, uint32_t last) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    uint32_t len = *reinterpret_cast<const w32*>(data + 8);
    for (uint32_t off = 8; off < last;) {
        uint8_t* p = data + off + 8 + len;
        off = (off + 8 + len + 7) & ~uint32_t{7};
        len = *reinterpret_cast<const w32*>(data + off);  // Before it is zeroed.
        for (; (reinterpret_cast<uintptr_t>(p) & 3) != 0; ++p) *p = 0;
        w32* const w = reinterpret_cast<w32*>(p);
#pragma GCC unroll 9
        for (int i = 0; i < 9; ++i) w[i] = 0;
    }
}

}  // namespace zilkworm::code_store_seal
