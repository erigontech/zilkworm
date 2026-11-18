// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstdlib>
#include <memory>

// Pads each payload in place (zeroing the next entry's header) so evmone needs no copy; sound only for the dense MphfBuilder layout, where no byte an account uses is zeroed.

namespace zilkworm::code_store_seal {

/// Entry starts of a code-store data section (8-aligned) whose entries tile it.
class DenseLayout {
  public:
    DenseLayout(const uint8_t* data, uint32_t data_size) noexcept;

    /// Whether the entries tile the section; the other members hold only then.
    bool dense() const noexcept { return starts_ != nullptr; }
    bool is_entry(uint64_t off) const noexcept {
        return (off & 7) == 0 && (off >> 3) < n_bits_ &&
               ((starts_[off >> 8] >> ((off >> 3) & 31)) & 1) != 0;
    }
    uint32_t last() const noexcept { return last_; }

  private:
    struct FreeDeleter {
        void operator()(uint32_t* p) const noexcept { std::free(p); }
    };
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

/// Zeroes the bytes after the payload of every entry but the last, leaving >= 36 zero bytes (evmone needs 33).
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
