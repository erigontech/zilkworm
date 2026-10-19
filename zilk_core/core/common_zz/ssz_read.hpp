// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Bounds-checked SSZ reads shared by the stateless-input decoders: little-endian scalars, the
// variable-field framing of a container, and lists of byte lists.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm::ssz {

using ::silkworm::ByteView;

// The caller has checked off + width <= v.size(). memcpy: the guest has no unaligned loads.
[[gnu::always_inline]] inline uint32_t rd_u32(ByteView v, size_t off) noexcept {
    uint32_t x;
    std::memcpy(&x, v.data() + off, sizeof(x));
    return x;
}
[[gnu::always_inline]] inline uint64_t rd_u64(ByteView v, size_t off) noexcept {
    uint64_t x;
    std::memcpy(&x, v.data() + off, sizeof(x));
    return x;
}
// ByteView::substr throws on a bad position; every caller has checked off + len <= v.size().
[[gnu::always_inline]] inline ByteView subv(ByteView v, size_t off, size_t len) noexcept {
    return ByteView{v.data() + off, len};
}

/// The variable-size fields of a container: the offset table entries sit at `offset_pos` within
/// the fixed region of `fixed_size` bytes. The first offset must equal `fixed_size`, the rest be
/// in order and in bounds; the last field runs to the end. `out[i]` is field i's bytes.
inline bool split_variable(ByteView body, size_t fixed_size, std::span<const size_t> offset_pos,
                           std::vector<ByteView>& out) {
    out.clear();
    if (body.size() < fixed_size) return false;
    std::vector<uint32_t> offs;
    offs.reserve(offset_pos.size() + 1);
    for (const size_t pos : offset_pos) offs.push_back(rd_u32(body, pos));
    if (offs.empty() || offs.front() != fixed_size) return false;
    offs.push_back(static_cast<uint32_t>(body.size()));
    for (size_t i = 0; i + 1 < offs.size(); ++i) {
        if (offs[i] > offs[i + 1] || offs[i + 1] > body.size()) return false;
        out.push_back(subv(body, offs[i], offs[i + 1] - offs[i]));
    }
    return true;
}

/// List[List[byte, elem_cap], count_cap] or ProgressiveList[ProgressiveList[byte]]: an offset
/// table of n uint32 followed by the elements. Rejects a table that is not a multiple of 4, an
/// offset out of order or out of bounds, more than `count_cap` elements or one over `elem_cap`
/// bytes. Clears `out`.
inline bool decode_byte_lists(ByteView blob, uint32_t elem_cap, uint32_t count_cap,
                              std::vector<ByteView>& out) {
    out.clear();
    if (blob.empty()) return true;
    if (blob.size() < 4) return false;
    const uint32_t first = rd_u32(blob, 0);
    if (first < 4 || (first & 3u) != 0 || first > blob.size()) return false;
    const uint32_t n = first / 4u;
    if (n > count_cap) return false;
    out.reserve(n);
    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t off = i == 0 ? first : rd_u32(blob, i * 4u);
        const uint32_t next = i + 1 < n ? rd_u32(blob, (i + 1) * 4u) : static_cast<uint32_t>(blob.size());
        if (off < first || off > next || next > blob.size()) return false;
        if (next - off > elem_cap) return false;
        out.push_back(subv(blob, off, next - off));
    }
    return true;
}

/// ProgressiveList[T] of a fixed-size T: `blob` is the items back to back.
inline bool split_fixed_items(ByteView blob, size_t item_size, std::vector<ByteView>& out) {
    out.clear();
    if (blob.size() % item_size != 0) return false;
    out.reserve(blob.size() / item_size);
    for (size_t off = 0; off < blob.size(); off += item_size) out.push_back(subv(blob, off, item_size));
    return true;
}

}  // namespace zilkworm::ssz
