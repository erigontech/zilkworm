// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/endian.hpp>

namespace silkworm::rlp {

struct Header {
    bool list{false};
    size_t payload_length{0};
};

inline constexpr uint8_t kEmptyStringCode{0x80};
inline constexpr uint8_t kEmptyListCode{0xC0};

void encode_header(Bytes& to, Header header);

void encode(Bytes& to, ByteView str);

// Writes the RLP of str to dst, returns bytes written; caller guarantees capacity.
size_t encode_into(uint8_t* dst, ByteView str) noexcept;

// Requires str.size() < 56 (caller's responsibility); no bounds check.
[[gnu::always_inline]] inline size_t encode_into_small(uint8_t* dst, ByteView s) noexcept {
    if (s.size() == 1 && s[0] < kEmptyStringCode) {
        dst[0] = s[0];
        return 1;
    }
    dst[0] = static_cast<uint8_t>(kEmptyStringCode + s.size());
    if (!s.empty()) std::memcpy(dst + 1, s.data(), s.size());
    return 1 + s.size();
}

template <UnsignedIntegral T>
void encode(Bytes& to, const T& n) {
    if (n == 0) {
        to.push_back(kEmptyStringCode);
    } else if (n < kEmptyStringCode) {
        to.push_back(static_cast<uint8_t>(n));
    } else {
        const ByteView be{endian::to_big_compact(n)};
        encode_header(to, {.list = false, .payload_length = be.size()});
        to.append(be);
    }
}

template <UnsignedIntegral T>
[[gnu::always_inline]] inline size_t encode_uint_into(uint8_t* dst, const T& n) noexcept {
    if (n == 0) {
        dst[0] = kEmptyStringCode;
        return 1;
    }
    if (n < kEmptyStringCode) {
        dst[0] = static_cast<uint8_t>(n);
        return 1;
    }
    const auto be = endian::to_big_compact(n);
    dst[0] = static_cast<uint8_t>(kEmptyStringCode + be.size());
    std::memcpy(dst + 1, be.data(), be.size());
    return 1 + be.size();
}

void encode(Bytes& to, bool);

size_t length_of_length(uint64_t payload_length) noexcept;

size_t length(ByteView) noexcept;

template <UnsignedIntegral T>
size_t length(const T& n) noexcept {
    if (n < kEmptyStringCode) {
        return 1;
    }
    const size_t n_bytes{intx::count_significant_bytes(n)};
    return n_bytes + length_of_length(n_bytes);
}

inline size_t length(bool) noexcept {
    return 1;
}

}  // namespace silkworm::rlp
