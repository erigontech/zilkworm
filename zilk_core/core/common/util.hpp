// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cassert>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <regex>
#include <string_view>
#include <vector>

#include <evmone_precompiles/keccak.hpp>
#include <intx/intx.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common_zz/keccak_memo.hpp>

// intx does not include operator<< overloading for uint<N>
namespace intx {

template <unsigned N>
inline std::ostream& operator<<(std::ostream& out, const uint<N>& value) {
    out << "0x" << intx::hex(value);
    return out;
}

}  // namespace intx

namespace silkworm {

//! \brief Strips leftmost zeroed bytes from byte sequence
//! \param [in] data : The view to process.
//! \pre data.data() must be 8-byte aligned and data.size() must be a multiple of 8
//! (an empty view is allowed).
//! \return A new view of the sequence
[[gnu::always_inline]] inline ByteView zeroless_view(ByteView data) noexcept {
    const uint8_t* p = data.data();
    const size_t n = data.size();
    assert((n & 7u) == 0);
    assert(n == 0 || (reinterpret_cast<uintptr_t>(p) & 7u) == 0);
    size_t skip = 0;
    while (skip + 8 <= n) {
        uint64_t w;
        std::memcpy(&w, std::assume_aligned<8>(p + skip), sizeof(w));
        if (w != 0) {
            // little-endian: buffer byte i is the i-th low byte of w.
            // Each term is true while the first non-zero byte lies *beyond*
            // the bytes it covers, so the true terms form a prefix whose
            // length == index of the first non-zero byte (0..7).
            // mask covers bytes +1 advances past byte
            skip += static_cast<size_t>((w & 0xFFu)              == 0) +  // [0]        -> 1
                    ((w & 0xFFFFu)              == 0) +                   // [0..1]     -> 2
                    ((w & 0xFFFFFFu)            == 0) +                   // [0..2]     -> 3
                    ((w & 0xFFFFFFFFu)          == 0) +                   // [0..3]     -> 4
                    ((w & 0xFFFFFFFFFFu)        == 0) +                   // [0..4]     -> 5
                    ((w & 0xFFFFFFFFFFFFu)      == 0) +                   // [0..5]     -> 6
                    ((w & 0xFFFFFFFFFFFFFFu)    == 0);                    // [0..6]     -> 7
            // (no 8th term: w != 0 guarantees the answer is <= 7)
            return ByteView{p + skip, n - skip};
        }
        skip += 8;
    }
    return ByteView{p + skip, n - skip};
}

inline bool has_hex_prefix(std::string_view s) {
    return s.length() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
}

inline bool is_valid_hex(std::string_view s) {
    static const std::regex kHexRegex("^0x[0-9a-fA-F]+$");
    return std::regex_match(s.data(), kHexRegex);
}

inline bool is_valid_dec(std::string_view s) {
    static const std::regex kHexRegex("^[0-9]+$");
    return std::regex_match(s.data(), kHexRegex);
}

inline bool is_valid_hash(std::string_view s) {
    if (s.length() != 2 + kHashLength * 2) {
        return false;
    }
    return is_valid_hex(s);
}

inline bool is_valid_address(std::string_view s) {
    if (s.length() != 2 + kAddressLength * 2) {
        return false;
    }
    return is_valid_hex(s);
}

//! \brief Returns a string representing the hex form of provided string of bytes
std::string to_hex(ByteView bytes, bool with_prefix = false);

//! \brief Returns a string representing the hex form of provided integral
template <typename T>
    requires(std::is_integral_v<T> && std::is_unsigned_v<T>)
std::string to_hex(T value, bool with_prefix = false) {
    // Buffer is 8-byte aligned and sized to a multiple of 8, as zeroless_view requires.
    alignas(8) uint8_t bytes[sizeof(T) < 8 ? 8 : sizeof(T)];
    if constexpr (sizeof(T) <= 8) {
        intx::be::store(bytes, static_cast<uint64_t>(value));
    } else {
        intx::be::store(bytes, value);
    }
    std::string hexed{to_hex(zeroless_view(bytes), with_prefix)};
    if (hexed.size() == (with_prefix ? 2 : 0)) {
        hexed += "00";
    }
    return hexed;
}

//! \brief Abridges a string to given length and eventually adds an ellipsis if input length is gt required length
std::string abridge(std::string_view input, size_t length);

std::optional<uint8_t> decode_hex_digit(char ch) noexcept;

std::optional<Bytes> from_hex(std::string_view hex) noexcept;

// Parses a string input value representing a size in
// human-readable format with qualifiers. eg "256MB"
std::optional<uint64_t> parse_size(const std::string& sizestr);

// Converts a number of bytes in a human-readable format
std::string human_size(uint64_t bytes, const char* unit = "B");

// Compares two strings for equality with case insensitivity
bool iequals(std::string_view a, std::string_view b);

// The length of the longest common prefix of a and b.
size_t prefix_length(ByteView a, ByteView b);

// keccak256("") — union blocks constexpr bit_cast of kEmptyHash
inline constexpr ethash::hash256 kEmptyHash256{
    .bytes = {0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
              0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70}};
static_assert([] {
    for (size_t i = 0; i < 32; ++i) {
        if (kEmptyHash256.bytes[i] != kEmptyHash.bytes[i]) return false;
    }
    return true;
}());

inline ethash::hash256 keccak256(ByteView view) {
    // size 0 excluded: slot.size==0 is the memo's vacancy sentinel and would false-hit
    if (view.size() != 0 && view.size() <= 32) [[likely]] {
        return zilkworm::keccak256_memo(view.data(), view.size());
    }
    size_t size = view.size();
    asm("" : "+r"(size));  // opaque: stops GCC re-splitting the fused gate
    if (size == 0) [[unlikely]] return kEmptyHash256;
    return ethash::keccak256(view.data(), size);
}

//! \brief Create an intx::uint256 from a string supporting both fixed decimal and scientific notation
template <UnsignedIntegral Int>
constexpr Int from_string_sci(const char* str) {
    auto s = str;
    auto m = Int{};

    int num_digits = 0;
    int num_decimal_digits = 0;
    bool count_decimals{false};
    char c = 0;
    while ((c = *s++)) {
        if (c == '.') {
            count_decimals = true;
            continue;
        }
        if (c == 'e') {
            if (*s++ != '+') intx::throw_<std::out_of_range>(s);
            break;
        }
        if (num_digits++ > std::numeric_limits<Int>::digits10) {
            // intx::throw_<std::out_of_range>(s);
        }
        if (count_decimals) {
            ++num_decimal_digits;
        }

        const auto d = intx::from_dec_digit(c);
        m = m * Int{10} + d;
        if (m < d) {
            // intx::throw_<std::out_of_range>(s);
        }
    }
    if (!c) {
        if (num_decimal_digits == 0) return m;
        intx::throw_<std::out_of_range>(s);
    }

    int e = 0;
    while ((c = *s++)) {
        const auto d = intx::from_dec_digit(c);
        e = e * 10 + d;
        if (e < d) {
            // intx::throw_<std::out_of_range>(s);
        }
    }
    if (e < num_decimal_digits) {
        // intx::throw_<std::out_of_range>(s);
    }

    auto x = m;
    auto exp = e - num_decimal_digits;
    while (exp > 0) {
        x *= Int{10};
        --exp;
    }
    return x;
}

inline std::ostream& operator<<(std::ostream& out, ByteView bytes) {
    for (const auto& b : bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int{b};
    }
    out << std::dec;
    return out;
}

inline std::ostream& operator<<(std::ostream& out, const Bytes& bytes) {
    out << to_hex(bytes);
    return out;
}

float to_float(const intx::uint256&) noexcept;

std::string snake_to_camel(std::string_view snake);

}  // namespace silkworm
