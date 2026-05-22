// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "decode.hpp"

#include <tuple>

#include <zilk_core/core/common/assert.hpp>
#include <zilk_core/core/common/endian.hpp>

namespace silkworm::rlp {

std::expected<Header, DecodingError> decode_header(ByteView& from) noexcept {
    if (from.empty()) {
        return std::unexpected{DecodingError::kInputTooShort};
    }

    Header h{.list = false};
    uint8_t b{from[0]};
    if (b < 0x80) {
        h.payload_length = 1;
    } else if (b < 0xB8) {
        from.remove_prefix(1);
        h.payload_length = b - 0x80u;
        if (h.payload_length == 1) {
            if (from.empty()) {
                return std::unexpected{DecodingError::kInputTooShort};
            }
            if (from[0] < 0x80) {
                return std::unexpected{DecodingError::kNonCanonicalSize};
            }
        }
    } else if (b < 0xC0) {
        from.remove_prefix(1);
        const size_t len_of_len{b - 0xB7u};
        if (from.size() < len_of_len) {
            return std::unexpected{DecodingError::kInputTooShort};
        }
        uint64_t len{0};
        if (DecodingResult res{endian::from_big_compact(from.substr(0, len_of_len), len)}; !res) {
            return std::unexpected{res.error()};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return std::unexpected{DecodingError::kNonCanonicalSize};
        }
    } else if (b < 0xF8) {
        from.remove_prefix(1);
        h.list = true;
        h.payload_length = b - 0xC0u;
    } else {
        from.remove_prefix(1);
        h.list = true;
        const size_t len_of_len{b - 0xF7u};
        if (from.size() < len_of_len) {
            return std::unexpected{DecodingError::kInputTooShort};
        }
        uint64_t len{0};
        if (DecodingResult res{endian::from_big_compact(from.substr(0, len_of_len), len)}; !res) {
            return std::unexpected{res.error()};
        }
        h.payload_length = static_cast<size_t>(len);
        from.remove_prefix(len_of_len);
        if (h.payload_length < 56) {
            return std::unexpected{DecodingError::kNonCanonicalSize};
        }
    }

    if (from.size() < h.payload_length) {
        return std::unexpected{DecodingError::kInputTooShort};
    }

    return h;
}

DecodingResult decode(ByteView& from, Bytes& to, Leftover mode) noexcept {
    const auto h{decode_header(from)};
    if (!h) {
        return std::unexpected{h.error()};
    }
    if (h->list) {
        return std::unexpected{DecodingError::kUnexpectedList};
    }
    to = from.substr(0, h->payload_length);
    from.remove_prefix(h->payload_length);
    if (mode != Leftover::kAllow && !from.empty()) {
        return std::unexpected{DecodingError::kInputTooLong};
    }
    return {};
}

DecodingResult decode(ByteView& from, bool& to, Leftover mode) noexcept {
    uint64_t i{0};
    if (DecodingResult res{decode(from, i, mode)}; !res) {
        return std::unexpected{res.error()};
    }
    if (i > 1) {
        return std::unexpected{DecodingError::kOverflow};
    }
    to = i;
    return {};
}

}  // namespace silkworm::rlp
