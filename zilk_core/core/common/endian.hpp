// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/decoding_result.hpp>

namespace silkworm::endian {

// NOLINTBEGIN(readability-identifier-naming)

const auto load_big_u16 = intx::be::unsafe::load<uint16_t>;

const auto load_big_u32 = intx::be::unsafe::load<uint32_t>;

const auto load_big_u64 = intx::be::unsafe::load<uint64_t>;

const auto load_little_u16 = intx::le::unsafe::load<uint16_t>;

const auto load_little_u32 = intx::le::unsafe::load<uint32_t>;

const auto load_little_u64 = intx::le::unsafe::load<uint64_t>;

const auto store_big_u16 = intx::be::unsafe::store<uint16_t>;

const auto store_big_u32 = intx::be::unsafe::store<uint32_t>;

const auto store_big_u64 = intx::be::unsafe::store<uint64_t>;

const auto store_little_u16 = intx::le::unsafe::store<uint16_t>;

const auto store_little_u32 = intx::le::unsafe::store<uint32_t>;

const auto store_little_u64 = intx::le::unsafe::store<uint64_t>;

// NOLINTEND(readability-identifier-naming)

// Returned view aliases a thread-local buffer; valid only until the next call (both overloads).
ByteView to_big_compact(uint64_t value);

ByteView to_big_compact(const intx::uint256& value);

// kOverflow if wider than T; kLeadingZero if not compact.
template <UnsignedIntegral T>
static DecodingResult from_big_compact(ByteView data, T& out) {
    if (data.size() > sizeof(T)) {
        return std::unexpected{DecodingError::kOverflow};
    }

    out = 0;
    if (data.empty()) {
        return {};
    }

    if (data[0] == 0) {
        return std::unexpected{DecodingError::kLeadingZero};
    }

#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    if constexpr (sizeof(T) <= 8)
    {
        T val = 0;
        for (size_t i = 0; i < data.size(); ++i)
            val = (val << 8) | data[i];
        out = val;
        return {};
    }
    else if constexpr (sizeof(T) == 32)
    {
        out = 0;
        const size_t sz = data.size();
        const uint8_t* end = data.data() + sz;
        size_t word_idx = 0;

        size_t remaining = sz;
        while (remaining >= 8)
        {
            end -= 8;
            uint64_t w = 0;
            for (size_t j = 0; j < 8; ++j)
                w = (w << 8) | end[j];
            out[word_idx++] = w;
            remaining -= 8;
        }
        if (remaining > 0)
        {
            const uint8_t* start = data.data();
            uint64_t w = 0;
            for (size_t j = 0; j < remaining; ++j)
                w = (w << 8) | start[j];
            out[word_idx] = w;
        }
        return {};
    }
    else
#endif
    {
        auto* ptr{reinterpret_cast<uint8_t*>(&out)};
        std::memcpy(ptr + (sizeof(T) - data.size()), &data[0], data.size());
        out = intx::to_big_endian(out);
        return {};
    }
}

}  // namespace silkworm::endian
