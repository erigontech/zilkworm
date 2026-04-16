// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

/*
Facilities to deal with byte order/endianness
See https://en.wikipedia.org/wiki/Endianness
*/

#include <cstdint>
#include <cstring>

#include <intx/intx.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/decoding_result.hpp>

namespace silkworm::endian {

// NOLINTBEGIN(readability-identifier-naming)

// Similar to boost::endian::load_big_u16
const auto load_big_u16 = intx::be::unsafe::load<uint16_t>;

// Similar to boost::endian::load_big_u32
const auto load_big_u32 = intx::be::unsafe::load<uint32_t>;

// Similar to boost::endian::load_big_u64
const auto load_big_u64 = intx::be::unsafe::load<uint64_t>;

// Similar to boost::endian::load_little_u16
const auto load_little_u16 = intx::le::unsafe::load<uint16_t>;

// Similar to boost::endian::load_little_u32
const auto load_little_u32 = intx::le::unsafe::load<uint32_t>;

// Similar to boost::endian::load_little_u64
const auto load_little_u64 = intx::le::unsafe::load<uint64_t>;

// Similar to boost::endian::store_big_u16
const auto store_big_u16 = intx::be::unsafe::store<uint16_t>;

// Similar to boost::endian::store_big_u32
const auto store_big_u32 = intx::be::unsafe::store<uint32_t>;

// Similar to boost::endian::store_big_u64
const auto store_big_u64 = intx::be::unsafe::store<uint64_t>;

// Similar to boost::endian::store_little_u16
const auto store_little_u16 = intx::le::unsafe::store<uint16_t>;

// Similar to boost::endian::store_little_u32
const auto store_little_u32 = intx::le::unsafe::store<uint32_t>;

// Similar to boost::endian::store_little_u64
const auto store_little_u64 = intx::le::unsafe::store<uint64_t>;

// NOLINTEND(readability-identifier-naming)

//! \brief Transforms a uint64_t stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A ByteView (std::string_view) into an internal static buffer (thread specific) of the function
//! \remarks each function call overwrites the buffer, therefore invalidating a previously returned result
//! \remarks so each returned ByteView must be used immediately (before a further call to the same function).
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
ByteView to_big_compact(uint64_t value);

//! \brief Transforms a uint256 stored in memory with native endianness to it's compacted big endian byte form
//! \param [in] value : the value to be transformed
//! \return A ByteView (std::string_view) into an internal static buffer (thread specific) of the function
//! \remarks each function call overwrites the buffer, therefore invalidating a previously returned result
//! \remarks so each returned ByteView must be used immediately (before a further call to the same function)
//! \remarks See Erigon TxIndex value
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero
ByteView to_big_compact(const intx::uint256& value);

//! \brief Parses unsigned integer from a compacted big endian byte form.
//! \param [in] data : byte view of a compacted value.
//! Its length must not be greater than the sizeof the UnsignedIntegral type; otherwise, kOverflow is returned.
//! \param [out] out: the corresponding integer with native endianness.
//! \return Success or kOverflow or kLeadingZero.
//! \remarks A "compact" big endian form strips leftmost bytes valued to zero;
//! if the input is not compact kLeadingZero is returned.
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
    // Direct BE→native construction avoids memcpy + bswap.
    // For ≤8 bytes: ~10 insns. For uint256: fills word-by-word from data end,
    // avoids the expensive full bswap(uint256) (~96 insns on rv32).
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
        // Fill uint64_t words from BE data, right-aligned in uint256.
        // words_[0] is least significant. data[0] is most significant byte.
        // Process from the END of data in up to 8-byte chunks.
        out = 0;
        const size_t sz = data.size();
        const uint8_t* end = data.data() + sz;
        size_t word_idx = 0;  // start from LSW

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
