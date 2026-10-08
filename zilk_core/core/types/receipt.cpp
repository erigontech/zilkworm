// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt.hpp"

#include <bit>
#include <cassert>
#include <cstring>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>

namespace silkworm::rlp {

namespace {

    // The size of the header encode_header writes for a payload of n bytes, without counting bits
    // (a 64-bit count of leading zeros is a libgcc call on rv32) for any size a receipt reaches.
    size_t header_length(size_t n) noexcept {
        return n < 56 ? 1 : n < 0x100 ? 2 : n < 0x10000 ? 3 : n < 0x1000000 ? 4 : length_of_length(n);
    }

    // Writes the header encode_header writes for a payload of n bytes; short_code is kEmptyStringCode
    // for a string and kEmptyListCode for a list.
    uint8_t* write_header(uint8_t* p, unsigned short_code, size_t n) noexcept {
        if (n < 56) {
            *p = static_cast<uint8_t>(short_code + n);
            return p + 1;
        }
        const size_t length_bytes{header_length(n) - 1};
        *p++ = static_cast<uint8_t>(short_code + 55 + length_bytes);
        for (size_t i{length_bytes}; i-- > 0;) {
            *p++ = static_cast<uint8_t>(n >> (8 * i));
        }
        return p;
    }

    // The payload of a log's list [address, topics, data].
    size_t log_payload(const Log& l) noexcept {
        const size_t topics{(1 + kHashLength) * l.topics.size()};
        const size_t n{l.data.size()};
        const size_t data{n == 1 && l.data[0] < kEmptyStringCode ? 1 : header_length(n) + n};
        return 1 + kAddressLength + header_length(topics) + topics + data;
    }

    uint8_t* copy(uint8_t* p, const uint8_t* src, size_t n) noexcept {
        std::memcpy(p, src, n);
        return p + n;
    }

    // Copies n bytes, a nonzero multiple of 4, to a dst of any alignment. On the strict-align guest a
    // memcpy of unknown alignment is a call, which costs more than this for the bloom, an address or a
    // topic. Words are loaded only from a src found 4-aligned (the fields are byte arrays, so their
    // alignment is checked, not assumed) and stored only from dst's first word boundary on: each stored
    // word joins the upper bytes of one source word to the lower bytes of the next (little endian), and
    // the bytes before the first and after the last stored word are written one by one.
    uint8_t* copy_words(uint8_t* dst, const uint8_t* src, size_t n) noexcept {
        typedef uint32_t __attribute__((may_alias)) w32;
        assert(n >= 4);
        if (std::endian::native != std::endian::little || (reinterpret_cast<uintptr_t>(src) & 3) != 0) {
            return copy(dst, src, n);
        }
        const w32* s{reinterpret_cast<const w32*>(src)};
        const size_t words{n / 4};
        const auto off{static_cast<unsigned>(reinterpret_cast<uintptr_t>(dst) & 3)};
        if (off == 0) {
            w32* d{reinterpret_cast<w32*>(dst)};
            for (size_t i{0}; i < words; ++i) {
                d[i] = s[i];
            }
            return dst + n;
        }
        const unsigned lead{4 - off};  // bytes before dst's first word boundary
        const unsigned shift{8 * lead};
        uint32_t w{s[0]};
        for (unsigned k{0}; k < lead; ++k) {
            dst[k] = static_cast<uint8_t>(w >> (8 * k));
        }
        w32* d{reinterpret_cast<w32*>(dst + lead)};
        for (size_t i{1}; i < words; ++i) {
            const uint32_t next{s[i]};
            d[i - 1] = (w >> shift) | (next << (32 - shift));
            w = next;
        }
        w >>= shift;
        uint8_t* tail{dst + lead + 4 * (words - 1)};
        for (unsigned k{0}; k < off; ++k, w >>= 8) {
            tail[k] = static_cast<uint8_t>(w);
        }
        return dst + n;
    }

}  // namespace

// Byte for byte what the generic encoders write (encode_header, then encode of the status, the gas, the
// bloom and the logs), in one pass: the lengths are summed first, then the buffer grows once and every
// header and field is written in place.
void encode(Bytes& to, const Receipt& r) {
    size_t logs_payload{0};
    for (const Log& l : r.logs) {
        const size_t n{log_payload(l)};
        logs_payload += header_length(n) + n;
    }
    const uint64_t gas{r.cumulative_gas_used};
    const auto hi{static_cast<uint32_t>(gas >> 32)};
    const auto lo{static_cast<uint32_t>(gas)};
    const uint32_t top{hi != 0 ? hi : lo};
    const size_t top_bytes{top < 0x100 ? 1u : top < 0x10000 ? 2u : top < 0x1000000 ? 3u : 4u};
    // The bytes after the gas's header; none below 0x80, where the gas is a single byte.
    const size_t gas_bytes{gas < kEmptyStringCode ? 0 : (hi != 0 ? 4u : 0u) + top_bytes};
    // The status, the gas, the bloom (its 3-byte header and 256 bytes) and the logs list.
    const size_t payload{1 + 1 + gas_bytes + 3 + kBloomByteLength + header_length(logs_payload) + logs_payload};
    const bool typed{r.type != TransactionType::kLegacy};
    const size_t total{(typed ? 1u : 0u) + header_length(payload) + payload};

    to.resize_and_overwrite(to.size() + total, [&](uint8_t* buf, size_t size) noexcept {
        uint8_t* p{buf + size - total};
        if (typed) {
            *p++ = static_cast<uint8_t>(r.type);
        }
        p = write_header(p, kEmptyListCode, payload);
        *p++ = r.success ? uint8_t{1} : kEmptyStringCode;
        if (gas_bytes == 0) {
            *p++ = gas == 0 ? kEmptyStringCode : static_cast<uint8_t>(gas);
        } else {
            // Big endian from the first nonzero byte, by 32-bit shifts: on rv32 a 64-bit shift by a
            // variable amount is a branch and several instructions.
            *p++ = static_cast<uint8_t>(kEmptyStringCode + gas_bytes);
            for (size_t i{top_bytes}; i-- > 0;) {
                *p++ = static_cast<uint8_t>(top >> (8 * i));
            }
            if (hi != 0) {
                for (size_t i{4}; i-- > 0;) {
                    *p++ = static_cast<uint8_t>(lo >> (8 * i));
                }
            }
        }
        p = write_header(p, kEmptyStringCode, kBloomByteLength);
        p = copy_words(p, r.bloom.data(), kBloomByteLength);
        p = write_header(p, kEmptyListCode, logs_payload);
        for (const Log& l : r.logs) {
            p = write_header(p, kEmptyListCode, log_payload(l));
            *p++ = static_cast<uint8_t>(kEmptyStringCode + kAddressLength);
            p = copy_words(p, l.address.bytes, kAddressLength);
            p = write_header(p, kEmptyListCode, (1 + kHashLength) * l.topics.size());
            for (const evmc::bytes32& t : l.topics) {
                *p++ = static_cast<uint8_t>(kEmptyStringCode + kHashLength);
                p = copy_words(p, t.bytes, kHashLength);
            }
            const size_t n{l.data.size()};
            if (n != 1 || l.data[0] >= kEmptyStringCode) {
                p = write_header(p, kEmptyStringCode, n);
            }
            if (n != 0) {
                p = copy(p, l.data.data(), n);
            }
        }
        assert(p == buf + size);
        return size;
    });
}

}  // namespace silkworm::rlp
