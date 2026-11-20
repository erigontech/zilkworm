// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

// Hashes code-store payloads as the input is read: a marked entry is skipped by sanitize(); any parse doubt falls back to plain reading, and a mark claims only that this entry's bytes hash to the key beside them.

namespace zilkworm::code_store_stream {

inline constexpr size_t kEnvelopeSize = kInputHeaderSizeMFBD;
inline constexpr size_t kBundleHeaderEnd = kEnvelopeSize + sizeof(FlatBundleHeader);
inline constexpr size_t kMphfHeaderSize = sizeof(MphfMapHeader);
inline constexpr size_t kPreStateMetaSize = sizeof(PreStateMeta);

static_assert(kInputHeaderSizeMFBD == 16);
static_assert(sizeof(FlatBundleHeader) == 56);
static_assert(sizeof(PreStateMeta) == 68);
static_assert(sizeof(MphfMapHeader) == 56);
static_assert(offsetof(FlatBundleHeader, direct_state_off) == 32);
static_assert(offsetof(PreStateMeta, code_store_offset) == 28);
static_assert(offsetof(PreStateMeta, code_store_size) == 32);
static_assert(offsetof(MphfMapHeader, data_offset) == 48);
static_assert(offsetof(MphfMapHeader, data_size) == 52);

/// Io: word(), read(dst, n), verify(dst, size, key) -> keccak256 of the first `size` bytes equals the 8 words at key. All stores use a may_alias type so the guest's typed reads of the witness records are ordered under strict aliasing.

/// Sets bit entry_offset / 8 of @p bits for every entry whose payload hashes to its key; returns the bytes read, stopping at an invalid entry header or the end of the data.
template <class Io>
uint32_t read_code_store(
    Io& io, uint32_t* dst_, uint32_t data_size, uint32_t* bits, uint32_t n_bits) {
    typedef uint32_t __attribute__((may_alias)) w32;
    w32* const dst = reinterpret_cast<w32*>(dst_);
    if (data_size < 8) return 0;
    dst[0] = io.word();
    dst[1] = io.word();
    uint32_t off = 8;
    while (data_size - off >= 40) {
        w32* const e = dst + off / 4;
        const uint32_t lo = io.word();
        const uint32_t hi = io.word();
        e[0] = lo;
        e[1] = hi;
        for (size_t k = 0; k < 8; ++k)
            e[2 + k] = io.word();
        const uint32_t room = data_size - off - 40;
        // Same limits as the layout check: len fits 32 bits (no wrap rounding to 8) and the padded payload fits the section.
        if (hi != 0 || lo < 32) return off + 40;
        const uint32_t len = lo - 32;
        const uint32_t padded = (len + 7) & ~uint32_t{7};
        if (padded > room) return off + 40;
        w32* payload = e + 10;
        uint32_t words = padded / 4;
        if (len > 32 && (off >> 3) < n_bits) {
            if (io.verify(payload, len, e + 2))
                bits[off >> 8] |= uint32_t{1} << ((off >> 3) & 31);
            // The hash took ceil(len / 4) words, one short of the padding when len mod 8 is 1..4.
            payload += (len + 3) / 4;
            words -= (len + 3) / 4;
        }
        for (uint32_t k = 0; k < words; ++k)
            payload[k] = io.word();
        off += 40 + padded;
    }
    return off;
}

/// Reads the first @p full_words words to dst (8-aligned), hashing code-store payloads if the input is a flat bundle the loaders' checks accept (then @p handshake and @p bits are set; @p bits must start zeroed); never reads past @p full_words.
template <class Io>
void read_input_words(Io& io, uint32_t* dst, size_t full_words, CodeStoreVerified& handshake,
                      uint32_t* bits, uint32_t n_bits) {
    const uint64_t limit = uint64_t{full_words} * 4;
    size_t pos = 0;
    auto read_to = [&](uint64_t end_bytes) {
        const size_t end = static_cast<size_t>(end_bytes / 4);
        if (end > pos) io.read(dst + pos, end - pos);
        pos = end;
    };
    auto read_rest = [&] { read_to(limit); };
    typedef uint32_t __attribute__((may_alias)) w32;
    auto word_at = [&](uint64_t byte_off) {
        return reinterpret_cast<const w32*>(dst)[byte_off / 4];
    };

    if (limit < kBundleHeaderEnd) return read_rest();
    read_to(kBundleHeaderEnd);
    const uint64_t direct_state_off = word_at(kEnvelopeSize + offsetof(FlatBundleHeader, direct_state_off));
    if (word_at(0) != kInputMagicMFBD || word_at(4) != kInputVersionMFBD ||
        word_at(8) != 1 || word_at(12) != 0 ||
        word_at(kEnvelopeSize) != kFlatBundleMagic ||
        word_at(kEnvelopeSize + 4) != kFlatBundleVersion ||
        direct_state_off % 8 != 0 || direct_state_off < sizeof(FlatBundleHeader))
        return read_rest();

    const uint64_t meta = kEnvelopeSize + direct_state_off;
    if (meta + kPreStateMetaSize > limit) return read_rest();
    read_to(meta + kPreStateMetaSize);
    const uint64_t code_store_off = word_at(meta + offsetof(PreStateMeta, code_store_offset));
    const uint64_t code_store_size = word_at(meta + offsetof(PreStateMeta, code_store_size));
    if (word_at(meta) != kMagic || word_at(meta + 4) != kVersion ||
        code_store_off % 8 != 0 || code_store_off < kPreStateMetaSize ||
        code_store_size < kMphfHeaderSize)
        return read_rest();

    const uint64_t store = meta + code_store_off;
    if (store + kMphfHeaderSize > limit) return read_rest();
    read_to(store + kMphfHeaderSize);
    const uint64_t data_off = word_at(store + offsetof(MphfMapHeader, data_offset));
    const uint64_t data_size = word_at(store + offsetof(MphfMapHeader, data_size));
    if (word_at(store) != kMphfCodeStoreMagic || word_at(store + 4) != kMphfMapVersion ||
        word_at(store + 8) == 0 || data_off % 8 != 0 || data_off < kMphfHeaderSize ||
        data_off + data_size > code_store_size || store + data_off + data_size > limit)
        return read_rest();

    const uint64_t data = store + data_off;
    read_to(data);
    uint32_t* const data_words = dst + data / 4;
    const uint32_t read = read_code_store(io, data_words, static_cast<uint32_t>(data_size), bits, n_bits);
    pos += read / 4;
    read_rest();
    if (data_size >= 8)
        handshake = {reinterpret_cast<const uint8_t*>(data_words), static_cast<uint32_t>(data_size), bits, n_bits};
}

}  // namespace zilkworm::code_store_stream
