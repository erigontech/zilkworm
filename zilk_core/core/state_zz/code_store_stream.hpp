// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

// Hashing the code store while the input is read, for the Airbender guest.
//
// The guest takes its input one word at a time from the oracle and sanitize() then hashes every
// code-store payload again from memory: 142M payload words read, and loaded again to be absorbed.
// Here the reader walks the code store's data section as it comes in, and for each payload over 32
// bytes feeds the words to the hash while it stores them, which saves the second load. A payload
// that hashes to the key stored with it is marked in a bitmap, and sanitize() skips the entries
// marked, see CodeStoreVerified. Everything else is read as before and hashed by sanitize().
//
// The reader parses the headers in front of the data section from the words it has stored, with
// the checks the loaders make later, and any doubt means plain reading from that word on: no
// marks, no change in what the guest ends up with in memory, which is the input bytes in every
// case. A mark claims only that the bytes of this very entry hash to the key beside them; whether
// the entry belongs to the witness is up to the loaders, which run on the same memory.

namespace zilkworm::code_store_stream {

// Word-aligned field offsets and sizes of the headers parsed, from the start of the input.
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

/// The words of the input are read in order, each stored at dst[i], through @p io:
///   uint32_t io.word()                                       the next word;
///   void io.read(uint32_t* dst, size_t n)                    the next n words to dst;
///   bool io.verify(uint32_t* dst, uint32_t size, const uint32_t* key)
///                                                            the next ceil(size / 4) words to dst,
///                                                            true if the Keccak-256 of the first
///                                                            size bytes of them equals the 8 words
///                                                            at key.

/// Reads the data section of the code store, data_size bytes at dst (8-byte aligned), which starts
/// with an 8-byte sentinel and goes on with entries [len:u64][key:32][payload][zeros to 8 bytes]
/// where len = 32 + the payload's size. Sets in @p bits (n_bits of them) bit entry_offset / 8 of
/// every entry whose payload hashes to its key. Returns the bytes read, at the entry whose header
/// does not describe an entry of the section, or the end of the data: the rest is the caller's
/// to read.
template <class Io>
uint32_t read_code_store(
    Io& io, uint32_t* dst, uint32_t data_size, uint32_t* bits, uint32_t n_bits) {
    if (data_size < 8) return 0;
    dst[0] = io.word();
    dst[1] = io.word();
    uint32_t off = 8;
    while (data_size - off >= 40) {
        uint32_t* const e = dst + off / 4;
        const uint32_t lo = io.word();
        const uint32_t hi = io.word();
        e[0] = lo;
        e[1] = hi;
        for (size_t k = 0; k < 8; ++k)
            e[2 + k] = io.word();
        const uint32_t room = data_size - off - 40;
        // The same limits the layout check puts on an entry: len fits in 32 bits, which leaves
        // the rounding to 8 bytes no wrap, and the padded payload fits in the section. The words
        // are stored, so that the reader goes on from here.
        if (hi != 0 || lo < 32) return off + 40;
        const uint32_t len = lo - 32;
        const uint32_t padded = (len + 7) & ~uint32_t{7};
        if (padded > room) return off + 40;
        uint32_t* payload = e + 10;
        uint32_t words = padded / 4;
        // A payload of 32 bytes or less is left to sanitize(), whose hashing of it is memoized.
        if (len > 32 && (off >> 3) < n_bits) {
            if (io.verify(payload, len, e + 2))
                bits[off >> 8] |= uint32_t{1} << ((off >> 3) & 31);
            // The hash took ceil(len / 4) words, which is one short of the padding when len mod 8
            // is 1 to 4.
            payload += (len + 3) / 4;
            words -= (len + 3) / 4;
        }
        for (uint32_t k = 0; k < words; ++k)
            payload[k] = io.word();
        off += 40 + padded;
    }
    return off;
}

/// Reads the first @p full_words words of the input to dst (8-byte aligned), hashing the code
/// store's payloads on the way if the input is a flat bundle of the layout the guest knows: one
/// bundle, and headers down to the code store's that pass the checks of the loaders. @p handshake
/// then holds the data section and @p bits, for sanitize(); on any other input it is left as it
/// was. @p bits must start zeroed. Parses forward only, and never reads a word past @p full_words.
template <class Io>
void read_input_words(Io& io, uint32_t* dst, size_t full_words, CodeStoreVerified& handshake,
                      uint32_t* bits, uint32_t n_bits) {
    const uint64_t limit = uint64_t{full_words} * 4;
    size_t pos = 0;  // Words read.
    auto read_to = [&](uint64_t end_bytes) {
        const size_t end = static_cast<size_t>(end_bytes / 4);
        if (end > pos) io.read(dst + pos, end - pos);
        pos = end;
    };
    auto read_rest = [&] { read_to(limit); };
    auto word_at = [&](uint64_t byte_off) { return dst[byte_off / 4]; };

    // The MFBD envelope and the flat bundle header: one bundle, which starts right after.
    if (limit < kBundleHeaderEnd) return read_rest();
    read_to(kBundleHeaderEnd);
    const uint64_t direct_state_off = word_at(kEnvelopeSize + offsetof(FlatBundleHeader, direct_state_off));
    if (word_at(0) != kInputMagicMFBD || word_at(4) != kInputVersionMFBD ||
        word_at(8) != 1 || word_at(12) != 0 ||
        word_at(kEnvelopeSize) != kFlatBundleMagic ||
        word_at(kEnvelopeSize + 4) != kFlatBundleVersion ||
        direct_state_off % 8 != 0 || direct_state_off < sizeof(FlatBundleHeader))
        return read_rest();

    // The pre-state header, at the direct state, the code store's behind it.
    const uint64_t meta = kEnvelopeSize + direct_state_off;
    if (meta + kPreStateMetaSize > limit) return read_rest();
    read_to(meta + kPreStateMetaSize);
    const uint64_t code_store_off = word_at(meta + offsetof(PreStateMeta, code_store_offset));
    const uint64_t code_store_size = word_at(meta + offsetof(PreStateMeta, code_store_size));
    if (word_at(meta) != kMagic || word_at(meta + 4) != kVersion ||
        code_store_off % 8 != 0 || code_store_off < kPreStateMetaSize ||
        code_store_size < kMphfHeaderSize)
        return read_rest();

    // The code store's header: the data section lies behind it, inside the code store and the input.
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
