// Airbender zkVM CSR interface — reading the input blob.
#pragma once

#include <cstddef>
#include <cstdint>
#include <new>
#include <utility>

#include <evmone_precompiles/keccak.h>
#include <zilk_core/core/state_zz/code_store_stream.hpp>

#include "airbender_csr.hpp"

namespace airbender {

namespace detail {

/// The next @p n words of the input to @p dst.
///
/// Blocks of 64 words: the copy is a CSR read and a store per word, so -funroll-loops's 8-word
/// body spent a quarter more on the loop counter and branch (2.25 instructions a word, for the
/// multi-megabyte witness); unrolled by 64 it is 2.03. Out of line, as the reader calls it from
/// several places and the unrolled body is 130 instructions.
[[gnu::noinline]] inline void read_words(uint32_t* dst, size_t n) {
    // Pointers, not an index: with both, GCC kept a copy of the index too, 4 instructions of
    // loop control per block instead of 2.
    uint32_t* const bulk_end = dst + (n & ~size_t{63});
    for (; dst != bulk_end; dst += 64)
    {
#pragma GCC unroll 64
        for (size_t k = 0; k < 64; ++k)
            dst[k] = csr_read_word();
    }
    for (n &= 63; n != 0; --n)
        *dst++ = csr_read_word();
}

/// The words of the input as zilkworm::code_store_stream reads them.
struct InputWords {
    uint32_t word() { return csr_read_word(); }
    void read(uint32_t* dst, size_t n) { read_words(dst, n); }
    bool verify(uint32_t* dst, uint32_t size, const uint32_t* key) {
        return ethash_keccak256_read_verify(dst, size, key) != 0;
    }
};

/// One bit per 8 bytes of the code store's data section, up to 16 MiB of it (the largest of the
/// 200-block corpus is 6.7 MiB): a payload larger than that is hashed by sanitize() as before.
/// Zero-initialized, so it is .bss, which costs nothing at startup: Airbender RAM starts zeroed.
inline constexpr uint32_t kCodeStoreBits = 1u << 21;
inline uint32_t code_store_bits[kCodeStoreBits / 32];

}  // namespace detail

/// Read input blob from CSR non-determinism oracle.
/// Protocol: first word = byte count, then ceil(n/4) LE words.
///
/// The code store's payloads are hashed as they are read, where the blob is a flat bundle of the
/// layout the guest knows, see zilkworm::code_store_stream: the result is the same bytes either way.
inline std::pair<uint8_t*, size_t> read_input_from_csr()
{
    uint32_t num_bytes = csr_read_word();
    uint8_t* buf = static_cast<uint8_t*>(::operator new(num_bytes));
    uint32_t* dst = reinterpret_cast<uint32_t*>(buf);

    size_t full_words = num_bytes / 4;
    detail::InputWords words;
    zilkworm::code_store_stream::read_input_words(
        words, dst, full_words, zilkworm::g_code_store_verified, detail::code_store_bits,
        detail::kCodeStoreBits);

    size_t written = full_words * 4;
    if (written < num_bytes) {
        uint32_t word = csr_read_word();
        uint8_t* tail = buf + written;
        while (written < num_bytes) {
            *tail++ = static_cast<uint8_t>(word & 0xFFu);
            word >>= 8;
            ++written;
        }
    }
    return {buf, num_bytes};
}

}  // namespace airbender
