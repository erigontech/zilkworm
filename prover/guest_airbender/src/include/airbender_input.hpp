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

/// Copies the next @p n words in out-of-line blocks of 64; stores go through a may_alias type because the guest reads the same bytes through witness record fields.
[[gnu::noinline]] inline void read_words(uint32_t* dst_, size_t n) {
    typedef uint32_t __attribute__((may_alias)) w32;
    w32* dst = reinterpret_cast<w32*>(dst_);
    // Pointers rather than an index: GCC otherwise keeps both, doubling loop control.
    w32* const bulk_end = dst + (n & ~size_t{63});
    for (; dst != bulk_end; dst += 64)
    {
#pragma GCC unroll 64
        for (size_t k = 0; k < 64; ++k)
            dst[k] = csr_read_word();
    }
    for (n &= 63; n != 0; --n)
        *dst++ = csr_read_word();
}

struct InputWords {
    uint32_t word() { return csr_read_word(); }
    void read(uint32_t* dst, size_t n) { read_words(dst, n); }
    bool verify(ethash_w32* dst, uint32_t size, const ethash_w32* key) {
        return ethash_keccak256_read_verify(dst, size, key) != 0;
    }
};

/// One bit per 8 bytes of the code store's data section, up to 16 MiB (larger payloads are hashed by sanitize()); .bss, as RAM starts zeroed.
inline constexpr uint32_t kCodeStoreBits = 1u << 21;
inline uint32_t code_store_bits[kCodeStoreBits / 32];

}  // namespace detail

/// Reads the input blob from the CSR oracle (first word = byte count, then ceil(n/4) LE words), hashing code-store payloads as they are read; the bytes are the same either way.
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
