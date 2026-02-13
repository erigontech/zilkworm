// Copyright The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Lightweight sys_println / sys_print for the Airbender prover guest.
// Communicates via the CSR-based "QuasiUART" protocol (no ebreak, no heap).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace airbender_print_detail {

inline void csr_write_word(uint32_t value) {
    asm volatile("csrrw x0, 0x7C0, %0" :: "r"(value) : "memory");
}

inline uint32_t pack_le_u32(const uint8_t b[4]) {
    return static_cast<uint32_t>(b[0])
         | (static_cast<uint32_t>(b[1]) << 8)
         | (static_cast<uint32_t>(b[2]) << 16)
         | (static_cast<uint32_t>(b[3]) << 24);
}

inline void write_str(const char* data, size_t len) {
    constexpr uint32_t kHelloMarker = 0xFFFFFFFFu;
    // Entry sequence
    csr_write_word(kHelloMarker);
    size_t words = (len + 3) / 4;
    csr_write_word(static_cast<uint32_t>(words + 1));
    csr_write_word(static_cast<uint32_t>(len));

    // Body – 4 bytes at a time
    uint8_t buf[4] = {};
    size_t buf_len = 0;
    for (size_t i = 0; i < len; ++i) {
        buf[buf_len++] = static_cast<uint8_t>(data[i]);
        if (buf_len == 4) {
            csr_write_word(pack_le_u32(buf));
            buf_len = 0;
        }
    }
    // Flush tail
    if (buf_len > 0) {
        for (size_t i = buf_len; i < 4; ++i) buf[i] = 0;
        csr_write_word(pack_le_u32(buf));
    }
}

} // namespace airbender_print_detail

inline void sys_print(const char* msg) {
    size_t len = 0;
    while (msg[len]) ++len;
    airbender_print_detail::write_str(msg, len);
}

inline void sys_println(const char* msg) {
    sys_print(msg);
    sys_print("\n");
}

inline void sys_println(std::string_view s) {
    airbender_print_detail::write_str(s.data(), s.size());
    sys_print("\n");
}
