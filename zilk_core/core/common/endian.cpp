// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "endian.hpp"

#include <zilk_core/core/common/util.hpp>

// The Airbender guest is single-threaded bare metal, where thread_local goes through emulated TLS
// (a call to __emutls_get_address) on every use.
#if defined(AIRBENDER)
#define ZILK_ENDIAN_SCRATCH static
#else
#define ZILK_ENDIAN_SCRATCH thread_local
#endif

namespace silkworm::endian {

ByteView to_big_compact(const uint64_t value) {
    if (!value) {
        return {};
    }
    // thread_local: caller gets ByteView into per-thread scratch.
    alignas(8) ZILK_ENDIAN_SCRATCH uint8_t full_be[sizeof(uint64_t)];
    store_big_u64(&full_be[0], value);
    return zeroless_view(full_be);
}

ByteView to_big_compact(const intx::uint256& value) {
    if (!value) {
        return {};
    }
    alignas(8) ZILK_ENDIAN_SCRATCH uint8_t full_be[sizeof(intx::uint256)];
    intx::be::store(full_be, value);
    return zeroless_view(full_be);
}

}  // namespace silkworm::endian
