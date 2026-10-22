// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "endian.hpp"

#include <zilk_core/core/common/util.hpp>

// The Airbender guest is single-threaded bare metal, where thread_local goes through emulated TLS
// (a call to __emutls_get_address) on every use: its runtime never initializes the tp register,
// so a thread_local store lands at TLS offset 0, address 0. The rv64 SP1 guest (hypercube) has a
// working tp, but plain statics are identical
// semantics for every guest (all single-threaded), so gate on any SP1.
#if defined(AIRBENDER) || defined(SP1)
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
