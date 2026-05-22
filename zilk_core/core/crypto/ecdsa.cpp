// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecdsa.h"

#include <evmone_precompiles/secp256k1.hpp>

bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id) {
    const auto hash = std::span<const uint8_t, 32>{message, 32};
    const auto r_bytes = std::span<const uint8_t, 32>{signature, 32};
    const auto s_bytes = std::span<const uint8_t, 32>{signature + 32, 32};
    const auto opt_address = evmmax::secp256k1::ecrecover(hash, r_bytes, s_bytes,
                                                          recovery_id != 0);
    if (!opt_address) {
        return false;
    }
    std::memcpy(out, opt_address->bytes, 20);
    return true;
}
