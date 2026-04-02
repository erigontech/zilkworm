// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ecdsa.h"

#if EVMONE_PRECOMPILES_LIBSECP256K1
#include <cstring>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <evmone_precompiles/keccak.hpp>

bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id) {
    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_static, &sig, signature, recovery_id != 0 ? 1 : 0) != 1)
        return false;

    secp256k1_pubkey pk;
    if (secp256k1_ecdsa_recover(secp256k1_context_static, &pk, &sig, message) != 1)
        return false;

    uint8_t pubkey_buf[65];
    size_t pubkey_len = sizeof(pubkey_buf);
    secp256k1_ec_pubkey_serialize(
        secp256k1_context_static, pubkey_buf, &pubkey_len, &pk, SECP256K1_EC_UNCOMPRESSED);

    // keccak256(uncompressed_pubkey[1..65]) → take last 20 bytes as address
    const auto h = ethash::keccak256(pubkey_buf + 1, 64);
    std::memcpy(out, &h.bytes[12], 20);
    return true;
}

#else
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
#endif
