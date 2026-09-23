// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

// Words in EVM are 32-bytes long
constexpr uint64_t num_words(uint64_t num_bytes) noexcept {
    return num_bytes / 32 + static_cast<uint64_t>(num_bytes % 32 != 0);
}

namespace protocol {

    // Both costs depend on the calldata's zero/non-zero split, taken as the non-zero byte count.

    // Returns the intrinsic gas of a transaction.
    // Refer to g0 in Section 6.2 "Execution" of the Yellow Paper
    // and EIP-3860 "Limit and meter initcode".
    intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, evmc_revision rev,
                                size_t non_zero_bytes) noexcept;

    // Returns the floor cost (valid since Pectra)
    // Refer to: EIP-7623: Increase calldata cost
    uint64_t floor_cost(const UnsignedTransaction& txn, size_t non_zero_bytes) noexcept;

    // Amsterdam (EIP-2780) resource-based intrinsic gas decomposition.
    // Mirrors evmone's compute_tx_intrinsic_cost_amsterdam
    // (third_party/evmone/test/state/state.cpp); the two must not drift.
    // The intrinsic is regular-gas only: every state-dependent charge (the created
    // account's NEW_ACCOUNT, the per-authorization NEW_ACCOUNT/AUTH_BASE) moved to
    // the top frame with EIP-8037 (EELS #3126).
    struct TxGasCost {
        int64_t regular{0};  // regular-gas component of g0 (EIP-2780/8038)
        int64_t floor{0};    // minimum gas cost (EIP-7623 floor per EIP-7976/7981)
    };
    TxGasCost amsterdam_tx_gas_cost(const Transaction& txn, size_t non_zero_bytes) noexcept;

}  // namespace protocol

}  // namespace silkworm
