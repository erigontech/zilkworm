// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

constexpr uint64_t num_words(uint64_t num_bytes) noexcept {
    return num_bytes / 32 + static_cast<uint64_t>(num_bytes % 32 != 0);
}

namespace protocol {

    // Both costs depend on the calldata's zero/non-zero split, taken as the non-zero byte count.

    // Intrinsic gas g0 (EIP-3860 initcode metering).
    intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, evmc_revision rev,
                                size_t non_zero_bytes) noexcept;

    // EIP-7623 floor cost (Pectra+).
    uint64_t floor_cost(const UnsignedTransaction& txn, size_t non_zero_bytes) noexcept;

    // Amsterdam (EIP-2780/8037) regular-gas-only intrinsic; mirrors evmone's compute_tx_intrinsic_cost_amsterdam and must not drift.
    struct TxGasCost {
        int64_t regular{0};  // regular-gas component of g0 (EIP-2780/8038)
        int64_t floor{0};    // minimum gas cost (EIP-7623 floor per EIP-7976/7981)
    };
    TxGasCost amsterdam_tx_gas_cost(const Transaction& txn, size_t non_zero_bytes) noexcept;

}  // namespace protocol

}  // namespace silkworm
