// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <intx/intx.hpp>

namespace silkworm {

inline constexpr intx::uint256 kSecp256k1n{
    intx::from_string<intx::uint256>("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")};

inline constexpr intx::uint256 kSecp256k1Halfn{kSecp256k1n >> 1};

bool is_valid_signature(const intx::uint256& r, const intx::uint256& s, bool homestead) noexcept;

}  // namespace silkworm
