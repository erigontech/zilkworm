// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// Yellow Paper Appendix F; EIP-155

#include <optional>

#include <intx/intx.hpp>

namespace silkworm {

struct YParityAndChainId {
    bool odd{false};
    std::optional<intx::uint256> chain_id{std::nullopt};  // EIP-155
};

//! chain_id is always returned unless v is 27 or 28.
std::optional<YParityAndChainId> v_to_y_parity_and_chain_id(const intx::uint256& v) noexcept;

intx::uint256 y_parity_and_chain_id_to_v(bool odd, const std::optional<intx::uint256>& chain_id) noexcept;

}  // namespace silkworm
