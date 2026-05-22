// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <zilk_core/core/state/intra_block_state.hpp>

namespace silkworm {

// EIP-779: Hardfork Meta: DAO Fork
void transfer_dao_balances(IntraBlockState& state);

}  // namespace silkworm
