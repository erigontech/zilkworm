// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <zilk_core/core/state_zz/direct_state.hpp>

using ::zilkworm::DirectState;

namespace silkworm {

// EIP-779: Hardfork Meta: DAO Fork
void transfer_dao_balances(DirectState& direct);

}  // namespace silkworm
