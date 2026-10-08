// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <zilk_core/core/state_zz/active_state.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#ifdef Z6M_HASH_STATE
#include <zilk_core/core/state_zz/hash_state.hpp>
#endif

using ::zilkworm::ActiveState;

namespace silkworm {

// EIP-779: Hardfork Meta: DAO Fork
void transfer_dao_balances(ActiveState& direct);

}  // namespace silkworm
