// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Compile-time choice of the read-side state backend (DirectState by default).

#pragma once

namespace zilkworm {

class DirectState;
class HashState;

#ifdef Z6M_HASH_STATE
using ActiveState = HashState;
#else
using ActiveState = DirectState;
#endif

// evmone per-transaction read view over the active backend.
class DirectStateView;
class HashStateView;

#ifdef Z6M_HASH_STATE
using ActiveStateView = HashStateView;
#else
using ActiveStateView = DirectStateView;
#endif

// Whether the trie fold keeps the pre-value / read-only check for backend S.
template <class S>
inline constexpr bool state_keeps_prevalue_check = true;

}  // namespace zilkworm
