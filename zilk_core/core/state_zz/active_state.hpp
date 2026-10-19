// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Compile-time choice of the read-side state backend (DirectState by default).
// See docs/hashstate.md, "Backend selection".

#pragma once

namespace zilkworm {

// Defined in direct_state.hpp / hash_state.hpp respectively. Forward-declared here so
// the ActiveState alias (and GridMPT's default template argument) need no complete type.
class DirectState;
class HashState;

#ifdef Z6M_HASH_STATE
using ActiveState = HashState;
#else
using ActiveState = DirectState;
#endif

// evmone per-transaction read view over the active backend, selected like ActiveState.
// See docs/hashstate.md, "Per-transaction state view".
class DirectStateView;
class HashStateView;

#ifdef Z6M_HASH_STATE
using ActiveStateView = HashStateView;
#else
using ActiveStateView = DirectStateView;
#endif

// Whether the trie fold keeps the pre-value / read-only check for backend S.
// See docs/hashstate.md, "Pre-value check trait".
template <class S>
inline constexpr bool state_keeps_prevalue_check = true;

}  // namespace zilkworm
