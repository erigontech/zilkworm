// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Compile-time selection of the read-side state backend for the trie fold path.
//
//   * default (Z6M_HASH_STATE undefined) -> ActiveState is DirectState, so the
//     default build is byte/behaviour-identical to today.
//   * Z6M_HASH_STATE defined             -> ActiveState is HashState (the SSZ/slib
//     input path).
//
// The selection is a plain type alias: there is NO runtime polymorphism. GridMPT
// takes the backend as a defaulted template parameter (mpt.hpp), so each build is
// fully monomorphic and every find_node_rlp seam stays inlined.
//
// Only forward declarations live here to keep the header light — pulling the heavy
// direct_state.hpp / hash_state.hpp into every trie TU is exactly what we avoid.

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

// Does the trie fold keep the pre-value / read-only check for this backend?
//
// DirectState (and any un-specialised backend) => yes: the DirectState update set
// carries initial_value and read-only entries, and calc_root_from_updates binds the
// pre-value and short-circuits read-only keys.
//
// HashState specialises this to false in hash_state.hpp: its update set carries no
// initial_value and no read-only entries (reads are already bound to prev_root at
// derive time), so the check must be compiled out of the fold.
//
// Kept here as a tiny trait — with the primary defaulting to true — so mpt.hpp and
// grid_mpt.cpp need NO hard dependency on hash_state.hpp (or on direct_state.hpp) to
// decide it: the DirectState build never has to see HashState at all.
template <class S>
inline constexpr bool state_keeps_prevalue_check = true;

}  // namespace zilkworm
