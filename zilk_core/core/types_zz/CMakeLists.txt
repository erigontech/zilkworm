# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0
#
# zilk_core/core/types_zz/ — flat reinterpret_cast'able POD types that pair with
# the FlatBundle wire format. Entries (Account) live in the top-level
# `zilkworm::` namespace. Compiled as a regular library so it can carry .cpp
# implementations; consumed PUBLIC from silkworm_core.
#
# Also hosts the witness reader (witness_input.hpp) and witness-trie walker
# (witness_trie.{hpp,cpp}) — peers of the core trie/rlp code they consume,
# moved here from dev/witness to fix a core→dev layering inversion. Their
# out-of-line deps (rlp::decode, keccak) resolve at final-executable link the
# same way flat_bundle.cpp's do, so no silkworm_core link edge is needed here.

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

# silkworm_core cannot be linked here (circular); its header-only include path suffices for account.cpp.
silkworm_library(silkworm_types_zz
  PUBLIC evmc evmone intx::intx magic_enum::magic_enum nlohmann_json::nlohmann_json
)

target_compile_features(silkworm_types_zz PUBLIC cxx_std_23)

# ODR: PUBLIC so every dependent TU agrees.
if(USE_HASH_KEY)
  target_compile_definitions(silkworm_types_zz PUBLIC USE_HASH_KEY=1)
endif()
