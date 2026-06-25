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

# account.{hpp,cpp} pulls evmc (for evmc::bytes32 / evmc::address types in the
# Account API surface) and intx (for the slow RLP re-encode path). Bytes,
# kHashLength, endian::to_big_compact, and rlp::* come from silkworm_core
# headers, but the .cpp consumes them with explicit include paths under
# zilk_core/core/, so silkworm_core must be available — however we can't link
# silkworm_core here without circular deps. Account's cpp only includes
# headers from silkworm_core that are themselves header-only-or-template
# (bytes.hpp / base.hpp / endian.hpp / rlp/encode.hpp), so the include path
# alone (PUBLIC -I${SILKWORM_MAIN_DIR}, set by silkworm_library) suffices.
silkworm_library(silkworm_types_zz
  PUBLIC evmc evmone intx::intx magic_enum::magic_enum nlohmann_json::nlohmann_json
)

target_compile_features(silkworm_types_zz PUBLIC cxx_std_23)
