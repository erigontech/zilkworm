# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# please keep the list sorted
add_subdirectory(blst)
add_subdirectory(ethash)
add_subdirectory(gmp)
add_subdirectory(intx) # depends on gmp
add_subdirectory(libff) # depends on gmp
add_subdirectory(secp256k1)

add_subdirectory(evmone) # depends on ethash, intx
