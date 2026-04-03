# Copyright 2025 The Zilkworm Authors
# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# project(silkworm LANGUAGES CXX)

if(SP1TURBO)
    add_compile_definitions(-DSP1)
    include_directories(${CMAKE_SOURCE_DIR}/../prover/guest_program/src/include)
endif()

if(SP1)
    add_compile_definitions(-DSP1)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../prover/guest_hypercube/src/include)
endif()

if(QEMU_DEBUG)
    add_compile_definitions(-DQEMU_DEBUG)
    include_directories(${SILKWORM_MAIN_DIR}/qemu_runner/src/include)
endif()

if(AIRBENDER)
    add_compile_definitions(-DAIRBENDER)
    include_directories(${CMAKE_SOURCE_DIR}/zilk_core)
    include_directories(${CMAKE_SOURCE_DIR}/prover/guest_airbender/src/include)
endif()

add_subdirectory(core)
add_subdirectory(dev)

if(SILKWORM_WASM_API)
    add_subdirectory(wasm)
endif()
 