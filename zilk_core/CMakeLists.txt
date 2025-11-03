# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# project(silkworm LANGUAGES CXX)

if(SP1)
    add_compile_definitions(-DSP1)
    include_directories(${CMAKE_SOURCE_DIR}/../guest_program/src/include)
endif()

if(QEMU_DEBUG)
    add_compile_definitions(-DQEMU_DEBUG)
    include_directories(${CMAKE_SOURCE_DIR}/../debug_build/src/include)
endif()


# Silkworm itself
add_subdirectory(core)
add_subdirectory(dev)

if(SILKWORM_WASM_API)
    add_subdirectory(wasm)
endif()
