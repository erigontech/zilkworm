# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

set(Z6M_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/elf64lriscv.xn")

include(${Z6M_ROOT}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

project(z6m_guest_hypercube C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_definitions(SP1)

include(CableBuildInfo)
cable_add_buildinfo_library(
    PROJECT_NAME zilkworm
    GIT_DESCRIBE ""
    GIT_BRANCH ""
)

include(GNUInstallDirs)

set(SILKWORM_MAIN_DIR "${Z6M_ROOT}")

set(SW_BIN "${CMAKE_BINARY_DIR}/zilkworm")

add_subdirectory("${Z6M_ROOT}/third_party" "${SW_BIN}/third_party")

add_subdirectory("${Z6M_ROOT}/zilk_core"   "${SW_BIN}/zilk_core")

add_executable(z6m_guest
    src/sp1_entrypoint.S
    src/sp1_runtime.cpp
    src/main.cpp
    src/atomic_stubs.c
    src/memcpy.cpp
    src/memmove.cpp
)

target_include_directories(z6m_guest PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${Z6M_ROOT}/third_party/evmone/lib"
    "${Z6M_ROOT}/third_party/evmone/lib/evmone_precompiles"
)

target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nostartfiles
    -T${LINKER_SCRIPT}
    -z norelro
    -Wl,--gc-sections
    -Wl,-e,_start
)

# Library search path: use the toolchain's rv64im/lp64 sysroot libraries.
# With -nostdlib the linker won't search them automatically.
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-sysroot
    OUTPUT_VARIABLE _SYSROOT OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-multi-directory
    OUTPUT_VARIABLE _MULTIDIR OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -march=rv64im -mabi=lp64 -print-libgcc-file-name
    OUTPUT_VARIABLE _LIBGCC_FILE OUTPUT_STRIP_TRAILING_WHITESPACE
)
get_filename_component(_LIBGCC_DIR "${_LIBGCC_FILE}" DIRECTORY)
target_link_directories(z6m_guest PRIVATE "${_SYSROOT}/lib/${_MULTIDIR}" "${_LIBGCC_DIR}")

# Link libraries wrapped in a group to handle circular deps.
target_link_libraries(z6m_guest PRIVATE
    -Wl,--start-group
    silkworm_dev
    silkworm_core
    evmone
    blst::blst
    -Wl,--end-group
    stdc++ c m gcc nosys
)

target_compile_options(z6m_guest PRIVATE
    -fno-asynchronous-unwind-tables
    $<$<COMPILE_LANGUAGE:CXX>:
        -fno-exceptions
        -fno-rtti
        -Wno-unused-parameter
        -Wno-missing-field-initializers
        -Wno-unused-variable
        -Wno-unused-but-set-variable
        -Wno-class-memaccess
        -Wno-ignored-attributes
        -Wno-psabi
        -Wno-narrowing
        -Wno-attributes
        -Wno-register
        -Wno-unused-function
        -Wno-cpp
        -Wno-int-in-bool-context
    >
)

set_target_properties(z6m_guest PROPERTIES
    SUFFIX ".elf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

find_program(OBJCOPY riscv-none-elf-objcopy REQUIRED)

add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${OBJCOPY} -O binary
        "$<TARGET_FILE:z6m_guest>" "${CMAKE_BINARY_DIR}/z6m_guest.bin"
    COMMAND ${OBJCOPY} -O binary -j .text
        "$<TARGET_FILE:z6m_guest>" "${CMAKE_BINARY_DIR}/z6m_guest.text"
    COMMENT "Creating binary and text images"
)
