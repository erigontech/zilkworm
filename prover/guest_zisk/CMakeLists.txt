# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

set(Z6M_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")
set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/zisk.ld")

include(${Z6M_ROOT}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release)

project(z6m_guest_zisk C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ZISK "Build for the ZisK zkVM" ON)
option(Z6M_ZISK_HEAP_STATS "Print heap high-water at exit" OFF)

add_compile_definitions(ZISK NO_THREAD_LOCAL)

include(GNUInstallDirs)

set(SILKWORM_MAIN_DIR "${Z6M_ROOT}")

set(SW_BIN "${CMAKE_BINARY_DIR}/zilkworm")

add_subdirectory("${Z6M_ROOT}/third_party" "${SW_BIN}/third_party")

add_subdirectory("${Z6M_ROOT}/zilk_core"   "${SW_BIN}/zilk_core")

add_executable(z6m_guest
    src/zisk_entrypoint.S
    src/zisk_runtime.cpp
    src/main.cpp
    src/runtime_stubs.c
)

target_include_directories(z6m_guest PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${Z6M_ROOT}/third_party/evmone/lib"
    "${Z6M_ROOT}/third_party/evmone/lib/evmone_precompiles"
)

if(Z6M_ZISK_HEAP_STATS)
    target_compile_definitions(z6m_guest PRIVATE Z6M_ZISK_HEAP_STATS)
endif()

target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nostartfiles
    -T${LINKER_SCRIPT}
    -Wl,-z,norelro
    -Wl,--gc-sections
    -Wl,-e,_start
    # Keep PROVIDEd map symbols for postlink checks.
    -Wl,--require-defined=_general_registers_data_start
    -Wl,--require-defined=_output_data_start
)
set_target_properties(z6m_guest PROPERTIES LINK_DEPENDS ${LINKER_SCRIPT})

# -nostdlib skips the multilib sysroot dirs.
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

target_link_libraries(z6m_guest PRIVATE
    silkworm_dev
    silkworm_core
    evmone
    blst::blst
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

find_package(Python3 COMPONENTS Interpreter REQUIRED)

add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/zisk_postlink.py $<TARGET_FILE:z6m_guest>
    COMMENT "ZisK post-link: ebreak->halt rewrite, layout checks"
)
