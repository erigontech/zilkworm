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

# Profiling build: counters on every SP1 ecall choke point + named runtime syscalls,
# printed to stdout at the end of the run (see src/include/guest_profile.hpp).
option(Z6M_GUEST_PROFILE "Instrument the guest with syscall/work counters (profiling only)" OFF)
if(Z6M_GUEST_PROFILE)
    add_compile_definitions(Z6M_GUEST_PROFILE)
endif()

# Phase-attribution build: emits the SP1 executor's cycle-tracker-report lines around the
# major phases (sanitize / rlp_decode / insert_block / recover_senders / execute_block /
# check_root); the prover prints report.cycle_tracker with Z6M_CYCLE_TRACKER=1.
option(Z6M_PHASE_TRACE "Instrument the guest with cycle-tracker phase markers (profiling only)" OFF)
if(Z6M_PHASE_TRACE)
    add_compile_definitions(Z6M_PHASE_TRACE)
endif()

# Read-side state backend for the guest; set here because the top-level option does not reach
# this separate project. See docs/hashstate.md, "Build flag and test targets".
option(Z6M_HASH_STATE "Build the guest with the HashState/slib (StatelessInputBytes) backend" OFF)
if(Z6M_HASH_STATE)
    add_compile_definitions(Z6M_HASH_STATE)
endif()

include(GNUInstallDirs)

set(SILKWORM_MAIN_DIR "${Z6M_ROOT}")

set(SW_BIN "${CMAKE_BINARY_DIR}/zilkworm")

add_subdirectory("${Z6M_ROOT}/third_party" "${SW_BIN}/third_party")

add_subdirectory("${Z6M_ROOT}/zilk_core"   "${SW_BIN}/zilk_core")

# memcpy, memmove, memset and memcmp, shared with the Airbender guest; here the __wrap_ targets of
# the -Wl,--wrap flags below.
set(MEM_BUILTINS_SRC "${Z6M_ROOT}/prover/guest_common/src/mem_builtins.cpp")

add_executable(z6m_guest
    src/sp1_entrypoint.S
    src/sp1_runtime.cpp
    src/main.cpp
    src/atomic_stubs.c
    ${MEM_BUILTINS_SRC}
)

# -fno-builtin: the copy and fill loops must not become the calls that -Wl,--wrap makes recurse.
# -O3: these are the guest's hot path whatever the build type is set to.
set_source_files_properties(${MEM_BUILTINS_SRC} PROPERTIES COMPILE_OPTIONS "-fno-builtin;-O3")

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
    -Wl,--wrap=memcpy
    -Wl,--wrap=memmove
    -Wl,--wrap=memcmp
    -Wl,--wrap=memset
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

find_program(OBJCOPY riscv-none-elf-objcopy REQUIRED)

add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${OBJCOPY} -O binary
        "$<TARGET_FILE:z6m_guest>" "${CMAKE_BINARY_DIR}/z6m_guest.bin"
    COMMAND ${OBJCOPY} -O binary -j .text
        "$<TARGET_FILE:z6m_guest>" "${CMAKE_BINARY_DIR}/z6m_guest.text"
    COMMENT "Creating binary and text images"
)

# Dev tool: syscall calibration guest (see src/calibration.cpp). Built only when asked;
# run with `z6m_profile_report --elf .../z6m_guest_calib.elf` to measure cycles/syscall.
option(Z6M_CALIBRATION_GUEST "Build the SP1 syscall calibration guest" OFF)
if(Z6M_CALIBRATION_GUEST)
    add_executable(z6m_guest_calib
        src/sp1_entrypoint.S
        src/sp1_runtime.cpp
        src/calibration.cpp
        src/atomic_stubs.c
        ${MEM_BUILTINS_SRC}
    )
    set_source_files_properties(${MEM_BUILTINS_SRC} PROPERTIES COMPILE_OPTIONS "-fno-builtin;-O3")
    target_include_directories(z6m_guest_calib PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
        "${Z6M_ROOT}/third_party/evmone/lib"
        "${Z6M_ROOT}/third_party/evmone/lib/evmone_precompiles"
    )
    target_link_options(z6m_guest_calib PRIVATE
        -nostdlib
        -nostartfiles
        -T${LINKER_SCRIPT}
        -z norelro
        -Wl,--gc-sections
        -Wl,-e,_start
        -Wl,--wrap=memcpy
        -Wl,--wrap=memmove
        -Wl,--wrap=memcmp
        -Wl,--wrap=memset
    )
    target_link_directories(z6m_guest_calib PRIVATE "${_SYSROOT}/lib/${_MULTIDIR}" "${_LIBGCC_DIR}")
    target_link_libraries(z6m_guest_calib PRIVATE evmone stdc++ c m gcc nosys)
    target_compile_options(z6m_guest_calib PRIVATE
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
    set_target_properties(z6m_guest_calib PROPERTIES SUFFIX ".elf" RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()
