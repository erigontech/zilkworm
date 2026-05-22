# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

set(Z6M_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

include(${Z6M_ROOT}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

project(SilkwormRVDemo C CXX ASM)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

# ========== Architecture detection ==========
# Detect based on CMAKE_SYSTEM_PROCESSOR set in toolchain file
set(START_ASM "start.S" CACHE STRING "Assembly startup file")
set(QEMU_SYSTEM "qemu-system-riscv32" CACHE STRING "QEMU system emulator")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
  set(ARCH_RV64 TRUE)
  message(STATUS "Building for RISC-V 64-bit (rv64im)")
  if(NOT DEFINED START_ASM OR START_ASM STREQUAL "start.S")
    set(START_ASM "start64.S")
  endif()
  if(NOT DEFINED QEMU_SYSTEM OR QEMU_SYSTEM STREQUAL "qemu-system-riscv32")
    set(QEMU_SYSTEM "qemu-system-riscv64")
  endif()
else()
  set(ARCH_RV64 FALSE)
  message(STATUS "Building for RISC-V 32-bit (rv32im)")
endif()

# QEMU_DEBUG flag — propagates to zilk_core via add_subdirectory
option(QEMU_DEBUG "Enable QEMU debug mode" OFF)

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

add_executable(z6m_debug
    src/sys_getentropy.c
    src/cppextern.cpp
    src/main.cpp
    src/${START_ASM}
    src/sys_sbrk_wrap.c
)

target_include_directories(z6m_debug PRIVATE
    "${Z6M_ROOT}/third_party/evmone/lib"
    "${Z6M_ROOT}/third_party/evmone/lib/evmone_precompiles"
)

target_link_libraries(z6m_debug PRIVATE
    silkworm_dev silkworm_core evmone blst::blst
    stdc++ c gcc nosys
)

target_link_options(z6m_debug PRIVATE
    -Wl,--gc-sections
    -Wl,-Map=${CMAKE_BINARY_DIR}/z6m_debug.map
)

# make all references to _sbrk/_sbrk_r go to our wrappers
target_link_options(z6m_debug PRIVATE
    -Wl,--wrap=_sbrk
    -Wl,--wrap=_sbrk_r
)

target_compile_options(z6m_debug PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-mstrict-align>
    $<$<COMPILE_LANGUAGE:CXX>:-mstrict-align>
)

# ========== CTest / EEST test generation ==========
# `EEST_RLP_DIR` and `EEST_JSON_DIR` are independent; either / both / neither may be set.
set(EEST_RLP_DIR  "" CACHE PATH "Directory of pre-converted batched-RLP EEST fixtures")
set(EEST_JSON_DIR "" CACHE PATH "Directory of raw EEST JSON fixtures")
if(EEST_RLP_DIR OR EEST_JSON_DIR)
    if(NOT BUILD_TESTING)
        message(FATAL_ERROR "To enable state transition tests, please enable testing (e.g., -DBUILD_TESTING=ON)")
    endif()
    include(CTest)
endif()

# Generate a driver script prepending a 1-byte format tag and register one ctest per fixture file.
function(_register_eest_tests label fmt_byte ext fixtures_dir)
    set(script "${CMAKE_CURRENT_BINARY_DIR}/qemu_run_${label}.sh")
    file(WRITE  "${script}" "#!/bin/bash\n")
    file(APPEND "${script}" "set -eo pipefail\n")
    file(APPEND "${script}" "{ printf '${fmt_byte}'; cat \"$1\"; } > stdin_payload.bin\n")
    file(APPEND "${script}" "rm -f semihost.log\n")
    file(APPEND "${script}" "exec ${QEMU_SYSTEM} -M virt -m 2G -display none -bios '${CMAKE_CURRENT_BINARY_DIR}/z6m_debug' -monitor none -serial none -chardev file,id=shlog,path=semihost.log -semihosting-config enable=on,target=native,chardev=shlog\n")
    file(CHMOD "${script}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

    file(GLOB_RECURSE files CONFIGURE_DEPENDS "${fixtures_dir}/*.${ext}")
    foreach(path ${files})
        file(RELATIVE_PATH rel "${fixtures_dir}" "${path}")
        set(test_name "state_transition/${label}/${rel}")
        string(REPLACE "/" "_" dir_name "${label}_${rel}")
        string(REPLACE ".${ext}" "" dir_name "${dir_name}")
        set(work_dir "${CMAKE_CURRENT_BINARY_DIR}/test_runs/${dir_name}")
        file(MAKE_DIRECTORY "${work_dir}")
        add_test(NAME "${test_name}" COMMAND "${script}" "${path}" WORKING_DIRECTORY "${work_dir}")
        set_tests_properties("${test_name}" PROPERTIES SKIP_RETURN_CODE 2)
    endforeach()
endfunction()

if(EEST_RLP_DIR)
    _register_eest_tests(rlp  "R" rlp  "${EEST_RLP_DIR}")
endif()
if(EEST_JSON_DIR)
    _register_eest_tests(json "J" json "${EEST_JSON_DIR}")
endif()
