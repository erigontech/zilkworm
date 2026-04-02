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
set(TESTS_DIR "" CACHE PATH "Directory containing external Execution Spec tests (JSON)")
if(TESTS_DIR)
    if(NOT BUILD_TESTING)
        message(FATAL_ERROR "To enable state transition tests, please enable testing (e.g., -DBUILD_TESTING=ON)")
    endif()

    include(CTest)

    # Get paths relative to build directory for relocatable tests
    file(RELATIVE_PATH TESTS_DIR_REL "${CMAKE_CURRENT_BINARY_DIR}" "${TESTS_DIR}")

    file(GLOB_RECURSE STATE_TRANSITION_TESTS CONFIGURE_DEPENDS "${TESTS_DIR}/*.json")

    foreach(TEST_JSON ${STATE_TRANSITION_TESTS})
        file(RELATIVE_PATH TEST_REL_PATH "${TESTS_DIR}" "${TEST_JSON}")
        file(RELATIVE_PATH TEST_JSON_REL "${CMAKE_CURRENT_BINARY_DIR}" "${TEST_JSON}")
        set(TEST_NAME "state_transition/${TEST_REL_PATH}")

        # Create a unique directory for this test to avoid file conflicts
        string(REPLACE "/" "_" TEST_DIR_NAME "${TEST_REL_PATH}")
        string(REPLACE ".json" "" TEST_DIR_NAME "${TEST_DIR_NAME}")
        set(TEST_WORK_DIR "${CMAKE_CURRENT_BINARY_DIR}/test_runs/${TEST_DIR_NAME}")
        file(MAKE_DIRECTORY "${TEST_WORK_DIR}")

        # Calculate paths relative to the test working directory
        file(RELATIVE_PATH Z6M_REL "${TEST_WORK_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/z6m_debug")
        file(RELATIVE_PATH TEST_JSON_FROM_WORK "${TEST_WORK_DIR}" "${TEST_JSON}")

        # Generate a test runner script to avoid quoting issues
        set(TEST_SCRIPT "${TEST_WORK_DIR}/run_test.sh")
        file(WRITE "${TEST_SCRIPT}" "#!/bin/bash\n")
        file(APPEND "${TEST_SCRIPT}" "set -e\n")
        file(APPEND "${TEST_SCRIPT}" "N=$(wc -c < '${TEST_JSON}')\n")
        file(APPEND "${TEST_SCRIPT}" "{ printf \"1 %u\\n\" $N; cat '${TEST_JSON}'; } > stdin_payload.bin\n")
        file(APPEND "${TEST_SCRIPT}" "exec ${QEMU_SYSTEM} -M virt -m 2G -display none -bios '${CMAKE_CURRENT_BINARY_DIR}/z6m_debug' -monitor none -serial none -chardev file,id=shlog,path=semihost.log -semihosting-config enable=on,target=native,chardev=shlog\n")
        file(CHMOD "${TEST_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

        add_test(
            NAME ${TEST_NAME}
            COMMAND "${TEST_SCRIPT}"
            WORKING_DIRECTORY "${TEST_WORK_DIR}"
        )
        set_tests_properties(${TEST_NAME} PROPERTIES SKIP_RETURN_CODE 2)
    endforeach()
endif()
