# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# riscv32im-toolchain.cmake
set(CMAKE_SYSTEM_NAME Generic)        # No OS (bare-metal target)
set(CMAKE_SYSTEM_PROCESSOR riscv32)   # Target CPU architecture

set(CMAKE_C_COMPILER   riscv32-unknown-elf-gcc)
set(CMAKE_CXX_COMPILER riscv32-unknown-elf-g++)
set(CMAKE_ASM_COMPILER riscv32-unknown-elf-gcc)


# set(GMP_LIBRARY "${CMAKE_SOURCE_DIR}/../prelibs/gmp")
# set(GMP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../prelibs/gmp")
set(BUILD_SHARED_LIBS "OFF")

# set(debug_flags "-Os")
set(debug_flags "-Og -ggdb3")
set(common_flags "-march=rv32im -mabi=ilp32 -mcmodel=medany -ffunction-sections -fdata-sections -fPIC") #"-ffreestanding"
set(CMAKE_C_FLAGS "${common_flags} -D_GLIBCXX_HAS_GTHREADS=0")
set(CMAKE_CXX_FLAGS "${common_flags} ${debug_flags} -fno-exceptions -fno-rtti -fno-threadsafe-statics ")  # "-nostdlib"


set(BUILD_TESTING OFF CACHE BOOL "Disable Silkworm tests")
set(SILKWORM_WASM_API OFF CACHE BOOL "No WASM for bare-metal")

set(LIBFF_WITH_GMP "OFF")
set(CATCH_BUILD_TESTING "OFF")
set(SILKWORM_CORE_USE_ABSEIL "OFF")
set(CMAKE_PREFIX_PATH "${CONAN_INSTALL_FOLDER}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_EXE_LINKER_FLAGS " -T${CMAKE_SOURCE_DIR}/elf-ld-verbose.dump.ld -z norelro") # -nostartfiles"