# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Cross-compilation toolchain for SP1 zkVM guest (rv64im bare-metal).
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)

set(BUILD_SHARED_LIBS OFF)

set(common_flags "-march=rv64im -mabi=lp64 -ffunction-sections -fdata-sections -fno-PIC")
set(opt_flags    "-O3 -DNDEBUG -fno-stack-protector -fno-builtin-trap")
set(no_cxx       "-fno-exceptions -fno-rtti -fno-threadsafe-statics")

set(CMAKE_C_FLAGS   "${common_flags} ${opt_flags}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${common_flags} ${opt_flags} ${no_cxx}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${common_flags}" CACHE STRING "" FORCE)

# Override CMake's default Release flags (-O3 -DNDEBUG) so that the opt_flags
# above are the sole source of optimization level.
set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

# Disable features not available on bare-metal
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL OFF CACHE BOOL "" FORCE)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
