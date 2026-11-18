# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Cross-compilation toolchain for SP1 zkVM guest (rv64im bare-metal).
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)
set(CMAKE_AR           riscv-none-elf-ar)
set(CMAKE_RANLIB       riscv-none-elf-ranlib)

set(BUILD_SHARED_LIBS OFF)

set(common_flags "-march=rv64im -mabi=lp64 -ffunction-sections -fdata-sections -fno-PIC")
# SP1 charges one cycle per retired instruction, so only instruction-removing optimizations pay: GCC's inlining limits are widened (roughly doubled; -flto loses here).
#
# -mtune=size prices a branch, mul and div at one instruction as SP1 does; -mstrict-align is required with it: that cost table allows unaligned access, so GCC merges byte loads into an `ld` that SP1 rejects (LD must be aligned to 8 bytes).
set(opt_flags    "-O3 -DNDEBUG -fno-stack-protector -fno-builtin-trap \
-funroll-loops \
--param inline-unit-growth=100 --param max-inline-insns-auto=60 \
--param large-function-growth=200 \
-mtune=size -mstrict-align")
set(no_cxx       "-fno-exceptions -fno-rtti -fno-threadsafe-statics")

# Not in common_flags: CMAKE_ASM_FLAGS must not force-include a C header.
set(bswap_inc "-include ${CMAKE_CURRENT_LIST_DIR}/../bswap_inline.h")
set(CMAKE_C_FLAGS   "${common_flags} ${opt_flags} ${bswap_inc}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${common_flags} ${opt_flags} ${no_cxx} ${bswap_inc}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${common_flags}" CACHE STRING "" FORCE)

# Release flags are cleared so opt_flags alone set the optimization level.
set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

# Disable features not available on bare-metal
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL OFF CACHE BOOL "" FORCE)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
