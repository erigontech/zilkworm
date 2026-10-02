# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# ZisK guest toolchain (rv64im bare-metal).
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv64)

set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)
set(CMAKE_AR           riscv-none-elf-ar)
set(CMAKE_RANLIB       riscv-none-elf-ranlib)

set(BUILD_SHARED_LIBS OFF)

# ZisK v1.3: Zba/Zbb/Zbs/Zbkb native; no A/C.
set(ZISK_MARCH "rv64im_zicsr_zba_zbb_zbs_zbkb" CACHE STRING "Guest -march")
# ROM/RAM lie beyond medlow's range.
set(arch_flags   "-march=${ZISK_MARCH} -mabi=lp64 -mcmodel=medany")
set(common_flags "${arch_flags} -ffunction-sections -fdata-sections -fno-PIC -fno-asynchronous-unwind-tables -fno-unwind-tables")
set(opt_flags    "-O3 -DNDEBUG -fno-stack-protector")
set(no_cxx       "-fno-exceptions -fno-rtti -fno-threadsafe-statics")

set(CMAKE_C_FLAGS   "${common_flags} ${opt_flags}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${common_flags} ${opt_flags} ${no_cxx}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${arch_flags}" CACHE STRING "" FORCE)

# Make opt_flags the sole optimization source.
set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

# Disable features not available on bare-metal
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL OFF CACHE BOOL "" FORCE)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
