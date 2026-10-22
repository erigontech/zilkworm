# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Cross-compilation toolchain for SP1 Turbo zkVM guest (rv32im bare-metal).
# Mirrors prover/guest_hypercube/cmake/riscv64im-sp1.cmake; the baseline keeps
# the flags of the pre-refactor guest_turbo build.rs (the old build's -Os was
# overridden by the Release profile's -O3, so the effective level is -O3).
# The hypercube toolchain's measured tuning flags (mtune=size, widened inline
# params) are kept next to them, ready to flip on once measured for rv32.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CMAKE_C_COMPILER   riscv32-unknown-elf-gcc)
set(CMAKE_CXX_COMPILER riscv32-unknown-elf-g++)
set(CMAKE_ASM_COMPILER riscv32-unknown-elf-gcc)
set(CMAKE_AR           riscv32-unknown-elf-ar)
set(CMAKE_RANLIB       riscv32-unknown-elf-ranlib)

set(BUILD_SHARED_LIBS OFF)

set(common_flags "-march=rv32im -mabi=ilp32 -mcmodel=medany -ffunction-sections -fdata-sections -ftls-model=local-exec")
set(opt_flags    "-O3 -DNDEBUG -fno-stack-protector")
set(no_cxx       "-fno-exceptions -fno-rtti")

# Tuned flag set from the rv64 guest (measured there; unmeasured on rv32):
#   -funroll-loops --param inline-unit-growth=100 --param max-inline-insns-auto=60
#   --param large-function-growth=200 -mtune=size -mstrict-align

set(CMAKE_C_FLAGS   "${common_flags} ${opt_flags}" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS "${common_flags} ${opt_flags} ${no_cxx}" CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS "${common_flags}" CACHE STRING "" FORCE)

set(CMAKE_C_FLAGS_RELEASE   "" CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELEASE "" CACHE STRING "" FORCE)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable features not available on bare-metal
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_WASM_API OFF CACHE BOOL "" FORCE)
set(SILKWORM_USE_MIMALLOC OFF CACHE BOOL "" FORCE)
set(CATCH_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(SILKWORM_CORE_USE_ABSEIL OFF CACHE BOOL "" FORCE)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
