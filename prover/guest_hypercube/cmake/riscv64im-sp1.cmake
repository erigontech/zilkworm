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
# SP1 charges one cycle per instruction retired, so the only optimizations that
# pay here are the ones that remove instructions. GCC's inlining defaults trade
# instruction count away for compile time and I-cache pressure, neither of which
# this target has, so they are widened (defaults: inline-unit-growth 40,
# max-inline-insns-auto 30, large-function-growth 100 -- each roughly doubled,
# deliberately modest since -flto showed maximum inlining loses badly here).
# Measured -2.298% guest cycles on the 200-block corpus; see the commit message
# for the full flag sweep.
#
# -mtune=size swaps GCC's RISC-V cost table (optimize_size_tune_info) for
# rocket's default. The two differ only in int_mul 4->1, int_div 33/65->1,
# branch_cost 3->1, memory_cost 5->2 and slow_unaligned_access true->false.
# Rocket's model is wrong for this target: pricing `mul` at four instructions
# makes GCC strength-reduce multiply-by-constant into shift/add chains, which
# costs MORE retired instructions and therefore more cycles here.
#
# -mstrict-align is REQUIRED, not cosmetic. It is the one field we must not
# take from the size table: without it GCC merges byte sequences into a 64-bit
# `ld` on pointers it cannot prove aligned, and SP1's executor rejects
# unaligned doubleword loads outright -- the guest builds cleanly and then
# panics on every block with
#   LD must be aligned to 8 bytes (base=0x1c0000004f, offset=0x10)
# Against the default tune -mstrict-align is a no-op (rocket is already
# strict), so it costs nothing and only cancels that one field.
#
# Measured -0.340% guest cycles / -0.085% prover gas on the 200-block corpus,
# better on 200/200 blocks, with gas_used and syscall_count byte-identical.
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
