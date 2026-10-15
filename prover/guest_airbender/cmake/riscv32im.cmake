# Cross-compilation toolchain for Airbender zkVM guest (rv32im bare-metal).
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv32)

set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)

set(BUILD_SHARED_LIBS OFF)

set(common_flags "-march=rv32im_zicsr -mabi=ilp32 -mstrict-align -mcmodel=medany -ffunction-sections -fdata-sections -fno-PIC")
# Airbender, like SP1, counts executed instructions, so the GCC inlining limits are widened the way
# guest_hypercube's riscv64im-sp1.cmake does (#164): defaults inline-unit-growth 40,
# max-inline-insns-auto 30, large-function-growth 100, each roughly doubled. On the 200-block
# mainnet corpus: -2.03% guest cycles, guest image 2.53 MB -> 3.00 MB (of the 4 MiB ROM).
# Builtins stay on so GCC expands fixed-size memcpy/memset/memcmp inline: under -fno-builtin every
# `std::memcpy(&u64, p, 8)` load was a ~35-cycle call, 41M of them per 200 blocks. Loops are still
# never turned into library calls (-fno-tree-loop-distribute-patterns), and src/mem_builtins.c,
# which implements those functions, keeps -fno-builtin. 200-block cycles -2.62%.
# -mbranch-cost=1 prices a conditional branch at one instruction, which is what it costs here,
# instead of the default rocket tuning's three. At three GCC if-converts short branches into
# straight-line sequences and evaluates both sides of && and ||, executing instructions that the
# branch would have skipped. It is the part of the SP1 guest's -mtune=size that carries over: that
# cost table's one-instruction divide makes GCC emit div for signed division by a power of two
# (libstdc++'s sort midpoints) and mulh for signed widening products by a constant, neither of
# which Airbender implements. 200-block cycles -0.18%.
set(opt_flags    "-O3 -DNDEBUG -fno-stack-protector -fno-tree-loop-distribute-patterns -fipa-pta -funroll-loops -flto -flto-partition=one -g -fomit-frame-pointer \
--param inline-unit-growth=100 --param max-inline-insns-auto=60 \
--param large-function-growth=200 \
-mbranch-cost=1")
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
