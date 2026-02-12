set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR riscv32)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER clang CACHE FILEPATH "" FORCE)
set(CMAKE_CXX_COMPILER clang++ CACHE FILEPATH "" FORCE)
set(CMAKE_ASM_COMPILER clang CACHE FILEPATH "" FORCE)

set(RISCV_TRIPLE riscv32-unknown-elf)

# Auto-detect the xPack (or other) riscv-none-elf GCC toolchain for sysroot/headers
find_program(_RISCV_GCC riscv-none-elf-gcc)
if(_RISCV_GCC)
  get_filename_component(_RISCV_BIN "${_RISCV_GCC}" DIRECTORY)
  get_filename_component(RISCV_GCC_ROOT "${_RISCV_BIN}" DIRECTORY)
  set(RISCV_SYSROOT "${RISCV_GCC_ROOT}/riscv-none-elf")

  # Detect GCC version for C++ header paths
  execute_process(
    COMMAND "${_RISCV_GCC}" -dumpversion
    OUTPUT_VARIABLE _RISCV_GCC_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  message(STATUS "Using RISC-V GCC sysroot: ${RISCV_SYSROOT} (GCC ${_RISCV_GCC_VERSION})")
else()
  message(WARNING "riscv-none-elf-gcc not found; stdlib headers may be missing")
endif()

set(COMMON_FLAGS "-target ${RISCV_TRIPLE} -march=rv32im -mabi=ilp32 -mrelax")
if(RISCV_SYSROOT)
  # Explicit include paths in the correct order for #include_next chains.
  # Do NOT use --sysroot here: it conflicts with -isystem ordering.
  set(COMMON_FLAGS "${COMMON_FLAGS} -isystem ${RISCV_SYSROOT}/include/c++/${_RISCV_GCC_VERSION}")
  set(COMMON_FLAGS "${COMMON_FLAGS} -isystem ${RISCV_SYSROOT}/include/c++/${_RISCV_GCC_VERSION}/riscv-none-elf")
  set(COMMON_FLAGS "${COMMON_FLAGS} -isystem ${RISCV_GCC_ROOT}/lib/gcc/riscv-none-elf/${_RISCV_GCC_VERSION}/include")
  set(COMMON_FLAGS "${COMMON_FLAGS} -isystem ${RISCV_GCC_ROOT}/lib/gcc/riscv-none-elf/${_RISCV_GCC_VERSION}/include-fixed")
  set(COMMON_FLAGS "${COMMON_FLAGS} -isystem ${RISCV_SYSROOT}/include")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} ${COMMON_FLAGS}")

if(DEFINED CMAKE_LINKER)
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=${CMAKE_LINKER}")
else()
  # Prefer lld, fall back to the GCC toolchain's ld
  find_program(_LLD ld.lld)
  if(_LLD)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
  elseif(_RISCV_GCC)
    find_program(_RISCV_LD riscv-none-elf-ld)
    if(_RISCV_LD)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=${_RISCV_LD}")
      # Add GCC library paths so the linker can find crtbegin.o, libgcc, etc.
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${RISCV_GCC_ROOT}/lib/gcc/riscv-none-elf/${_RISCV_GCC_VERSION}/rv32im/ilp32")
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${RISCV_SYSROOT}/lib/rv32im/ilp32")
    endif()
  endif()
endif()

set(BUILD_TESTING OFF CACHE BOOL "Disable Silkworm tests")
set(SILKWORM_WASM_API OFF CACHE BOOL "No WASM for bare-metal")

set(LIBFF_WITH_GMP "OFF")
set(CATCH_BUILD_TESTING "OFF")
set(SILKWORM_CORE_USE_ABSEIL "OFF")
set(CMAKE_PREFIX_PATH "${CONAN_INSTALL_FOLDER}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

find_program(CMAKE_OBJCOPY NAMES llvm-objcopy objcopy)