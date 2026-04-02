# riscv64im-toolchain.cmake
set(CMAKE_SYSTEM_NAME Generic)        # No OS (bare-metal target)
set(CMAKE_SYSTEM_PROCESSOR riscv64)   # Target CPU architecture

# Cross-compiler executables
set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)


# set(GMP_LIBRARY "${CMAKE_SOURCE_DIR}/../prelibs/gmp")
# set(GMP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../prelibs/gmp")
set(BUILD_SHARED_LIBS "OFF")

set(common_flags "-march=rv64im -mabi=lp64 -mcmodel=medany -ffunction-sections -fdata-sections -fPIC") #"-ffreestanding"
set(CMAKE_C_FLAGS "${common_flags} -D_GLIBCXX_HAS_GTHREADS=0")
set(CMAKE_CXX_FLAGS "${common_flags} -fno-exceptions -fno-rtti -fno-threadsafe-statics ")  # "-nostdlib"
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3")
set(CMAKE_ASM_FLAGS "${common_flags}")
set(CMAKE_ASM_FLAGS_DEBUG "-g3")


set(BUILD_TESTING OFF CACHE BOOL "Disable Silkworm tests")
set(SILKWORM_WASM_API OFF CACHE BOOL "No WASM for bare-metal")

set(LIBFF_WITH_GMP "OFF")
set(CATCH_BUILD_TESTING "OFF")
set(SILKWORM_CORE_USE_ABSEIL "OFF")
set(CMAKE_PREFIX_PATH "${CONAN_INSTALL_FOLDER}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
# It clashes with double inclusion if declared here
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T${CMAKE_SOURCE_DIR}/qemu-xpack.ld -z norelro") # -nostartfiles"
