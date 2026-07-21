cmake_minimum_required(VERSION 3.20)

project(z6m_guest_airbender LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(LINKER_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/link.x")
set(MEMORY_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/memory.x")

add_executable(z6m_guest
    src/main.cpp
    src/airbender_runtime.cpp
    src/simple_allocator.cpp
    src/mem_builtins.c
    src/runtime_stubs.c
    src/start.S
)

# zilk_core headers (print.hpp, mphf_map.hpp, ...) dispatch on AIRBENDER;
# without it they fall back to the iostream host implementation.
target_compile_definitions(z6m_guest PRIVATE AIRBENDER)

option(USE_HASH_KEY "Enable node-store account recovery for witness preimage gaps" OFF)
if(USE_HASH_KEY)
  # Must match the zilkworm subbuild: the flag gates header code compiled
  # into both the static libs and this target's TUs.
  target_compile_definitions(z6m_guest PRIVATE USE_HASH_KEY=1)
endif()


# ====== For Zilkworm project at .. ===============
set(SW_INSTALL_DIR ${CMAKE_BINARY_DIR}/zilkworm-install CACHE PATH "")
set(SW_INCLUDE_DIR ${SW_INSTALL_DIR}/include)
set(SW_BIN         "${CMAKE_BINARY_DIR}/zilkworm")
set(SW_INC_INSTALL  "${CMAKE_BINARY_DIR}/zilkworm-install/include")

add_library(silkworm_core STATIC IMPORTED GLOBAL)
set_target_properties(silkworm_core PROPERTIES
  IMPORTED_LOCATION "${SW_BIN}/zilk_core/core/libsilkworm_core.a"
)

add_library(silkworm_dev STATIC IMPORTED GLOBAL)
set_target_properties(silkworm_dev PROPERTIES
  IMPORTED_LOCATION "${SW_BIN}/zilk_core/dev/libsilkworm_dev.a"
)
if (EXISTS "${SW_INC_INSTALL}")
  target_include_directories(z6m_guest PRIVATE "${SW_INC_INSTALL}")
endif()
# evmc headers are no longer exported by the subbuild install (EVMC folded
# into evmone); include them straight from the submodule.
target_include_directories(z6m_guest PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../third_party/evmone/evmc/include")
# FetchContent deps live in the zilkworm build tree, not the install prefix.
target_include_directories(z6m_guest SYSTEM PRIVATE
  "${SW_BIN}/_deps/nlohmann_json-src/include"
  "${SW_BIN}/_deps/magic_enum-src/include"
)
# ======================================


# Prevent GCC/LTO from pattern-matching our custom memcpy/memmove/memset
# loops back into library calls.  Also compile without LTO so the strong
# symbol definition survives into the final link and overrides newlib.
set_source_files_properties(src/mem_builtins.c PROPERTIES
    COMPILE_OPTIONS "-fno-tree-loop-distribute-patterns;-fno-lto"
)

target_include_directories(z6m_guest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/include)
target_compile_options(z6m_guest PRIVATE
    # -ffreestanding
    -fno-exceptions
    -fno-rtti
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fno-stack-protector
    -fno-omit-frame-pointer
    -fdata-sections
    -ffunction-sections
)

target_link_options(z6m_guest PRIVATE
    -nostdlib
    -Wl,-T,${MEMORY_SCRIPT}
    -Wl,-T,${LINKER_SCRIPT}
    -Wl,-e,_start
    -Wl,--gc-sections
)

# Link libraries inside --start-group/--end-group for circular dependency resolution
target_link_libraries(z6m_guest PRIVATE
    -Wl,--start-group
    silkworm_dev silkworm_core
    "${CMAKE_BINARY_DIR}/zilkworm/zilk_core/core/types_zz/libsilkworm_types_zz.a"
    "${CMAKE_BINARY_DIR}/zilkworm/third_party/libevmone.a"
    "${CMAKE_BINARY_DIR}/zilkworm/deps/src/blst/libblst.a"
    # evmc loader/instructions libs no longer produced by the subbuild
    # (EVMC folded into evmone); the baremetal guest never dlopens VMs.
    # libsecp256k1 disabled — using evmone's built-in ecrecover
    # "${CMAKE_BINARY_DIR}/zilkworm/_deps/libsecp256k1-build/lib/libsecp256k1.a"
    c m gcc nosys stdc++
    -Wl,--end-group
)


set_target_properties(z6m_guest PROPERTIES
    OUTPUT_NAME "z6m_guest"
    SUFFIX ".elf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

if(NOT CMAKE_OBJCOPY)
    find_program(CMAKE_OBJCOPY NAMES llvm-objcopy objcopy)
endif()

if(CMAKE_OBJCOPY)
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/z6m_guest.bin
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:z6m_guest> ${CMAKE_BINARY_DIR}/z6m_guest.bin
        DEPENDS z6m_guest
        COMMENT "Generating z6m_guest.bin"
    )

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/z6m_guest.text
        COMMAND ${CMAKE_OBJCOPY} -O binary --only-section=.text $<TARGET_FILE:z6m_guest> ${CMAKE_BINARY_DIR}/z6m_guest.text
        DEPENDS z6m_guest
        COMMENT "Generating z6m_guest.text"
    )

    add_custom_target(artifacts ALL DEPENDS ${CMAKE_BINARY_DIR}/z6m_guest.bin ${CMAKE_BINARY_DIR}/z6m_guest.text)
else()
    message(WARNING "objcopy not found; z6m_guest.bin/z6m_guest.text will not be generated")
endif()