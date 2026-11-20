cmake_minimum_required(VERSION 3.20)

project(z6m_guest_airbender LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(LINKER_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/link.x")
set(MEMORY_SCRIPT "${CMAKE_CURRENT_LIST_DIR}/memory.x")

set(MEM_BUILTINS_SRC "${CMAKE_CURRENT_LIST_DIR}/../guest_common/src/mem_builtins.cpp")

add_executable(z6m_guest
    src/main.cpp
    src/airbender_runtime.cpp
    src/simple_allocator.cpp
    ${MEM_BUILTINS_SRC}
    src/hashtable_policy.cpp
    src/runtime_stubs.c
    src/start.S
)

# zilk_core headers (print.hpp, mphf_map.hpp, ...) dispatch on AIRBENDER, else use the iostream host code.
target_compile_definitions(z6m_guest PRIVATE AIRBENDER)

option(USE_HASH_KEY "Enable node-store account recovery for witness preimage gaps" ON)
if(USE_HASH_KEY)
  # Must match the zilkworm subbuild: the flag gates header code compiled into both the static libs and this target.
  target_compile_definitions(z6m_guest PRIVATE USE_HASH_KEY=1)
endif()


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
# evmc headers come straight from the submodule (EVMC folded into evmone).
target_include_directories(z6m_guest PRIVATE
  "${CMAKE_CURRENT_LIST_DIR}/../../third_party/evmone/evmc/include")
# FetchContent deps live in the zilkworm build tree, not the install prefix.
target_include_directories(z6m_guest SYSTEM PRIVATE
  "${SW_BIN}/_deps/nlohmann_json-src/include"
  "${SW_BIN}/_deps/magic_enum-src/include"
)


# -fno-builtin, no LTO: the strong mem builtins override newlib; -fno-toplevel-reorder keeps their callers in jal range.
set_source_files_properties(${MEM_BUILTINS_SRC} PROPERTIES
    COMPILE_OPTIONS "-fno-builtin;-fno-tree-loop-distribute-patterns;-fno-lto;-fno-toplevel-reorder"
)

# hashtable_policy.cpp defines the --wrap target; built without LTO like mem_builtins.cpp, within jal range of callers.
set_source_files_properties(src/hashtable_policy.cpp PROPERTIES COMPILE_OPTIONS "-fno-lto")

target_include_directories(z6m_guest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/include)
target_compile_options(z6m_guest PRIVATE
    -fno-exceptions
    -fno-rtti
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fno-stack-protector
    # The frame pointer is set in cmake/riscv32im.cmake (omitted; a profiling build sets -fno-omit-frame-pointer there).
    -fdata-sections
    -ffunction-sections
)

target_link_options(z6m_guest PRIVATE
    -nostdlib
    -Wl,-T,${MEMORY_SCRIPT}
    -Wl,-T,${LINKER_SCRIPT}
    -Wl,-e,_start
    -Wl,--gc-sections
    # Unordered-container growth check: soft-float in libstdc++ on rv32im, integer in hashtable_policy.cpp.
    -Wl,--wrap=_ZNKSt8__detail20_Prime_rehash_policy14_M_need_rehashEjjj
)

# Link libraries inside --start-group/--end-group for circular dependency resolution
target_link_libraries(z6m_guest PRIVATE
    -Wl,--start-group
    silkworm_dev silkworm_core
    "${CMAKE_BINARY_DIR}/zilkworm/zilk_core/core/types_zz/libsilkworm_types_zz.a"
    "${CMAKE_BINARY_DIR}/zilkworm/third_party/libevmone.a"
    "${CMAKE_BINARY_DIR}/zilkworm/deps/src/blst/libblst.a"
    # EVMC is folded into evmone, so there are no evmc loader/instructions libs; the guest never dlopens VMs.
    c m gcc nosys stdc++
    -Wl,--end-group
)


set_target_properties(z6m_guest PROPERTIES
    OUTPUT_NAME "z6m_guest"
    SUFFIX ".elf"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    # The linker scripts are not sources: relink when either changes.
    LINK_DEPENDS "${LINKER_SCRIPT};${MEMORY_SCRIPT}"
)

# Dead-code guard: see cmake/check_no_dead_code.cmake.
add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -DNM=${CMAKE_NM} -DELF=$<TARGET_FILE:z6m_guest>
            -P ${CMAKE_CURRENT_LIST_DIR}/cmake/check_no_dead_code.cmake
    COMMENT "Checking z6m_guest.elf for dead-code clusters"
    VERBATIM
)

# Unsigned M guard: see cmake/check_unsigned_muldiv.cmake.
if(NOT CMAKE_OBJDUMP)
    find_program(CMAKE_OBJDUMP NAMES riscv-none-elf-objdump llvm-objdump objdump)
endif()
add_custom_command(TARGET z6m_guest POST_BUILD
    COMMAND ${CMAKE_COMMAND} -DOBJDUMP=${CMAKE_OBJDUMP} -DELF=$<TARGET_FILE:z6m_guest>
            -P ${CMAKE_CURRENT_LIST_DIR}/cmake/check_unsigned_muldiv.cmake
    COMMENT "Checking z6m_guest.elf for signed multiplies and divides"
    VERBATIM
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