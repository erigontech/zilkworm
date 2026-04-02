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
    src/simple_allocator.cpp
    src/mem_builtins.c
    src/runtime_stubs.c
    src/start.S
)


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
# FetchContent deps live in the zilkworm build tree, not the install prefix.
target_include_directories(z6m_guest SYSTEM PRIVATE
  "${SW_BIN}/_deps/nlohmann_json-src/include"
  "${SW_BIN}/_deps/magic_enum-src/include"
)
# ======================================


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
    "${CMAKE_BINARY_DIR}/zilkworm/third_party/libevmone.a"
    "${CMAKE_BINARY_DIR}/zilkworm/deps/src/blst/libblst.a"
    "${CMAKE_BINARY_DIR}/zilkworm-install/lib/libevmc-loader.a"
    "${CMAKE_BINARY_DIR}/zilkworm-install/lib/libevmc-instructions.a"
    "${CMAKE_BINARY_DIR}/zilkworm/_deps/libsecp256k1-build/lib/libsecp256k1.a"
    c gcc nosys stdc++
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