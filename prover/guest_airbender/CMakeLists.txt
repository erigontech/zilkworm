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
# ======================================


target_include_directories(z6m_guest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/src/include)
target_compile_options(z6m_guest PRIVATE
    -ffreestanding
    -fno-exceptions
    -fno-rtti
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -fno-stack-protector
    -fno-omit-frame-pointer
    -fdata-sections
    -ffunction-sections
)

# Link Silkworm libs (uncomment when z6m_debug target is defined)
# target_link_options(z6m_debug PRIVATE -Wl,--start-group)
# target_link_libraries(z6m_debug PRIVATE
#  c gcc nosys stdc++
#  silkworm_dev silkworm_core)
# target_link_options(z6m_debug PRIVATE -Wl,--end-group)
########################


target_link_options(z6m_guest PRIVATE
    -nostdlib
    -nodefaultlibs
    -Wl,-T,${MEMORY_SCRIPT}
    -Wl,-T,${LINKER_SCRIPT}
    -Wl,-e,_start
    -Wl,--gc-sections
)


# If you later see unresolved symbols from 3rd-party .a's, also add:
# target_link_libraries(z6m_debug PRIVATE
#   "${CMAKE_BINARY_DIR}/zilkworm-install/lib/libevmc-loader.a"
#   "${CMAKE_BINARY_DIR}/zilkworm-install/lib/libevmc-instructions.a"
#   "${CMAKE_BINARY_DIR}/zilkworm/third_party/libevmone.a"
#   "${CMAKE_BINARY_DIR}/zilkworm/deps/src/blst/libblst.a"
# )


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