# Copyright 2025 Modifications: The Zilkworm Authors

# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

# reduce the log verbosity of evmone/cmake/cable
if(NOT CMAKE_MESSAGE_LOG_LEVEL)
  set(CMAKE_MESSAGE_LOG_LEVEL_EMPTY YES)
  set(CMAKE_MESSAGE_LOG_LEVEL NOTICE)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

# restore the log verbosity
if(CMAKE_MESSAGE_LOG_LEVEL_EMPTY)
  unset(CMAKE_MESSAGE_LOG_LEVEL)
endif()

if(NOT CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE
      ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/cxx23.cmake
      CACHE FILEPATH "" FORCE
  )
  include("${CMAKE_TOOLCHAIN_FILE}")
endif()

project(zilkworm)
set(PROJECT_VERSION 0.1.0-alpha.2)

include(CTest)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(USE_HASH_KEY "Enable node-store account recovery for witness preimage gaps" OFF)
if(USE_HASH_KEY)
  add_compile_definitions(USE_HASH_KEY=1)
endif()
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CORE_USE_ABSEIL "Allow use of Abseil in Silkworm Core" OFF)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)
option(SILKWORM_CLANG_TIDY "Clang-Tidy linter" OFF)
option(SILKWORM_SANITIZE "Build instrumentation for sanitizers" OFF)
option(SILKWORM_FUZZER "Build instrumentation for fuzzers" OFF)
option(SILKWORM_FUZZER_SANITIZERS "CLang sanitizer options for fuzzers" OFF)
option(SILKWORM_USE_MIMALLOC "Enable using mimalloc for dynamic memory management" ON)
option(SILKWORM_ALLOW_UNUSED_VAR_WARNINGS "Turn unused variable errors into warnings" OFF)

get_filename_component(SILKWORM_MAIN_DIR . ABSOLUTE)
set(SILKWORM_MAIN_SRC_DIR "${SILKWORM_MAIN_DIR}/zilk_core")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_settings.cmake)

add_subdirectory(third_party)

# Unit-test framework. Placed before compiler_warnings.cmake so Catch2
# builds without the project's -Werror set.
if(BUILD_TESTING)
  include(FetchContent)
  FetchContent_Declare(
    Catch2
    URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.15.1.tar.gz
    URL_HASH SHA256=be23a52b85cf04cd9587612147a10b023d59ed9757fa1843cc99e615d6c0893c
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  )
  FetchContent_MakeAvailable(Catch2)
  list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_warnings.cmake)

if(SILKWORM_CLANG_TIDY)
  find_program(CLANG_TIDY clang-tidy PATHS "${CMAKE_BINARY_DIR}/tidy/bin" NO_CACHE REQUIRED)
  set(CMAKE_C_CLANG_TIDY "${CLANG_TIDY}")
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY}")
endif()

add_subdirectory(zilk_core)

# Aggregate Catch2 unit-test target. New *_test.cpp files join its source
# list; each TEST_CASE is registered with ctest individually. Defined here
# (not in zilk_core/) so projects embedding zilk_core with BUILD_TESTING=ON
# but without Catch2 (qemu_runner) are unaffected.
if(BUILD_TESTING)
  add_executable(zilkworm.tests
    zilk_core/core/trie_zz/grid_mpt_delete_test.cpp
    zilk_core/core/trie_zz/grid_mpt_fold_orphan_test.cpp
    zilk_core/dev/cli/mphf_map_test.cpp
  )
  target_link_libraries(zilkworm.tests PRIVATE silkworm_core Catch2::Catch2WithMain)
  include(Catch)
  catch_discover_tests(zilkworm.tests)
endif()

# All unit tests target
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/common/get_all_targets.cmake)
get_all_targets(UNIT_TEST_TARGETS)
list(FILTER UNIT_TEST_TARGETS INCLUDE REGEX "_test$")
list(REMOVE_ITEM UNIT_TEST_TARGETS backend_kv_test benchmark_test sentry_client_test)
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  # avoid fatal error C1002: compiler is out of heap space
  list(REMOVE_ITEM UNIT_TEST_TARGETS silkworm_rpcdaemon_test)
endif()
message(VERBOSE "UNIT_TEST_TARGETS: ${UNIT_TEST_TARGETS}")
add_custom_target(all_unit_tests DEPENDS ${UNIT_TEST_TARGETS})


include(GNUInstallDirs)        # <-- for CMAKE_INSTALL_INCLUDEDIR, LIBDIR, BINDIR …

install(
    DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/zilk_core/core
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zilk_core
)

install(
    DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/zilk_core/dev
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zilk_core
)

install(
    FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/zilk_core/print.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/zilk_core
)

# Header-only transitive deps since this is fetched and qemu has split build required by zilk_core public headers
install(
    DIRECTORY
    ${CMAKE_BINARY_DIR}/_deps/nlohmann_json-src/include/nlohmann
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(
    DIRECTORY
    ${CMAKE_BINARY_DIR}/_deps/magic_enum-src/include/magic_enum
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
