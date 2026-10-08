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
set(PROJECT_VERSION 0.1.0-alpha.3)

include(CTest)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
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
  # The Airbender guest's bump allocator defines the global operator new/delete and malloc, so it
  # cannot be linked into a host test: it would replace the allocator of the whole process. The
  # test compiles its text with those names mapped to guest_*, so it runs the guest file itself
  # (a change to it shows up here) without taking over the host's allocation.
  set(GUEST_ALLOCATOR_SRC ${CMAKE_CURRENT_SOURCE_DIR}/prover/guest_airbender/src/simple_allocator.cpp)
  set(GUEST_ALLOCATOR_TEST_SOURCES)
  if(EXISTS ${GUEST_ALLOCATOR_SRC})
    set(GUEST_ALLOCATOR_TEST_SRC ${CMAKE_CURRENT_BINARY_DIR}/guest_allocator_test/simple_allocator_renamed.cpp)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${GUEST_ALLOCATOR_SRC})
    file(READ ${GUEST_ALLOCATOR_SRC} guest_allocator_text)
    string(REPLACE "operator new[]" "guest_new_array" guest_allocator_text "${guest_allocator_text}")
    string(REPLACE "operator delete[]" "guest_delete_array" guest_allocator_text "${guest_allocator_text}")
    string(REPLACE "operator new" "guest_new" guest_allocator_text "${guest_allocator_text}")
    string(REPLACE "operator delete" "guest_delete" guest_allocator_text "${guest_allocator_text}")
    set(guest_allocator_prelude "#include <cerrno>\n#include <cstddef>\n#include <cstdint>\n#include <cstdlib>\n#include <new>\n")
    foreach(name malloc free calloc realloc memalign aligned_alloc posix_memalign
                 _malloc_r _free_r _realloc_r _calloc_r _memalign_r)
      string(APPEND guest_allocator_prelude "#define ${name} guest_${name}\n")
    endforeach()
    # configure_file leaves the output alone when the content is unchanged, so no needless rebuilds.
    file(WRITE ${GUEST_ALLOCATOR_TEST_SRC}.in "${guest_allocator_prelude}${guest_allocator_text}")
    configure_file(${GUEST_ALLOCATOR_TEST_SRC}.in ${GUEST_ALLOCATOR_TEST_SRC} COPYONLY)
    set(GUEST_ALLOCATOR_TEST_SOURCES ${GUEST_ALLOCATOR_TEST_SRC} zilk_core/dev/cli/guest_allocator_test.cpp)
  endif()

  add_executable(zilkworm.tests
    ${GUEST_ALLOCATOR_TEST_SOURCES}
    zilk_core/core/execution/addmod_words_test.cpp
    zilk_core/core/execution/bn254_mul_test.cpp
    zilk_core/core/execution/delegation_probe_test.cpp
    zilk_core/core/common_zz/data_byte_count_test.cpp
    zilk_core/core/execution/div_mod_frontend_test.cpp
    zilk_core/core/execution/precompile_lookup_test.cpp
    zilk_core/core/execution/exp_pow2_base_test.cpp
    zilk_core/core/execution/kzg_pairing_test.cpp
    zilk_core/core/execution/mulmod_sparse_test.cpp
    zilk_core/core/execution/secp256k1_ecrecover_test.cpp
    zilk_core/core/protocol/intrinsic_gas_test.cpp
    zilk_core/core/rlp/decode_bounds_test.cpp
    zilk_core/core/types/receipt_logs_test.cpp
    zilk_core/core/types/max_gas_cost_test.cpp
    zilk_core/core/rlp/significant_bytes_test.cpp
    zilk_core/core/types/receipt_test.cpp
    zilk_core/core/types/transaction_rlp_view_test.cpp
    zilk_core/core/trie_zz/grid_mpt_delete_test.cpp
    zilk_core/core/trie_zz/grid_mpt_fold_orphan_test.cpp
    zilk_core/core/trie_zz/grid_mpt_unfold_test.cpp
    zilk_core/core/trie_zz/encode_branch_patch_test.cpp
    zilk_core/core/trie_zz/grid_mpt_kprefix_test.cpp
    zilk_core/core/trie_zz/full_branch_hash_test.cpp
    zilk_core/core/trie_zz/grid_mpt_word_loads_test.cpp
    zilk_core/core/trie_zz/account_leaf_rlp_test.cpp
    zilk_core/core/state_zz/node_verify_test.cpp
    zilk_core/core/trie_zz/unfold_hash_copy_test.cpp
    zilk_core/dev/cli/mphf_map_test.cpp
    zilk_core/dev/cli/addr_hash_orphan_test.cpp
    zilk_core/dev/cli/account_read_spoof_test.cpp
    zilk_core/dev/cli/account_read_honest_test.cpp
    zilk_core/dev/cli/delegation_clearing_storage_test.cpp
    zilk_core/dev/cli/direct_state_handle_test.cpp
    zilk_core/dev/cli/code_store_collision_len_test.cpp
    zilk_core/dev/cli/storage_host_path_test.cpp
    zilk_core/dev/cli/call_frame_result_test.cpp
    zilk_core/dev/cli/word_layout_test.cpp
    zilk_core/dev/cli/jumpdest_map_test.cpp
    zilk_core/dev/cli/jumpdest_single_bound_test.cpp
    zilk_core/dev/cli/lean_code_cache_test.cpp
    zilk_core/dev/cli/cmp_jumpi_fusion_test.cpp
    zilk_core/dev/cli/call_message_test.cpp
    zilk_core/dev/cli/mstore_grow_test.cpp
    zilk_core/dev/cli/underflow_bounds_test.cpp
    zilk_core/dev/cli/const_mask_and_fusion_test.cpp
    zilk_core/dev/cli/push1_alu_fusion_test.cpp
    zilk_core/dev/cli/sar_words_test.cpp
    zilk_core/dev/cli/shift_stack_words_test.cpp
    zilk_core/dev/cli/signextend_fusion_test.cpp
    zilk_core/dev/cli/code_store_stream_test.cpp
    zilk_core/dev/cli/code_store_verified_test.cpp
    zilk_core/dev/cli/env_push_log_test.cpp
    zilk_core/dev/cli/mem_builtins_test.cpp
    zilk_core/dev/cli/mem_builtins_host.c
    zilk_core/dev/cli/code_store_seal_test.cpp
    zilk_core/dev/cli/in_place_code_test.cpp
    zilk_core/dev/cli/strict_diag_test.cpp
  )
  # The guest's memcpy and friends, built for the host with the guest's code-generation flags: the
  # byte loops must not be turned into the libc calls this file replaces. The guest is built with
  # -mstrict-align, where a misaligned word access traps but x86 runs it silently, so the alignment
  # sanitizer stands in for it.
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(MEM_BUILTINS_HOST_FLAGS -fno-builtin -fno-tree-loop-distribute-patterns -fsanitize=alignment
                                -fno-sanitize-recover=alignment
    )
    set_source_files_properties(
      zilk_core/dev/cli/mem_builtins_host.c PROPERTIES COMPILE_OPTIONS "${MEM_BUILTINS_HOST_FLAGS}"
    )
    target_link_options(zilkworm.tests PRIVATE -fsanitize=alignment)
  endif()
  # addr_hash_orphan_test drives StateTransition::run (silkworm_dev). ld64 resolves the
  # silkworm_core<->types_zz archive cycle globally; --start-group is GNU-ld-only.
  if(APPLE)
    set(ZILK_TEST_LIBS silkworm_dev silkworm_core silkworm_types_zz)
  else()
    set(ZILK_TEST_LIBS -Wl,--start-group silkworm_dev silkworm_core silkworm_types_zz -Wl,--end-group)
  endif()
  # kzg_pairing_test builds proofs and its reference pairing with blst.
  target_link_libraries(zilkworm.tests PRIVATE ${ZILK_TEST_LIBS} blst::blst Catch2::Catch2WithMain)
  # The Airbender guest's blst cyclotomic squaring only exists inside evmone's patch script. The
  # test extracts the script's text with Python and runs it on a host emulation of the BigInt
  # delegation, so it needs a host toolchain with Python.
  find_package(Python3 COMPONENTS Interpreter)
  if(Python3_Interpreter_FOUND AND NOT AIRBENDER AND NOT MSVC AND NOT CMAKE_CROSSCOMPILING)
    set(BLST_CYC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/blst_cyclotomic")
    set(BLST_CYC_PATCH_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/cmake/patch_blst_airbender.sh")
    set(BLST_CYC_GEN "${CMAKE_CURRENT_BINARY_DIR}/blst_cyclotomic_gen")
    add_custom_command(
      OUTPUT "${BLST_CYC_GEN}/base_block.inc" "${BLST_CYC_GEN}/cand_block.inc"
      COMMAND ${CMAKE_COMMAND} -E make_directory "${BLST_CYC_GEN}"
      COMMAND ${Python3_EXECUTABLE} -I "${BLST_CYC_DIR}/extract.py" "${BLST_CYC_PATCH_SCRIPT}" "${BLST_CYC_GEN}"
      DEPENDS "${BLST_CYC_PATCH_SCRIPT}" "${BLST_CYC_DIR}/extract.py"
      VERBATIM
    )
    add_library(blst_cyclotomic_diff STATIC "${BLST_CYC_DIR}/blst_cyclotomic_diff.c"
                                            "${BLST_CYC_GEN}/base_block.inc" "${BLST_CYC_GEN}/cand_block.inc")
    target_include_directories(blst_cyclotomic_diff PRIVATE "${BLST_CYC_DIR}" "${BLST_CYC_GEN}")
    # blst's C, not the repository's: the project's -Werror -pedantic set does not apply to it
    target_compile_options(blst_cyclotomic_diff PRIVATE -w -O2)
    target_sources(zilkworm.tests PRIVATE "${BLST_CYC_DIR}/blst_cyclotomic_test.cpp")
    target_include_directories(zilkworm.tests PRIVATE "${BLST_CYC_DIR}")
    target_link_libraries(zilkworm.tests PRIVATE blst_cyclotomic_diff)
  else()
    message(STATUS "blst cyclotomic differential test skipped (needs Python3 on a host build)")
  endif()
  # The Airbender guest's blst mul_mont_384 only exists inside evmone's patch script. The test
  # extracts the script's text with Python and runs it on a host emulation of the BigInt
  # delegation, so it needs a host toolchain with Python.
  if(Python3_Interpreter_FOUND AND NOT AIRBENDER AND NOT MSVC AND NOT CMAKE_CROSSCOMPILING)
    set(BLST_MONT384_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/blst_mont384")
    set(BLST_PATCH_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/cmake/patch_blst_airbender.sh")
    set(BLST_MONT384_GEN "${CMAKE_CURRENT_BINARY_DIR}/blst_mont384_gen")
    add_custom_command(
      OUTPUT "${BLST_MONT384_GEN}/cand_block.inc"
      COMMAND ${CMAKE_COMMAND} -E make_directory "${BLST_MONT384_GEN}"
      COMMAND ${Python3_EXECUTABLE} -I "${BLST_MONT384_DIR}/extract.py" "${BLST_PATCH_SCRIPT}" cand
              "${BLST_MONT384_GEN}/cand_block.inc"
      DEPENDS "${BLST_PATCH_SCRIPT}" "${BLST_MONT384_DIR}/extract.py"
      VERBATIM
    )
    add_library(blst_mont384_diff STATIC "${BLST_MONT384_DIR}/blst_mont384_diff.c"
                                         "${BLST_MONT384_GEN}/cand_block.inc")
    target_include_directories(blst_mont384_diff PRIVATE "${BLST_MONT384_DIR}" "${BLST_MONT384_GEN}")
    # blst's C, not the repository's: the project's -Werror -pedantic set does not apply to it
    target_compile_options(blst_mont384_diff PRIVATE -w -O2)
    target_sources(zilkworm.tests PRIVATE "${BLST_MONT384_DIR}/blst_mont384_test.cpp")
    target_include_directories(zilkworm.tests PRIVATE "${BLST_MONT384_DIR}")
    target_link_libraries(zilkworm.tests PRIVATE blst_mont384_diff)
  else()
    message(STATUS "blst mul_mont_384 differential test skipped (needs Python3 on a host build)")
  endif()
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
