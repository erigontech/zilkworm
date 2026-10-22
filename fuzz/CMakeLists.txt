# Copyright 2026 The Zilkworm Authors (modifications)
# SPDX-License-Identifier: Apache-2.0

# libFuzzer harnesses over the parsers and checkers an attacker controls. Built only
# when SILKWORM_FUZZER=ON (with SILKWORM_SANITIZE_COMPILER_OPTIONS carrying
# -fsanitize=fuzzer-no-link,address,undefined for the library); each target adds
# -fsanitize=fuzzer to pull in libFuzzer's main.

if(NOT SILKWORM_FUZZER)
  return()
endif()

# silkworm_dev brings in silkworm_core and silkworm_types_zz; the two core archives
# reference each other, so GNU ld needs the group.
if(APPLE)
  set(Z6M_FUZZ_CORE_LIBS silkworm_dev silkworm_core silkworm_types_zz)
else()
  set(Z6M_FUZZ_CORE_LIBS -Wl,--start-group silkworm_dev silkworm_core silkworm_types_zz -Wl,--end-group)
endif()

function(z6m_add_fuzzer name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE ${Z6M_FUZZ_CORE_LIBS})
  target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
  target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

z6m_add_fuzzer(fuzz_rlp fuzz_rlp.cpp)
z6m_add_fuzzer(fuzz_types fuzz_types.cpp)
z6m_add_fuzzer(fuzz_state_transition fuzz_state_transition.cpp)
z6m_add_fuzzer(fuzz_slib fuzz_slib.cpp)
z6m_add_fuzzer(fuzz_mpt fuzz_mpt.cpp)
z6m_add_fuzzer(fuzz_prestate fuzz_prestate.cpp)
z6m_add_fuzzer(fuzz_precompiles fuzz_precompiles.cpp)
target_include_directories(fuzz_precompiles PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party/evmone
  ${CMAKE_SOURCE_DIR}/third_party/evmone/evmc/include)

# evmone's own differential fuzzer (advanced vs baseline interpreters), reused as-is.
add_executable(fuzz_evmone ${CMAKE_SOURCE_DIR}/third_party/evmone/test/fuzzer/fuzzer.cpp)
target_include_directories(fuzz_evmone PRIVATE
  ${CMAKE_SOURCE_DIR}/third_party
  ${CMAKE_SOURCE_DIR}/third_party/evmone
  ${CMAKE_SOURCE_DIR}/third_party/evmone/include
  ${CMAKE_SOURCE_DIR}/third_party/evmone/lib
  ${CMAKE_SOURCE_DIR}/third_party/evmone/test
  ${CMAKE_SOURCE_DIR}/third_party/evmone/evmc/include)
target_link_libraries(fuzz_evmone PRIVATE evmone)
target_compile_options(fuzz_evmone PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_evmone PRIVATE -fsanitize=fuzzer)
