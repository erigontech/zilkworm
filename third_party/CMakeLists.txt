# Copyright 2025 The Zilkworm Authors
# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# please keep the list sorted
# add_subdirectory(blst)

include(evmone/cmake/blst.cmake)

set(INTX_INSTALL TRUE)
add_subdirectory(intx)



# add_subdirectory(evmone) # depends on intx
if(SP1TURBO)
  # FIXME: I'm not sure why this is not propagated from the top-level CMakeLists.txt.
  add_compile_definitions(-DSP1TURBO)
  include_directories(${CMAKE_SOURCE_DIR}/prover/guest_program/src/include)
endif()

if(SP1)
    add_compile_definitions(-DSP1)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../prover/guest_hypercube/src/include)
endif()

if(SILKWORM_WASM_API)
  add_compile_definitions(EVMC_LOADER_MOCK)
endif()
add_subdirectory(evmone/evmc)

add_library(
  evmone
  evmone/lib/evmone/advanced_analysis.cpp
  evmone/lib/evmone/advanced_analysis.hpp
  evmone/lib/evmone/advanced_execution.cpp
  evmone/lib/evmone/advanced_execution.hpp
  evmone/lib/evmone/advanced_instructions.cpp
  evmone/lib/evmone/baseline_analysis.cpp
  evmone/lib/evmone/baseline_execution.cpp
  evmone/lib/evmone/baseline_instruction_table.cpp
  evmone/lib/evmone/baseline_instruction_table.hpp
  evmone/lib/evmone/baseline.hpp
  evmone/lib/evmone/constants.hpp
  evmone/lib/evmone/delegation.cpp
  evmone/lib/evmone/delegation.hpp
  evmone/lib/evmone_precompiles/secp256r1.cpp
  evmone/lib/evmone/execution_state.hpp
  evmone/lib/evmone/instructions_calls.cpp
  evmone/lib/evmone/instructions_opcodes.hpp
  evmone/lib/evmone/instructions_storage.cpp
  evmone/lib/evmone/instructions_traits.hpp
  evmone/lib/evmone/instructions_xmacro.hpp
  evmone/lib/evmone/instructions.hpp
  evmone/lib/evmone/tracing.cpp
  evmone/lib/evmone/tracing.hpp
  evmone/lib/evmone/vm.cpp
  evmone/lib/evmone/vm.hpp
  evmone/lib/evmone_precompiles/keccak.c
  evmone/lib/evmone_precompiles/blake2b.cpp
  evmone/lib/evmone_precompiles/ripemd160.cpp
  evmone/lib/evmone_precompiles/sha256.cpp
  evmone/lib/evmone_precompiles/modexp.cpp
  evmone/lib/evmone_precompiles/mulmod.cpp
  evmone/lib/evmone_precompiles/kzg.cpp
  evmone/lib/evmone_precompiles/bn254.cpp
  evmone/lib/evmone_precompiles/pairing/bn254/pairing.cpp
  evmone/lib/evmone_precompiles/secp256k1.cpp
  evmone/lib/evmone_precompiles/bls.cpp
  evmone/test/state/host.cpp
  evmone/test/state/precompiles.cpp
  evmone/test/state/state.cpp
  evmone/test/state/system_contracts.cpp
)
set_source_files_properties(evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.11.0")
target_include_directories(
  evmone
  PUBLIC evmone/include evmone/lib
  INTERFACE .
  PRIVATE ..
)
target_link_libraries(
  evmone
  PUBLIC evmc intx::intx blst::blst
)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(
    evmone
    PRIVATE -fno-exceptions
            # evmone uses vendor specific attributes without macro guards.
            # https://github.com/ethereum/evmone/blob/master/CMakeLists.txt#L62-L66
            $<$<CXX_COMPILER_ID:GNU>:-Wno-attributes>
            $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-unknown-attributes>
  )
endif()

if(SILKWORM_CORE_USE_ABSEIL)
  # Propagate SILKWORM_CORE_USE_ABSEIL to allow using Silkworm's preferred FlatHashMap.
  find_package(absl REQUIRED)
  target_compile_definitions(evmone PRIVATE SILKWORM_CORE_USE_ABSEIL)
  target_link_libraries(evmone PRIVATE absl::flat_hash_map)
endif()

if(AIRBENDER)
  target_compile_definitions(evmone PRIVATE AIRBENDER)
  target_include_directories(evmone PRIVATE
    ${CMAKE_SOURCE_DIR}/prover/guest_airbender/src/include
    ${CMAKE_SOURCE_DIR}/zilk_core
  )
  set(EVMONE_PRECOMPILES_LIBSECP256K1 ON CACHE BOOL "" FORCE)
endif()

# libsecp256k1: optimized ECDSA recovery (ecrecover precompile).
# Pure C, no ASM — cross-compiles for rv32im bare-metal.
if(EVMONE_PRECOMPILES_LIBSECP256K1)
  include(FetchContent)
  FetchContent_Declare(
    libsecp256k1
    URL https://github.com/bitcoin-core/secp256k1/archive/refs/tags/v0.7.1.tar.gz
    URL_HASH SHA256=958f204dbafc117e73a2604285dc2eb2a5128344d3499c114dcba5de54cb7a9e
  )
  set(BUILD_SHARED_LIBS_ORIG ${BUILD_SHARED_LIBS})
  set(BUILD_SHARED_LIBS OFF)
  set(SECP256K1_ENABLE_MODULE_ECDH OFF)
  set(SECP256K1_ENABLE_MODULE_RECOVERY ON)
  set(SECP256K1_ENABLE_MODULE_EXTRAKEYS OFF)
  set(SECP256K1_ENABLE_MODULE_SCHNORRSIG OFF)
  set(SECP256K1_ENABLE_MODULE_MUSIG OFF)
  set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF)
  set(SECP256K1_ASM OFF)
  set(SECP256K1_BUILD_TESTS OFF)
  set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF)
  set(SECP256K1_BUILD_CTIME_TESTS OFF)
  set(SECP256K1_BUILD_EXAMPLES OFF)
  set(SECP256K1_ENABLE_API_VISIBILITY_ATTRIBUTES OFF)
  set(SECP256K1_VALGRIND OFF)
  FetchContent_MakeAvailable(libsecp256k1)
  foreach(TARGET secp256k1 secp256k1_precomputed)
    set_target_properties(${TARGET} PROPERTIES
      COMPILE_OPTIONS $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-w>
    )
  endforeach()
  add_library(libsecp256k1::secp256k1 ALIAS secp256k1)
  target_link_libraries(evmone PRIVATE libsecp256k1::secp256k1)
  target_compile_definitions(evmone PUBLIC EVMONE_PRECOMPILES_LIBSECP256K1=1)
  set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_ORIG})
endif()

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/evmone/include
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/evmone/test/state
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/evmone/test
  FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/evmone/lib/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp"
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/evmone/lib/
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.h"
)

# EEST batched-RLP fixtures root. Populated by `make eest-rlp-build` or by CI's cache + bulk-convert step.
set(EEST_RLP_DIR "" CACHE PATH "EEST batched-RLP fixtures root")
