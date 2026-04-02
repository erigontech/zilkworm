# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")
include(FetchContent)

FetchContent_Declare(
    magic_enum
    URL https://github.com/Neargye/magic_enum/releases/download/v0.9.7/magic_enum-v0.9.7.tar.gz
    URL_HASH SHA256=c047bc7ca0b76752168140e7ae9a4a30d72bf6530c196fdfbf5105a39d40cc46
    EXCLUDE_FROM_ALL
    SYSTEM
)
FetchContent_MakeAvailable(magic_enum)

FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
    URL_HASH SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa
    EXCLUDE_FROM_ALL
    SYSTEM
)
FetchContent_MakeAvailable(nlohmann_json)


if(SILKWORM_CORE_ONLY)
  if(MSVC)
    add_compile_options(/EHsc)
  else()
    add_compile_options(-fno-exceptions)
  endif()
endif()

set(SILKWORM_CORE_PUBLIC_LIBS
    evmc
    evmone
    intx::intx
    magic_enum::magic_enum
    # secp256k1
)
set(SILKWORM_CORE_PRIVATE_LIBS
    blst::blst
    nlohmann_json::nlohmann_json
)

silkworm_library(
  silkworm_core
  PUBLIC ${SILKWORM_CORE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_CORE_PRIVATE_LIBS}
)

target_compile_features(silkworm_core PUBLIC cxx_std_23)

if(EVMONE_PRECOMPILES_LIBSECP256K1)
  target_link_libraries(silkworm_core PRIVATE libsecp256k1::secp256k1)
endif()

# unit tests
# set(TEST_TARGET silkworm_core_test)

# if(SILKWORM_WASM_API)
#   # Stub clang exception handlers on WASM after Catch2 3.x due to https://github.com/WebAssembly/wasi-sdk/issues/329
#   target_sources(${TEST_TARGET} PRIVATE "${SILKWORM_MAIN_SRC_DIR}/wasm/exception_handling_stub.cpp")
#   # Skip generation of RPATH linker option for wasm-ld present by default after building Catch2 v3.6.0 from sources
#   set_target_properties(${TEST_TARGET} PROPERTIES SKIP_BUILD_RPATH TRUE)
# endif()

if(SILKWORM_CORE_ONLY)
  if(MSVC)
    target_compile_options(${TEST_TARGET} PRIVATE /EHa- /EHsc)
  else()
    target_compile_options(${TEST_TARGET} PRIVATE -fno-exceptions)
  endif()
endif()
