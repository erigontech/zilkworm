# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Microsoft.GSL REQUIRED)
find_package(tl-expected REQUIRED)

# Gather test source files
file(GLOB TRIE_ZZ_TEST_SRC
    CONFIGURE_DEPENDS
    "*_test.cpp"
)

# Include grid_mpt.cpp implementation and other required source files
# Also include RLP implementation, ethash keccak, and common utility files needed for encoding
# Include hash_builder and nibbles for HashBuilder test
set(TRIE_ZZ_IMPL_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../grid_mpt.cpp
    ${SILKWORM_MAIN_DIR}/zilk_core/core/rlp/encode.cpp
    ${SILKWORM_MAIN_DIR}/zilk_core/core/rlp/decode.cpp
    ${SILKWORM_MAIN_DIR}/zilk_core/core/common/endian.cpp
    ${SILKWORM_MAIN_DIR}/zilk_core/core/common/util.cpp
    # ${SILKWORM_MAIN_DIR}/zilk_core/core/trie/hash_builder.cpp
    # ${SILKWORM_MAIN_DIR}/zilk_core/core/trie/nibbles.cpp
    # ${SILKWORM_MAIN_DIR}/zilk_core/core/trie/node.cpp
    ${SILKWORM_MAIN_DIR}/third_party/ethash/ethash/lib/keccak/keccak.c
)

# Create test executable
add_executable(trie_zz_test ${TRIE_ZZ_TEST_SRC} ${TRIE_ZZ_IMPL_SRC})

# Link against required libraries
target_link_libraries(trie_zz_test
    PRIVATE
        evmc
        Microsoft.GSL::GSL
        tl::expected
)

# Include directories
target_include_directories(trie_zz_test
    PRIVATE
        ${SILKWORM_MAIN_DIR}
        ${SILKWORM_MAIN_DIR}/silkworm
        ${SILKWORM_MAIN_DIR}/third_party/evmone/evmone/lib
        ${SILKWORM_MAIN_DIR}/third_party/intx/intx/include
        ${SILKWORM_MAIN_DIR}/third_party/ethash/ethash/include
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Enable C++20
target_compile_features(trie_zz_test PRIVATE cxx_std_20)

# Compiler options
if(NOT MSVC)
    target_compile_options(trie_zz_test PRIVATE
        -fno-exceptions
        -Wno-attributes
    )
endif()

# Register with CTest (if available)
if(BUILD_TESTING)
    include(CTest)
    add_test(NAME trie_zz_test COMMAND trie_zz_test)
endif()
