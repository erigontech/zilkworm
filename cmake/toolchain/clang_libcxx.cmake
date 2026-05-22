# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/cxx23.cmake)

# coroutines support
set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -stdlib=libc++"
    CACHE STRING "" FORCE
)
