# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS NO)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)

cmake_policy(SET CMP0063 NEW)
cmake_policy(SET CMP0074 NEW)

set(CMAKE_OSX_DEPLOYMENT_TARGET
    "15.0"
    CACHE STRING ""
)
