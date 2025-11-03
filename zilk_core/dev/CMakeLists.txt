# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(nlohmann_json REQUIRED)

set(LIBS_PRIVATE 
)

# cmake-format: off
set(LIBS_PUBLIC
    ethash::keccak
    nlohmann_json::nlohmann_json
    silkworm_core
)
# cmake-format: on

silkworm_library(
  silkworm_dev
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

# set_property(TARGET silkworm_dev APPEND PROPERTY
#   INTERFACE_LINK_LIBRARIES nlohmann_json::nlohmann_json)

## Enable it only for local testing due to gmp ld linking issue
if(NOT CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv32")
  add_subdirectory(cli)
endif()
