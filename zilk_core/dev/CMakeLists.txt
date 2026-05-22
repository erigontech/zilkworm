# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

set(LIBS_PRIVATE
)

# cmake-format: off
set(LIBS_PUBLIC
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

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|aarch64|arm64)$")
  add_subdirectory(cli)
endif()
