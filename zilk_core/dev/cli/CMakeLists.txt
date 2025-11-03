
# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0


add_executable(state_transition "runner.cpp")
target_link_libraries(state_transition PRIVATE silkworm_dev)
# file(GLOB STATE_TRANSITION_TESTS CONFIGURE_DEPENDS "state_transition_sample*.json")
# add_custom_command(
#   TARGET state_transition
#   POST_BUILD
#   COMMAND ${CMAKE_COMMAND} ARGS -E copy_if_different ${STATE_TRANSITION_TESTS} "${CMAKE_CURRENT_BINARY_DIR}"
# )
