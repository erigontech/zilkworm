
# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0


# witness_trie / witness_input now live in zilk_core/core/types_zz/
# (silkworm_types_zz, brought in transitively via silkworm_core), alongside
# flat_bundle. silkworm_types_zz picks them up via its directory glob
# (GLOB_RECURSE), the same way it does the other types_zz sources.
add_executable(state_transition "runner.cpp")
target_link_libraries(state_transition PRIVATE silkworm_dev)

# ld64 (Apple) resolves the silkworm_core<->types_zz archive cycle globally; --start-group is GNU-ld-only.
if(APPLE)
    set(ZILK_CLI_TRIE_LIBS silkworm_dev silkworm_core silkworm_types_zz)
else()
    set(ZILK_CLI_TRIE_LIBS -Wl,--start-group silkworm_dev silkworm_core silkworm_types_zz -Wl,--end-group)
endif()

add_executable(json_witness_to_flat_bundle "json_witness_to_flat_bundle.cpp")
target_link_libraries(json_witness_to_flat_bundle PRIVATE ${ZILK_CLI_TRIE_LIBS})

# One-shot converter: legacy unifiedBlockAndStateRlp → flatWitnessBundle.
add_executable(legacy_to_flat_bundle "legacy_to_flat_bundle.cpp")
target_link_libraries(legacy_to_flat_bundle PRIVATE ${ZILK_CLI_TRIE_LIBS})

# EEST JSON → MFBD-wrapped FlatBundle converter. Two modes:
#   emit         --json <PATH> --index <N>          single subtest → stdout
#   bulk-convert --input-dir <D> --output-dir <D>   parallel mirror tree
# Uses silkworm::trie::HashBuilder (twice, with cross-verify) to build per-
# account storage roots + the global state root, captures the produced
# MPT nodes into the node-store, and assembles via build_flat_bundle.
add_executable(eest_to_flat_bundle "eest_to_flat_bundle.cpp")
target_link_libraries(eest_to_flat_bundle PRIVATE ${ZILK_CLI_TRIE_LIBS})

# mphf_map_test.cpp is a TU of the zilkworm.tests target (top-level CMakeLists.txt).

# Soundness regression: a witness whose flat keys omit an existing account or slot
# makes the EVM read it as empty, and check_root must reject it (flag-off: the
# walk of the claim that the key is absent; with -DUSE_HASH_KEY=ON the read
# recovers it instead). Standalone executable, exit code = failure count.
add_executable(witness_hide_node_test "witness_hide_node_test.cpp")
target_link_libraries(witness_hide_node_test PRIVATE ${ZILK_CLI_TRIE_LIBS})
if(BUILD_TESTING)
    add_test(NAME witness_hide_node_test COMMAND witness_hide_node_test)
endif()

# Regression: the MFBD runner's bundle cursor used to overshoot the envelope end
# (align8 of the last bundle's unaligned section end), wrapping the next span's
# extent; load_flat_bundle then read its header out of bounds. Standalone, exit
# code = failure count.
add_executable(mfbd_cursor_overshoot_test "mfbd_cursor_overshoot_test.cpp")
target_link_libraries(mfbd_cursor_overshoot_test PRIVATE ${ZILK_CLI_TRIE_LIBS})
if(BUILD_TESTING)
    add_test(NAME mfbd_cursor_overshoot_test COMMAND mfbd_cursor_overshoot_test)
endif()

# Regression: hostile input must fail through the kRunFailure sentinel, not escape
# run() as an exception (the guest entry has no handler; it used to reach
# std::terminate). Standalone, exit code = failure count.
add_executable(malformed_input_sentinel_test "malformed_input_sentinel_test.cpp")
target_link_libraries(malformed_input_sentinel_test PRIVATE ${ZILK_CLI_TRIE_LIBS})
if(BUILD_TESTING)
    add_test(NAME malformed_input_sentinel_test COMMAND malformed_input_sentinel_test)
endif()

# Regression: validate_block_header must reject a block whose parent_hash names
# a header with a number other than header.number - 1 (read_header looks up by
# hash alone). Standalone, exit code = failure count.
add_executable(parent_number_check_test "parent_number_check_test.cpp")
target_link_libraries(parent_number_check_test PRIVATE ${ZILK_CLI_TRIE_LIBS})
if(BUILD_TESTING)
    add_test(NAME parent_number_check_test COMMAND parent_number_check_test)
endif()

# file(GLOB STATE_TRANSITION_TESTS CONFIGURE_DEPENDS "state_transition_sample*.json")
# add_custom_command(
#   TARGET state_transition
#   POST_BUILD
#   COMMAND ${CMAKE_COMMAND} ARGS -E copy_if_different ${STATE_TRANSITION_TESTS} "${CMAKE_CURRENT_BINARY_DIR}"
# )

set(EEST_MFBD_DIR "" CACHE PATH "Directory of pre-converted MFBD EEST fixtures")
set(EEST_JSON_DIR "" CACHE PATH "Directory of raw EEST JSON fixtures")
if(EEST_MFBD_DIR OR EEST_JSON_DIR)
    if(NOT BUILD_TESTING)
        message(FATAL_ERROR "To enable state transition tests, please enable testing (e.g., -DBUILD_TESTING=ON)")
    endif()
endif()

# The EEST fixtures the runner is known to get wrong, see the list for why. Each is registered WILL_FAIL,
# so one that passes again fails ctest until it is taken off the list.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../eest-known-failures.txt" EEST_KNOWN_FAILURES REGEX "^[^#]")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../eest-known-failures.txt")

function(_register_eest_tests label ext fixtures_dir)
    file(GLOB_RECURSE files CONFIGURE_DEPENDS "${fixtures_dir}/*.${ext}")
    foreach(path ${files})
        file(RELATIVE_PATH rel "${fixtures_dir}" "${path}")
        set(test_name "state_transition/${label}/${rel}")
        add_test(NAME "${test_name}" COMMAND $<TARGET_FILE:state_transition> "${path}")
        set_tests_properties("${test_name}" PROPERTIES SKIP_RETURN_CODE 2)
        # The list names fixtures by their JSON path under blockchain_tests/.
        string(REGEX REPLACE "^blockchain_tests/" "" fixture "${rel}")
        string(REGEX REPLACE "\\.${ext}$" ".json" fixture "${fixture}")
        # The list describes the DirectState runner, which runs a test's blocks on one witness in
        # place; the HashState arm rebuilds the state from each block's own witness.
        if(fixture IN_LIST EEST_KNOWN_FAILURES AND NOT Z6M_HASH_STATE)
            set_tests_properties("${test_name}" PROPERTIES WILL_FAIL TRUE)
        endif()
    endforeach()
endfunction()

if(EEST_MFBD_DIR)
    _register_eest_tests(mfbd mfbd "${EEST_MFBD_DIR}")
endif()
if(EEST_JSON_DIR)
    _register_eest_tests(json json "${EEST_JSON_DIR}")
endif()
