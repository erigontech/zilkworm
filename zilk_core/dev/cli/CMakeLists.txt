
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

# Soundness repro: a witness that omits an existing read-only account still
# passes check_root while the EVM reads it as empty. Standalone executable;
# fails until the hidden-node gap is fixed. Run:
#   build/zilk_core/dev/cli/witness_hide_node_test
add_executable(witness_hide_node_test "witness_hide_node_test.cpp")
target_link_libraries(witness_hide_node_test PRIVATE silkworm_core)

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

function(_register_eest_tests label ext fixtures_dir)
    file(GLOB_RECURSE files CONFIGURE_DEPENDS "${fixtures_dir}/*.${ext}")
    foreach(path ${files})
        file(RELATIVE_PATH rel "${fixtures_dir}" "${path}")
        set(test_name "state_transition/${label}/${rel}")
        add_test(NAME "${test_name}" COMMAND $<TARGET_FILE:state_transition> "${path}")
        set_tests_properties("${test_name}" PROPERTIES SKIP_RETURN_CODE 2)
    endforeach()
endfunction()

if(EEST_MFBD_DIR)
    _register_eest_tests(mfbd mfbd "${EEST_MFBD_DIR}")
endif()
if(EEST_JSON_DIR)
    _register_eest_tests(json json "${EEST_JSON_DIR}")
endif()
