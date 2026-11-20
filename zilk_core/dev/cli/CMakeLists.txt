
# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0


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

add_executable(legacy_to_flat_bundle "legacy_to_flat_bundle.cpp")
target_link_libraries(legacy_to_flat_bundle PRIVATE ${ZILK_CLI_TRIE_LIBS})

# EEST JSON -> MFBD-wrapped FlatBundle converter.
add_executable(eest_to_flat_bundle "eest_to_flat_bundle.cpp")
target_link_libraries(eest_to_flat_bundle PRIVATE ${ZILK_CLI_TRIE_LIBS})

# mphf_map_test.cpp is a TU of the zilkworm.tests target (top-level CMakeLists.txt).

# Soundness regression: check_root must reject a witness whose flat keys omit an existing account or slot. Exit code = failure count.
add_executable(witness_hide_node_test "witness_hide_node_test.cpp")
target_link_libraries(witness_hide_node_test PRIVATE ${ZILK_CLI_TRIE_LIBS})
if(BUILD_TESTING)
    add_test(NAME witness_hide_node_test COMMAND witness_hide_node_test)
endif()

set(EEST_MFBD_DIR "" CACHE PATH "Directory of pre-converted MFBD EEST fixtures")
set(EEST_JSON_DIR "" CACHE PATH "Directory of raw EEST JSON fixtures")
if(EEST_MFBD_DIR OR EEST_JSON_DIR)
    if(NOT BUILD_TESTING)
        message(FATAL_ERROR "To enable state transition tests, please enable testing (e.g., -DBUILD_TESTING=ON)")
    endif()
endif()

# Known runner failures, each WILL_FAIL so one that passes again fails ctest until it is delisted.
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
        # The list describes the DirectState runner; the HashState arm rebuilds state from each block's own witness.
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
