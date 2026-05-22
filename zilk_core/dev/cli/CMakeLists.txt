
# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0


add_executable(state_transition "runner.cpp")
target_link_libraries(state_transition PRIVATE silkworm_dev)

set(EEST_RLP_DIR  "" CACHE PATH "Directory of pre-converted batched-RLP EEST fixtures")
set(EEST_JSON_DIR "" CACHE PATH "Directory of raw EEST JSON fixtures")
if(EEST_RLP_DIR OR EEST_JSON_DIR)
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

if(EEST_RLP_DIR)
    _register_eest_tests(rlp  rlp  "${EEST_RLP_DIR}")
endif()
if(EEST_JSON_DIR)
    _register_eest_tests(json json "${EEST_JSON_DIR}")
endif()
