# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# VS Code C++ Configuration Generator
# This script generates .vscode/c_cpp_properties.json automatically

function(generate_vscode_config)
    # Get all include directories from all targets
    get_property(all_targets DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY BUILDSYSTEM_TARGETS)
    
    set(all_include_dirs "")
    set(all_defines "")
    
    foreach(target ${all_targets})
        get_target_property(target_includes ${target} INCLUDE_DIRECTORIES)
        get_target_property(target_defines ${target} COMPILE_DEFINITIONS)
        get_target_property(target_interface_includes ${target} INTERFACE_INCLUDE_DIRECTORIES)
        
        if(target_includes)
            list(APPEND all_include_dirs ${target_includes})
        endif()
        
        if(target_interface_includes)
            list(APPEND all_include_dirs ${target_interface_includes})
        endif()
        
        if(target_defines)
            list(APPEND all_defines ${target_defines})
        endif()
    endforeach()
    
    # Add Conan include directories
    if(CMAKE_PREFIX_PATH)
        foreach(prefix_path ${CMAKE_PREFIX_PATH})
            if(EXISTS "${prefix_path}/include")
                list(APPEND all_include_dirs "${prefix_path}/include")
            endif()
        endforeach()
    endif()
    
    # Remove duplicates and convert to JSON format
    list(REMOVE_DUPLICATES all_include_dirs)
    list(REMOVE_DUPLICATES all_defines)
    
    # Convert paths to JSON array format
    set(json_includes "\"${CMAKE_SOURCE_DIR}/**\"")
    foreach(include_dir ${all_include_dirs})
        string(APPEND json_includes ",\n                \"${include_dir}\"")
    endforeach()
    
    # Convert defines to JSON array format
    set(json_defines "")
    list(LENGTH all_defines defines_count)
    if(defines_count GREATER 0)
        list(GET all_defines 0 first_define)
        set(json_defines "\"${first_define}\"")
        list(REMOVE_AT all_defines 0)
        foreach(define ${all_defines})
            string(APPEND json_defines ",\n                \"${define}\"")
        endforeach()
    endif()
    
    # Generate the JSON content
    set(vscode_config_content "{
    \"configurations\": [
        {
            \"name\": \"Linux\",
            \"includePath\": [
                ${json_includes}
            ],
            \"defines\": [
                ${json_defines}
            ],
            \"compilerPath\": \"${CMAKE_CXX_COMPILER}\",
            \"cStandard\": \"c17\",
            \"cppStandard\": \"gnu++20\",
            \"intelliSenseMode\": \"linux-gcc-x64\",
            \"compileCommands\": \"${CMAKE_BINARY_DIR}/compile_commands.json\"
        }
    ],
    \"version\": 4
}")
    
    # Write to .vscode/c_cpp_properties.json
    file(MAKE_DIRECTORY "${CMAKE_SOURCE_DIR}/.vscode")
    file(WRITE "${CMAKE_SOURCE_DIR}/.vscode/c_cpp_properties.json" "${vscode_config_content}")
    
    message(STATUS "Generated .vscode/c_cpp_properties.json with ${defines_count} defines and include directories")
endfunction()

# Call this function at the end of your main CMakeLists.txt
# generate_vscode_config()