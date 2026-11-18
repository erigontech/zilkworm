# Copyright 2026 The Zilkworm Authors (modifications)
# Copyright 2025 The Original Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/compiler_settings_sanitize.cmake)

if(MSVC)

  message("MSVC_VERSION = ${MSVC_VERSION}")
  message("MSVC_CXX_ARCHITECTURE_ID = ${MSVC_CXX_ARCHITECTURE_ID}")

  # cmake-format: off

  add_compile_definitions(_WIN32_WINNT=0x0602)  # Min Windows 8
  add_compile_definitions(VC_EXTRALEAN)         # Process windows headers faster ...
  add_compile_definitions(WIN32_LEAN_AND_MEAN)  # ... and prevent winsock mismatch with Boost's
  add_compile_definitions(NOMINMAX)             # Prevent MSVC to tamper with std::min/std::max
  add_compile_definitions(PSAPI_VERSION=2)      # For process info

  # Avoids LNK1104 for libboost_date_time on MSVC.
  add_compile_definitions(BOOST_DATE_TIME_NO_LIB)


  add_compile_options(/MP)            # Enable parallel compilation
  add_compile_options(/EHa)           # Enable standard C++ unwinding
  add_compile_options(/await:strict)  # Enable coroutine support in std namespace

  # CLion mis-parses MSVC's file(line,column) diagnostics; the classic format works around it.
  add_compile_options(/diagnostics:classic)
  add_compile_options(/bigobj) # Increase .obj sections, needed for hard coded pre-verified hashes

  # Required for proper detection of __cplusplus
  add_compile_options(/Zc:__cplusplus)

  if(CMAKE_BUILD_TYPE MATCHES "Release")
    add_compile_options(/GL)
    set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} /LTCG")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /RELEASE")
  endif()

  if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /VERBOSE /TIME")
  endif()

  # cmake-format: on

elseif("${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU")

  # coroutines support
  if(NOT SILKWORM_WASM_API)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fcoroutines>)
  endif()

elseif("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$")

  if(SILKWORM_CLANG_COVERAGE)
    add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
    add_link_options(-fprofile-instr-generate -fcoverage-mapping)
  endif()

  # configure libc++ (skip for bare-metal cross-compilation)
  if(NOT SILKWORM_WASM_API AND NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
    # std::views::join is experimental on clang < 18 and Apple clang < 16
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 18)
      add_compile_options(-fexperimental-library)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 16)
      add_compile_options(-fexperimental-library)
    endif()
    link_libraries(c++)
    link_libraries(c++abi)
  endif()

else()
  message(WARNING "${CMAKE_CXX_COMPILER_ID} is not a supported compiler. Use at your own risk.")
endif()

if(SILKWORM_SANITIZE_COMPILER_OPTIONS)
  add_compile_options(${SILKWORM_SANITIZE_COMPILER_OPTIONS})
  add_link_options(${SILKWORM_SANITIZE_COMPILER_OPTIONS})
  add_compile_definitions(SILKWORM_SANITIZE)

  # asio's atomic_thread_fence is unsupported on GCC with thread sanitizer.
  if("${SILKWORM_SANITIZE}" STREQUAL "thread" AND "${CMAKE_CXX_COMPILER_ID}" MATCHES "GNU")
    add_compile_options(-Wno-error=tsan)
  endif()

  # MDBX triggers unaligned access errors in sanitizer builds
  add_compile_definitions(MDBX_UNALIGNED_OK=0)
endif()

# Position independent code
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

# Stack
set(SILKWORM_STACK_SIZE 0x1000000)

if(MSVC)
  add_link_options(/STACK:${SILKWORM_STACK_SIZE})
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,${SILKWORM_STACK_SIZE})
else()
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")
    add_link_options(-Wl,-z,stack-size=${SILKWORM_STACK_SIZE})
  endif()

  # https://clang.llvm.org/docs/SafeStack.html
  if("${CMAKE_CXX_COMPILER_ID}" MATCHES ".*Clang$"
     AND NOT SILKWORM_WASM_API
     AND NOT SILKWORM_SANITIZE
     AND NOT SILKWORM_FUZZER
     AND NOT CMAKE_SYSTEM_NAME STREQUAL "Generic"
  )
    add_compile_options(-fsanitize=safe-stack)
    add_link_options(-fsanitize=safe-stack)
  endif()
endif()

add_compile_definitions(SILKWORM_CAPI_COMPONENT)
