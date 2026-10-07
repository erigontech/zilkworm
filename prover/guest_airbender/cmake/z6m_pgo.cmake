# Profile-guided optimization of the Airbender guest, driven by Z6M_PGO. pgo/README.md describes
# the profile and how to regenerate it.
#
#   OFF   No profile flag, source, macro, dependency or linker-script change.
#   GEN   Instrumented training build. pgo/gcov_dump.c prints the arc counters over the UART at the
#         end of a run; pgo/mkprofile.py turns the logs of the training runs into pgo/profile/,
#         pgo/manifest.txt and pgo/flags-*.txt.
#   USE   -fprofile-use with the committed profile. Configuring fails unless the profile was
#         recorded for exactly this source, compiler and set of compile flags.
#   AUTO  USE when that holds, otherwise OFF with a warning that says what differs. This is the
#         Makefile's default, so that an edit to a profiled file never breaks a build.
#
# Included by the root CMakeLists.txt (zilkworm subbuild: evmone, silkworm_*) and by
# prover/guest_airbender/CMakeLists.txt (z6m_guest), so both projects see one rule set.
#
# The profile does not depend on where the tree or the toolchain is installed:
# - Both stages pass --param=profile-func-internal-id=1, so a .gcda names each function by its
#   position in the translation unit. The default name of a function with internal linkage is a
#   hash of the absolute path of its source file and object, and -fprofile-prefix-map, which only
#   rewrites the file names written to .gcno notes, does not change it.
# - The other path-dependent field, the line checksum of each function (a hash of its line and of
#   the absolute name of its file), is zeroed in the committed .gcda files, and USE passes
#   -Wno-coverage-mismatch so that GCC ignores it. That also silences GCC's control-flow and
#   counter-count checks, which is why the manifest check below pins every input exactly.
# - Each project copies the .gcda files next to its objects, where GCC looks for them.
#
# Staleness: pgo/manifest.txt records the SHA-256 of every file the profiled translation units
# include (their sources, project headers, fetched headers and toolchain headers), of the compiler
# proper (cc1, cc1plus), and the list of profiled sources. pgo/flags-<project>.txt holds their
# compile flags as configured (CMAKE_<LANG>_FLAGS, target, directory, source and usage-requirement
# properties, with the tree and toolchain paths replaced by <root> and <toolchain>).

set(Z6M_PGO "OFF" CACHE STRING "Profile-guided optimization of the guest: OFF, GEN, USE or AUTO")
set_property(CACHE Z6M_PGO PROPERTY STRINGS OFF GEN USE AUTO)
if(NOT Z6M_PGO MATCHES "^(OFF|GEN|USE|AUTO)$")
  message(FATAL_ERROR "Z6M_PGO must be OFF, GEN, USE or AUTO, not '${Z6M_PGO}'")
endif()

get_filename_component(Z6M_PGO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
set(Z6M_PGO_DIR "${Z6M_PGO_ROOT}/prover/guest_airbender/pgo")

# Only GEN changes the build before the deferred step below: the guest's GEN-only link script,
# dump hook and libgcov (prover/guest_airbender/CMakeLists.txt).
set(Z6M_PGO_LIBS "")
if(Z6M_PGO STREQUAL "GEN")
  set(Z6M_PGO_LIBS gcov)
endif()

set(Z6M_PGO_GEN_OPTIONS -fprofile-arcs -fprofile-update=single -fprofile-info-section
                        --param=profile-func-internal-id=1)
# Partial training keeps the functions the training never ran optimized for speed, not size.
# Value profiling stays off: the guest has a 1-cycle divide and the value profilers would need
# calloc. -Wno-coverage-mismatch: see above. -Werror=missing-profile: a profiled source without its
# .gcda, or a function missing from it, stops the build.
set(Z6M_PGO_USE_OPTIONS -fprofile-use -fprofile-partial-training -fno-profile-values
                        --param=profile-func-internal-id=1 -Wno-coverage-mismatch -Werror=missing-profile)
set(Z6M_PGO_USE_LINK_OPTIONS -fprofile-use -fprofile-partial-training -fno-profile-values)

# The runtime and the dump hook are never instrumented.
set(Z6M_PGO_RUNTIME_REGEX "/(main\\.cpp|airbender_runtime\\.cpp|runtime_stubs\\.c|gcov_dump\\.c)$")
# Cold files, left out of both stages: instrumenting every file overflows the 4 MiB ROM.
set(Z6M_PGO_COLD_REGEX "/(state_transition|bal|secp256r1|mphf_builder|advanced_instructions|advanced_execution|advanced_analysis|system_contracts|genesis[a-z_]*|bls|ethash_rule_set|direct_state_builder|eip_7685_requests|ripemd160|validation|evmc_bytes32|kzg[a-z_]*|tracing|witness_converter|test_util|blake2b)\\.cpp$")
# Compiled, but nothing in them is reachable from the guest: instrumentation leaves them without
# counters, so there is no profile to read.
set(Z6M_PGO_NO_COUNTERS_REGEX "/(common/assert|trie/prefix_set|types_zz/witness_trie)\\.cpp$")
# The interpreter and the file that holds its entry point are instrumented but stay unprofiled:
# with a profile dispatch_cgoto spills and costs 900M cycles on the corpus.
set(Z6M_PGO_UNPROFILED_REGEX "/lib/evmone/(baseline_execution|vm)\\.cpp$")

# z6m_pgo(KEY TARGET... [LINK EXECUTABLE]) profiles the sources of the TARGETs and, with LINK, adds
# the profile's link options to EXECUTABLE. KEY names the project in the manifest. The work runs at
# the end of the top-level directory, once every compile property is final.
function(z6m_pgo key)
  if(Z6M_PGO STREQUAL "OFF")
    return()
  endif()
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "LINK" "")
  # A deferred call evaluates its arguments when it runs, so they are spelled out here.
  cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${CMAKE_SOURCE_DIR}]] CALL _z6m_pgo_apply [[${key}]] [[${arg_LINK}]] ${arg_UNPARSED_ARGUMENTS})")
endfunction()

# Replaces the tree and toolchain paths in VAR by <root> and <toolchain> where a path starts with
# them (the root may also occur inside a path, as /build does in /build/prover/guest_airbender/build).
# A match consumes the delimiter after it, so a second pass catches a path right behind another.
macro(_z6m_pgo_normalize var)
  set(_z6m_pgo_text "\n${${var}}\n")
  foreach(_z6m_pgo_pass 1 2)
    foreach(_z6m_pgo_path toolchain root)
      string(REGEX REPLACE "([^A-Za-z0-9_.+@/-])${Z6M_PGO_${_z6m_pgo_path}_RE}([/;>\n])" "\\1<${_z6m_pgo_path}>\\2"
             _z6m_pgo_text "${_z6m_pgo_text}")
    endforeach()
  endforeach()
  string(REGEX REPLACE "^\n(.*)\n$" "\\1" ${var} "${_z6m_pgo_text}")
endmacro()

# Appends "NAME=value" for each property in ARGN of TARGET to text.
macro(_z6m_pgo_target_props target)
  foreach(prop ${ARGN})
    get_target_property(value ${target} ${prop})
    if(NOT value STREQUAL "value-NOTFOUND")
      string(APPEND text "  ${prop}=${value}\n")
    endif()
  endforeach()
endmacro()

# Sets OUT to the compile flags of TARGETS and of the profiled sources TUS: everything CMake puts on
# their compile lines, before the profile options are added.
function(_z6m_pgo_flags out targets tus)
  string(TOUPPER "${CMAKE_BUILD_TYPE}" config)
  set(text "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}\n")
  foreach(target IN LISTS targets)
    string(APPEND text "target ${target}\n")
    get_target_property(dir ${target} SOURCE_DIR)
    foreach(var CMAKE_C_FLAGS CMAKE_CXX_FLAGS CMAKE_C_FLAGS_${config} CMAKE_CXX_FLAGS_${config})
      get_directory_property(value DIRECTORY "${dir}" DEFINITION ${var})
      string(APPEND text "  ${var}=${value}\n")
    endforeach()
    get_directory_property(value DIRECTORY "${dir}" COMPILE_DEFINITIONS)
    string(APPEND text "  directory COMPILE_DEFINITIONS=${value}\n")
    _z6m_pgo_target_props(${target} COMPILE_OPTIONS COMPILE_DEFINITIONS COMPILE_FLAGS INCLUDE_DIRECTORIES
      COMPILE_FEATURES C_STANDARD C_EXTENSIONS CXX_STANDARD CXX_EXTENSIONS CXX_STANDARD_REQUIRED
      POSITION_INDEPENDENT_CODE INTERPROCEDURAL_OPTIMIZATION C_VISIBILITY_PRESET CXX_VISIBILITY_PRESET
      VISIBILITY_INLINES_HIDDEN)
    # Usage requirements of every target it links, transitively.
    get_target_property(queue ${target} LINK_LIBRARIES)
    set(seen "")
    while(queue)
      list(POP_FRONT queue dep)
      if(NOT TARGET "${dep}" OR dep IN_LIST seen)
        continue()
      endif()
      list(APPEND seen "${dep}")
      string(APPEND text "  uses ${dep}\n")
      _z6m_pgo_target_props(${dep} INTERFACE_COMPILE_OPTIONS INTERFACE_COMPILE_DEFINITIONS
        INTERFACE_INCLUDE_DIRECTORIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES INTERFACE_COMPILE_FEATURES
        INTERFACE_POSITION_INDEPENDENT_CODE SYSTEM INTERFACE_LINK_LIBRARIES)
      get_target_property(next ${dep} INTERFACE_LINK_LIBRARIES)
      if(next)
        list(APPEND queue ${next})
      endif()
    endwhile()
  endforeach()
  foreach(item IN LISTS tus)
    string(REPLACE "|" ";" item "${item}")
    list(GET item 1 target)
    list(GET item 2 src)
    string(APPEND text "source ${target} ${src}\n")
    foreach(prop COMPILE_OPTIONS COMPILE_DEFINITIONS COMPILE_FLAGS INCLUDE_DIRECTORIES LANGUAGE)
      get_source_file_property(value "${src}" TARGET_DIRECTORY ${target} ${prop})
      if(NOT value STREQUAL "NOTFOUND")
        string(APPEND text "  ${prop}=${value}\n")
      endif()
    endforeach()
  endforeach()
  _z6m_pgo_normalize(text)
  set(${out} "${text}" PARENT_SCOPE)
endfunction()

# Sets REASONS to what keeps the committed profile from applying to this project: the compiler,
# the profiled sources (TUS, "flat-name|source" items), an input file or the flags (FLAGS) differ.
function(_z6m_pgo_check key tus flags reasons_out)
  set(reasons "")
  set(manifest "${Z6M_PGO_DIR}/manifest.txt")
  if(NOT EXISTS "${manifest}")
    set(${reasons_out} "there is no committed profile (no ${manifest})" PARENT_SCOPE)
    return()
  endif()
  file(STRINGS "${manifest}" lines REGEX "^[a-z]")

  # The compiler proper: its version line and the SHA-256 of cc1 and cc1plus.
  execute_process(COMMAND "${CMAKE_CXX_COMPILER}" --version OUTPUT_VARIABLE version OUTPUT_STRIP_TRAILING_WHITESPACE)
  string(REGEX REPLACE "\n.*" "" version "${version}")
  set(have_tools "compiler ${version}")
  foreach(tool cc1 cc1plus)
    execute_process(COMMAND "${CMAKE_CXX_COMPILER}" -print-prog-name=${tool} OUTPUT_VARIABLE path OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(EXISTS "${path}")
      file(SHA256 "${path}" hash)
    else()
      set(hash "missing")
    endif()
    list(APPEND have_tools "tool ${tool} ${hash}")
  endforeach()
  set(want_tools "${lines}")
  list(FILTER want_tools INCLUDE REGEX "^(compiler|tool) ")
  set(differ "")
  foreach(item IN LISTS have_tools)
    if(NOT item IN_LIST want_tools)
      list(APPEND differ "'${item}'")
    endif()
  endforeach()
  if(differ)
    list(JOIN differ ", " differ)
    list(JOIN want_tools "', '" want_tools)
    list(APPEND reasons "the compiler differs: this build has ${differ}, the profile was recorded with '${want_tools}'")
  endif()

  # The profiled sources of this project.
  set(want_tus "${lines}")
  list(FILTER want_tus INCLUDE REGEX "^tu ${key} ")
  list(TRANSFORM want_tus REPLACE "^tu ${key} ([^ ]+) (.*)$" "\\1|<root>/\\2")
  set(have_tus "${tus}")
  list(TRANSFORM have_tus REPLACE "^([^|]*)[|][^|]*[|]([^|]*)[|].*$" "\\1|\\2")
  _z6m_pgo_normalize(have_tus)
  list(SORT want_tus)
  list(SORT have_tus)
  if(NOT want_tus STREQUAL have_tus)
    set(added "${have_tus}")
    list(REMOVE_ITEM added ${want_tus})
    set(removed "${want_tus}")
    list(REMOVE_ITEM removed ${have_tus})
    list(TRANSFORM added REPLACE "^[^|]*[|]<root>/" "")
    list(TRANSFORM removed REPLACE "^[^|]*[|]<root>/" "")
    list(JOIN added ", " added)
    list(JOIN removed ", " removed)
    set(what "")
    if(added)
      string(APPEND what " (new: ${added})")
    endif()
    if(removed)
      string(APPEND what " (gone: ${removed})")
    endif()
    list(APPEND reasons "the set of profiled sources differs${what}")
  endif()
  foreach(tu IN LISTS want_tus)
    string(REGEX REPLACE "[|].*" "" flat "${tu}")
    if(NOT EXISTS "${Z6M_PGO_DIR}/profile/${flat}")
      list(APPEND reasons "pgo/profile/${flat} is missing")
    endif()
  endforeach()

  # Every file the profiled translation units include.
  set(changed "")
  set(n 0)
  foreach(line IN LISTS lines)
    if(line MATCHES "^(src|sys) ([0-9a-f]+) (.*)$")
      if(CMAKE_MATCH_1 STREQUAL "src")
        set(path "${Z6M_PGO_ROOT}/${CMAKE_MATCH_3}")
      else()
        set(path "${Z6M_PGO_TOOLCHAIN}/${CMAKE_MATCH_3}")
      endif()
      set(want "${CMAKE_MATCH_2}")
      set(name "${CMAKE_MATCH_3}")
      math(EXPR n "${n} + 1")
      set(hash "missing")
      if(EXISTS "${path}")
        file(SHA256 "${path}" hash)
      endif()
      if(NOT hash STREQUAL want)
        list(APPEND changed "${name}")
      endif()
    endif()
  endforeach()
  if(changed)
    list(LENGTH changed count)
    list(SUBLIST changed 0 8 shown)
    if(count GREATER 8)
      list(APPEND shown "...")
    endif()
    list(JOIN shown ", " shown)
    list(APPEND reasons "${count} of the ${n} files the profiled sources include changed since the profile was recorded: ${shown}")
  endif()

  # The compile flags.
  set(recorded "${Z6M_PGO_DIR}/flags-${key}.txt")
  if(NOT EXISTS "${recorded}")
    list(APPEND reasons "pgo/flags-${key}.txt is missing")
  else()
    file(READ "${recorded}" want_flags)
    if(NOT want_flags STREQUAL flags)
      list(APPEND reasons "the compile flags of the profiled sources differ: compare ${CMAKE_BINARY_DIR}/z6m_pgo/flags-${key}.txt with pgo/flags-${key}.txt")
    endif()
  endif()
  set(${reasons_out} "${reasons}" PARENT_SCOPE)
endfunction()

function(_z6m_pgo_apply key link_target)
  set(targets ${ARGN})
  get_filename_component(Z6M_PGO_TOOLCHAIN "${CMAKE_CXX_COMPILER}" DIRECTORY)
  get_filename_component(Z6M_PGO_TOOLCHAIN "${Z6M_PGO_TOOLCHAIN}/.." REALPATH)
  # Both as regular expressions, for _z6m_pgo_normalize.
  string(REGEX REPLACE "([][+.*()^$?|\\\\])" "\\\\\\1" Z6M_PGO_root_RE "${Z6M_PGO_ROOT}")
  string(REGEX REPLACE "([][+.*()^$?|\\\\])" "\\\\\\1" Z6M_PGO_toolchain_RE "${Z6M_PGO_TOOLCHAIN}")

  # The instrumented sources (GEN) and, of those, the profiled ones (USE), as
  # "flat profile name|target|source|.gcda path" items.
  set(gen_sources "")
  set(tus "")
  foreach(target IN LISTS targets)
    get_target_property(src_dir ${target} SOURCE_DIR)
    get_target_property(bin_dir ${target} BINARY_DIR)
    get_target_property(sources ${target} SOURCES)
    foreach(src IN LISTS sources)
      if(NOT src MATCHES "\\.(c|cpp)$" OR src MATCHES "[$]")
        continue()
      endif()
      cmake_path(ABSOLUTE_PATH src BASE_DIRECTORY "${src_dir}" NORMALIZE OUTPUT_VARIABLE abs)
      if(abs MATCHES "${Z6M_PGO_RUNTIME_REGEX}" OR abs MATCHES "${Z6M_PGO_COLD_REGEX}" OR
         abs MATCHES "${Z6M_PGO_NO_COUNTERS_REGEX}")
        continue()
      endif()
      list(APPEND gen_sources "${target}|${abs}")
      if(abs MATCHES "${Z6M_PGO_UNPROFILED_REGEX}")
        continue()
      endif()
      # GCC reads <object without its suffix>.gcda, next to the object. The committed copy has a
      # flat name: the build directories hold CMakeFiles, which .gitignore skips.
      file(RELATIVE_PATH rel "${src_dir}" "${abs}")
      set(gcda "${bin_dir}/CMakeFiles/${target}.dir/${rel}.gcda")
      file(RELATIVE_PATH flat "${CMAKE_BINARY_DIR}" "${gcda}")
      if(flat MATCHES "[.][.]|[+|]")
        message(FATAL_ERROR "Z6M_PGO: no flat profile name for ${abs} (${flat})")
      endif()
      string(REPLACE "/" "+" flat "${key}/${flat}")
      list(APPEND tus "${flat}|${target}|${abs}|${gcda}")
    endforeach()
  endforeach()

  _z6m_pgo_flags(flags "${targets}" "${tus}")
  file(WRITE "${CMAKE_BINARY_DIR}/z6m_pgo/flags-${key}.txt" "${flags}")

  if(Z6M_PGO STREQUAL "GEN")
    foreach(item IN LISTS gen_sources)
      string(REPLACE "|" ";" item "${item}")
      list(GET item 0 target)
      list(GET item 1 src)
      set_property(SOURCE "${src}" TARGET_DIRECTORY ${target} APPEND PROPERTY COMPILE_OPTIONS ${Z6M_PGO_GEN_OPTIONS})
    endforeach()
    if(link_target)
      target_link_options(${link_target} PRIVATE -fprofile-arcs)
    endif()
    return()
  endif()

  _z6m_pgo_check(${key} "${tus}" "${flags}" reasons)
  # An edit to the profile or to a profiled input re-runs this check before the next build, also
  # when a build tree is rebuilt without the Makefile.
  set(inputs "")
  if(EXISTS "${Z6M_PGO_DIR}/manifest.txt")
    file(STRINGS "${Z6M_PGO_DIR}/manifest.txt" inputs REGEX "^src ")
    list(TRANSFORM inputs REPLACE "^src [0-9a-f]+ " "${Z6M_PGO_ROOT}/")
  endif()
  set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${Z6M_PGO_DIR}/manifest.txt" "${Z6M_PGO_DIR}/flags-${key}.txt" ${inputs})
  if(reasons)
    list(JOIN reasons ";\n  " reasons)
    if(Z6M_PGO STREQUAL "USE")
      message(FATAL_ERROR "Z6M_PGO=USE: the committed profile does not match this build of ${key}:\n"
                          "  ${reasons}.\nRegenerate it (prover/guest_airbender/pgo/README.md), or "
                          "build with Z6M_PGO=AUTO or OFF.")
    endif()
    message(WARNING "Z6M_PGO=AUTO: building ${key} without the committed profile, because\n"
                    "  ${reasons}.\nRegenerate it (prover/guest_airbender/pgo/README.md) to build "
                    "the profiled guest; Z6M_PGO=OFF builds without it and without this warning.")
    return()
  endif()

  message(STATUS "Z6M_PGO=${Z6M_PGO}: building ${key} with the committed profile")
  foreach(item IN LISTS tus)
    string(REPLACE "|" ";" item "${item}")
    list(GET item 0 flat)
    list(GET item 1 target)
    list(GET item 2 src)
    list(GET item 3 gcda)
    configure_file("${Z6M_PGO_DIR}/profile/${flat}" "${gcda}" COPYONLY)
    set_property(SOURCE "${src}" TARGET_DIRECTORY ${target} APPEND PROPERTY OBJECT_DEPENDS "${gcda}")
    set_property(SOURCE "${src}" TARGET_DIRECTORY ${target} APPEND PROPERTY COMPILE_OPTIONS ${Z6M_PGO_USE_OPTIONS})
  endforeach()
  if(link_target)
    target_link_options(${link_target} PRIVATE ${Z6M_PGO_USE_LINK_OPTIONS})
  endif()
endfunction()
