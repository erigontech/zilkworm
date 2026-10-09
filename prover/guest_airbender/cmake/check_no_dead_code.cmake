# Post-link check on the guest ELF: fails the build if code that nothing in the guest should reach
# has come back. The guest copies all of .rodata from ROM to RAM at the start of every block, so
# each of these clusters costs cycles in every block even though it never runs:
#   std::format  -> Ryu, the unicode tables, and the libstdc++ locale and facet machinery
#                   (about 0.5 MB of text and 190 KB of .rodata)
#   evmone's advanced interpreter, and its 32 KB instruction table, which only the "advanced"
#   VM option selects (compiled out with EVMONE_ADVANCED=0)
# Run as: cmake -DNM=<nm> -DELF=<elf> -P check_no_dead_code.cmake
execute_process(
    COMMAND ${NM} --demangle ${ELF}
    OUTPUT_VARIABLE symbols
    RESULT_VARIABLE rc
)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${NM} failed on ${ELF}")
endif()

set(dead_patterns
    "std::__format::"
    "ryu::"
    "std::__unicode::"
    "std::locale::_Impl::_Impl"
    "std::locale::locale\\(\\)"
    "evmone::advanced::"
)

set(found "")
foreach(pattern IN LISTS dead_patterns)
    string(REGEX MATCHALL "[^\n]*${pattern}[^\n]*" hits "${symbols}")
    if(hits)
        list(GET hits 0 first)
        list(LENGTH hits count)
        string(APPEND found "\n  ${pattern} -- ${count} symbols, e.g. ${first}")
    endif()
endforeach()

if(found)
    message(FATAL_ERROR
        "${ELF} links code that must stay out of the guest (std::format or a locale user in "
        "guest-reachable code?):${found}")
endif()
