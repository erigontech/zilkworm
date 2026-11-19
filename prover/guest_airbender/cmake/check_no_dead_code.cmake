# Post-link: fail if std::format or evmone's advanced interpreter returns (.rodata is copied per block).
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
