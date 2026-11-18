# Post-link check: fails the build if the ELF holds a signed mulh, mulhsu, div or rem, which Airbender's machine decodes as illegal (the prover panics); source must keep such arithmetic unsigned. Allowlisted newlib/libgcc __sfvwrite_r and execute_stack_op run only on a failing guest.
#
cmake_minimum_required(VERSION 3.20)  # IN_LIST in script mode

# Run as: cmake -DOBJDUMP=<objdump> -DELF=<elf> -P check_unsigned_muldiv.cmake
set(allowed __sfvwrite_r execute_stack_op)

execute_process(
    COMMAND ${OBJDUMP} -d --no-show-raw-insn ${ELF}
    OUTPUT_VARIABLE disassembly
    RESULT_VARIABLE rc
)
if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${OBJDUMP} failed on ${ELF}")
endif()

# Function headers and signed M instructions, in address order.
string(REGEX MATCHALL "\n[0-9a-f]+ <[^>\n]+>:|\t(mulh|mulhsu|div|rem)\t[^\n]*" items "${disassembly}")

set(function "")
set(found "")
foreach(item IN LISTS items)
    if(item MATCHES "^\n[0-9a-f]+ <([^>]+)>:$")
        set(function "${CMAKE_MATCH_1}")
    elseif(NOT function IN_LIST allowed)
        string(STRIP "${item}" insn)
        string(APPEND found "\n  ${function}: ${insn}")
    endif()
endforeach()

if(found)
    message(FATAL_ERROR
        "${ELF} holds signed multiplies or divides, which Airbender's v3 machine cannot execute. "
        "Keep the arithmetic unsigned in these functions (e.g. a product of sizes in uint64_t):${found}")
endif()
