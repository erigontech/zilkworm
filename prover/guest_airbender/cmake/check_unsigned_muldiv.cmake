# Post-link check on the guest ELF: fails the build if it holds a signed multiply or divide.
#
# Airbender's v3 machine decodes RV32IM without the signed M instructions (mulh, mulhsu, div,
# rem): they decode as illegal, and the prover panics when it executes one. GCC has no option to
# leave them out of -march=rv32im code, and emits them for signed widening products and divisions
# (int64_t values derived from 32-bit sizes, signed divisions by constants), so the source must
# keep such arithmetic unsigned, and this check names any function that does not.
#
# The allowlisted functions come prebuilt from newlib and libgcc and run only on a failing guest:
# __sfvwrite_r writes to a stdio stream (assert and terminate messages), execute_stack_op unwinds
# an exception (the guest has none to catch).
#
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
