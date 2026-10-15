// Host build of the Airbender guest's memcpy, memmove, memset and memcmp for mem_builtins_test.cpp:
// prover/guest_common/src/mem_builtins.cpp as Airbender builds it, with 4-byte words and the CSR
// MEMCOPY blocks. The functions are renamed so they do not replace the host libc's, and the CSR
// MEMCOPY the guest issues is the test's csr_memcopy32(), which checks the delegation's operand
// rules. The CMake target gives this file the guest's -fno-builtin and
// -fno-tree-loop-distribute-patterns, so the loops stay loops.
#define ZILK_MEM_NAME(name) zilk_guest_##name
#define ZILK_MEM_WORD uint32_t
#define ZILK_MEM_BLOCK32 1

// Overridable so an out-of-tree harness can point this wrapper at another copy of the file.
#ifndef ZILK_MEM_BUILTINS_SRC
#define ZILK_MEM_BUILTINS_SRC "../../../prover/guest_common/src/mem_builtins.cpp"
#endif
#include ZILK_MEM_BUILTINS_SRC
