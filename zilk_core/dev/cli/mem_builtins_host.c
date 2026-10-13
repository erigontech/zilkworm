// Host build of the Airbender guest's memcpy, memmove, memset and memcmp for
// mem_builtins_test.cpp. The functions are renamed so they do not replace the host libc's, and the
// CSR MEMCOPY the guest issues is the test's csr_memcopy32(), which checks the delegation's operand
// rules. The CMake target gives this file the guest's -fno-builtin and
// -fno-tree-loop-distribute-patterns, so the byte loops stay loops.
#define memcpy zilk_guest_memcpy
#define memmove zilk_guest_memmove
#define memset zilk_guest_memset
#define memcmp zilk_guest_memcmp

// Overridable so an out-of-tree harness can point this wrapper at another copy of the file.
#ifndef ZILK_MEM_BUILTINS_SRC
#define ZILK_MEM_BUILTINS_SRC "../../../prover/guest_airbender/src/mem_builtins.c"
#endif
#include ZILK_MEM_BUILTINS_SRC
