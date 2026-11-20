// Host build of the Airbender guest's mem builtins for mem_builtins_test.cpp, renamed so they do not replace libc's.
#define ZILK_MEM_NAME(name) zilk_guest_##name
#define ZILK_MEM_WORD uint32_t
#define ZILK_MEM_BLOCK32 1

// Overridable so an out-of-tree harness can point this wrapper at another copy of the file.
#ifndef ZILK_MEM_BUILTINS_SRC
#define ZILK_MEM_BUILTINS_SRC "../../../prover/guest_common/src/mem_builtins.cpp"
#endif
#include ZILK_MEM_BUILTINS_SRC
