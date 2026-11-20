/* SP1 entry point: set gp and sp, then call __start (C++ runtime init, then main). */

    .section .text._start
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la      gp, __global_pointer$
    .option pop

    /* Stack top = 0x78000000 (SP1 convention). */
    li      sp, 0x78000000

    call    __start

    /* __start halts; if it ever returns, spin. */
1:  j       1b

    .size _start, . - _start
