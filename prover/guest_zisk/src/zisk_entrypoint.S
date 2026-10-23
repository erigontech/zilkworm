/* Copyright 2026 The Zilkworm Authors */
/* SPDX-License-Identifier: Apache-2.0 */

    .section .text.init,"ax",@progbits
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la      gp, _global_pointer
    .option pop

    la      sp, _init_stack_top

    /* Loader zero-fills .bss; no clearing needed. */
    call    __start

1:  j       1b

    .size _start, . - _start
