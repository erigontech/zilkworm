/* src/entry.S — minimal trampoline for stock crt0
 * -rv32im only (no CSR/WFI)
 * Requires from link.ld:  __stack_top  (top of RAM)
 * Optional: __global_pointer$  (if present, we'll set gp)
 */
    .section .text.entry
    .globl __entry
    .option  norvc

__entry:
    .cfi_startproc
    .cfi_undefined ra
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, __stack_top
    add s0, sp, zero
    jal zero, main
    .cfi_endproc
    .end