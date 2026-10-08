# Vendored from 0xPolygonHermez/zisk v1.3.1-alpha (306a9c93),
# ziskos/entrypoint/src/dma/memmove.s. Changed: .attribute 5 (guest -march), EOF newline.
# Copyright (c) 2025 SilentSig Switzerland GmbH
# SPDX-License-Identifier: MIT OR Apache-2.0
        .section ".note.GNU-stack","",@progbits
        .text
        .attribute      4, 16
        .attribute      5, "rv64im_zicsr_zba_zbb_zbs_zbkb"
        .globl  memmove
        .p2align        4
        .type   memmove,@function
memmove:
        csrs    0x813, a1                  # Marker: Write count (a2) to CSR 0x813
        add	x0,a0,a2
        ret        
        .size memmove, .-memmove
        .section .text.hot,"ax",@progbits
