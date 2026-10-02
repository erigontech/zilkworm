# Vendored from 0xPolygonHermez/zisk v1.3.1-alpha (306a9c93),
# ziskos/entrypoint/src/dma/memcmp.s. Changed: .attribute 5 (guest -march), EOF newline.
# Copyright (c) 2025 SilentSig Switzerland GmbH
# SPDX-License-Identifier: MIT OR Apache-2.0
        .section ".note.GNU-stack","",@progbits
        .text
        .attribute      4, 16
        .attribute      5, "rv64im_zicsr_zba_zbb_zbs_zbkb"
        .globl  memcmp
        .p2align        4
        .type   memcmp,@function
memcmp:
        csrrs   a0,0x814, a1  # DMA memcmp: result -> a0, src -> a1
        add	x0,a0,a2      # Marker: dst (a0), count (a2)       
        ret
               
        .size memcmp, .-memcmp
        .section .text.hot,"ax",@progbits
