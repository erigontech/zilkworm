#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0
"""extract.py SCRIPT PREFIX OUT

Copies the airbender_384 block (the BigInt-CSR Montgomery arithmetic that patch_blst_airbender.sh
splices into blst) out of the patch script, so that the host test compiles the exact text the
guest compiles. The CSR instruction becomes a call to the emulator in bigint_emu.h, the
fallback MUL_MONT_IMPL(384) include is dropped and every name is prefixed, so two versions of
the block can live in one translation unit.
"""
import re
import sys

src = open(sys.argv[1]).read()
pre = sys.argv[2]
m = re.search(r'airbender_384 = r"""(.*?)"""', src, re.S)
if m is None:
    sys.exit('no airbender_384 block in ' + sys.argv[1])
blk = m.group(1)
i = blk.index('limb_t _bls_csr(')
j = blk.index('{', i)
depth = 0
for k in range(j, len(blk)):
    if blk[k] == '{':
        depth += 1
    elif blk[k] == '}':
        depth -= 1
        if depth == 0:
            break
blk = blk[:j] + '{ return emu_csr(mut, immut, mask); }' + blk[k + 1:]
blk = re.sub(r'\bmul_mont_384\(', pre + '_mul_mont_384(', blk)
blk = re.sub(r'\bsqr_mont_384\(', pre + '_sqr_mont_384(', blk)
blk = re.sub(r'#else\s*\nMUL_MONT_IMPL\(384\)\s*\n#endif', '#endif', blk)
blk = blk.replace('#define _BLS_ALIGN32', '#undef _BLS_ALIGN32\n#define _BLS_ALIGN32')
for name in sorted(set(re.findall(r'\b(_bls_\w+)\b', blk)), key=len, reverse=True):
    blk = re.sub(r'\b%s\b' % name, pre + name, blk)
open(sys.argv[3], 'w').write(blk)
