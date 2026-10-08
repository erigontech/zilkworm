#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0
"""extract.py SCRIPT OUTDIR

Copies the two versions of cyclotomic_sqr_fp12 out of patch_blst_airbender.sh, so that the host
test compiles the exact text the guest compiles and the exact text of blst v0.3.17 it replaces:
  OUTDIR/base_block.inc  blst's original (old_cyclotomic), function renamed base_cyclotomic_sqr_fp12
  OUTDIR/cand_block.inc  the fused version, with the CSR instruction routed to the emulator in
                         bigint_emu.h and coverage counters spliced into the rare paths
"""
import os
import re
import sys

src = open(sys.argv[1]).read()
out = sys.argv[2]

m = re.search(r'old_cyclotomic = """(.*?)"""', src, re.S)
if m is None:
    sys.exit('no old_cyclotomic block in ' + sys.argv[1])
base = m.group(1)
assert base.count('cyclotomic_sqr_fp12(') == 1
base = base.replace('cyclotomic_sqr_fp12(', 'base_cyclotomic_sqr_fp12(')

m = re.search(r'new_cyclotomic = r"""(.*?)""" \+ old_cyclotomic', src, re.S)
if m is None:
    sys.exit('no new_cyclotomic block in ' + sys.argv[1])
blk = m.group(1)
head, tail = '#ifdef AIRBENDER_BIGINT_CSR\n', '#else\n'
if not (blk.startswith(head) and blk.endswith(tail)):
    sys.exit('new_cyclotomic is not wrapped in #ifdef AIRBENDER_BIGINT_CSR ... #else')
blk = blk[len(head):-len(tail)]

# the CSR instruction becomes a call to the emulator
i = blk.index('limb_t _cyc_csr(')
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


def splice(blk, pattern, repl):
    blk, n = re.subn(pattern, repl, blk, flags=re.M)
    if n != 1:
        sys.exit('coverage anchor not found exactly once: ' + pattern)
    return blk


# coverage: how often the out-of-line subtraction is called and taken, and the q estimates
blk = splice(blk, r'^(    limb_t tmp\[12\], borrow = 0;)$', r'\1 cov_reduce_calls++;')
blk = splice(blk, r'^(    if \(!?borrow\))$', r'    cov_reduce_taken += !borrow;\n\1')
blk = splice(blk, r'^(    q =\s+\(h3 >= .*;)$', r'\1 cov_q[q]++;')

os.makedirs(out, exist_ok=True)
open(os.path.join(out, 'base_block.inc'), 'w').write(base)
open(os.path.join(out, 'cand_block.inc'), 'w').write(blk)
