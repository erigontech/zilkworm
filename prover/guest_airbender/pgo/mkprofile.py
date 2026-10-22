#!/usr/bin/env python3
"""Turns the training runs of a Z6M_PGO=GEN guest into the committed profile.

    pgo/mkprofile.py BUILD LOGDIR

BUILD is the build directory of the GEN guest (prover/guest_airbender/build), LOGDIR the output of
pgo/train.sh: blocks/b<block>.log for the blocks of pgo/train_blocks.txt, and eest.txt with an
eest/<test, '/' as '__'>.log per EEST test. The EEST tests used for training are half of them, the
ones whose name below for_<fork>/ has a SHA-256 with an even first byte (eest_training below), so
that a test and its copies for other forks fall in the same half and the other half stays unseen.
Writes, next to this script (or to --out):

- profile/<project>+<object path>.gcda: the merged arc counters of every profiled translation unit,
  under a flat name ('+' for '/'; the build directories hold CMakeFiles, which .gitignore skips).
- manifest.txt: the compiler, the profiled sources, and the SHA-256 of every file they include.
- flags-<project>.txt: the compile flags of the profiled sources, copied from BUILD.

Each log carries one gcov-tool merge-stream (a gcfn record and a gcda image per instrumented object,
in hex over the UART). The runs are added up, each run of a training set weighted by the set's
weight in WEIGHTS below. The result is made independent of where the GEN guest was built and when:
the time stamp, the object checksum and every function's line checksum (a hash of the absolute
source path) are zeroed, which cmake/z6m_pgo.cmake relies on. The object summary is what libgcov
would have written (the embedded dump writes none, and GCC 15 crashes at the LTO link on an empty
one), except that RUNS is fixed (see below).
"""
import argparse
import fractions
import glob
import hashlib
import os
import re
import struct
import subprocess
import sys

GCFN, GCDA = 0x6763666e, 0x67636461
FUNCTION, ARCS, SUMMARY = 0x01000000, 0x01a10000, 0xa1000000
HERE = os.path.dirname(os.path.abspath(__file__))
# Weight of one run of each training set: a block and an EEST test count the same.
WEIGHTS = {'blocks': 1, 'eest': 1}
# The summary's run count. GCC treats a block whose count is below RUNS / 20 as never executed
# (optimized for size and moved to .text.unlikely) and one at most RUNS as never hot. One run keeps
# every block that any training run reached out of the never-executed class.
RUNS = 1
# Instrumented but not profiled (cmake/z6m_pgo.cmake): the interpreter and vm.cpp.
UNPROFILED = re.compile(r'/lib/evmone/(baseline_execution|vm)\.cpp\.gcda$')


def eest_training(test):
    """Whether the EEST test (its path below blockchain_tests/) is in the training half."""
    return hashlib.sha256(test.split('/', 1)[1].encode()).digest()[0] % 2 == 0


def decode(log):
    """The merge-stream of one run, or None if the run did not reach the end of main."""
    text = open(log, errors='replace').read()
    if 'UART: `GCD-END`' not in text:
        return None
    return bytes.fromhex(''.join(re.findall(r'UART: `GCD:([0-9a-f]*)`', text)))


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def objects(stream):
    """Yields (gcda path, image) for each object of a merge-stream. The gcfn length word is the byte
    length of the name including its NUL, unpadded."""
    o = 0
    while o < len(stream):
        assert u32(stream, o) == GCFN
        n = u32(stream, o + 8)
        name = stream[o + 12:o + 12 + n].rstrip(b'\0').decode()
        o += 12 + n
        start = o
        assert u32(stream, o) == GCDA
        o += 16
        while u32(stream, o) != 0:
            length = u32(stream, o + 4)
            o += 8 + (0 if length >= 0x80000000 else length)
        o += 4
        yield name, stream[start:o]


def parse(image):
    """(version, [(ident, cfg checksum, [counter values])]) of a gcda image. A record of all-zero
    counters has a negative length and no payload."""
    version = u32(image, 4)
    fns, o = [], 16
    while True:
        tag = u32(image, o)
        if tag == 0:
            break
        length = u32(image, o + 4)
        o += 8
        if tag == FUNCTION:
            ident, _lineno, cfg = struct.unpack_from('<III', image, o)
            fns.append((ident, cfg, None))
        elif tag == ARCS:
            if length >= 0x80000000:
                values = [0] * ((0x100000000 - length) // 8)
            else:
                values = list(struct.unpack_from(f'<{length // 8}q', image, o))
            ident, cfg, old = fns[-1]
            assert old is None
            fns[-1] = (ident, cfg, values)
        elif tag != SUMMARY:
            sys.exit(f'unexpected gcda tag {tag:#x}')
        o += 0 if length >= 0x80000000 else length
    return version, fns


def write(path, version, fns, runs, sum_max):
    out = bytearray(struct.pack('<IIII', GCDA, version, 0, 0))
    out += struct.pack('<IIII', SUMMARY, 8, runs, sum_max & 0xffffffff)
    for ident, cfg, values in fns:
        out += struct.pack('<IIIII', FUNCTION, 12, ident, 0, cfg)
        if values is not None:
            if any(values):
                out += struct.pack('<II', ARCS, 8 * len(values)) + struct.pack(f'<{len(values)}q', *values)
            else:
                out += struct.pack('<II', ARCS, (0x100000000 - 8 * len(values)) & 0xffffffff)
    out += struct.pack('<I', 0)
    open(path, 'wb').write(out)


def flat_name(build, path):
    """<project>+<path in that project's build directory>, '+' for '/'."""
    for key, base in (('zilkworm', os.path.join(build, 'zilkworm')), ('guest', build)):
        if path.startswith(base + '/'):
            rel = os.path.relpath(path, base)
            assert '+' not in rel and not rel.startswith('..'), path
            return key + '+' + rel.replace('/', '+')
    sys.exit(f'{path} is not an object of the GEN build {build}: the logs come from another build')


def depfile_inputs(depfile):
    text = open(depfile).read().replace('\\\n', ' ')
    return text.split(':', 1)[1].split()


def sha256(path):
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('build')
    ap.add_argument('logdir')
    ap.add_argument('--blocks', default=os.path.join(HERE, 'train_blocks.txt'), help='training blocks (default: %(default)s)')
    ap.add_argument('--eest-weight', type=float, default=WEIGHTS['eest'], help='weight of one EEST run, 0 for none (default: %(default)s)')
    ap.add_argument('--runs', type=int, default=RUNS, help='summary run count (default: %(default)s)')
    ap.add_argument('--out', default=HERE, help='output directory (default: %(default)s)')
    args = ap.parse_args()
    # Only the ratio matters. Both weights are made integers: a counter rounded on its own would
    # leave the arc counts inconsistent, which GCC rejects as a corrupted profile.
    ratio = fractions.Fraction(args.eest_weight).limit_denominator(1000)
    WEIGHTS['blocks'], WEIGHTS['eest'] = ratio.denominator, ratio.numerator
    build, logdir, out_dir = os.path.realpath(args.build), args.logdir, args.out
    sets = [('blocks', [f'b{line.strip()}' for line in open(args.blocks) if line.strip()])]
    if WEIGHTS['eest']:
        tests = [line.strip() for line in open(os.path.join(logdir, 'eest.txt')) if line.strip()]
        sets.append(('eest', [t.replace('/', '__') for t in tests if eest_training(t)]))

    merged = {}   # flat name -> (version, [(ident, cfg, values)])
    sum_max = 0
    used = {}
    for kind, names in sets:
        weight = WEIGHTS[kind]
        used[kind] = 0
        for name in names:
            stream = decode(os.path.join(logdir, kind, name + '.log'))
            if stream is None:
                # A block must finish; an EEST test that fails or stops at the cycle limit is left out.
                if kind == 'blocks':
                    sys.exit(f'{kind}/{name}.log: no GCD-END, the run did not finish')
                continue
            used[kind] += 1
            run_max = 0
            for path, image in objects(stream):
                flat = flat_name(build, path)
                version, fns = parse(image)
                for _, _, values in fns:
                    run_max = max([run_max] + values)
                if flat not in merged:
                    merged[flat] = (version, [(i, c, None if v is None else [weight * x for x in v]) for i, c, v in fns])
                    continue
                mversion, mfns = merged[flat]
                assert mversion == version and len(mfns) == len(fns), flat
                for k, ((i, c, v), (mi, mc, mv)) in enumerate(zip(fns, mfns)):
                    assert (i, c) == (mi, mc) and (v is None) == (mv is None) and (v is None or len(v) == len(mv)), flat
                    if v is not None:
                        mfns[k] = (mi, mc, [a + weight * b for a, b in zip(mv, v)])
            sum_max += weight * run_max

    runs = ', '.join(f'{used[k]} {"block" if k == "blocks" else "EEST"} runs' for k, _ in sets)
    out = os.path.join(out_dir, 'profile')
    os.makedirs(out, exist_ok=True)
    for f in os.listdir(out):
        os.remove(os.path.join(out, f))
    tus, inputs = [], set()
    cxx = compiler(build)
    toolchain = os.path.realpath(os.path.join(os.path.dirname(cxx), '..'))
    for flat, (version, fns) in sorted(merged.items()):
        if UNPROFILED.search('/' + flat.replace('+', '/')):
            continue
        write(os.path.join(out, flat), version, fns, args.runs, sum_max)
        key, rel = flat.split('+', 1)
        objdir = os.path.join(build, 'zilkworm') if key == 'zilkworm' else build
        obj = os.path.join(objdir, rel.replace('+', '/'))[:-len('.gcda')] + '.obj'
        deps = depfile_inputs(obj + '.d')
        source = os.path.relpath(os.path.realpath(deps[0]), os.path.realpath(build_root(build)))
        tus.append(f'tu {key} {flat} {source}')
        for dep in deps:
            dep = os.path.realpath(dep)
            assert os.path.getmtime(dep) <= os.path.getmtime(obj), f'{dep} changed after the GEN build compiled {obj}'
            inputs.add(dep)

    root = os.path.realpath(build_root(build))
    lines = ['# The profile in profile/ was recorded for exactly these inputs; cmake/z6m_pgo.cmake checks them.',
             f'# Written by mkprofile.py from {runs}.']
    lines.append('compiler ' + subprocess.run([cxx, '--version'], capture_output=True, text=True, check=True).stdout.split('\n')[0])
    for tool in ('cc1', 'cc1plus'):
        path = subprocess.run([cxx, f'-print-prog-name={tool}'], capture_output=True, text=True, check=True).stdout.strip()
        lines.append(f'tool {tool} {sha256(path)}')
    lines += sorted(tus)
    for dep in sorted(inputs):
        if dep.startswith(root + '/'):
            lines.append(f'src {sha256(dep)} {os.path.relpath(dep, root)}')
        elif dep.startswith(toolchain + '/'):
            lines.append(f'sys {sha256(dep)} {os.path.relpath(dep, toolchain)}')
        else:
            sys.exit(f'{dep} is neither in the tree {root} nor in the toolchain {toolchain}')
    open(os.path.join(out_dir, 'manifest.txt'), 'w').write('\n'.join(lines) + '\n')
    for key, objdir in (('zilkworm', os.path.join(build, 'zilkworm')), ('guest', build)):
        flags = open(os.path.join(objdir, 'z6m_pgo', f'flags-{key}.txt')).read()
        open(os.path.join(out_dir, f'flags-{key}.txt'), 'w').write(flags)
    print(f'{len(tus)} profile files from {runs}; {len(inputs)} inputs in manifest.txt')


def compiler(build):
    """The C++ compiler of the GEN build."""
    for path in glob.glob(os.path.join(build, 'CMakeFiles', '*', 'CMakeCXXCompiler.cmake')):
        m = re.search(r'^set\(CMAKE_CXX_COMPILER "([^"]+)"\)', open(path).read(), re.M)
        if m:
            return m.group(1)
    sys.exit(f'no CMAKE_CXX_COMPILER in {build}/CMakeFiles/*/CMakeCXXCompiler.cmake')


def build_root(build):
    """The source tree of a build directory <root>/prover/guest_airbender/build."""
    return os.path.join(build, '..', '..', '..')


main()
