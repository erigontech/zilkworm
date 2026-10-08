#!/usr/bin/env python3

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""
ZisK emulator runner for the z6m ZisK guest.

Frames each input as ziskemu expects ([u64 LE len][raw][pad to 8], loaded at
INPUT_ADDR+8), runs ziskemu on the guest ELF, decodes the 112-byte public
values from the -o file and compares them byte-for-byte with the native
runner's `Public Values:` line.

With --prover, each input runs through the z6m_prover_zisk host
(`execute`, zisk-sdk) instead of ziskemu; its `Public Values:` and
`cycles=` lines take the place of the .out file and the steps line.

Writes <log-dir>/results.tsv, per-input .out/.log/.native.log files and
<log-dir>/summary.log. Exits 1 on any MISMATCH or ERROR.

Usage:
    python3 zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf \\
        --dir temp/runtime/zisk_corpus --native build/zilk_core/dev/cli/state_transition
    python3 zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf \\
        --eest-dir <mfbd>/blockchain_tests --filter cancun -j 16
    python3 zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf \\
        --dir temp/runtime/zisk_corpus --prover prover/prover_zisk/target/release/z6m_prover_zisk \\
        -j 2 --threads 7
"""

import argparse
import hashlib
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

PV_LEN = 112
OUT_LEN = 256
RUN_FAILURE = (1 << 64) - 1
RUN_SKIPPED = (1 << 64) - 2
PV_FIELDS = (("gas_used", 0, 8), ("pre_state_root", 8, 40), ("post_state_root", 40, 72),
             ("block_hash", 72, 104), ("chain_id", 104, 112))
STATUSES = ("PASS", "FAIL", "SKIP", "MISMATCH", "ERROR")

STEPS_RE = re.compile(r"process_rom\(\) steps=(\d+)")
HALT_ERROR_RE = re.compile(r"finished with error at step=(\d+) pc=(0x[0-9a-fA-F]+)")
NATIVE_PV_RE = re.compile(r"Public Values: 0x([0-9a-fA-F]{224})\b")
NATIVE_GAS_RE = re.compile(r"^Cumulative Gas Used: (\d+)", re.M)
NATIVE_FAIL_RE = re.compile(r"^FAIL: ", re.M)
NATIVE_SKIP_RE = re.compile(r"^SKIP: ", re.M)
PROVER_ERROR_RE = re.compile(r"^Error: (.+)$", re.M)
PROVER_STEPS_RE = re.compile(r"^(?:Executed|FAILED|SKIPPED) block \d+ \(.*?cycles=(\d+)", re.M)


@dataclass
class Input:
    path: str
    rel: str
    name: str


@dataclass
class Result:
    inp: Input
    status: str = "ERROR"
    gas: Optional[int] = None
    steps: Optional[int] = None
    pv: Optional[bytes] = None
    native_pv: Optional[bytes] = None
    reason: str = ""


def fmt(n: Optional[int]) -> str:
    return "-" if n is None else f"{n:,}"


def classify(gas: int) -> str:
    if gas == RUN_FAILURE:
        return "FAIL"
    if gas == RUN_SKIPPED:
        return "SKIP"
    return "PASS"


# -- Discovery ----------------------------------------------------------------

def log_name(rel: str) -> str:
    name = rel[:-len(".mfbd")] if rel.endswith(".mfbd") else rel
    name = name.replace(os.sep, "--")
    if len(name) > 200:  # keep under NAME_MAX with suffixes
        name = name[:180] + "-" + hashlib.sha1(rel.encode()).hexdigest()[:12]
    return name


def discover_corpus(data_dir: str) -> List[Input]:
    """<dir>/<N>/flatWitnessBundle<N>.mfbd, sorted by block number."""
    found = []
    for entry in os.listdir(data_dir):
        if not entry.isdigit():
            continue
        f = os.path.join(data_dir, entry, f"flatWitnessBundle{entry}.mfbd")
        if os.path.isfile(f):
            found.append((int(entry), Input(f, os.path.relpath(f, data_dir), entry)))
    return [inp for _, inp in sorted(found, key=lambda t: t[0])]


def discover_eest(root: str) -> List[Input]:
    found = []
    for d, _, files in os.walk(root):
        for fn in files:
            if fn.endswith(".mfbd"):
                f = os.path.join(d, fn)
                rel = os.path.relpath(f, root)
                found.append(Input(f, rel, log_name(rel)))
    found.sort(key=lambda i: i.rel)
    return found


# -- Execution ----------------------------------------------------------------

def write_framed(src: str, dst: str) -> None:
    """ZiskStdin::write_slice layout: [u64 LE len][raw][pad to 8]."""
    n = os.path.getsize(src)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(struct.pack("<Q", n))
        shutil.copyfileobj(fi, fo, 1 << 20)
        if fo.tell() != 8 + n:
            raise OSError(f"{src} changed while framing")
        fo.write(b"\0" * (-(8 + n) % 8))


def run_logged(cmd: List[str], log_path: str, timeout: int, env: Dict[str, str],
               src: str) -> Tuple[Optional[int], str]:
    """Run cmd with stdout+stderr into log_path. rc is None on timeout."""
    with open(log_path, "wb") as log:
        log.write(f"# input: {src}\n$ {shlex.join(cmd)}\n".encode())
        log.flush()
        try:
            rc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=log,
                                stderr=subprocess.STDOUT, timeout=timeout, env=env).returncode
        except subprocess.TimeoutExpired:
            rc = None
    with open(log_path, "rb") as log:
        return rc, log.read().decode("utf-8", "replace")


def run_zisk(args, inp: Input, res: Result, env: Dict[str, str]) -> str:
    """Run ziskemu on one input; return an error reason or ''."""
    out = os.path.join(args.log_dir, inp.name + ".out")
    if os.path.exists(out):
        os.remove(out)
    framed = None
    if args.legacy_inputs:
        input_args = ["--legacy-inputs", inp.path]
    else:
        framed = os.path.join(args.log_dir, inp.name + ".in")
        write_framed(inp.path, framed)
        input_args = ["-i", framed]
    cmd = args.ziskemu + ["-e", args.elf, *input_args, "-o", out, "-m"]
    if args.max_steps:
        cmd += ["-n", str(args.max_steps)]
    if args.stats:
        cmd.append("-X")
    try:
        rc, text = run_logged(cmd, os.path.join(args.log_dir, inp.name + ".log"),
                              args.timeout, env, inp.path)
    finally:
        if framed:
            os.remove(framed)

    m = STEPS_RE.search(text)
    res.steps = int(m.group(1)) if m else None
    if rc is None:
        return f"ziskemu timeout after {args.timeout}s"
    if rc != 0:
        return f"ziskemu rc={rc}"
    if not os.path.isfile(out):
        return "missing .out"
    with open(out, "rb") as f:
        data = f.read()
    if len(data) != OUT_LEN:
        return f".out is {len(data)} bytes, expected {OUT_LEN}"
    res.pv = data[:PV_LEN]
    res.gas = int.from_bytes(res.pv[:8], "little")
    # CHalt ends the run with rc 0
    halt = HALT_ERROR_RE.search(text)
    if halt:
        return f"halted with error at step={halt.group(1)} pc={halt.group(2)}"
    if any(data[PV_LEN:]):
        return f"nonzero output past byte {PV_LEN}"
    if not any(data):
        return "all-zero .out"
    return ""


def run_prover(args, inp: Input, res: Result, env: Dict[str, str]) -> str:
    """Run `z6m_prover_zisk execute` on one input; return an error reason or ''."""
    cmd = [args.prover, "--elf", args.elf, "execute", "--file-name", inp.path,
           "--data-dir", os.path.join(args.log_dir, "prover")]
    rc, text = run_logged(cmd, os.path.join(args.log_dir, inp.name + ".log"),
                          args.timeout, env, inp.path)
    m = PROVER_STEPS_RE.search(text)
    res.steps = int(m.group(1)) if m else None
    if rc is None:
        return f"prover timeout after {args.timeout}s"
    m = NATIVE_PV_RE.search(text)
    if not m:
        err = PROVER_ERROR_RE.search(text)
        return f"prover rc={rc}: " + (err.group(1) if err else "no Public Values line")
    res.pv = bytes.fromhex(m.group(1))
    res.gas = int.from_bytes(res.pv[:8], "little")
    if not any(res.pv):
        return "all-zero public values (guest aborted)"
    # Host exits 1 on FAILED blocks.
    want_rc = 1 if classify(res.gas) == "FAIL" else 0
    if rc != want_rc:
        return f"prover rc={rc}, expected {want_rc}"
    return ""


def run_native(args, inp: Input, res: Result,
               env: Dict[str, str]) -> Tuple[str, Optional[str]]:
    """Run the native runner; return (error reason, class)."""
    rc, text = run_logged([args.native, inp.path],
                          os.path.join(args.log_dir, inp.name + ".native.log"), args.timeout, env,
                          inp.path)
    if rc is None:
        return f"native timeout after {args.timeout}s", None
    m = NATIVE_PV_RE.search(text)
    if not m:
        return f"native rc={rc}, no Public Values line", None
    res.native_pv = bytes.fromhex(m.group(1))
    if NATIVE_FAIL_RE.search(text):
        return "", "FAIL"
    if NATIVE_SKIP_RE.search(text):
        return "", "SKIP"
    if NATIVE_GAS_RE.search(text):
        return "", "PASS"
    return f"native rc={rc}, no outcome line", None


def describe_mismatch(res: Result, zclass: str, nclass: str) -> str:
    parts = []
    if zclass != nclass:
        parts.append(f"class {zclass} vs native {nclass}")
    fields = [n for n, lo, hi in PV_FIELDS if res.pv[lo:hi] != res.native_pv[lo:hi]]
    if fields:
        parts.append("differs: " + ",".join(fields))
    return "; ".join(parts)


def run_one(args, inp: Input, env: Dict[str, str]) -> Result:
    res = Result(inp)
    try:
        reason = (run_prover if args.prover else run_zisk)(args, inp, res, env)
        native_reason, nclass = "", None
        if args.native:
            native_reason, nclass = run_native(args, inp, res, env)
    except OSError as e:
        res.reason = f"{type(e).__name__}: {e}"
        return res
    if reason or native_reason:
        res.reason = reason or native_reason
        return res
    zclass = classify(res.gas)
    if args.native and (res.pv != res.native_pv or zclass != nclass):
        res.status = "MISMATCH"
        res.reason = describe_mismatch(res, zclass, nclass)
    else:
        res.status = zclass
    return res


# -- Reporting ----------------------------------------------------------------

def progress_line(done: int, total: int, res: Result) -> str:
    gas = res.gas if res.gas is not None and res.gas < RUN_SKIPPED else None
    line = (f"  [{done}/{total}] {res.status:<8} {res.inp.rel}  "
            f"gas={fmt(gas)} steps={fmt(res.steps)}")
    return line + (f"  -- {res.reason}" if res.reason else "")


def write_tsv(results: List[Result], path: str) -> None:
    with open(path, "w") as f:
        f.write("file\tstatus\tgas\tsteps\tpv_hex\tnative_pv_hex\n")
        for r in results:
            f.write("\t".join([
                r.inp.rel, r.status,
                "" if r.gas is None else str(r.gas),
                "" if r.steps is None else str(r.steps),
                r.pv.hex() if r.pv else "",
                r.native_pv.hex() if r.native_pv else "",
            ]) + "\n")


def report(results: List[Result], log_dir: str) -> int:
    counts = {s: sum(1 for r in results if r.status == s) for s in STATUSES}
    lines = [
        "",
        "=" * 70,
        "  ZISK EXECUTE SUMMARY",
        "=" * 70,
    ]
    problems = [r for r in results if r.status in ("MISMATCH", "ERROR")]
    if problems:
        lines.append("  Problems:")
        lines += [f"    {r.status:<8} {r.inp.rel}  -- {r.reason}" for r in problems]
    lines += [
        f"  Results: {os.path.join(log_dir, 'results.tsv')}",
        f"  Logs:    {log_dir}",
        "=" * 70,
        f"Total: {len(results)}, Passed: {counts['PASS']}, Failed: {counts['FAIL']}, "
        f"Skipped: {counts['SKIP']}, Mismatch: {counts['MISMATCH']}, Error: {counts['ERROR']}",
    ]
    text = "\n".join(lines)
    print(text, flush=True)
    with open(os.path.join(log_dir, "summary.log"), "w") as f:
        f.write(text.lstrip("\n") + "\n")
    return counts["MISMATCH"] + counts["ERROR"]


# -- Main ---------------------------------------------------------------------

def resolve_ziskemu(arg: Optional[str]) -> List[str]:
    if arg:
        return shlex.split(arg)
    if os.environ.get("ZISKEMU"):
        return shlex.split(os.environ["ZISKEMU"])
    local = os.path.join(REPO_ROOT, "temp", "runtime", "zisk_target", "release", "ziskemu")
    return [local] if os.access(local, os.X_OK) else ["ziskemu"]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the ZisK guest under ziskemu and compare public values with native")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", help="Single .mfbd file")
    src.add_argument("--dir", help="Corpus dir of <N>/flatWitnessBundle<N>.mfbd")
    src.add_argument("--eest-dir", help="EEST fixtures tree, walked for *.mfbd")
    parser.add_argument("--elf", required=True, help="ZisK guest ELF")
    parser.add_argument("--filter", default=None,
                        help="Only run inputs whose relative path matches this regex")
    parser.add_argument("--native", default=None,
                        help="Native state_transition binary to compare against")
    parser.add_argument("--ziskemu", default=None,
                        help="ziskemu command prefix (default: $ZISKEMU, then "
                             "temp/runtime/zisk_target/release/ziskemu, then PATH)")
    parser.add_argument("-j", "--jobs", type=int, default=8, help="Parallel runs (default: 8)")
    parser.add_argument("--timeout", type=int, default=900,
                        help="Per-run timeout in seconds (default: 900)")
    parser.add_argument("--max-steps", type=int, default=None,
                        help="Pass -n to ziskemu (default: ziskemu's 2^36-1)")
    parser.add_argument("--log-dir", default=None,
                        help="Output dir (default: temp/zisk_execute)")
    parser.add_argument("--stats", action="store_true",
                        help="Pass -X to ziskemu (opcode/memory stats in the .log)")
    parser.add_argument("--legacy-inputs", action="store_true",
                        help="Let ziskemu frame the raw file (--legacy-inputs) instead of -i")
    parser.add_argument("--prover", default=None,
                        help="Run inputs through this z6m_prover_zisk host (zisk-sdk) "
                             "instead of ziskemu")
    parser.add_argument("--threads", type=int, default=None,
                        help="With --prover: RAYON_NUM_THREADS per host process "
                             "(the SDK emulates on 16 threads)")
    args = parser.parse_args()

    args.elf = os.path.abspath(args.elf)
    if not os.path.isfile(args.elf):
        print(f"ERROR: ELF not found: {args.elf}", file=sys.stderr)
        return 1
    if args.native:
        args.native = os.path.abspath(args.native)
        if not os.path.isfile(args.native) or not os.access(args.native, os.X_OK):
            print(f"ERROR: native runner not found: {args.native}", file=sys.stderr)
            return 1
    if args.prover:
        args.prover = os.path.abspath(args.prover)
        if not os.path.isfile(args.prover) or not os.access(args.prover, os.X_OK):
            print(f"ERROR: prover not found: {args.prover}", file=sys.stderr)
            return 1
        bad = [f for f, on in (("--ziskemu", args.ziskemu), ("--max-steps", args.max_steps),
                               ("--stats", args.stats), ("--legacy-inputs", args.legacy_inputs))
               if on]
        if bad:
            print(f"ERROR: {', '.join(bad)} only apply to ziskemu runs, not --prover",
                  file=sys.stderr)
            return 1
    else:
        if args.threads is not None:
            print("ERROR: --threads only applies with --prover", file=sys.stderr)
            return 1
        args.ziskemu = resolve_ziskemu(args.ziskemu)
        if not args.ziskemu or not shutil.which(args.ziskemu[0]):
            print(f"ERROR: ziskemu not found: {shlex.join(args.ziskemu)} "
                  f"(set --ziskemu or $ZISKEMU)", file=sys.stderr)
            return 1

    if args.input:
        if not os.path.isfile(args.input):
            print(f"ERROR: input not found: {args.input}", file=sys.stderr)
            return 1
        inputs = [Input(os.path.abspath(args.input), args.input,
                        log_name(os.path.basename(args.input)))]
    else:
        root = os.path.abspath(args.dir or args.eest_dir)
        if not os.path.isdir(root):
            print(f"ERROR: directory not found: {root}", file=sys.stderr)
            return 1
        inputs = discover_corpus(root) if args.dir else discover_eest(root)
    if args.filter:
        pat = re.compile(args.filter)
        inputs = [i for i in inputs if pat.search(i.rel)]
    if not inputs:
        print("ERROR: no inputs found", file=sys.stderr)
        return 1

    args.log_dir = os.path.abspath(args.log_dir or os.path.join(REPO_ROOT, "temp", "zisk_execute"))
    tmp_dir = os.path.join(args.log_dir, "tmp")
    os.makedirs(tmp_dir, exist_ok=True)
    env = dict(os.environ, TMPDIR=tmp_dir)
    if args.threads:
        env["RAYON_NUM_THREADS"] = str(args.threads)

    print("=" * 70)
    print(f"  ZisK Execute: {len(inputs)} inputs, jobs={args.jobs}")
    print("=" * 70)
    if args.prover:
        print(f"  Prover:  {args.prover} execute"
              f"{f' (RAYON_NUM_THREADS={args.threads})' if args.threads else ''}")
    else:
        print(f"  ziskemu: {shlex.join(args.ziskemu)}")
    print(f"  ELF:     {args.elf}")
    print(f"  Native:  {args.native or '(none)'}")
    if not args.prover:
        print(f"  Input:   {'--legacy-inputs' if args.legacy_inputs else '-i (framed)'}"
              f"{', -X' if args.stats else ''}"
              f"{f', -n {args.max_steps}' if args.max_steps else ''}")
    print(f"  Log dir: {args.log_dir}\n", flush=True)

    results: List[Optional[Result]] = [None] * len(inputs)
    pool = ThreadPoolExecutor(max_workers=max(1, args.jobs))
    try:
        futures = {pool.submit(run_one, args, inp, env): i for i, inp in enumerate(inputs)}
        for done, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            results[futures[fut]] = res
            print(progress_line(done, len(inputs), res), flush=True)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)

    write_tsv(results, os.path.join(args.log_dir, "results.tsv"))
    return 1 if report(results, args.log_dir) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(130)
