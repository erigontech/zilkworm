#!/usr/bin/env python3

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""
Compare SP1-execution cycle / prover-gas counts between two `hypercube-eest`
runs (typically: this branch vs main).

Inputs are the raw run logs as produced by the workflow: each per-fixture
line is either
    `PASS <name>.json (gas_used=…, cycles=…, prover_gas=…, syscall_count=…)`
on the JSON-path branch, or
    `file <name>.rlp (cycles=…, prover_gas=…, syscall_count=…)`
on the RLP-path branch. Tests are paired by basename (the fork-prefix path
isn't carried in the per-line output — duplicates across forks are merged).

Fetch logs via:
    gh run view <id> --log > /tmp/run.log

Usage:
    python3 tools/scripts/compare_eest_cycles.py /tmp/main.log /tmp/branch.log
"""
import argparse
import re
import statistics
import sys

# `eest_runner.py` prefixes each prover stdout line with `[<shard>]`
# (e.g. `[berlin]`, `[stStaticCall]`). The same file basename exists under
# multiple forks (e.g. both `[osaka] test_invalid.rlp` and
# `[prague] test_invalid.rlp`), so the shard prefix is required to key tests
# uniquely. Without it, basename collisions silently merge unrelated tests.
RE_PASS = re.compile(
    r'\[([^\]]+)\] \[\d+/\d+\] PASS (\S+)\.(?:json|rlp) '
    r'\((?:gas_used=\d+, )?cycles=(\d+), prover_gas=(\d+), syscall_count=(\d+)\)'
)
RE_FILE = re.compile(
    r'\[([^\]]+)\] \[\d+/\d+\] file (\S+)\.(?:json|rlp) '
    r'\(cycles=(\d+), prover_gas=(\d+), syscall_count=(\d+)\)'
)


def parse(path: str) -> dict[tuple[str, str], tuple[int, int, int]]:
    """Parse cycles/prover_gas/syscalls keyed by (shard, file basename)."""
    out: dict[tuple[str, str], tuple[int, int, int]] = {}
    with open(path) as f:
        for line in f:
            m = RE_PASS.search(line) or RE_FILE.search(line)
            if m:
                key = (m.group(1), m.group(2))
                out[key] = (int(m.group(3)), int(m.group(4)), int(m.group(5)))
    return out


def fmt_int(n: int) -> str:
    return f"{n:>14,}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("baseline_log", help="Reference run (e.g. main).")
    ap.add_argument("candidate_log", help="Comparison run (e.g. this branch).")
    ap.add_argument("--top", type=int, default=10, help="How many speedups / regressions to list.")
    args = ap.parse_args()

    base = parse(args.baseline_log)
    cand = parse(args.candidate_log)
    common = sorted(set(base) & set(cand))
    if not common:
        print("ERROR: no common fixtures matched between the two logs", file=sys.stderr)
        return 1
    print(f"baseline tests: {len(base)}, candidate tests: {len(cand)}, common: {len(common)}")

    cyc_ratios: list[float] = []
    gas_ratios: list[float] = []
    cyc_b = cyc_c = gas_b = gas_c = 0
    biggest: list[tuple[float, tuple[str, str], int, int]] = []

    for key in common:
        bc, bg, _ = base[key]
        cc, cg, _ = cand[key]
        cyc_b += bc; cyc_c += cc
        gas_b += bg; gas_c += cg
        if bc:
            r = cc / bc
            cyc_ratios.append(r)
            biggest.append((r, key, bc, cc))
        if bg:
            gas_ratios.append(cg / bg)

    biggest.sort()

    def _pct(arr, p):
        if not arr: return 0.0
        s = sorted(arr)
        i = max(0, min(len(s) - 1, int(round(p / 100 * (len(s) - 1)))))
        return s[i]

    def _pct_row(label: str, arr: list[float]) -> None:
        if not arr:
            print(f"  {label:<11} (no data)")
            return
        cells = [f"{_pct(arr, p):.3f}" for p in (0, 1, 5, 10, 25, 50, 75, 90, 95, 99, 100)]
        gm = f"{statistics.geometric_mean(arr):.3f}"
        widths = [7, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5]
        formatted = " ".join(c.rjust(w) for c, w in zip(cells, widths))
        print(f"  {label:<11} {formatted}    {gm}")

    print("\n=== Per-test ratio distribution (candidate / baseline; <1 = candidate faster) ===")
    print(f"  metric         min     p1     p5    p10    p25 median    p75   p90   p95   p99   max   geo-mean")
    print("  " + "-" * 100)
    _pct_row("cycles",     cyc_ratios)
    _pct_row("prover_gas", gas_ratios)

    print("\n=== Aggregate totals ===")
    print(f"  cycles      : baseline={fmt_int(cyc_b)}  candidate={fmt_int(cyc_c)}  ratio={cyc_c/cyc_b:.3f}  ({(1-cyc_c/cyc_b)*100:+.1f}%)")
    print(f"  prover_gas  : baseline={fmt_int(gas_b)}  candidate={fmt_int(gas_c)}  ratio={gas_c/gas_b:.3f}  ({(1-gas_c/gas_b)*100:+.1f}%)")

    print("\n=== Cycle-ratio bucket counts (cumulative) ===")
    for thr in (0.10, 0.25, 0.50, 0.75, 0.90, 1.00):
        n = sum(1 for r in cyc_ratios if r <= thr)
        print(f"  ratio ≤ {thr:.2f}: {n:>5} of {len(cyc_ratios)} ({100*n/len(cyc_ratios):5.1f}%)")

    regressions = [x for x in biggest if x[0] > 1.0]
    print(f"\n=== Regressions: {len(regressions)} of {len(common)} ===")
    for r, (sh, name), bc, cc in sorted(regressions, reverse=True)[:args.top]:
        print(f"  ratio={r:.3f}  cycles {fmt_int(bc)} -> {fmt_int(cc)}   [{sh}] {name}")

    print(f"\n=== Top {args.top} speedups ===")
    for r, (sh, name), bc, cc in biggest[:args.top]:
        print(f"  ratio={r:.3f}  cycles {fmt_int(bc)} -> {fmt_int(cc)}   [{sh}] {name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
