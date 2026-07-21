#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""Compare execution metrics produced by the zkevm-benchmark-workload runner.

Reads the per-fixture JSON reports written under <metrics-dir>/<client>/<zkvm>/ for
two execution clients (Zilkworm and Reth) and prints a validation summary, an
aggregate cycle comparison, a per-test-family breakdown, and the best/worst N
fixtures for Zilkworm.

Usage:
    tools/ere_compare.py <metrics-dir> [--reth-glob reth-*] [--zilk-glob zilkworm-*] [--top 10]
"""
import argparse
import glob
import json
import os
import sys


def load(metrics_dir, pattern):
    """Map fixture name -> (cycles, output_matched) for the client dir matching pattern."""
    roots = [d for d in glob.glob(os.path.join(metrics_dir, pattern)) if os.path.isdir(d)]
    if not roots:
        sys.exit(f"no client directory matching {pattern!r} under {metrics_dir}")
    out = {}
    for root in roots:
        for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
            if os.path.basename(f) == "hardware.json":
                continue
            d = json.load(open(f))
            ex = d.get("execution", {})
            if "success" in ex:
                out[d["name"]] = (ex["success"]["total_num_cycles"], ex["success"].get("output_matched"))
            else:
                reason = ""
                for k, v in ex.items():
                    if isinstance(v, dict):
                        reason = v.get("reason", k)
                out[d["name"]] = (None, reason or "failed")
    return out


def family(name):
    return name.split("::", 1)[0].replace(".py", "")


def short(name, width=60):
    n = name.split("::", 1)[1] if "::" in name else name
    n = (n.replace("fork_Osaka-", "")
          .replace("blockchain_test-", "")
          .replace("-benchmark-gas-value_10M", "")
          .strip("[]"))
    return n[:width]


def validate(metrics_dir, client_glob):
    """Single-client gate: every fixture must complete with output_matched. Exit 1 otherwise."""
    m = load(metrics_dir, client_glob)
    total = len(m)
    failed = [(k, v[1]) for k, v in m.items() if v[0] is None]
    mismatched = [k for k, v in m.items() if v[0] is not None and not v[1]]
    completed = total - len(failed)
    matched = completed - len(mismatched)
    print(f"=== VALIDATION ({client_glob}) ===")
    print(f"  total {total}  completed {completed}  output_matched {matched}"
          f"  incomplete {len(failed)}  mismatched {len(mismatched)}")
    for k, reason in failed[:10]:
        print(f"  INCOMPLETE: {short(k)} -> {reason}")
    for k in mismatched[:10]:
        print(f"  MISMATCH:   {short(k)}")
    ok = total > 0 and not failed and not mismatched
    print("  RESULT: PASS" if ok else "  RESULT: FAIL")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("metrics_dir")
    ap.add_argument("--reth-glob", default="reth-*")
    ap.add_argument("--zilk-glob", default="zilkworm-*")
    ap.add_argument("--validate", metavar="CLIENT_GLOB",
                    help="validate a single client's metrics (e.g. 'zilkworm-*'): "
                         "exit 0 only if every fixture completed with output_matched")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    if a.validate:
        validate(a.metrics_dir, a.validate)

    R = load(a.metrics_dir, a.reth_glob)
    Z = load(a.metrics_dir, a.zilk_glob)

    def summarize(tag, m):
        ok = [k for k, v in m.items() if v[0] is not None]
        matched = sum(1 for k in ok if m[k][1])
        return ok, matched

    rok, rmatch = summarize("reth", R)
    zok, zmatch = summarize("zilkworm", Z)
    print("=== VALIDATION ===")
    print(f"  Reth     : completed {len(rok)}  output_matched {rmatch}  mismatches {len(rok) - rmatch}")
    print(f"  Zilkworm : completed {len(zok)}  output_matched {zmatch}  mismatches {len(zok) - zmatch}")
    rfail = [k for k, v in R.items() if v[0] is None]
    zfail = [k for k, v in Z.items() if v[0] is None]
    if rfail:
        print(f"  Reth incomplete ({len(rfail)}): e.g. {short(rfail[0])} -> {R[rfail[0]][1]}")
    if zfail:
        print(f"  Zilkworm incomplete ({len(zfail)}): e.g. {short(zfail[0])} -> {Z[zfail[0]][1]}")

    common = sorted(set(rok) & set(zok))
    if not common:
        sys.exit("no fixtures completed by both clients")
    rows = [(k, R[k][0], Z[k][0], Z[k][0] / R[k][0]) for k in common]
    rsum = sum(r for _, r, _, _ in rows)
    zsum = sum(z for _, _, z, _ in rows)
    ratios = sorted(r for *_, r in rows)
    zwin = sum(1 for *_, r in rows if r < 1)

    def pct(p):
        return ratios[min(len(ratios) - 1, int(p * len(ratios)))]

    print(f"\n=== CYCLE COMPARISON ({len(common)} fixtures completed by both) ===")
    print(f"  total cycles Reth     : {rsum:,}")
    print(f"  total cycles Zilkworm : {zsum:,}")
    print(f"  ratio Z/R (total): {zsum / rsum:.3f}   (Reth = {rsum / zsum:.2f}x Zilkworm)")
    print(f"  per-fixture Z/R  : median {pct(0.5):.3f}  mean {sum(ratios) / len(ratios):.3f}"
          f"  min {ratios[0]:.3f}  max {ratios[-1]:.3f}")
    print(f"  Zilkworm fewer cycles  : {zwin}/{len(common)} ({100 * zwin / len(common):.0f}%)")

    agg = {}
    for k, rc, zc, _ in rows:
        a3 = agg.setdefault(family(k), [0, 0, 0])
        a3[0] += 1
        a3[1] += rc
        a3[2] += zc
    print("\n=== BY FAMILY (Z/R total-cycle ratio; <1 = Zilkworm cheaper) ===")
    for fam, (n, rc, zc) in sorted(agg.items(), key=lambda x: x[1][2] / x[1][1]):
        print(f"  {fam:32s} n={n:3d}  Z/R={zc / rc:5.2f}")

    def table(title, rs):
        print(f"\n=== {title} ===")
        print(f"  {'fixture':60s} {'reth':>19s} {'zilkworm':>19s} {'z/r':>9s}")
        for k, rc, zc, ra in rs:
            print(f"  {short(k):60s} {rc:>15,} {zc:>15,} {ra:>9.3f}")

    table(f"Best {a.top} for Zilkworm (lowest Z/R)", sorted(rows, key=lambda x: x[3])[:a.top])
    table(f"Worst {a.top} for Zilkworm (highest Z/R)", sorted(rows, key=lambda x: -x[3])[:a.top])


if __name__ == "__main__":
    main()
