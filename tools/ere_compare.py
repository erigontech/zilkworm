#!/usr/bin/env python3
# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""Report execution metrics produced by the zkevm-benchmark-workload runner.

Reads the per-fixture JSON reports written under <metrics-dir>/<client>/<zkvm>/.
For two execution clients (Zilkworm and Reth) it prints a validation summary, an
aggregate cost comparison, a per-test-family breakdown, and the best/worst N
fixtures for Zilkworm. --validate gates one client on output_matched; --cost prints
one client's SP1 estimated cost: totals, components, families, heaviest fixtures.
--table prints one row per metric and one column per client directory, as plain
text or, with --markdown, a GitHub table.

Usage:
    tools/ere_compare.py <metrics-dir> [--reth-glob reth-*] [--zilk-glob zilkworm-*] [--top 10]
    tools/ere_compare.py --validate 'zilkworm-*' <metrics-dir>
    tools/ere_compare.py --cost 'zilkworm-*' <metrics-dir> [--top 10]
    tools/ere_compare.py --table 'zilkworm-*' [--table 'reth-*'] <metrics-dir> [--markdown] [--workload DIR]
"""
import argparse
import glob
import json
import os
import statistics
import sys
from collections import namedtuple

import ere_workload

Record = namedtuple("Record", "completed output_matched cost reason cost_kind family parts ere_rev")

# SP1 ExecutionReport::gas(): cost / 10 * 10 / 191
SP1_GAS_DIVISOR = 191

COMPONENTS = {
    "opcode": "RISC-V instructions (total - syscall - system)",
    "syscall": "syscalls, incl. precompile chips",
    "system": "chips every program runs (memory)",
}


def _cost(d, ex):
    """(scalar cost, kind, components): legacy execution cycles when present, else the
    summed cost_estimation components. ere >= v0.17 records no cycles on
    `--action execute`; they come from `--action estimate-cost`."""
    s = ex.get("success", {})
    if "total_num_cycles" in s:
        return s["total_num_cycles"], "cycles", None
    ce = (d.get("cost_estimation") or {}).get("success")
    if ce and isinstance(ce.get("cost"), dict):
        return sum(ce["cost"].values()), "estimated cost", ce["cost"]
    return None, None, None


def _family(d):
    """Test file for EEST-generated fixtures; source directory for block exports."""
    md = d.get("metadata") or {}
    orig = md.get("original_test_name") or d.get("name", "")
    if "::" in orig:
        return orig.split("::", 1)[0].replace(".py", "")
    return os.path.dirname(md.get("source_path") or "") or "(blocks)"


def _roots(metrics_dir, pattern):
    return sorted(d for d in glob.glob(os.path.join(metrics_dir, pattern)) if os.path.isdir(d))


def load(metrics_dir, pattern, action=None):
    """Map fixture name -> Record for the client dir matching pattern. The `action` block
    (execution, cost_estimation) decides completion; by default `execution`, or
    `cost_estimation` for records without one (`--action estimate-cost` only)."""
    roots = _roots(metrics_dir, pattern)
    if not roots:
        sys.exit(f"no client directory matching {pattern!r} under {metrics_dir}")
    out = {}
    for root in roots:
        for f in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
            if os.path.basename(f) == "hardware.json":
                continue
            d = json.load(open(f))
            ex = d.get("execution") or {}
            key = action or ("execution" if ex else "cost_estimation")
            block = d.get(key) or {}
            ok = block.get("success")
            if ok:
                cost, kind, parts = _cost(d, ex)
                rev = (ok.get("context") or {}).get("ere_revision")
                out[d["name"]] = Record(True, ok.get("output_matched"), cost, "", kind, _family(d), parts, rev)
            else:
                reason = next((v.get("reason", k) for k, v in block.items() if isinstance(v, dict)), "")
                reason = reason or ("failed" if block else f"no {key} record")
                out[d["name"]] = Record(False, None, None, reason, None, _family(d), None, None)
    return out


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
    failed = [(k, v[3]) for k, v in m.items() if not v[0]]
    mismatched = [k for k, v in m.items() if v[0] and not v[1]]
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


def _estimates(m):
    """(estimated rows, [(missing, reason)], [mismatched]) of a cost_estimation load."""
    rows = {k: v for k, v in m.items() if v.completed and v.parts is not None}
    missing = [(k, v.reason) for k, v in m.items() if k not in rows]
    mismatched = [k for k, v in rows.items() if not v.output_matched]
    return rows, missing, mismatched


def ere_version(release, revs):
    """The lockfile's ere version when it built these records, else their ere_revision."""
    if release and all(release[1].startswith(r) for r in revs):
        return release[0]
    return ",".join(sorted(revs)) or "?"


def summary_table(metrics_dir, globs, workload, markdown=False):
    """One column per client directory matching globs: ere version, estimate counts and cost."""
    release = ere_workload.ere_release(workload)
    cols = []
    for pattern in globs:
        roots = _roots(metrics_dir, pattern)
        if not roots:
            cols.append([pattern] + ["-"] * 5)
        for root in roots:
            name = os.path.basename(root)
            m = load(metrics_dir, glob.escape(name), "cost_estimation")
            rows, missing, mismatched = _estimates(m)
            cost = sum(v.cost for v in rows.values())
            cols.append([name, ere_version(release, {v.ere_rev for v in m.values() if v.ere_rev}),
                         f"{len(rows)}/{len(m)}", str(len(rows) - len(mismatched)), str(len(missing)),
                         f"{cost / 1e9:,.2f}"])
    labels = ["", "ere-version", "completed", "output_matched", "incomplete", "cost (G)"]
    table = list(zip(labels, *cols))
    if markdown:
        print("| " + " | ".join(table[0]) + " |")
        print("|" + "---|" * len(table[0]))
        for r in table[1:]:
            print("| " + " | ".join(r) + " |")
        return
    widths = [max(map(len, col)) for col in zip(*table)]
    for r in table:
        print("   ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())


def cost_report(metrics_dir, client_glob, top):
    """Single-client SP1 estimated cost from `--action estimate-cost` records. Exit 1 if there are none."""
    m = load(metrics_dir, client_glob, "cost_estimation")
    rows, missing, mismatched = _estimates(m)
    print(f"=== SP1 ESTIMATED COST ({client_glob}) ===")
    if not rows:
        print(f"  no cost estimates among {len(m)} fixtures (run ere-hosts --action estimate-cost)")
        sys.exit(1)
    costs = [v.cost for v in rows.values()]
    total = sum(costs)
    print("  unit: ere's SP1 cost, 3 * trace area + chip complexity, summed over fixtures")
    print(f"  fixtures estimated   : {len(rows)}/{len(m)}  output_matched {len(rows) - len(mismatched)}"
          f"  incomplete {len(missing)}")
    print(f"  total estimated cost : {total:,}")
    print(f"  ~ SP1 prover gas     : {total // SP1_GAS_DIVISOR:,}  (cost/{SP1_GAS_DIVISOR}, the prover_gas sp1_benchmark reports)")
    print(f"  per fixture          : mean {statistics.mean(costs):,.0f}  median {statistics.median(costs):,.0f}"
          f"  min {min(costs):,}  max {max(costs):,}")
    for k, reason in missing[:10]:
        print(f"  INCOMPLETE: {short(k)} -> {reason}")
    for k in mismatched[:10]:
        print(f"  MISMATCH:   {short(k)}")

    parts = {}
    for v in rows.values():
        for c, x in v.parts.items():
            parts[c] = parts.get(c, 0) + x
    print("\n=== COST COMPONENTS (total estimated cost) ===")
    for c, x in sorted(parts.items(), key=lambda p: -p[1]):
        print(f"  {c:8s} {x:>22,} {100 * x / total:6.1f}%  {COMPONENTS.get(c, '')}")

    fams = {}
    for v in rows.values():
        acc = fams.setdefault(v.family, [0, 0])
        acc[0] += 1
        acc[1] += v.cost
    print("\n=== BY FAMILY (total estimated cost) ===")
    for fam, (n, x) in sorted(fams.items(), key=lambda f: -f[1][1]):
        print(f"  {fam:48s} n={n:4d}  {x:>22,} {100 * x / total:6.1f}%  mean {x / n:,.0f}")

    print(f"\n=== Heaviest {min(top, len(rows))} fixtures (estimated cost) ===")
    for k, v in sorted(rows.items(), key=lambda r: -r[1].cost)[:top]:
        print(f"  {short(k):60s} {v.cost:>19,}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("metrics_dir")
    ap.add_argument("--reth-glob", default="reth-*")
    ap.add_argument("--zilk-glob", default="zilkworm-*")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--validate", metavar="CLIENT_GLOB",
                      help="validate a single client's metrics (e.g. 'zilkworm-*'): "
                           "exit 0 only if every fixture completed with output_matched")
    mode.add_argument("--cost", metavar="CLIENT_GLOB",
                      help="report a single client's SP1 estimated cost (e.g. 'zilkworm-*')")
    mode.add_argument("--table", metavar="CLIENT_GLOB", action="append",
                      help="summary table column(s), repeatable: ere version, completed, "
                           "output_matched, incomplete, estimated cost in G")
    ap.add_argument("--markdown", action="store_true", help="print --table as a GitHub markdown table")
    ap.add_argument("--workload", help="workload checkout whose Cargo.lock names the ere version "
                                       "(default: the parent of metrics_dir)")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    if a.validate:
        validate(a.metrics_dir, a.validate)
    if a.cost:
        cost_report(a.metrics_dir, a.cost, a.top)
        return
    if a.table:
        summary_table(a.metrics_dir, a.table,
                      a.workload or os.path.dirname(os.path.abspath(a.metrics_dir)), a.markdown)
        return

    R = load(a.metrics_dir, a.reth_glob)
    Z = load(a.metrics_dir, a.zilk_glob)

    def summarize(tag, m):
        ok = [k for k, v in m.items() if v[0]]
        matched = sum(1 for k in ok if m[k][1])
        return ok, matched

    rok, rmatch = summarize("reth", R)
    zok, zmatch = summarize("zilkworm", Z)
    print("=== VALIDATION ===")
    print(f"  Reth     : completed {len(rok)}  output_matched {rmatch}  mismatches {len(rok) - rmatch}")
    print(f"  Zilkworm : completed {len(zok)}  output_matched {zmatch}  mismatches {len(zok) - zmatch}")
    rfail = [k for k, v in R.items() if not v[0]]
    zfail = [k for k, v in Z.items() if not v[0]]
    if rfail:
        print(f"  Reth incomplete ({len(rfail)}): e.g. {short(rfail[0])} -> {R[rfail[0]][3]}")
    if zfail:
        print(f"  Zilkworm incomplete ({len(zfail)}): e.g. {short(zfail[0])} -> {Z[zfail[0]][3]}")

    common = sorted(k for k in set(rok) & set(zok)
                    if R[k][2] is not None and Z[k][2] is not None and R[k][4] == Z[k][4])
    if not common:
        sys.exit("no fixtures with cost data completed by both clients "
                 "(ere >= v0.17 records no cycles on --action execute; use --action estimate-cost)")

    def pct(ratios, p):
        return ratios[min(len(ratios) - 1, int(p * len(ratios)))]

    def table(title, rs):
        print(f"\n=== {title} ===")
        print(f"  {'fixture':60s} {'reth':>19s} {'zilkworm':>19s} {'z/r':>9s}")
        for k, rc, zc, ra in rs:
            print(f"  {short(k):60s} {rc:>15,} {zc:>15,} {ra:>9.3f}")

    # Legacy execution cycles and estimated cost are different units: one report per kind.
    for kind in sorted({R[k][4] for k in common}):
        keys = [k for k in common if R[k][4] == kind]
        rows = [(k, R[k][2], Z[k][2], Z[k][2] / R[k][2]) for k in keys]
        rsum = sum(r for _, r, _, _ in rows)
        zsum = sum(z for _, _, z, _ in rows)
        ratios = sorted(r for *_, r in rows)
        zwin = sum(1 for *_, r in rows if r < 1)
        print(f"\n=== {kind.upper()} COMPARISON ({len(rows)} fixtures completed by both) ===")
        print(f"  total Reth     : {rsum:,}")
        print(f"  total Zilkworm : {zsum:,}")
        print(f"  ratio Z/R (total): {zsum / rsum:.3f}   (Reth = {rsum / zsum:.2f}x Zilkworm)")
        print(f"  per-fixture Z/R  : median {pct(ratios, 0.5):.3f}  mean {sum(ratios) / len(ratios):.3f}"
              f"  min {ratios[0]:.3f}  max {ratios[-1]:.3f}")
        print(f"  Zilkworm cheaper : {zwin}/{len(rows)} ({100 * zwin / len(rows):.0f}%)")

        agg = {}
        for k, rc, zc, _ in rows:
            a3 = agg.setdefault(R[k][5], [0, 0, 0])
            a3[0] += 1
            a3[1] += rc
            a3[2] += zc
        print(f"\n=== BY FAMILY ({kind}; Z/R total ratio, <1 = Zilkworm cheaper) ===")
        for fam, (n, rc, zc) in sorted(agg.items(), key=lambda x: x[1][2] / x[1][1]):
            print(f"  {fam:48s} n={n:4d}  Z/R={zc / rc:5.2f}")

        table(f"Best {a.top} for Zilkworm ({kind}, lowest Z/R)", sorted(rows, key=lambda x: x[3])[:a.top])
        table(f"Worst {a.top} for Zilkworm ({kind}, highest Z/R)", sorted(rows, key=lambda x: -x[3])[:a.top])

if __name__ == "__main__":
    main()
