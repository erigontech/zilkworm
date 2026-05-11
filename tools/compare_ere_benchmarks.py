#!/usr/bin/env python3

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""Compare Zilkworm vs Reth ERE benchmark results."""

import json
import os
import sys
from collections import defaultdict

def load_metrics(metrics_dir):
    """Load all metric files from a directory tree."""
    results = {}
    for root, dirs, files in os.walk(metrics_dir):
        for f in files:
            if not f.endswith('.json'):
                continue
            path = os.path.join(root, f)
            data = json.load(open(path))
            name = data.get('name', f)
            ex = data.get('execution', {})
            if 'success' in ex:
                results[name] = {
                    'status': 'success',
                    'cycles': ex['success'].get('total_num_cycles', 0),
                    'duration_secs': ex['success'].get('execution_duration', {}).get('secs', 0),
                    'gas': data.get('metadata', {}).get('block_used_gas', 0),
                }
            elif 'crashed' in ex:
                results[name] = {
                    'status': 'crashed',
                    'reason': ex['crashed'].get('reason', 'unknown'),
                }
            elif 'timeout' in ex:
                results[name] = {
                    'status': 'timeout',
                }
    return results


def compare(reth_dir, zilk_dir):
    reth = load_metrics(reth_dir)
    zilk = load_metrics(zilk_dir)

    all_tests = set(reth.keys()) | set(zilk.keys())

    # Categorize
    both_success = []
    zilk_only_success = []
    reth_only_success = []
    both_crashed = []
    zilk_wins = 0
    reth_wins = 0

    for name in sorted(all_tests):
        r = reth.get(name, {'status': 'missing'})
        z = zilk.get(name, {'status': 'missing'})

        if r['status'] == 'success' and z['status'] == 'success':
            both_success.append((name, r, z))
            if z['cycles'] < r['cycles']:
                zilk_wins += 1
            else:
                reth_wins += 1
        elif z['status'] == 'success' and r['status'] != 'success':
            zilk_only_success.append(name)
        elif r['status'] == 'success' and z['status'] != 'success':
            reth_only_success.append(name)
        elif r['status'] != 'success' and z['status'] != 'success':
            both_crashed.append(name)

    print("=" * 80)
    print("ERE zkEVM Benchmark Comparison: Zilkworm vs Reth")
    print("=" * 80)

    print(f"\nTotal test fixtures: {len(all_tests)}")
    print(f"Reth tests found: {len(reth)}")
    print(f"Zilkworm tests found: {len(zilk)}")

    reth_success = sum(1 for r in reth.values() if r['status'] == 'success')
    zilk_success = sum(1 for z in zilk.values() if z['status'] == 'success')
    reth_crashed = sum(1 for r in reth.values() if r['status'] in ('crashed', 'timeout'))
    zilk_crashed = sum(1 for z in zilk.values() if z['status'] in ('crashed', 'timeout'))

    print(f"\nReth:     {reth_success} success, {reth_crashed} crashed/timeout")
    print(f"Zilkworm: {zilk_success} success, {zilk_crashed} crashed/timeout")
    print(f"\nCompletion advantage: Zilkworm completes {zilk_success - reth_success:+d} more tests")

    print(f"\n--- Comparable Tests (both succeeded): {len(both_success)} ---")
    print(f"Zilkworm faster: {zilk_wins}/{len(both_success)}")
    print(f"Reth faster:     {reth_wins}/{len(both_success)}")

    if both_success:
        # Sort by Zilkworm advantage (lower ratio = better for Zilkworm)
        by_ratio = []
        for name, r, z in both_success:
            ratio = z['cycles'] / r['cycles'] if r['cycles'] > 0 else float('inf')
            by_ratio.append((name, r['cycles'], z['cycles'], ratio))

        by_ratio.sort(key=lambda x: x[3])

        print(f"\n{'Test Name':<75} {'Reth':>12} {'Zilkworm':>12} {'Ratio':>8}")
        print("-" * 110)
        for name, rc, zc, ratio in by_ratio:
            short = name[:74]
            marker = " <-- Zilkworm wins" if ratio < 1.0 else ""
            print(f"{short:<75} {rc:>12,} {zc:>12,} {ratio:>7.2f}x{marker}")

        ratios = [x[3] for x in by_ratio]
        avg_ratio = sum(ratios) / len(ratios)
        total_reth = sum(x[1] for x in by_ratio)
        total_zilk = sum(x[2] for x in by_ratio)

        print(f"\nAverage ratio (Zilkworm/Reth): {avg_ratio:.3f}x")
        print(f"Total cycles — Reth: {total_reth:,}, Zilkworm: {total_zilk:,}")
        print(f"Overall speedup: {total_reth/total_zilk:.2f}x in Zilkworm's favor" if total_zilk < total_reth
              else f"Overall: Reth {total_zilk/total_reth:.2f}x faster in aggregate")

    # By category
    print(f"\n--- By Test Category ---")
    cats = defaultdict(lambda: {'zilk_wins': 0, 'reth_wins': 0, 'total': 0})
    for name, r, z in both_success:
        cat = name.split('::')[0] if '::' in name else 'other'
        ratio = z['cycles'] / r['cycles']
        cats[cat]['total'] += 1
        if ratio < 1.0:
            cats[cat]['zilk_wins'] += 1
        else:
            cats[cat]['reth_wins'] += 1

    for cat in sorted(cats.keys()):
        c = cats[cat]
        print(f"  {cat}: Zilkworm {c['zilk_wins']}/{c['total']}, Reth {c['reth_wins']}/{c['total']}")

    if zilk_only_success:
        print(f"\n--- Tests only Zilkworm completed ({len(zilk_only_success)}): ---")
        for name in zilk_only_success[:10]:
            print(f"  {name[:90]}")
        if len(zilk_only_success) > 10:
            print(f"  ... and {len(zilk_only_success) - 10} more")

    if reth_only_success:
        print(f"\n--- Tests only Reth completed ({len(reth_only_success)}): ---")
        for name in reth_only_success[:10]:
            print(f"  {name[:90]}")
        if len(reth_only_success) > 10:
            print(f"  ... and {len(reth_only_success) - 10} more")

    # Verdict
    print(f"\n{'=' * 80}")
    print("VERDICT")
    print(f"{'=' * 80}")
    if zilk_success > reth_success:
        print(f"  Reliability: Zilkworm WINS (completes {zilk_success} vs {reth_success} tests)")
    else:
        print(f"  Reliability: Reth WINS (completes {reth_success} vs {zilk_success} tests)")

    if len(both_success) > 0:
        if zilk_wins > reth_wins:
            print(f"  Cycle Count: Zilkworm WINS ({zilk_wins}/{len(both_success)} faster)")
        else:
            print(f"  Cycle Count: Reth WINS ({reth_wins}/{len(both_success)} faster)")

    overall_better = (zilk_success > reth_success) and (zilk_wins >= reth_wins or zilk_success - reth_success > reth_wins - zilk_wins)
    if overall_better or (zilk_wins > reth_wins):
        print(f"\n  OVERALL: Zilkworm results are BETTER than Reth")
    else:
        print(f"\n  OVERALL: Results are MIXED — Zilkworm may need more optimization")


if __name__ == '__main__':
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base = os.path.join(repo_root, 'third_party/zkevm-benchmark-workload/zkevm-metrics')

    # Find Reth and Zilkworm metric directories
    reth_dir = None
    zilk_dir = None
    for entry in os.listdir(base):
        full = os.path.join(base, entry)
        if not os.path.isdir(full):
            continue
        if entry.startswith('reth'):
            reth_dir = full
        elif entry.startswith('zilkworm'):
            zilk_dir = full

    if not reth_dir:
        print("ERROR: No Reth metrics directory found")
        sys.exit(1)
    if not zilk_dir:
        print("ERROR: No Zilkworm metrics directory found")
        sys.exit(1)

    # Find SP1 subdirectory
    for entry in os.listdir(reth_dir):
        if entry.startswith('sp1'):
            reth_dir = os.path.join(reth_dir, entry)
            break
    for entry in os.listdir(zilk_dir):
        if entry.startswith('sp1'):
            zilk_dir = os.path.join(zilk_dir, entry)
            break

    print(f"Reth metrics: {reth_dir}")
    print(f"Zilkworm metrics: {zilk_dir}")
    print()

    compare(reth_dir, zilk_dir)
