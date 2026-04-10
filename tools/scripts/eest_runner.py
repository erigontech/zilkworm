#!/usr/bin/env python3
"""
EEST Test Runner for z6m HyperCube prover.

Discovers test shard directories under eest-fixtures/blockchain_tests,
launches z6m_prover --test-service --test-dir for each shard in parallel
(staggered by a configurable delay), and aggregates results.

Usage:
    python3 eest_runner.py --fixtures third_party/eest-fixtures
    python3 eest_runner.py --fixtures third_party/eest-fixtures --stagger 30 --max-parallel 4
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ShardResult:
    shard: str
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    exit_code: int = -1
    duration_s: float = 0.0
    error: str = ""


SUMMARY_RE = re.compile(r"Total:\s*(\d+),\s*Passed:\s*(\d+),\s*Failed:\s*(\d+)(?:,\s*Skipped:\s*(\d+))?")


def find_git_root() -> Optional[str]:
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_available_memory_gb() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 * 1024)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    return 16.0


def discover_shards(fixtures_dir: str) -> List[str]:
    """Discover test shards under blockchain_tests/.

    - blockchain_tests/{fork} (excluding static/, Testing/) -> one shard each
    - blockchain_tests/static/state_tests/{subdir} -> one shard each
    """
    bt = os.path.join(fixtures_dir, "blockchain_tests")
    shards = []

    # Fork-level shards
    for name in sorted(os.listdir(bt)):
        if name in ("static", "Testing"):
            continue
        d = os.path.join(bt, name)
        if not os.path.isdir(d):
            continue
        if not _has_json(d):
            continue
        shards.append(os.path.join("blockchain_tests", name))

    # static/state_tests sub-shards
    static_st = os.path.join(bt, "static", "state_tests")
    if os.path.isdir(static_st):
        for name in sorted(os.listdir(static_st)):
            d = os.path.join(static_st, name)
            if not os.path.isdir(d):
                continue
            if not _has_json(d):
                continue
            shards.append(os.path.join("blockchain_tests", "static", "state_tests", name))

    return shards


def _has_json(d: str) -> bool:
    """Check if directory contains at least one .json file (recursive)."""
    for root, _, files in os.walk(d):
        for f in files:
            if f.endswith(".json"):
                return True
    return False


def parse_summary(output: str) -> Tuple[int, int, int, int]:
    """Parse Total/Passed/Failed/Skipped from test-service stdout."""
    m = SUMMARY_RE.search(output)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0)
    return 0, 0, 0, 0


RAM_PER_INSTANCE_GB = 10
RAM_CHECK_INTERVAL = 15


@dataclass
class ShardProc:
    """Tracks a running shard process and its output collector thread."""
    result: ShardResult
    proc: subprocess.Popen
    start_time: float
    log_path: str
    output_lines: List[str] = field(default_factory=list)
    reader_thread: Optional[threading.Thread] = None


def _stream_output(proc: subprocess.Popen, shard_name: str,
                   output_lines: List[str]):
    """Read stdout line-by-line, print in real time, collect for parsing."""
    prefix = shard_name.split("/")[-1]
    for line in proc.stdout:
        line = line.rstrip("\n")
        output_lines.append(line)
        # Print PASS/FAIL/summary lines and test progress in real time
        if any(k in line for k in ("[", "PASS", "FAIL", "Total:", "warn", "error")):
            print(f"    [{prefix}] {line}", flush=True)
    if proc.stdout:
        proc.stdout.close()


def run_shards(prover: str, fixtures_dir: str, shards: List[str],
               log_dir: str, stagger: int, max_parallel: int,
               max_file_size_bytes: int = 0) -> List[ShardResult]:
    """Launch shard processes with staggered starts and memory-aware scheduling."""
    results: List[ShardResult] = []
    active: List[ShardProc] = []
    pending = list(shards)
    next_launch = time.time()

    print(f"\n{'='*70}")
    print(f"  EEST Runner: {len(shards)} shards, max_parallel={max_parallel}, stagger={stagger}s")
    print(f"{'='*70}\n", flush=True)

    while pending or active:
        # Try to launch next shard: must pass both stagger delay AND memory check
        can_launch = (pending
                      and len(active) < max_parallel
                      and time.time() >= next_launch)
        if can_launch:
            avail = get_available_memory_gb()
            if avail >= RAM_PER_INSTANCE_GB:
                shard = pending.pop(0)
                test_dir = os.path.join(fixtures_dir, shard)
                shard_log = os.path.join(log_dir, shard.replace("/", "--") + ".log")
                exec_log = os.path.join(log_dir, shard.replace("/", "--") + ".exec.log")

                cmd = [prover, "--test-service",
                       "--test-dir", test_dir,
                       "--execution-log-file", exec_log]
                if max_file_size_bytes > 0:
                    cmd.extend(["--max-file-size", str(max_file_size_bytes)])

                print(f"  [{len(shards)-len(pending)}/{len(shards)}] "
                      f"Launching: {shard} [{avail:.1f}GB free, "
                      f"{len(active)} active]", flush=True)

                try:
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, bufsize=1)
                    sr = ShardResult(shard=shard)
                    sp = ShardProc(result=sr, proc=proc,
                                   start_time=time.time(), log_path=shard_log)
                    # Start background thread to stream output in real time
                    sp.reader_thread = threading.Thread(
                        target=_stream_output,
                        args=(proc, shard, sp.output_lines),
                        daemon=True)
                    sp.reader_thread.start()
                    active.append(sp)
                    results.append(sr)
                except (FileNotFoundError, PermissionError) as e:
                    sr = ShardResult(shard=shard, error=str(e), exit_code=1)
                    results.append(sr)
                    print(f"    ERROR launching {shard}: {e}", flush=True)

                next_launch = time.time() + stagger
            else:
                # Stagger elapsed but not enough memory — wait and retry
                print(f"    Waiting for memory: {avail:.1f}GB free, "
                      f"need {RAM_PER_INSTANCE_GB}GB, "
                      f"{len(active)} active, {len(pending)} pending",
                      flush=True)

        # Reap completed processes, collect results, free resources
        still_active = []
        for sp in active:
            ret = sp.proc.poll()
            if ret is not None:
                # Wait for reader thread to finish draining stdout
                if sp.reader_thread:
                    sp.reader_thread.join(timeout=5)
                sp.proc.wait()

                duration = time.time() - sp.start_time
                sp.result.exit_code = ret
                sp.result.duration_s = duration

                output = "\n".join(sp.output_lines)
                try:
                    with open(sp.log_path, "w") as f:
                        f.write(output)
                except OSError:
                    pass

                total, passed, failed, skipped = parse_summary(output)
                sp.result.total = total
                sp.result.passed = passed
                sp.result.failed = failed
                sp.result.skipped = skipped

                status = "PASS" if failed == 0 and total > 0 else "FAIL"
                avail = get_available_memory_gb()
                print(f"  [{status}] {sp.result.shard}: "
                      f"{passed}/{total} passed "
                      f"({duration:.0f}s, {len(active)-1} active, "
                      f"{len(pending)} pending, {avail:.1f}GB free)",
                      flush=True)
            else:
                still_active.append(sp)
        active = still_active

        if active or pending:
            time.sleep(2)

    return results


def print_report(results: List[ShardResult]) -> Tuple[int, int, int]:
    """Print aggregate report, return (total, passed, failed)."""
    total = sum(r.total for r in results)
    passed = sum(r.passed for r in results)
    failed = sum(r.failed for r in results)
    skipped = sum(r.skipped for r in results)
    errored = sum(1 for r in results if r.error or r.exit_code != 0)

    print(f"\n{'='*70}")
    print(f"  EEST AGGREGATE SUMMARY")
    print(f"{'='*70}")
    print(f"  Shards:  {len(results)}")
    print(f"  Total:   {total}")
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    if skipped:
        print(f"  Skipped: {skipped}")
    if errored:
        print(f"  Errored: {errored} shard(s) had errors")

    # Print failed shards
    fail_shards = [r for r in results if r.failed > 0 or r.error]
    if fail_shards:
        print(f"\n  Failed shards:")
        for r in fail_shards:
            if r.error:
                print(f"    {r.shard}: ERROR - {r.error}")
            else:
                print(f"    {r.shard}: {r.failed} failures")

    # Print timing
    durations = [(r.shard, r.duration_s) for r in results if r.duration_s > 0]
    if durations:
        durations.sort(key=lambda x: -x[1])
        total_time = max(r.duration_s for r in results) if results else 0
        print(f"\n  Wall time: {total_time:.0f}s")
        print(f"  Top 5 slowest shards:")
        for shard, dur in durations[:5]:
            print(f"    {dur:6.0f}s  {shard}")

    print(f"{'='*70}")
    return total, passed, failed


def main() -> int:
    parser = argparse.ArgumentParser(description="EEST Test Runner for z6m")
    parser.add_argument("--fixtures", required=True,
                        help="Path to eest-fixtures directory")
    parser.add_argument("--stagger", type=int, default=60,
                        help="Seconds between shard launches (default: 60)")
    parser.add_argument("--max-parallel", type=int, default=0,
                        help="Max parallel processes (0=auto, default: 0)")
    parser.add_argument("--log-dir", default=None,
                        help="Directory for shard logs (default: temp/eest_logs)")
    parser.add_argument("--fail-threshold", type=int, default=5,
                        help="Max allowed failures before exit 1 (default: 5)")
    parser.add_argument("--max-file-size", type=int, default=20,
                        help="Max test file size in MB (0=no limit, default: 20)")
    parser.add_argument("--filter", default=None,
                        help="Only run shards matching this substring")
    args = parser.parse_args()

    fixtures = os.path.abspath(args.fixtures)
    if not os.path.isdir(fixtures):
        print(f"ERROR: fixtures dir not found: {fixtures}", file=sys.stderr)
        return 1

    git_root = find_git_root()
    if not git_root:
        print("ERROR: not in a git repository", file=sys.stderr)
        return 1

    prover = os.path.join(git_root, "prover", "target", "release", "z6m_prover")
    if not os.path.isfile(prover) or not os.access(prover, os.X_OK):
        print(f"ERROR: prover not found: {prover}", file=sys.stderr)
        return 1

    # Discover
    shards = discover_shards(fixtures)
    if args.filter:
        shards = [s for s in shards if args.filter in s]
    if not shards:
        print("ERROR: no shards found", file=sys.stderr)
        return 1

    print(f"  Prover: {prover}")
    print(f"  Fixtures: {fixtures}")
    print(f"  Shards discovered: {len(shards)}")
    for s in shards:
        print(f"    {s}")

    # Parallelism
    if args.max_parallel <= 0:
        mem_gb = get_available_memory_gb()
        max_par = max(1, int((mem_gb - 4) / RAM_PER_INSTANCE_GB))
        print(f"  Memory: {mem_gb:.1f}GB -> auto max_parallel={max_par}")
    else:
        max_par = args.max_parallel
        print(f"  max_parallel={max_par} (user-set)")

    # Log dir
    log_dir = args.log_dir or os.path.join(git_root, "temp", "eest_logs")
    os.makedirs(log_dir, exist_ok=True)
    print(f"  Log dir: {log_dir}")

    # Run
    max_file_size_bytes = args.max_file_size * 1024 * 1024  # MB to bytes
    results = run_shards(prover, fixtures, shards, log_dir,
                         stagger=args.stagger, max_parallel=max_par,
                         max_file_size_bytes=max_file_size_bytes)

    # Report
    total, passed, failed = print_report(results)

    if total == 0:
        print("\nERROR: no tests executed", file=sys.stderr)
        return 1
    if failed > args.fail_threshold:
        print(f"\nFAIL: {failed} failures exceed threshold ({args.fail_threshold})",
              file=sys.stderr)
        return 1
    if failed > 0:
        print(f"\nWARNING: {failed} failure(s), within threshold ({args.fail_threshold})")
    else:
        print(f"\nSUCCESS: all {total} tests passed!")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(130)
