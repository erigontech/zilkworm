#!/usr/bin/env python3

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""
SP1 Benchmark Tool for z6m (zilk).
Usage: python3 sp1_benchmark.py --dir /path/to/witness_data
"""

import argparse
import datetime
import os
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class BlockRecord:
    block: int
    gas_used: int
    cycle_count: int
    prover_gas: int
    syscall_count: int
    input_path: str = ""

    @property
    def cycles_per_gas(self) -> float:
        return self.cycle_count / self.gas_used if self.gas_used else 0.0

    @property
    def prover_gas_per_gas(self) -> float:
        return self.prover_gas / self.gas_used if self.gas_used else 0.0


@dataclass
class ChunkInfo:
    index: int
    start_block: int
    end_block: int
    block_count: int
    log_file: str


def fmt(n) -> str:
    """Format a number with commas."""
    if isinstance(n, float):
        return f"{n:,.2f}"
    return f"{n:,}"


# -- Git helpers --------------------------------------------------------------

def find_git_root() -> Optional[str]:
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def get_git_info() -> Tuple[str, str, str]:
    """Return (short_hash, branch, commit_message)."""
    commit, branch, message = "unknown", "unknown", ""
    for cmd, target in [
        (["git", "rev-parse", "--short", "HEAD"], "commit"),
        (["git", "rev-parse", "--abbrev-ref", "HEAD"], "branch"),
        (["git", "log", "-1", "--format=%s"], "message"),
    ]:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                val = r.stdout.strip()
                if target == "commit":
                    commit = val
                elif target == "branch":
                    branch = val
                else:
                    message = val
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return commit, branch, message


# -- Discovery ----------------------------------------------------------------

def discover_blocks(data_dir: str) -> Tuple[str, List[int]]:
    """Discover blocks in data_dir (which directly contains numbered block dirs).

    Returns (prover_data_dir, sorted_block_numbers).  The prover expects
    --data-dir to be the parent of a blocks/ subdirectory, so we create a
    temporary directory with a ``blocks`` symlink pointing at data_dir.
    """
    blocks = []
    try:
        for entry in os.listdir(data_dir):
            if os.path.isdir(os.path.join(data_dir, entry)):
                try:
                    blocks.append(int(entry))
                except ValueError:
                    continue
    except PermissionError as e:
        print(f"ERROR: Cannot read blocks directory: {e}", file=sys.stderr)
        sys.exit(1)
    blocks.sort()

    import tempfile
    wrapper = tempfile.mkdtemp(prefix="z6m_bench_")
    os.symlink(os.path.abspath(data_dir), os.path.join(wrapper, "blocks"))

    return wrapper, blocks


def get_available_memory_gb() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / (1024 * 1024)
    except (FileNotFoundError, ValueError, IndexError):
        pass
    try:
        r = subprocess.run(["free", "-g"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            parts = r.stdout.strip().split("\n")[1].split()
            if len(parts) >= 7:
                return float(parts[6])
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, IndexError):
        pass
    return 16.0


def compute_parallelism(total_blocks: int) -> int:
    mem_gb = get_available_memory_gb()
    mem_based = max(1, int((mem_gb - 4) / 8))
    block_based = max(1, total_blocks // 25)
    actual = max(1, min(mem_based, block_based))
    print(f"  Available memory: {mem_gb:.1f} GB")
    print(f"  Memory-based parallelism: {mem_based}")
    print(f"  Block-based parallelism (blocks/25): {block_based}")
    print(f"  Actual parallelism: {actual}")
    return actual


# -- Chunking -----------------------------------------------------------------

def split_into_chunks(block_list: List[int], n_chunks: int,
                      output_dir: str) -> List[ChunkInfo]:
    """Split block_list into n_chunks groups.

    Each chunk uses --start-block/--end-block markers from its first and
    last block.  The prover skips missing blocks in the range automatically.
    """
    if not block_list:
        return []
    n_chunks = max(1, min(n_chunks, len(block_list)))
    chunk_size = len(block_list) // n_chunks
    remainder = len(block_list) % n_chunks
    chunks, offset = [], 0
    for i in range(n_chunks):
        size = chunk_size + (1 if i < remainder else 0)
        blks = block_list[offset : offset + size]
        if not blks:
            break
        chunks.append(ChunkInfo(
            index=i, start_block=blks[0], end_block=blks[-1],
            block_count=len(blks),
            log_file=os.path.join(output_dir, f"chunk_{i:03d}.log"),
        ))
        offset += size
    return chunks


# -- Execution ----------------------------------------------------------------

RAM_PER_INSTANCE_GB = 8
RAM_WAIT_INTERVAL = 15


def run_prover_chunks(prover: str, data_dir: str,
                      chunks: List[ChunkInfo]) -> bool:
    """Launch prover processes with memory-aware scheduling.

    Each chunk is a single prover invocation with --start-block/--end-block.
    The prover skips missing blocks in the range automatically.
    """
    processes: List[Tuple[ChunkInfo, subprocess.Popen, str]] = []
    all_ok = True

    print(f"\n{'='*60}")
    print(f"  Launching prover: {len(chunks)} chunk(s)")
    print(f"{'='*60}")

    for i, chunk in enumerate(chunks):
        # Let the previous process settle its memory before checking
        if i > 0:
            print(f"  Waiting {RAM_WAIT_INTERVAL}s for last instance of z6m_prover to init...")
            time.sleep(RAM_WAIT_INTERVAL)

        while get_available_memory_gb() < RAM_PER_INSTANCE_GB:
            print(f"  Waiting for memory: {get_available_memory_gb():.1f} GB "
                  f"available, need {RAM_PER_INSTANCE_GB} GB. "
                  f"Retrying in {RAM_WAIT_INTERVAL}s...")
            time.sleep(RAM_WAIT_INTERVAL)

        cmd = [prover, "--test-service",
               "--start-block", str(chunk.start_block),
               "--end-block", str(chunk.end_block),
               "--data-dir", data_dir,
               "--execution-log-file", chunk.log_file]
        print(f"  Launching chunk {chunk.index}: "
              f"blocks {chunk.start_block}..{chunk.end_block} "
              f"({chunk.block_count} blocks)")
        try:
            stdout_path = chunk.log_file + ".stdout"
            stdout_fh = open(stdout_path, "w")
            proc = subprocess.Popen(cmd, stdout=stdout_fh,
                                    stderr=subprocess.STDOUT)
            stdout_fh.close()
            processes.append((chunk, proc, stdout_path))
        except (FileNotFoundError, PermissionError) as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            for _, p in processes:
                p.kill()
            return False

    # Monitor
    print(f"\n  Monitoring {len(processes)} processes...")
    completed = set()
    start_time = time.time()
    while len(completed) < len(processes):
        for idx, (chunk, proc, stdout_path) in enumerate(processes):
            if idx in completed:
                continue
            ret = proc.poll()
            if ret is not None:
                completed.add(idx)
                elapsed = time.time() - start_time
                status = "OK" if ret == 0 else f"FAILED (exit {ret})"
                print(f"  Chunk {chunk.index} finished: {status} "
                      f"[{elapsed:.0f}s elapsed, "
                      f"{len(completed)}/{len(processes)} done]")
                if ret != 0:
                    all_ok = False
                    try:
                        with open(stdout_path) as f:
                            lines = f.readlines()
                        for line in lines[-20:]:
                            print(f"    {line.rstrip()}")
                    except Exception:
                        pass
        if len(completed) < len(processes):
            time.sleep(2)
    return all_ok


def merge_chunk_logs(chunks: List[ChunkInfo], merged_path: str) -> str:
    entries: List[Tuple[int, str]] = []
    block_pat = re.compile(r"block (\d+) executed")
    for chunk in chunks:
        if not os.path.isfile(chunk.log_file):
            print(f"  WARNING: Chunk log not found: {chunk.log_file}")
            continue
        with open(chunk.log_file) as f:
            for line in f:
                line = line.rstrip("\n")
                m = block_pat.search(line)
                entries.append((int(m.group(1)) if m else 999_999_999_999, line))
    entries.sort(key=lambda x: x[0])
    with open(merged_path, "w") as f:
        for _, line in entries:
            f.write(line + "\n")
    return merged_path


# -- Log parsing --------------------------------------------------------------

LOG_PATTERN = re.compile(
    r"\[([^\]]*)\]\s+block\s+(\d+)\s+executed,\s+"
    r"gas_used=(\d+),\s+cycle_count=(\d+),\s+"
    r"prover_gas=(\d+),\s+syscall_count=(\d+),\s+input=(.*)"
)


def parse_execution_log(log_path: str) -> List[BlockRecord]:
    records = []
    if not os.path.isfile(log_path):
        print(f"  WARNING: Log file not found: {log_path}")
        return records
    with open(log_path) as f:
        for line in f:
            m = LOG_PATTERN.search(line)
            if m:
                records.append(BlockRecord(
                    block=int(m.group(2)), gas_used=int(m.group(3)),
                    cycle_count=int(m.group(4)), prover_gas=int(m.group(5)),
                    syscall_count=int(m.group(6)), input_path=m.group(7).strip(),
                ))
    records.sort(key=lambda r: r.block)
    return records


# -- Report -------------------------------------------------------------------

def generate_report(records: List[BlockRecord], block_range: Tuple[int, int],
                    total_blocks: int, git_commit: str, git_branch: str,
                    git_message: str) -> str:
    lines = [
        "# SP1 Benchmark Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Block range | {fmt(block_range[0])} -- {fmt(block_range[1])} "
        f"({fmt(total_blocks)} blocks) |",
        f"| **Git commit** | `{git_commit}` (\"{git_message}\") |",
        f"| **Git branch** | `{git_branch}` |",
        "",
        "---",
        "",
        "## Summary Statistics",
        "",
        "| Metric | Avg | Median | Min | Max | Total |",
        "|--------|-----|--------|-----|-----|-------|",
    ]

    cycles = [r.cycle_count for r in records]
    pgas = [r.prover_gas for r in records]
    gas = [r.gas_used for r in records]
    sc = [r.syscall_count for r in records]
    cpg = [r.cycles_per_gas for r in records]
    ppg = [r.prover_gas_per_gas for r in records]

    med = lambda d: statistics.median(d) if d else 0

    tot_cycles, tot_pgas = sum(cycles), sum(pgas)
    tot_gas, tot_sc = sum(gas), sum(sc)
    tot_cpg = tot_cycles / tot_gas if tot_gas else 0
    tot_ppg = tot_pgas / tot_gas if tot_gas else 0

    for label, vals, total in [
        ("cycle_count", cycles, tot_cycles),
        ("prover_gas", pgas, tot_pgas),
        ("gas_used", gas, tot_gas),
        ("syscall_count", sc, tot_sc),
    ]:
        lines.append(
            f"| {label} | {fmt(int(statistics.mean(vals)))} "
            f"| {fmt(int(med(vals)))} | {fmt(min(vals))} "
            f"| {fmt(max(vals))} | {fmt(total)} |"
        )
    for label, vals, total in [
        ("cycles/gas", cpg, tot_cpg),
        ("prover_gas/gas", ppg, tot_ppg),
    ]:
        lines.append(
            f"| {label} | {statistics.mean(vals):,.2f} "
            f"| {med(vals):,.2f} | {min(vals):,.2f} "
            f"| {max(vals):,.2f} | {total:,.2f} |"
        )
    lines.append("")
    return "\n".join(lines)



# -- Main ---------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="SP1 Benchmark Tool for z6m")
    parser.add_argument("--dir", required=True,
                        help="Path to directory containing numbered block dirs")
    parser.add_argument("--start", type=int, default=None,
                        help="First block number (default: first available)")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of blocks to run (default: all from --start)")
    args = parser.parse_args()

    print("=" * 60)
    print("  SP1 Benchmark Tool")
    print("=" * 60)

    data_dir = os.path.abspath(args.dir)
    git_root = find_git_root()
    if not git_root:
        print("ERROR: Not inside a git repository.", file=sys.stderr)
        return 1

    prover = os.path.join(git_root, "prover", "target", "release", "z6m_prover")
    if not os.path.isfile(prover) or not os.access(prover, os.X_OK):
        print(f"ERROR: Prover not found or not executable: {prover}",
              file=sys.stderr)
        return 1

    # Discovery
    print("\n[Discovery]")
    print(f"  Data directory: {data_dir}")
    print(f"  Prover: {prover}")
    prover_data_dir, block_list = discover_blocks(data_dir)
    if not block_list:
        print("ERROR: No blocks found.", file=sys.stderr)
        return 1
    print(f"  Found {len(block_list)} blocks "
          f"(range: {block_list[0]}..{block_list[-1]})")

    # Apply --start / --count filters
    if args.start is not None:
        block_list = [b for b in block_list if b >= args.start]
        if not block_list:
            print(f"ERROR: No blocks >= {args.start}.", file=sys.stderr)
            return 1
    if args.count is not None:
        block_list = block_list[:args.count]
    print(f"  Selected {len(block_list)} blocks "
          f"(range: {block_list[0]}..{block_list[-1]})")

    print(f"\n  Computing parallelism...")
    actual_parallel = compute_parallelism(len(block_list))

    git_commit, git_branch, git_message = get_git_info()
    print(f"\n  Git: {git_commit} ({git_branch})")

    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.join(git_root, "temp", "benchmarks", f"benchmark_{ts}")
    os.makedirs(output_dir, exist_ok=True)
    print(f"  Output directory: {output_dir}")

    # Chunking
    print(f"\n[Chunking]")
    chunks = split_into_chunks(block_list, actual_parallel, output_dir)
    for c in chunks:
        print(f"  Chunk {c.index}: blocks {c.start_block}..{c.end_block} "
              f"({c.block_count} blocks) -> {os.path.basename(c.log_file)}")

    # Execution
    print(f"\n[Execution]")
    ok = run_prover_chunks(prover, prover_data_dir, chunks)
    if not ok:
        print("\nWARNING: Some chunks failed. Proceeding with available data.")

    # Merge logs
    merged_log = os.path.join(output_dir, "execution.log")
    merge_chunk_logs(chunks, merged_log)
    print(f"  Merged log: {merged_log}")

    # Analysis
    print(f"\n[Analysis]")
    records = parse_execution_log(merged_log)
    print(f"  Parsed {len(records)} records")
    if not records:
        print("ERROR: No records parsed.", file=sys.stderr)
        return 1

    report = generate_report(
        records, (records[0].block, records[-1].block), len(records),
        git_commit, git_branch, git_message,
    )

    report_path = os.path.join(output_dir, "summary.md")
    with open(report_path, "w") as f:
        f.write(report)

    print("\n" + report)
    print(f"Report written to: {report_path}")
    print(f"Execution log: {merged_log}")
    print(f"Output directory: {output_dir}")
    print(f"\nBenchmark complete!")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
        sys.exit(130)
