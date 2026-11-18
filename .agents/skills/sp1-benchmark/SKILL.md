---
name: sp1-benchmark
description: Use when the user asks to "benchmark", "run benchmark", "compare performance", "profile blocks", "cycle count comparison", or discusses SP1 prover performance testing. Runs batch block execution benchmarks and compares C++ vs Rust (or other) provers.
---

# SP1 Benchmark Skill

Run batch SP1 prover benchmarks, compare C++ vs Rust performance, and report results.

## Overview

This skill benchmarks the z6m SP1 prover by executing blocks from witness data and measuring cycle counts, gas used, prover gas, and syscall counts. It supports comparing two prover builds (e.g., C++ vs Rust, or before/after an optimization).

## Step 1: Resolve Parameters

### Block range
- If the user specifies a range (e.g., "benchmark 500 blocks"), use that count starting from the first available block.
- If the user specifies specific blocks (e.g., "24490786 to 24491786"), use that range.
- Default: 200 blocks starting from the first available block in the data directory.

### Data directory
- If the user specifies a directory, use it.
- Otherwise, check memory files for recently used directories.
- The `--data-dir` flag should point to the **parent** of the `blocks/` directory (e.g., `/mnt/my_drive/witness_blocks`, not `.../witness_blocks/blocks/`).
- Discover available block range: `ls <data-dir>/blocks/ | sort -n | head -1` and `... | tail -1` and `... | wc -l`.

### Comparison target
- If the user asks to compare (e.g., "vs Rust", "vs main branch"), set up a comparison.
- For Rust comparison: check if `/tmp/main_500_worktree/prover/target/release/z6m_prover` exists. If not, create an independent worktree of the `main` branch and build the Rust prover there via a background subagent.
- For before/after comparison: create an independent worktree of the current commit, run the "before" benchmark there.

### Output directory
- Create a timestamped output directory: `./temp/benchmarks/<YYYY-MM-DD_HHMMSS>/`
- Generate the timestamp at the start of the run (before launching benchmarks).
- All output files for this run go into this directory.

## Step 2: Build (if needed)

If the prover binary doesn't exist or is stale, build it:
```bash
make z6m_guest_cpp && make z6m_prover_cpp
```

For comparison targets in worktrees, launch a **background subagent** (ALWAYS background, NEVER foreground) to build in the worktree.

## Step 3: Run Benchmarks

### CRITICAL: Always use background subagents or background Bash commands

NEVER run benchmarks in the foreground. Benchmarks take minutes to hours. Always use:
```
run_in_background: true
```

### Prover invocation

Single block:
```bash
<prover_path> execute --block-number <N> --data-dir <data_dir>
```

Batch benchmark:
```bash
<prover_path> --test-service \
  --start-block <START> --end-block <END> \
  --data-dir <data_dir> \
  --execution-log-file <output_log>
```

Use **absolute paths** for the prover binary. The binary location depends on the worktree:
- Main: `/workspace/prover/target/release/z6m_prover`
- Worktree: `<worktree_path>/prover/target/release/z6m_prover`

### Git info

At the start of every run, capture commit and branch dynamically:
```bash
git log --oneline -1   # e.g., "b9ed9a35b Add memmove forwarding..."
git branch --show-current  # e.g., "chfast/memmove"
```
NEVER hardcode or guess commit/branch — always query git.

### Memory-aware parallel execution

Each z6m_prover instance uses ~**8 GB of RAM**. ALWAYS run in parallel when memory allows.

#### Step 3a: Assess available memory
```bash
awk '/MemAvailable/ {printf "%.0f\n", $2/1024/1024}' /proc/meminfo
```
- `max_parallel = floor((available_gb - 4) / 8)` — reserve 4 GB for OS
- Minimum: 1, maximum: cap at 8

#### Step 3b: Split block range into chunks
- **Minimum chunk size: 25 blocks**
- `actual_parallel = min(max_parallel, floor(total_blocks / 25))`
- `actual_parallel = max(actual_parallel, 1)`

Each chunk gets its own log: `execution_chunk_N.log`.

#### Step 3c: Staggered launch
Launch ALL chunks as parallel background Bash commands in a **single message**, each with a built-in sleep delay:
```bash
# Chunk N (delay = (N-1) * 30 seconds):
sleep <delay> && <prover_path> --test-service \
  --start-block <CHUNK_START> --end-block <CHUNK_END> \
  --data-dir <data_dir> \
  --execution-log-file <output_dir>/execution_chunk_<N>.log
```
Stagger is **30 seconds** between chunks.

#### Step 3d: Wait for all chunks to complete
All background commands send completion notifications. Wait for ALL before analysis.

#### Step 3e: Merge logs
```bash
cat <output_dir>/execution_chunk_*.log | sort -t' ' -k2 > <output_dir>/execution.log
```

### Log file locations

- **Single run (parallel)**: `execution_chunk_1.log` ... `execution_chunk_N.log` → merged into `execution.log`
- **Single run (serial, max_parallel=1)**: `execution.log` directly
- **Comparison run**: `execution_cpp.log` / `execution_rust.log` (each side gets its own chunks if parallel)

### Comparison parallel execution

When comparing two provers, apply chunking to BOTH. Memory budget:
- `max_parallel_per_prover = floor((available_gb - 4) / (8 * 2))`
- Minimum 1 per prover.

### Log format

Each line in the execution log:
```
[<timestamp>] block <N> executed, gas_used=<gas>, cycle_count=<cycles>, prover_gas=<pgas>, syscall_count=<sc>, input=<path>
```

## Step 4: Analyze Comparison Results

Once both benchmarks complete, parse and compare using inline Python:

```python
import re, statistics

def parse_log(path):
    blocks = {}
    with open(path) as f:
        for line in f:
            m = re.search(r'block (\d+) executed, gas_used=(\d+), cycle_count=(\d+), prover_gas=(\d+), syscall_count=(\d+)', line)
            if m:
                blocks[int(m.group(1))] = {
                    'cycles': int(m.group(3)),
                    'gas': int(m.group(2)),
                    'prover_gas': int(m.group(4)),
                    'syscall_count': int(m.group(5)),
                }
    return blocks
```

### Required comparison output metrics

Report a summary table with:

| Metric | Prover A | Prover B | Delta |
|--------|----------|----------|-------|
| Blocks tested | N | N | - |
| Avg cycles | X | Y | +/-Z% |
| Avg prover gas | X | Y | +/-Z% |
| Avg cycles/gas | X | Y | +/-Z% |
| Avg prover_gas/gas | X | Y | +/-Z% |
| Total cycles | X | Y | savings |
| Total prover gas | X | Y | savings |
| Gas mismatches | N | - | - |
| A faster | N/total | - | pct |
| B faster | N/total | - | pct |

### Percentile distribution (delta between A and B)

| Percentile | cycles delta | prover_gas delta | cycles/gas delta | prover_gas/gas delta |
|-----------|-------------|------------------|------------------|----------------------|
| p5 | X% | X% | X% | X% |
| p10 | X% | X% | X% | X% |
| p25 | X% | X% | X% | X% |
| p50 (median) | X% | X% | X% | X% |
| p75 | X% | X% | X% | X% |
| p90 | X% | X% | X% | X% |
| p95 | X% | X% | X% | X% |
| p99 | X% | X% | X% | X% |

### Gas correctness
Report the number of gas mismatches (blocks where gas_used differs between the two provers). This MUST be zero for a valid comparison.

### Biggest wins/losses
Report the block numbers with the largest improvement and largest regression for both cycles and prover_gas.

## Step 4a: Single Run Analysis

When running a single prover benchmark (no comparison target), produce a full standalone report.

### Per-block table

| Block | gas_used | cycle_count | prover_gas | syscall_count | cycles/gas | prover_gas/gas |
|-------|----------|-------------|------------|---------------|------------|----------------|
| N     | X        | Y           | Z          | S             | Y/X        | Z/X            |

For runs with more than 50 blocks, show only the top 10 most expensive blocks (by cycle count) and bottom 10, plus a note about the full table being in the log.

### Summary statistics

| Metric | Avg | Median | Min | Max | Total |
|--------|-----|--------|-----|-----|-------|
| cycle_count | X | X | X | X | X |
| prover_gas | X | X | X | X | X |
| gas_used | X | X | X | X | X |
| syscall_count | X | X | X | X | - |
| cycles/gas | X | X | X | X | total_cycles/total_gas |
| prover_gas/gas | X | X | X | X | total_pgas/total_gas |

### Percentile distribution

| Percentile | cycle_count | prover_gas | cycles/gas | prover_gas/gas |
|-----------|-------------|------------|------------|----------------|
| p5 | X | X | X | X |
| p10 | X | X | X | X |
| p25 | X | X | X | X |
| p50 | X | X | X | X |
| p75 | X | X | X | X |
| p90 | X | X | X | X |
| p95 | X | X | X | X |
| p99 | X | X | X | X |

## Step 5: Persist Results

### Output directory structure

All results are saved to `./temp/benchmarks/<YYYY-MM-DD_HHMMSS>/` (relative to project root `/workspace`).

For a **single run**:
```
./temp/benchmarks/2026-03-06_143022/
  summary.md          # Self-contained human-readable report
  execution.log       # Raw prover output log
```

For a **comparison run**:
```
./temp/benchmarks/2026-03-06_143022/
  summary.md          # Self-contained comparison report
  execution_a.log     # Prover A raw log (e.g., execution_cpp.log)
  execution_b.log     # Prover B raw log (e.g., execution_rust.log)
```

### summary.md format

The summary.md must be a **self-contained report** that includes:

1. **Header**: Date, block range, prover binary path(s), data directory, git commit hash(es)
2. **Results**: All tables from Step 4 or Step 4a (depending on run type)
3. **Configuration**: Build flags, branch name, any relevant environment details
4. **Raw log paths**: Absolute paths to the execution log files in the same directory

Example header for summary.md:
```markdown
# SP1 Benchmark Results — 2026-03-06 14:30:22

- **Type**: Comparison (C++ vs Rust)
- **Block range**: 24490786 - 24491786 (983 blocks)
- **Data dir**: /mnt/data/witness_blocks
- **Prover A**: /tmp/feature_worktree/prover/target/release/z6m_prover (commit abc1234, branch som/remove-rust)
- **Prover B**: /tmp/main_500_worktree/prover/target/release/z6m_prover (commit def5678, branch main)
- **Logs**: execution_cpp.log, execution_rust.log

## Results
...
```

### Memory updates

- If results are significant (new baseline, regression detected, etc.), also update `MEMORY.md` with a one-line summary pointing to the benchmark directory.
- Always note the benchmark directory path in the response to the user.

## Reference: Recent Benchmark Results

### 1000-block benchmark (2026-03-06)
- Range: 24490786-24491786 (983 blocks executed)
- C++ avg: 175,421,331 cycles, Rust avg: 192,962,364 cycles
- C++ faster on 983/983 blocks (100%)
- Median improvement: -8.9% (C++ faster)
- Distribution: p5=-10.7%, p25=-9.5%, p50=-8.9%, p75=-8.5%, p95=-8.0%
- Zero gas mismatches
- Logs: `/tmp/cpp_1000_benchmark.log`, `/tmp/rust_1000_benchmark.log`

## Reference: Known Prover Locations

- C++ (current branch): `prover/target/release/z6m_prover`
