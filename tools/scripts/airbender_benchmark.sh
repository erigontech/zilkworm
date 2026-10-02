#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Runs the Airbender guest (via z6m_prover_airbender execute) against every
# flat-bundle block in the given directory and reports gas/cycle statistics.
# Mirrors tools/scripts/release_state_root_check.sh conventions.
#
# Expects the corpus layout produced by `make sp1-benchmark-corpus`:
#   <blocks_dir>/<N>/flatWitnessBundle<N>.mfbd

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROVER="$PROJECT_DIR/prover/prover_airbender/target/release/z6m_prover_airbender"
GUEST_BASE="$PROJECT_DIR/prover/guest_airbender/build/z6m_guest"
JOBS=$(( $(nproc) < 8 ? $(nproc) : 8 ))
LOG_DIR="$PROJECT_DIR/temp/airbender_benchmark"
BLOCKS_DIR=""
TIMEOUT_S=600

usage() {
    echo "Usage: $0 --dir <blocks_dir> [-j threads] [-s start_block] [-e end_block] [-l log_dir] [-t timeout_s]"
    echo ""
    echo "  --dir   Path to the MFBD corpus directory (required)"
    echo "  -j      Parallel jobs (default: min(nproc, 8))"
    echo "  -s      Start block number (inclusive)"
    echo "  -e      End block number (inclusive)"
    echo "  -l      Log output directory"
    echo "  -t      Per-block timeout in seconds (default: 600)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) BLOCKS_DIR="$2"; shift 2 ;;
        -j)    JOBS="$2";       shift 2 ;;
        -s)    START="$2";      shift 2 ;;
        -e)    END="$2";        shift 2 ;;
        -l)    LOG_DIR="$2";    shift 2 ;;
        -t)    TIMEOUT_S="$2";  shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$BLOCKS_DIR" || ! -d "$BLOCKS_DIR" ]]; then
    echo "Error: --dir is required and must exist"
    usage
    exit 1
fi
if [[ ! -x "$PROVER" ]]; then
    echo "Error: prover not built at $PROVER (run: make z6m_prover_airbender)"
    exit 1
fi
if [[ ! -f "$GUEST_BASE.bin" ]]; then
    echo "Error: guest binary not found at $GUEST_BASE.bin (run: make z6m_guest_airbender)"
    exit 1
fi

mkdir -p "$LOG_DIR"
BLOCK_LOG_DIR="$LOG_DIR/blocks"
mkdir -p "$BLOCK_LOG_DIR"
SUMMARY_LOG="$LOG_DIR/summary.log"
> "$SUMMARY_LOG"

echo "=== Airbender 200-block Benchmark ===" | tee -a "$SUMMARY_LOG"
echo "Blocks dir: $BLOCKS_DIR" | tee -a "$SUMMARY_LOG"
echo "Log dir:    $LOG_DIR" | tee -a "$SUMMARY_LOG"
echo "Jobs:       $JOBS" | tee -a "$SUMMARY_LOG"
echo "" | tee -a "$SUMMARY_LOG"

# Collect block list
BLOCK_LIST=()
mapfile -t ALL_BLOCKS < <(ls "$BLOCKS_DIR" | sort -n)
for block_num in "${ALL_BLOCKS[@]}"; do
    mfbd="$BLOCKS_DIR/$block_num/flatWitnessBundle${block_num}.mfbd"
    [[ ! -f "$mfbd" ]] && continue
    if [[ -n "${START:-}" && "$block_num" -lt "$START" ]]; then continue; fi
    if [[ -n "${END:-}"   && "$block_num" -gt "$END"   ]]; then continue; fi
    BLOCK_LIST+=("$block_num")
done

TOTAL=${#BLOCK_LIST[@]}
echo "Blocks to run: $TOTAL" | tee -a "$SUMMARY_LOG"

run_block() {
    local block_num="$1"
    local mfbd="$BLOCKS_DIR/$block_num/flatWitnessBundle${block_num}.mfbd"
    local log_file="$BLOCK_LOG_DIR/${block_num}.log"

    local output rc
    output=$(timeout "$TIMEOUT_S" "$PROVER" --guest-bin "$GUEST_BASE" \
             execute --file-name "$mfbd" 2>&1)
    rc=$?
    echo "$output" > "$log_file"

    if [[ $rc -eq 124 ]]; then
        echo "FAIL $block_num TIMEOUT"
    elif [[ $rc -ne 0 ]]; then
        echo "FAIL $block_num rc=$rc"
    elif echo "$output" | grep -q "run FAILED\|reached_end=false"; then
        echo "FAIL $block_num guest-failure"
    fi
}

export -f run_block
export PROVER GUEST_BASE BLOCKS_DIR BLOCK_LOG_DIR TIMEOUT_S

FAILED_BLOCKS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && FAILED_BLOCKS+=("$line")
done < <(
    printf '%s\n' "${BLOCK_LIST[@]}" | \
    xargs -P "$JOBS" -I{} bash -c 'run_block "$1"' _ {}
)

FAILED=${#FAILED_BLOCKS[@]}
PASSED=$(( TOTAL - FAILED ))

# Aggregate gas/cycle stats from the per-block "Executed block" lines.
python3 - "$BLOCK_LOG_DIR" <<'PY' | tee -a "$SUMMARY_LOG"
import os, re, sys

log_dir = sys.argv[1]
pat = re.compile(r"Executed block (\d+) \(gas_used=(\d+), cycles=(\d+)")
rows = []
for f in sorted(os.listdir(log_dir)):
    with open(os.path.join(log_dir, f), errors="replace") as fh:
        m = pat.search(fh.read())
    if m:
        rows.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))

if not rows:
    print("\nNo successful executions parsed.")
    sys.exit(0)

total_gas = sum(r[1] for r in rows)
total_cycles = sum(r[2] for r in rows)
cpg = [r[2] / r[1] for r in rows if r[1]]
print(f"\n=== Cycle statistics ({len(rows)} blocks) ===")
print(f"Total gas    : {total_gas:,}")
print(f"Total cycles : {total_cycles:,}")
print(f"Cycles/gas   : mean {sum(cpg)/len(cpg):.2f}  "
      f"min {min(cpg):.2f}  max {max(cpg):.2f}  "
      f"aggregate {total_cycles/total_gas:.2f}")
worst = sorted(rows, key=lambda r: r[2]/r[1] if r[1] else 0, reverse=True)[:5]
print("Worst cycles/gas blocks:")
for b, g, c in worst:
    print(f"  block {b}: {c/g:.2f} ({c:,} cycles / {g:,} gas)")
PY

echo "" | tee -a "$SUMMARY_LOG"
echo "=== Results ===" | tee -a "$SUMMARY_LOG"
echo "Total : $TOTAL" | tee -a "$SUMMARY_LOG"
echo "Passed: $PASSED" | tee -a "$SUMMARY_LOG"
echo "Failed: $FAILED" | tee -a "$SUMMARY_LOG"
if [[ $FAILED -gt 0 ]]; then
    printf '%s\n' "${FAILED_BLOCKS[@]}" | tee -a "$SUMMARY_LOG"
fi
echo "Per-block logs: $BLOCK_LOG_DIR" | tee -a "$SUMMARY_LOG"

[[ $FAILED -eq 0 ]]
