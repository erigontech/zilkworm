#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Builds state_transition in Release mode and runs it against all witness blocks
# that have a .bin file, counting state root mismatches.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_DIR/build/zilk_core/dev/cli/state_transition"
JOBS=$(nproc)
LOG_DIR="$PROJECT_DIR/temp/release_state_root_check"
BLOCKS_DIR=""

usage() {
    echo "Usage: $0 --dir <blocks_dir> [-j threads] [-s start_block] [-e end_block] [-l log_dir]"
    echo ""
    echo "  --dir   Path to the blocks directory (required)"
    echo "  -j      Parallel jobs (default: nproc)"
    echo "  -s      Start block number (inclusive)"
    echo "  -e      End block number (inclusive)"
    echo "  -l      Log output directory"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            BLOCKS_DIR="$2"
            shift 2
            ;;
        -j)
            JOBS="$2"
            shift 2
            ;;
        -s)
            START="$2"
            shift 2
            ;;
        -e)
            END="$2"
            shift 2
            ;;
        -l)
            LOG_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$BLOCKS_DIR" ]]; then
    echo "Error: --dir is required"
    usage
    exit 1
fi

if [[ ! -d "$BLOCKS_DIR" ]]; then
    echo "Error: blocks directory does not exist: $BLOCKS_DIR"
    exit 1
fi

mkdir -p "$LOG_DIR"
SUMMARY_LOG="$LOG_DIR/summary.log"
MISMATCH_LOG="$LOG_DIR/mismatches.log"
> "$SUMMARY_LOG"
> "$MISMATCH_LOG"

echo "=== Release State Root Check ===" | tee -a "$SUMMARY_LOG"
echo "Project: $PROJECT_DIR" | tee -a "$SUMMARY_LOG"
echo "Blocks dir: $BLOCKS_DIR" | tee -a "$SUMMARY_LOG"
echo "Log dir: $LOG_DIR" | tee -a "$SUMMARY_LOG"
echo "" | tee -a "$SUMMARY_LOG"

# Build in Release mode
echo "Building state_transition (Release)..." | tee -a "$SUMMARY_LOG"
cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE \
    -DCMAKE_C_COMPILER:FILEPATH=/usr/bin/gcc \
    -DCMAKE_CXX_COMPILER:FILEPATH=/usr/bin/g++ \
    --no-warn-unused-cli \
    -B "$PROJECT_DIR/build" \
    -G Ninja \
    -S "$PROJECT_DIR" 2>&1 | tail -5

cmake --build "$PROJECT_DIR/build" \
    --config Release \
    --target state_transition \
    -- -j"$JOBS" 2>&1 | tail -5

echo "Build complete: $BINARY" | tee -a "$SUMMARY_LOG"
echo "" | tee -a "$SUMMARY_LOG"

# Collect block list from --dir
BLOCK_LIST=()
mapfile -t ALL_BLOCKS < <(ls "$BLOCKS_DIR" | sort -n)
for block_num in "${ALL_BLOCKS[@]}"; do
    bin_file="$BLOCKS_DIR/$block_num/unifiedBlockAndStateRlp${block_num}.bin"
    [[ ! -f "$bin_file" ]] && continue
    if [[ -n "${START:-}" && "$block_num" -lt "$START" ]]; then continue; fi
    if [[ -n "${END:-}"   && "$block_num" -gt "$END"   ]]; then continue; fi
    BLOCK_LIST+=("$bin_file")
done

TOTAL=${#BLOCK_LIST[@]}
echo "Blocks to process: $TOTAL" | tee -a "$SUMMARY_LOG"
echo "" | tee -a "$SUMMARY_LOG"

# Run blocks in parallel, detect mismatches
run_block() {
    local bin_file="$1"
    local log_dir="$2"
    local label
    label=$(basename "$bin_file" .bin)
    local log_file="$log_dir/${label}.log"

    local output rc
    output=$(timeout 60 "$BINARY" "$bin_file" 2>&1)
    rc=$?

    echo "$output" > "$log_file"

    if [[ $rc -eq 124 ]]; then
        echo "TIMEOUT: $bin_file" >&2
    elif echo "$output" | grep -q "ERROR: State Root Mismatch"; then
        echo "$bin_file"
    fi
}

export BINARY
export -f run_block

echo "Running $TOTAL blocks with -j$JOBS ..." | tee -a "$SUMMARY_LOG"

BLOCK_LOG_DIR="$LOG_DIR/blocks"
mkdir -p "$BLOCK_LOG_DIR"

MISMATCH_BLOCKS=()
while IFS= read -r line; do
    [[ -n "$line" ]] && MISMATCH_BLOCKS+=("$line")
done < <(
    printf '%s\n' "${BLOCK_LIST[@]}" | \
    xargs -P "$JOBS" -I{} bash -c \
        'run_block "$1" "'"$BLOCK_LOG_DIR"'"' \
        _ {}
)

MISMATCH_COUNT=${#MISMATCH_BLOCKS[@]}

# Report
echo "" | tee -a "$SUMMARY_LOG"
echo "=== Results ===" | tee -a "$SUMMARY_LOG"
echo "Total blocks run : $TOTAL" | tee -a "$SUMMARY_LOG"
echo "State root mismatches: $MISMATCH_COUNT" | tee -a "$SUMMARY_LOG"

if [[ $MISMATCH_COUNT -gt 0 ]]; then
    echo "" | tee -a "$SUMMARY_LOG"
    echo "Blocks with state root mismatch:" | tee -a "$SUMMARY_LOG"
    for b in "${MISMATCH_BLOCKS[@]}"; do
        echo "  $b" | tee -a "$SUMMARY_LOG" "$MISMATCH_LOG"
    done
fi

echo "" | tee -a "$SUMMARY_LOG"
echo "Per-block logs : $BLOCK_LOG_DIR" | tee -a "$SUMMARY_LOG"
echo "Mismatch list  : $MISMATCH_LOG" | tee -a "$SUMMARY_LOG"
echo "Summary        : $SUMMARY_LOG" | tee -a "$SUMMARY_LOG"
