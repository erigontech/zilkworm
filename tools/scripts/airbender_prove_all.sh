#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Proves every MFBD flat-bundle block in the given corpus directory with the
# Airbender GPU prover (base layer by default). Sequential — the GPU is the
# bottleneck. Resumable: blocks whose proof.bin already exists are skipped.
#
# Corpus layout (from `make sp1-benchmark-corpus`):
#   <blocks_dir>/<N>/flatWitnessBundle<N>.mfbd

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROVER="$PROJECT_DIR/prover/prover_airbender/target/release/z6m_prover_airbender"
GUEST_BASE="$PROJECT_DIR/prover/guest_airbender/build/z6m_guest"
SETUP_DIR="$PROJECT_DIR/temp/airbender_setup"
LOG_DIR="$PROJECT_DIR/temp/airbender_prove"
PROOF_DIR="$PROJECT_DIR/temp/airbender_proofs"
UNTIL="base"
BLOCKS_DIR=""
TIMEOUT_S=1200

usage() {
    echo "Usage: $0 --dir <blocks_dir> [-s start] [-e end] [-l log_dir] [-o proof_dir] [-u base|unrolled|unified] [-t timeout_s]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) BLOCKS_DIR="$2"; shift 2 ;;
        -s)    START="$2";      shift 2 ;;
        -e)    END="$2";        shift 2 ;;
        -l)    LOG_DIR="$2";    shift 2 ;;
        -o)    PROOF_DIR="$2";  shift 2 ;;
        -u)    UNTIL="$2";      shift 2 ;;
        -t)    TIMEOUT_S="$2";  shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [[ -z "$BLOCKS_DIR" || ! -d "$BLOCKS_DIR" ]]; then
    echo "Error: --dir is required and must exist"; usage; exit 1
fi
if [[ ! -x "$PROVER" || ! -f "$GUEST_BASE.bin" ]]; then
    echo "Error: prover/guest not built (make z6m_prover_airbender)"; exit 1
fi

mkdir -p "$LOG_DIR/blocks" "$PROOF_DIR"
SUMMARY_LOG="$LOG_DIR/summary.log"
> "$SUMMARY_LOG"

# Setup cache (compute once if missing)
if [[ ! -f "$SETUP_DIR/setup.bin" ]]; then
    echo "Computing setup cache into $SETUP_DIR ..."
    "$PROVER" --guest-bin "$GUEST_BASE" setup --setup-dir "$SETUP_DIR" --until "$UNTIL" || exit 1
fi

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
echo "=== Airbender prove-all: $TOTAL blocks (until=$UNTIL) ===" | tee -a "$SUMMARY_LOG"

PASSED=0; FAILED=0; SKIPPED=0; k=0
FAILED_BLOCKS=()
for block_num in "${BLOCK_LIST[@]}"; do
    k=$((k+1))
    mfbd="$BLOCKS_DIR/$block_num/flatWitnessBundle${block_num}.mfbd"
    out_dir="$PROOF_DIR/$block_num"
    log_file="$LOG_DIR/blocks/${block_num}.log"

    if [[ -f "$out_dir/proof.bin" ]]; then
        SKIPPED=$((SKIPPED+1))
        echo "PROGRESS $k/$TOTAL block $block_num skipped (proof exists)"
        continue
    fi

    t0=$SECONDS
    timeout "$TIMEOUT_S" "$PROVER" --guest-bin "$GUEST_BASE" prove \
        --file-name "$mfbd" --gpu --until "$UNTIL" \
        --setup-dir "$SETUP_DIR" --output-dir "$out_dir" \
        > "$log_file" 2>&1
    rc=$?
    dt=$(( SECONDS - t0 ))

    # A proof of a FAILED guest execution is not a pass: the prover proves
    # whatever ran, including runs that ended in a state-root mismatch.
    if [[ $rc -eq 0 ]] && grep -q "Proving complete" "$log_file" && [[ -f "$out_dir/proof.bin" ]] \
       && ! grep -q "run FAILED\|ERROR: State Root Mismatch" "$log_file"; then
        PASSED=$((PASSED+1))
        echo "PROGRESS $k/$TOTAL block $block_num ok (${dt}s)"
    else
        FAILED=$((FAILED+1))
        FAILED_BLOCKS+=("$block_num")
        [[ $rc -eq 124 ]] && reason="TIMEOUT" || reason="rc=$rc"
        echo "FAIL $k/$TOTAL block $block_num $reason (${dt}s)"
    fi
done

{
    echo ""
    echo "=== Results ==="
    echo "Total  : $TOTAL"
    echo "Proved : $PASSED"
    echo "Skipped: $SKIPPED"
    echo "Failed : $FAILED"
    if [[ $FAILED -gt 0 ]]; then
        echo "Failed blocks:"
        printf '  %s\n' "${FAILED_BLOCKS[@]}"
    fi
    echo "Per-block logs: $LOG_DIR/blocks"
    echo "Proofs        : $PROOF_DIR"
} | tee -a "$SUMMARY_LOG"

echo "DONE proved=$PASSED skipped=$SKIPPED failed=$FAILED total=$TOTAL"
[[ $FAILED -eq 0 ]]
