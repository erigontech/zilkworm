#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Entrypoint of the Airbender prover image (prover/Dockerfile, target airbender).
#
# With arguments it runs the prover with them, as `docker run IMAGE prove --file-name ...` or
# `docker run IMAGE verify --proof ... --vk ...`.
#
# Without arguments it runs the proving service, configured from the environment, and starts it
# again whenever it exits. That makes the image usable as is where there is no restart policy,
# such as vast.ai's Entrypoint launch mode (pass the variables with -e). In vast.ai's SSH and
# Jupyter modes, which replace the entrypoint, run this script from the onstart script instead.
#
#   RPC_URL               execution client JSON-RPC serving debug_executionWitness (required)
#   WS_URL                its WebSocket endpoint, for newHeads (optional; polls without it)
#   PROVE_EVERY           prove the blocks whose number is a multiple of this (default 100)
#   EXECUTE_EVERY         execute without proving every N-th block (default: none)
#   START_BLOCK           first block (default: the chain's tip)
#   FETCH_TIMEOUT         seconds one attempt at fetching a block and its witness may take (default 60)
#   MAX_LAG               once at the tip, the most blocks the service may fall behind before it
#                         skips ahead to the tip (default 10; 0 never skips)
#   DATA_DIR              verification key, blocks, logs and proofs (default /data; mount a volume)
#   ETHPROOFS_ENDPOINT, ETHPROOFS_TOKEN, ETHPROOFS_CLUSTER_ID
#                         post to Ethproofs; with any of them unset nothing is posted (a dry run)
#   RESTART_DELAY         seconds to wait before starting the service again (default 30)
#   PROVER_EXTRA_ARGS     further prover options, word-split
#   Z6M_REPLAY_THREADS    the prover's trace replay threads (default: Airbender's 8)
#   Z6M_CONCURRENT_PREFLIGHT=1
#                         simulate each block alongside proving instead of first (saves
#                         ~0.5 s a block, but a block the guest rejects aborts the service)
set -euo pipefail

GUEST=${GUEST_BIN:-/opt/z6m/z6m_guest}
PROVER=${PROVER_BIN:-z6m_prover_airbender}

if [ $# -gt 0 ]; then
    exec "$PROVER" --guest-bin "$GUEST" "$@"
fi

: "${RPC_URL:?RPC_URL is required: an execution client JSON-RPC URL serving debug_executionWitness}"
DATA_DIR=${DATA_DIR:-/data}
PROVE_EVERY=${PROVE_EVERY:-100}
RESTART_DELAY=${RESTART_DELAY:-30}

# The verification key (EVKEY001) that the service's proofs verify against: a function of the
# guest and the prover's recursion programs, so it is computed once for each of them, and a
# volume reused by another image (or a local build of another guest) gets its own. Publish it
# next to the proofs (the Ethproofs verifier and `verify --vk` take it).
VK_ID=$(cat "$GUEST.bin" "$GUEST.text" "${FSV_DIR:?FSV_DIR is required}"/fsv_*.bin "$FSV_DIR"/fsv_*.text \
        | sha256sum | cut -c1-16)
VK_DIR=${VK_DIR:-$DATA_DIR/vk-${ZILKWORM_REVISION:-local}-$VK_ID}
mkdir -p "$DATA_DIR" "$VK_DIR"

if [ -n "${ETHPROOFS_ENDPOINT:-}" ] && [ -n "${ETHPROOFS_TOKEN:-}" ] && [ -n "${ETHPROOFS_CLUSTER_ID:-}" ]; then
    echo "[entrypoint] posting to Ethproofs at $ETHPROOFS_ENDPOINT, cluster $ETHPROOFS_CLUSTER_ID"
else
    echo "[entrypoint] ETHPROOFS_ENDPOINT, ETHPROOFS_TOKEN and ETHPROOFS_CLUSTER_ID not all set: dry run, nothing is posted"
    unset ETHPROOFS_ENDPOINT ETHPROOFS_TOKEN ETHPROOFS_CLUSTER_ID
fi

if [ ! -s "$VK_DIR/vk.bin" ]; then
    echo "[entrypoint] computing the verification key into $VK_DIR/vk.bin"
    "$PROVER" --guest-bin "$GUEST" vk --output "$VK_DIR/vk.bin.tmp"
    mv "$VK_DIR/vk.bin.tmp" "$VK_DIR/vk.bin"
fi
echo "[entrypoint] verification key: $VK_DIR/vk.bin (sha256 $(sha256sum "$VK_DIR/vk.bin" | cut -d' ' -f1))"

service_args() {
    args=(--guest-bin "$GUEST" --service --gpu
          --rpc-url "$RPC_URL" --data-dir "$DATA_DIR" --output-dir "$DATA_DIR/proofs"
          --prove-every "$PROVE_EVERY")
    [ -n "${WS_URL:-}" ] && args+=(--ws-url "$WS_URL")
    [ -n "${EXECUTE_EVERY:-}" ] && args+=(--execute-every "$EXECUTE_EVERY")
    [ -n "${START_BLOCK:-}" ] && args+=(--start-block "$START_BLOCK")
    [ -n "${FETCH_TIMEOUT:-}" ] && args+=(--fetch-timeout "$FETCH_TIMEOUT")
    [ -n "${MAX_LAG:-}" ] && args+=(--max-lag "$MAX_LAG")
    # shellcheck disable=SC2206
    [ -n "${PROVER_EXTRA_ARGS:-}" ] && args+=($PROVER_EXTRA_ARGS)
    return 0
}

child=0
trap 'echo "[entrypoint] stopping"; [ "$child" -gt 0 ] && kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 0' TERM INT

while true; do
    service_args
    "$PROVER" "${args[@]}" &
    child=$!
    rc=0
    wait "$child" || rc=$?
    child=0
    echo "[entrypoint] service exited with status $rc; starting it again in ${RESTART_DELAY}s"
    sleep "$RESTART_DELAY" &
    wait $! || true
    # A restart starts at the tip: the service proves blocks by their number, so the cadence holds.
    unset START_BLOCK
done
