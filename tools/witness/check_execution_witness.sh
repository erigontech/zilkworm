#!/usr/bin/env bash
# Checks debug_executionWitness responses against the Zilkworm stateless validator (z6m_prover in execute mode).
# Requires: curl, python3. Default DIR = this z6m repo root (no temp scaffold).

set -euo pipefail

COUNT=1
POLL_SECS=4
START=""
END=""
while [ $# -gt 0 ]; do
    case "$1" in
        --block)       BLK="$2"; shift 2 ;;
        --start-block) START="$2"; shift 2 ;;
        --end-block)   END="$2"; shift 2 ;;
        --count|-n)    COUNT="$2"; shift 2 ;;
        --poll-secs)   POLL_SECS="$2"; shift 2 ;;
        --data-dir)    DATA_DIR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,4p' "$0"; echo
            echo "Env:   RPC=<rpc-url>  BLK=<block-num>  DIR=<z6m-repo-root>  DATA_DIR=<data-root>"
            echo "Flags: --block <N>             single-block mode"
            echo "       --start-block N --end-block M   sweep contiguous range [N, M]"
            echo "       --count|-n <N>          poll for the next-latest tip N times (default 1)"
            echo "       --poll-secs <S>         seconds between polls (default 4)"
            echo "       --data-dir <path>       prover data-dir (default: \$DIR/temp/mainnet)"
            exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Default DIR = this repo root (two levels up from tools/witness/).
DIR=${DIR:-$(cd "$(dirname "$0")/../.." && pwd)}
DATA_DIR=${DATA_DIR:-$DIR/temp/mainnet}
RPC=${RPC:-http://localhost:8545}
PROVER="$DIR/prover/target/release/z6m_prover"

if [ -n "$START" ] || [ -n "$END" ]; then
    [ -n "$START" ] && [ -n "$END" ] || { echo "--start-block and --end-block must be passed together" >&2; exit 1; }
    [ "$START" -le "$END" ] || { echo "--start-block must be <= --end-block" >&2; exit 1; }
fi

rpc() {
    curl -fsS -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$1\",\"params\":$2,\"id\":1}" "$RPC" \
        | python3 -c "import json,sys; json.dump(json.load(sys.stdin)['result'], sys.stdout)"
}

echo "Using z6m repo:    $DIR"
echo "Using data-dir:    $DATA_DIR"
mkdir -p "$DATA_DIR/blocks"

# Build z6m_prover if missing.
if [ ! -x "$PROVER" ]; then
    echo "Building z6m_prover (one-time) ..."
    (cd "$DIR" && make z6m_prover >/dev/null 2>&1) || { echo "make z6m_prover failed" >&2; exit 1; }
fi

# Run the prover for one block, capture and classify the output.
# Stages:
#   VALID                : "execution complete, block=" / "Executed block N (...)", non-sentinel gas_used
#   kWrong<...>          : "Validation error kWrong<...>" + gas_used=u64::MAX
#   OTHER                : anything else (e.g. host panic, prover crash)
classify_run() {
    local BLK="$1"
    local LOG="$2"
    local KW; KW=$(grep -m1 -oE "Validation error kWrong[A-Za-z]+" "$LOG" | head -1)
    if [ -n "$KW" ]; then
        echo "block $BLK: ${KW#Validation error }"
        return
    fi
    # Two success-log formats: "execution complete, block=" (cycle_count=) on
    # main/strict-witness; "Executed block N (...)" (cycles=) on som/witness_validation.
    local OK; OK=$(grep -m1 -E "execution complete, block=|Executed block " "$LOG" | head -1)
    if [ -n "$OK" ]; then
        local GAS CYC
        GAS=$(echo "$OK" | sed -n 's/.*gas_used=\([0-9]*\).*/\1/p')
        CYC=$(echo "$OK" | sed -n 's/.*cycle_count=\([0-9]*\).*/\1/p')
        [ -n "$CYC" ] || CYC=$(echo "$OK" | sed -n 's/.*cycles=\([0-9]*\).*/\1/p')
        if [ "$GAS" = "18446744073709551615" ]; then
            echo "block $BLK: SENTINEL_FAIL cycles=$CYC"
        else
            echo "block $BLK: VALID gas=$GAS cycles=$CYC"
        fi
        return
    fi
    echo "block $BLK: OTHER ($(tail -1 "$LOG" | head -c 200))"
}

run_one() {
    local BLK="$1"
    local LOG="$DATA_DIR/logs/$BLK.log"
    mkdir -p "$DATA_DIR/logs"
    RUST_LOG=info "$PROVER" --service \
        --rpc-url "$RPC" \
        --start-block "$BLK" --end-block "$BLK" \
        --execute-every 1 \
        --data-dir "$DATA_DIR" \
        > "$LOG" 2>&1 || true
    classify_run "$BLK" "$LOG"
}

# Mode dispatch.
RESULTS=()
if [ -n "$START" ]; then
    for BLK in $(seq -f "%.0f" "$START" "$END"); do
        RESULTS+=("$(run_one "$BLK")")
    done
elif [ "$COUNT" -eq 1 ]; then
    BLK=${BLK:-$(rpc eth_blockNumber '[]' | python3 -c "import json,sys; print(int(json.load(sys.stdin),16))")}
    RESULTS+=("$(run_one "$BLK")")
else
    SEEN=0; LAST=0
    while [ "$SEEN" -lt "$COUNT" ]; do
        TIP=$(rpc eth_blockNumber '[]' | python3 -c "import json,sys; print(int(json.load(sys.stdin),16))")
        if [ "$TIP" -le "$LAST" ]; then sleep "$POLL_SECS"; continue; fi
        BLK="$TIP"
        SEEN=$((SEEN + 1))
        RESULTS+=("$(run_one "$BLK")")
        LAST="$BLK"
    done
fi

echo
echo "=== per-block ==="
for r in "${RESULTS[@]}"; do echo "$r"; done
echo
echo "=== tally ==="
printf '%s\n' "${RESULTS[@]}" | awk '{
    # second token is the verdict (after "block N:")
    v = $3
    if (v == "VALID") k="VALID"
    else if (v == "SENTINEL_FAIL") k="SENTINEL_FAIL"
    else if (v ~ /^kWrong/) k=v
    else k="OTHER"
    cnt[k]++
}
END { for (k in cnt) printf "  %-30s %d\n", k, cnt[k] }'
