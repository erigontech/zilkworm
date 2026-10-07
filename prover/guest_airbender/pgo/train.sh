#!/bin/bash
# Runs the instrumented guest (Z6M_PGO=GEN) on the training set, one log per run, for mkprofile.py.
#
#   prover/guest_airbender/pgo/train.sh PROVER GUEST CORPUS FIXTURES LOGDIR [JOBS]
#
#   PROVER    the z6m_prover_airbender binary
#   GUEST     the GEN guest without its extension (prover/guest_airbender/build/z6m_guest)
#   CORPUS    the benchmark corpus, <block>/flatWitnessBundle<block>.mfbd (make sp1-benchmark-corpus)
#   FIXTURES  the EEST blockchain_tests directory
#             (tools/test-fixtures.sh test-fixtures.json test-fixtures-cache eest_stable)
#   LOGDIR    receives blocks/b<block>.log, eest.txt (every test) and eest/<test, '/' as '__'>.log
#   JOBS      parallel runs (default: the number of CPUs)
#
# Every EEST test runs; mkprofile.py trains on half of them. A run that fails or stops at the cycle
# limit leaves a log without the counters: mkprofile.py rejects a missing block and leaves out such
# an EEST test.
set -eu
[ $# -ge 5 ] || { sed -n '2,15p' "$0"; exit 2; }
PGO=$(cd "$(dirname "$0")" && pwd)
export PROVER=$1 GUEST=$2 CORPUS=$3 FIXTURES=$4 LOGDIR=$5
JOBS=${6:-$(nproc)}
for f in "$PROVER" "$GUEST.bin" "$GUEST.text"; do [ -f "$f" ] || { echo "no $f"; exit 2; }; done
mkdir -p "$LOGDIR/blocks" "$LOGDIR/eest"

run_block() {
  "$PROVER" --guest-bin "$GUEST" execute --file-name "$CORPUS/$1/flatWitnessBundle$1.mfbd" > "$LOGDIR/blocks/b$1.log" 2>&1 || true
}
run_test() {
  "$PROVER" --guest-bin "$GUEST" execute --is-test --file-name "$FIXTURES/$1" > "$LOGDIR/eest/${1//\//__}.log" 2>&1 || true
}
export -f run_block run_test

grep -v '^\s*$' "$PGO/train_blocks.txt" | xargs -P "$JOBS" -I{} bash -c 'run_block "$1"' _ {}
(cd "$FIXTURES" && find . -name '*.json' | sed 's#^\./##' | LC_ALL=C sort) > "$LOGDIR/eest.txt"
xargs -P "$JOBS" -I{} bash -c 'run_test "$1"' _ {} < "$LOGDIR/eest.txt"
echo "logs in $LOGDIR: $(grep -l 'GCD-END' "$LOGDIR"/blocks/*.log | wc -l) blocks and" \
     "$(grep -l 'GCD-END' "$LOGDIR"/eest/*.log | wc -l) EEST tests with counters"
