#!/usr/bin/env bash
# ere-fetch-fixtures: download + cache the EEST stateless fixtures (R2 block
# export, Sepolia by default) consumed by the ERE benchmark (make ere-validate).
#
# Usage: tools/ere-fetch-fixtures.sh [first|all|latest N]
#   first (default)  catalog + manifest + first batch -> eest_batch/
#   all              also every batch, sha256-verified, extracted -> all_blocks/
#   latest N         only the N latest batches, sha256-verified, extracted -> latest/
#
# Env overrides:
#   ERE_FIXTURES_BASE   R2 catalog root, or its index.html / manifest.json URL
#                       (default: Sepolia export)
#   ERE_FIXTURES_CACHE  local cache dir (default: test-fixtures-cache/ere-sepolia)
#
# Run from the repo root. Requires: curl, python3, tar (zstd), shasum.
set -euo pipefail

MODE="${1:-first}"
BASE="${ERE_FIXTURES_BASE:-https://pub-afa6b160acfb4919bda1d0e2a00b5b77.r2.dev/testnets/sepolia}"
BASE="${BASE%/}"; BASE="${BASE%/index.html}"; BASE="${BASE%/manifest.json}"; BASE="${BASE%/batches.jsonl}"
CACHE="${ERE_FIXTURES_CACHE:-test-fixtures-cache/ere-sepolia}"

case "$MODE" in
    first|all) ;;
    latest) [[ "${2:-}" =~ ^[1-9][0-9]*$ ]] || { echo "usage: $0 latest N (N >= 1)" >&2; exit 2; } ;;
    *) echo "usage: $0 [first|all|latest N]" >&2; exit 2 ;;
esac

mkdir -p "$CACHE/archives"

echo "fetching catalog + manifest from $BASE"
curl -fsSL "$BASE/batches.jsonl" -o "$CACHE/batches8.jsonl"
curl -fsSL "$BASE/manifest.json" -o "$CACHE/manifest.json"

# <relative-path> <sha256-no-0x> <dest-dir>: download (if absent), verify, extract.
dl_verify_extract() {
    local path="$1" sha="$2" dest="$3" f="$CACHE/archives/${1##*/}"
    [ -f "$f" ] || curl -fsSL "$BASE/$path" -o "$f"
    printf '%s  %s\n' "$sha" "$f" | shasum -a 256 -c - >/dev/null
    tar --zstd -xf "$f" -C "$dest"
}

# Fixture JSONs under blockchain_tests/ (devnet-8) or blockchain_tests_engine/ (tests-zkevm v21).
count_blocks() {
    find "$1" -path '*/blockchain_tests*/*' -name '*.json' | wc -l | tr -d ' '
}

# N latest batches, ordered by (end, start) block like the upstream R2 validator -> latest/.
if [ "$MODE" = latest ]; then
    rm -rf "$CACHE/latest"; mkdir -p "$CACHE/latest"
    first="" last=""
    while read -r path sha; do
        dl_verify_extract "$path" "$sha" "$CACHE/latest"
        echo "  $path"
        first="${first:-$path}" last="$path"
    done < <(python3 -c 'import json, sys
rows = sorted((json.loads(l) for l in open(sys.argv[1]) if l.strip()),
              key=lambda d: (d["batchEndBlock"], d["batchStartBlock"]))
for d in rows[-int(sys.argv[2]):]:
    print(d["path"], d["sha256"][2:])' "$CACHE/batches8.jsonl" "$2")
    first="${first##*/}" last="${last##*/}" last="${last%.tar.zst}"
    echo "cached $(count_blocks "$CACHE/latest") blocks (${first%%-*}..${last#*-}) -> $CACHE/latest"
    exit 0
fi

# First batch -> eest_batch/ (the default ERE_INPUT_FOLDER).
read -r first_path first_sha < <(python3 -c 'import json, sys
d = json.loads(next(open(sys.argv[1])))
print(d["path"], d["sha256"][2:])' "$CACHE/batches8.jsonl")
rm -rf "$CACHE/eest_batch"; mkdir -p "$CACHE/eest_batch"
dl_verify_extract "$first_path" "$first_sha" "$CACHE/eest_batch"
echo "cached first batch -> $CACHE/eest_batch"

# Full corpus -> all_blocks/.
if [ "$MODE" = all ]; then
    echo "downloading + extracting all $(wc -l < "$CACHE/batches8.jsonl" | tr -d " ") batches ..."
    rm -rf "$CACHE/all_blocks"; mkdir -p "$CACHE/all_blocks"
    while read -r path sha; do
        dl_verify_extract "$path" "$sha" "$CACHE/all_blocks"
    done < <(python3 -c 'import json, sys
for line in open(sys.argv[1]):
    d = json.loads(line)
    print(d["path"], d["sha256"][2:])' "$CACHE/batches8.jsonl")
    echo "cached $(count_blocks "$CACHE/all_blocks") blocks -> $CACHE/all_blocks"
fi
