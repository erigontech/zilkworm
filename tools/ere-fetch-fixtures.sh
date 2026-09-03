#!/usr/bin/env bash
# ere-fetch-fixtures: download + cache the glamsterdam-devnet-8 EEST stateless
# fixtures (R2 block export) consumed by the ERE benchmark (make ere-validate).
#
# Usage: tools/ere-fetch-fixtures.sh [first|all]
#   first (default)  catalog + manifest + first batch (10 blocks) -> eest_batch/
#   all              also every batch, sha256-verified, extracted -> all_blocks/
#                    (~3 GB download, ~17 GB extracted; all 6478 blocks)
#
# Env overrides:
#   ERE_FIXTURES_BASE   R2 base URL (default: glamsterdam-devnet-8 export)
#   ERE_FIXTURES_CACHE  local cache dir (default: test-fixtures-cache/ere-glamsterdam-devnet-8)
#
# Run from the repo root. Requires: curl, python3, tar (zstd), shasum.
set -euo pipefail

MODE="${1:-first}"
BASE="${ERE_FIXTURES_BASE:-https://pub-760ad8b3dd9547539f829c1ea30f18b5.r2.dev/devnets/glamsterdam-devnet-8}"
CACHE="${ERE_FIXTURES_CACHE:-test-fixtures-cache/ere-glamsterdam-devnet-8}"

case "$MODE" in
    first|all) ;;
    *) echo "usage: $0 [first|all]" >&2; exit 2 ;;
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

# First batch (10 blocks) -> eest_batch/ (the default ERE_INPUT_FOLDER).
read -r first_path first_sha < <(python3 -c 'import json, sys
d = json.loads(next(open(sys.argv[1])))
print(d["path"], d["sha256"][2:])' "$CACHE/batches8.jsonl")
rm -rf "$CACHE/eest_batch"; mkdir -p "$CACHE/eest_batch"
dl_verify_extract "$first_path" "$first_sha" "$CACHE/eest_batch"
echo "cached first batch -> $CACHE/eest_batch"

# Full corpus -> all_blocks/.
if [ "$MODE" = all ]; then
    echo "downloading + extracting all batches (~3 GB download, ~17 GB extracted) ..."
    rm -rf "$CACHE/all_blocks"; mkdir -p "$CACHE/all_blocks"
    while read -r path sha; do
        dl_verify_extract "$path" "$sha" "$CACHE/all_blocks"
    done < <(python3 -c 'import json, sys
for line in open(sys.argv[1]):
    d = json.loads(line)
    print(d["path"], d["sha256"][2:])' "$CACHE/batches8.jsonl")
    echo "cached $(find "$CACHE/all_blocks/blockchain_tests" -name '*.json' | wc -l | tr -d ' ') blocks -> $CACHE/all_blocks"
fi
