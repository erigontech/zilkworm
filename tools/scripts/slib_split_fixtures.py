#!/usr/bin/env python3

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

"""Split multi-case blockchain_test fixture JSONs into one-case-per-file.

The tests-zkevm-benchmark fixtures pack many parametrized cases into a single
JSON file (e.g. keccak.json = 18 cases keyed by pytest node id). Feeding such a
file to `z6m_prover execute --is-test --file-name` runs ALL cases in the file and
SUMS their cycles into one reported number, so to get a per-case (= per-block,
since these fixtures carry exactly one block per case) cycle count each case must
live in its own file.

This walks --in recursively, skips the `.meta` sidecar directory, and writes each
top-level case object out as `{case_id: case_obj}` to
`--out/<file_stem>__<case_id>.json`. The `slib-benchmark` Makefile target then
runs one prover invocation per emitted file.
"""

import argparse
import hashlib
import json
import os
import re
import sys


def slug(s: str) -> str:
    """Filesystem-safe slug for a fixture stem or pytest node id.

    Collision-free under truncation: a plain 180-char cut used to drop the
    distinguishing tail of long pytest node ids (in tests-zkevm-benchmark the
    same stem exists in all three gas-budget dirs and only a trailing
    `value_10M/30M/60M` differs, so 655 of 3464 cases silently overwrote each
    other). When the sanitized name exceeds 180 chars, keep the head and append
    a short digest of the FULL name, so distinct inputs always map to distinct
    slugs while short names stay byte-identical to the old behavior.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    if len(safe) <= 180:
        return safe
    digest = hashlib.sha256(safe.encode()).hexdigest()[:12]
    return f"{safe[:167]}_{digest}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--in", dest="indir", required=True,
                    help="fixtures blockchain_tests dir (searched recursively)")
    ap.add_argument("--out", dest="outdir", required=True,
                    help="output dir for one-case-per-file JSONs")
    args = ap.parse_args()

    if not os.path.isdir(args.indir):
        print(f"ERROR: input dir not found: {args.indir}", file=sys.stderr)
        return 1
    os.makedirs(args.outdir, exist_ok=True)

    n_files = 0
    n_cases = 0
    emitted: dict[str, int] = {}  # output path -> times seen (residual-duplicate guard)
    for root, _dirs, files in os.walk(args.indir):
        # Skip the .meta sidecar (index.json / fixtures.ini), not test cases.
        if (os.sep + ".meta") in (root + os.sep):
            continue
        for fn in sorted(files):
            if not fn.endswith(".json"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path) as fh:
                    doc = json.load(fh)
            except (json.JSONDecodeError, OSError) as e:
                print(f"  skip {path}: {e}", file=sys.stderr)
                continue
            if not isinstance(doc, dict) or not doc:
                continue
            n_files += 1
            stem = os.path.splitext(fn)[0]
            for case_id, case in doc.items():
                out = os.path.join(args.outdir, f"{slug(stem)}__{slug(case_id)}.json")
                # Residual-duplicate guard: identical stem+case_id in two input
                # files (never the truncation case, which slug() already
                # disambiguates) would still overwrite. Emit a deterministic
                # __dupN sibling instead so every input case survives.
                seen = emitted.get(out, 0)
                emitted[out] = seen + 1
                if seen:
                    base, ext = os.path.splitext(out)
                    out = f"{base}__dup{seen + 1}{ext}"
                with open(out, "w") as fh:
                    json.dump({case_id: case}, fh)
                n_cases += 1

    print(f"  split {n_cases} cases from {n_files} files into {args.outdir}")
    if n_cases == 0:
        print("ERROR: no cases emitted (empty or missing fixtures?)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
