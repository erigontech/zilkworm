# Tools

## EEST JSON → RLP test vectors

The Zilkworm test runners (native `state_transition`, QEMU rv32/rv64,
SP1 prover) consume **batched unified-RLP** files, one `.rlp` per source EEST
JSON. The conversion happens at build time:

1. The EEST version is pinned by the `third_party/eest-fixtures` submodule
   (sha in the parent gitlink). Bumping EEST = bumping that submodule.
2. CI sparse-checks-out `blockchain_tests/` from the pinned sha and runs
   `z6m_eest_convert bulk-convert` (rayon-parallel, ~10-15 s on 8 cores)
   to produce the RLP tree.
3. The output is cached via `actions/cache@v4` keyed on
   `(eest_sha, converter_src_sha)`. Subsequent CI runs hit the cache and
   skip the conversion entirely.

There is no published RLP archive; the converter is the only source of
truth and is content-deterministic (verified by running `bulk-convert`
twice and `diff -r`-ing the outputs).

### 1. Local dev: build the RLP tree

```bash
git submodule update --init third_party/eest-fixtures   # ~3 GB sparse if you set sparse-checkout
make eest-rlp-build                                      # builds converter + bulk-convert (~30 s + 15 s)
```

The output lands at `third_party/eest-fixtures-rlp/dev-<short-eest-sha>/`
(content-addressed by sha so different submodule checkouts coexist).
A `manifest.json` is written in the output dir; `make eest-rlp-build`
no-ops when it exists, so subsequent test runs cost nothing extra.

To force a regeneration: `rm <dir>/manifest.json` and re-run.

To run the converter directly (debugging a single JSON):

```bash
cd prover && cargo build --release --manifest-path common/Cargo.toml \
    --no-default-features --features eest-convert --bin z6m_eest_convert

prover/target/release/z6m_eest_convert emit \
    --json third_party/eest-fixtures/blockchain_tests/.../foo.json \
    --index 0 > foo.rlp
```

### 2. CI: cache key + cache restore

Each EEST workflow runs four steps before the test phase:

1. **Compute key**: `git ls-tree HEAD third_party/eest-fixtures` for the
   eest sha; `sha256sum` over the converter sources for `converter_sha`;
   key = `rlp-eest-<eest_sha>-<converter_sha>`.
2. **`actions/cache@v4`** keyed exactly on the above. No restore-keys.
3. **Init eest-fixtures sparse** (only on cache miss).
4. **Build + run converter** (only on cache miss). Subsequent steps
   consume `EEST_RLP_DIR=third_party/eest-fixtures-rlp/<key>/`.

Cache hit: ~0 s. Cache miss: ~30 s build + ~15 s convert.

### 3. Update the in-use EEST version

```bash
git -C third_party/eest-fixtures fetch --tags
git -C third_party/eest-fixtures checkout <new-version>
git add third_party/eest-fixtures
git commit -m "Bump EEST to <new-version>"
```

That's it. CI re-runs against the new sha, the cache key changes, the
converter regenerates the RLP tree once, subsequent runs hit the cache.

### 4. JSON path (developer-only)

CI exercises the RLP path only. The same test pipelines also accept raw EEST
JSON fixtures — useful when iterating on the converter, validating against
unconverted upstream tests, or debugging a single subtest. The JSON tree is
the [`third_party/eest-fixtures`](../third_party/eest-fixtures) submodule;
initialise it first:

```bash
git submodule update --init third_party/eest-fixtures
```

| Pipeline | RLP target (CI) | JSON target (dev-only) |
|---|---|---|
| native `state_transition` ctest | `make eest-blockchain-tests` | `make eest-blockchain-tests-json` |
| SP1 prover service (single dir) | `make eest-prover-test` | `make eest-prover-test-json` |
| SP1 prover service (sharded) | `make tests TESTS_SUBDIR=…` | `make tests-json TESTS_SUBDIR=…` |
| SP1 prover service (orchestrator) | `python3 tools/scripts/eest_runner.py` | `python3 tools/scripts/eest_runner.py --format=json` |
| QEMU rv32/rv64 ctest | `make rerun-ctest [ARCH=rv64]` (in `qemu_runner/`) | `make rerun-ctest-json [ARCH=rv64]` (in `qemu_runner/`) |

Override `EEST_JSON_DIR=…` to point at a custom JSON tree.

The `state_transition` and `z6m_prover --test-service` binaries auto-detect
file format by extension, so a directory containing both `.rlp` and `.json`
files works without further flags.

For the on-the-wire byte layout consumed by every runner — see [`docs/architecture.md`](../docs/architecture.md)
("Input Format" section).
