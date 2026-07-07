# Tools

## EEST JSON → MFBD test vectors

The Zilkworm test runners (native `state_transition`, QEMU rv32/rv64,
SP1 prover) consume **MFBD-wrapped FlatBundle** files, one `.mfbd` per
source EEST JSON. The conversion happens at build time:

1. The EEST version is pinned by the `third_party/eest-fixtures` submodule
   (sha in the parent gitlink). Bumping EEST = bumping that submodule.
2. CI sparse-checks-out `blockchain_tests/` from the pinned sha and runs
   the C++ `eest_to_flat_bundle bulk-convert` binary (std::async-parallel)
   to produce the MFBD tree.
3. The output is cached via `actions/cache@v4` keyed on
   `(eest_sha, cpp_converter_src_sha)`. Subsequent CI runs hit the cache
   and skip the conversion entirely.

There is no published MFBD archive; the converter is the only source of
truth and is content-deterministic (verified by running `bulk-convert`
twice and `diff -r`-ing the outputs).

For the on-the-wire MFBD byte layout, see
[`docs/flat_witness_bundle.md`](../docs/flat_witness_bundle.md).

### 1. Local dev: build the MFBD tree

```bash
git submodule update --init third_party/eest-fixtures   # ~3 GB sparse if you set sparse-checkout
make eest-mfbd-build                                     # builds the C++ converter + bulk-convert
```

The output lands at `third_party/eest-fixtures-mfbd/dev-<short-eest-sha>/`
(content-addressed by sha so different submodule checkouts coexist).
A `manifest.json` is written in the output dir; `make eest-mfbd-build`
no-ops when it exists, so subsequent test runs cost nothing extra.

To force a regeneration: `rm <dir>/manifest.json` and re-run.

To run the converter directly (debugging a single JSON):

```bash
# Build the C++ converter binary:
make z6m_eest_convert

# Emit a single subtest:
build/zilk_core/dev/cli/eest_to_flat_bundle emit \
    --json third_party/eest-fixtures/blockchain_tests/.../foo.json \
    --index 0 > foo.mfbd
```

### 2. CI: cache key + cache restore

Each EEST workflow runs four steps before the test phase:

1. **Compute key**: `git ls-tree HEAD third_party/eest-fixtures` for the
   eest sha; `sha256sum zilk_core/dev/cli/eest_to_flat_bundle.cpp` for
   `conv_sha`; key = `mfbd-eest-<eest_sha>-<conv_sha>`.
2. **`actions/cache@v4`** keyed exactly on the above. No restore-keys.
3. **Init eest-fixtures sparse** (only on cache miss).
4. **Build + run converter** (only on cache miss). Subsequent steps
   consume `EEST_MFBD_DIR=third_party/eest-fixtures-mfbd/<key>/`.

Cache hit: ~0 s. Cache miss: ~30 s C++ build + ~15 s convert.

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

CI exercises the MFBD path only. The same test pipelines also accept raw EEST
JSON fixtures — useful when iterating on the converter, validating against
unconverted upstream tests, or debugging a single subtest. The JSON tree is
the [`third_party/eest-fixtures`](../third_party/eest-fixtures) submodule;
initialise it first:

```bash
git submodule update --init third_party/eest-fixtures
```

| Pipeline | MFBD target (CI) | JSON target (dev-only) |
|---|---|---|
| native `state_transition` ctest | `make eest-blockchain-tests` | `make eest-blockchain-tests-json` |
| SP1 prover service (single dir) | `make eest-prover-test` | `make eest-prover-test-json` |
| SP1 prover service (sharded) | `make tests TESTS_SUBDIR=…` | `make tests-json TESTS_SUBDIR=…` |
| SP1 prover service (orchestrator) | `python3 tools/scripts/eest_runner.py` | `python3 tools/scripts/eest_runner.py --format=json` |
| QEMU rv32/rv64 ctest | `make rerun-ctest [ARCH=rv64]` (in `qemu_runner/`) | `make rerun-ctest-json [ARCH=rv64]` (in `qemu_runner/`) |

Override `EEST_JSON_DIR=…` to point at a custom JSON tree.

The `state_transition` and `z6m_prover --test-service` binaries auto-detect
file format by the leading 4-byte magic (`MFBD` vs `EJSN`), so a directory
containing both `.mfbd` and `.json` files works without further flags.

For the on-the-wire byte layout consumed by every runner — see
[`docs/flat_witness_bundle.md`](../docs/flat_witness_bundle.md).

## Check debug_executionWitness content

We have some scripts to validate the `debug_executionWitness` payload an execution client returns for a block — i.e.
whether the witness contains every trie node and preimage needed to re-execute the block statelessly. Two scripts run
a full stateless validation against a stateless validator (Zilkworm and Reth); the third one inspects a witness for
preimage completeness.

Both the stateless validation scripts fetch over JSON-RPC by default (`RPC`, default `http://localhost:8545`); the node
must expose `debug_getRawBlock` and `debug_executionWitness`.

### 1. Zilkworm validator — `check_execution_witness.sh`

Runs Zilkworm `z6m_prover` in execute mode (built on first use via `make z6m_prover`)
and classifies each block: `VALID`, `SENTINEL_FAIL`, a `kWrong<…>` validation
error, or `OTHER`.

```bash
# Single block over RPC (defaults to the chain tip if --block omitted)
RPC=<rpc-url> tools/witness/check_execution_witness.sh --block 25350549

# Contiguous range over RPC
RPC=<rpc-url> tools/witness/check_execution_witness.sh --start-block 25350540 --end-block 25350549

# Poll over RPC the next-latest tip N times
RPC=<rpc-url> tools/witness/check_execution_witness.sh --count 5 --poll-secs 4
```

Env: `RPC`, `BLK`, `DIR` (z6m repo root), `DATA_DIR` (prover data-dir,
default `$DIR/temp/mainnet`, shared with fetched blocks). Logs land in
`$DATA_DIR/logs/<N>.log`.

### 2. Reth validator — `check_execution_witness_reth.sh`

Cross-checks against Reth's stateless validator. It clones and patches `paradigmxyz/stateless`,
so the state-root calculation surfaces the exact blinded-node position (account hash + slot hash +
missing nibble path) instead of a generic error, then builds a small `reth-check` binary and runs
it per block. On failure it prints `INVALID -> <msg>` and, for a missing storage proof, resolves
the `(address, slot)` preimages and reports whether an exclusion/inclusion proof is present or missing.

The script accepts also local block/witness files via `--rlp`/`--witness`:

- `blockRlp<N>.json` — the RLP-encoded block (`debug_getRawBlock` response)
- `executionWitness<N>.json` — the witness (`debug_executionWitness` response), as the
  raw RPC envelope or the bare `result` object; `.json`, `.json.gz`, or `.json.tar.gz`.

```bash
# Single block over RPC
RPC=<rpc-url> tools/witness/check_execution_witness_reth.sh --block 25350549

# Poll over RPC the next-latest tip N times
RPC=<rpc-url> tools/witness/check_execution_witness_reth.sh --count 5

# Local files in some dir, no RPC
tools/witness/check_execution_witness_reth.sh --block 25350549 \
    --rlp /tmp/blockRlp25350549.json --witness /tmp/executionWitness25350549.json
```

Requires `rustup` (toolchain 1.93+, auto-installed), `curl`, `python3`, and
network access (clones Reth + stateless on first run). Env: `RPC`, `BLK`,
`DIR` (reuse a built project dir; otherwise a temp dir is used and removed on
exit unless `--keep-dir`).

### 3. Preimage completeness — `verify_witness_preimages.py`

Static witness check (no execution). Walks the account trie and each non-empty storage subtrie and
reports trie leaves whose preimages are absent from `witness.keys`. The account/slot listed are a
*superset* of true violations (a reported leaf may be a sibling not strictly required for execution);
you need to cross-reference with the EVM access trace to obtain true violations. For this you use
`--check-addr` option, which classifies specific addresses (`present`/`absent`/`blinded`)
and flags any whose preimage is missing from `keys`.

```bash
python3 tools/witness/verify_witness_preimages.py executionWitness25350549.json
python3 tools/witness/verify_witness_preimages.py executionWitness25350549.json \
    --check-addr 0x0e0c281ff05d34729cd764dcfc4fa999b720407c
```

Requires `pycryptodome` (`pip install pycryptodome`).
