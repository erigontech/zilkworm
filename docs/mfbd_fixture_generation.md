# MFBD fixtures and corpora

**Backend: DirectState.** How the MFBD bundles that the DirectState tests and benchmarks consume
are produced, and how to regenerate them. The byte layout is in
[flat_witness_bundle.md](flat_witness_bundle.md); the CI cache keys for the EEST tree are in
[`../tools/README.md`](../tools/README.md). The HashState corpora are in
[slib_corpus_validation.md](slib_corpus_validation.md).

```bash
# EEST fixtures (regenerates only when the release pin or the converter changed)
make eest-mfbd-build           # test-fixtures-cache/eest_stable/fixtures/**/*.json -> test-fixtures-cache/mfbd-<sha>/**/*.mfbd
make eest-blockchain-tests     # build + run the ctest suite against those .mfbd

# Benchmark corpus (never regenerates on its own)
make sp1-benchmark-corpus      # temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin -> temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd
make sp1-benchmark             # rebuild guest+prover, run the 200-block prover sweep
```

## 1. What an MFBD fixture is

An `.mfbd` file is an MFBD envelope wrapping one or more FlatBundle (`FBND`) blobs. Every converter
stamps `kFlatBundleVersion` into the FlatBundle header, and `load_flat_bundle()` rejects a bundle
whose version differs.

| Set | Lives in | Source | Regenerates |
| --- | --- | --- | --- |
| **Benchmark corpus** (200 mainnet blocks) | `$(BENCH_CORPUS_DIR)/<N>/flatWitnessBundle<N>.mfbd` | `$(BENCH_SRC_DIR)/<N>/unifiedBlockAndStateRlp<N>.bin` (legacy RLP) | by hand, `make sp1-benchmark-corpus` |
| **EEST fixtures** | `test-fixtures-cache/mfbd-<sha>/blockchain_tests/**/*.mfbd` | `test-fixtures-cache/eest_stable/fixtures/blockchain_tests/**/*.json` (the tarball pinned in `test-fixtures.json`) | automatically, `make eest-mfbd-build` |

## 2. The three converters

All three are in `zilk_core/dev/cli/`, call `::zilkworm::build_flat_bundle` (`flat_bundle.hpp`) and
wrap the FBND blob in the 16-byte MFBD header, so the native runner, the QEMU runner and the
provers take their output unchanged. Build one with
`cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S . && cmake --build build --target <tool>`.

| Tool | Invocation | Input | Output | `network` section |
| --- | --- | --- | --- | --- |
| `legacy_to_flat_bundle` | `legacy_to_flat_bundle <in.bin> <out.mfbd>` | one legacy 5-item RLP bundle (genesis, block, pre-state, ancestors, pre-trie) | one `.mfbd`, `n_bundles=1` | `"Mainnet"` |
| `eest_to_flat_bundle` | `bulk-convert --input-dir <D> --output-dir <D>`, or `emit --json <f> --index <i>` to stdout | EEST `blockchain_tests` JSON tree | a mirrored `.mfbd` tree, one `.mfbd` per JSON with all its subtests | the fixture's `network` field, `"Mainnet"` when absent |
| `json_witness_to_flat_bundle` | `json_witness_to_flat_bundle < witness.json > out.mfbd` | the `{block, headers, state, codes, keys}` JSON that `prover/common/src/fetcher.rs` builds from a `debug_executionWitness` response | one `.mfbd` | `"Mainnet"` |

`legacy_to_flat_bundle` produces the benchmark corpus and `eest_to_flat_bundle` the EEST fixtures.
`json_witness_to_flat_bundle` is a thin CLI over `zilk_core/dev/witness_converter.{hpp,cpp}`, the
converter the Rust hosts link through `prover/witness_ffi`: a block fetched with `z6m_prover fetch`
is written as `<data-dir>/blocks/<N>/flatWitnessBundle<N>.mfbd` directly.

## 3. Benchmark corpus

```
$(BENCH_SRC_DIR)/<N>/unifiedBlockAndStateRlp<N>.bin      # raw source (legacy RLP), default temp/200_benchmark_blocks
$(BENCH_CORPUS_DIR)/<N>/flatWitnessBundle<N>.mfbd        # converted corpus, default temp/200_benchmark_blocks_mfbd_v2
```

- **Raw blocks.** CI downloads them from the `benchmark-200-spread` release of
  `erigontech/zilkworm-testdata` (the URL is in `.github/workflows/sp1-benchmark.yml`).
- **Convert.** `make sp1-benchmark-corpus` builds `legacy_to_flat_bundle` and converts every `.bin`
  under `$(BENCH_SRC_DIR)`. It is a plain loop with no manifest and no staleness check: it always
  re-converts whatever is present, and nothing ties the `_v2` directory suffix to
  `kFlatBundleVersion`.
- **Prover sweep.** `make sp1-benchmark` runs
  `python3 tools/scripts/sp1_benchmark.py --dir $(BENCH_CORPUS_DIR)` after `z6m_prover` and
  `sp1-benchmark-corpus`; results go to `temp/benchmarks/benchmark_<timestamp>/`.
- **Host state-root check.** `tools/scripts/release_state_root_check.sh --dir <blocks_dir>` builds
  `state_transition` (Release), runs each `flatWitnessBundle<N>.mfbd` and reports
  `State root mismatches`.
- **CI.** `.github/workflows/sp1-benchmark.yml` (SP1) and
  `.github/workflows/airbender-benchmark.yml` (Airbender) regenerate the corpus with the converter
  they just built and run it on every push and PR.

## 4. EEST fixtures

**Source.** `test-fixtures.json` pins a fixture release tarball per corpus key (`url`, `sha256`,
`size`). The `eest_stable` key points at an `ethereum/execution-specs` release (`tests@<ver>`).
`make test-fixtures` (`tools/test-fixtures.sh`) downloads, sha256-verifies and extracts it into
`test-fixtures-cache/eest_stable/fixtures/`. Re-runs are no-ops while the pin matches.

**Generate.** `make eest-mfbd-build`:

1. Builds `eest_to_flat_bundle` (`make z6m_eest_convert`).
2. `EEST_SHA` is the first 12 hex digits of the manifest's `eest_stable.sha256`; the output
   directory is `EEST_MFBD_DIR = test-fixtures-cache/mfbd-<EEST_SHA>`.
3. If `mfbd-<sha>/manifest.json` already records the sha256 of the current converter binary, it
   stops there.
4. Otherwise it fetches the fixtures, runs `eest_to_flat_bundle bulk-convert` into
   `mfbd-<sha>/blockchain_tests`, and writes `manifest.json = {"eest_sha":…,"converter_sha":…}`.

So the tree is keyed twice: by the pinned tarball (a fixture bump lands in a new `mfbd-<sha>/`) and
by the converter binary (a change to any source that affects the output bytes rebuilds within the
same directory). To force a regeneration, delete `manifest.json`.

**Consume.**

| Target | Runs | CI |
| --- | --- | --- |
| `make eest-blockchain-tests` | native `state_transition` on every `.mfbd`, one ctest case each (`-DEEST_MFBD_DIR`) | `eest-blockchain-tests.yml` |
| `make eest-prover-test` | `z6m_prover --test-service --test-dir $(EEST_MFBD_DIR)` under the SP1 executor | `hypercube-eest.yml` (the same command, sharded by `tools/scripts/eest_runner.py`) |
| `make selftest` | one fixture (`add11`) converted with `emit` and executed | |
| `cd qemu_runner && make rerun-ctest` | the fixtures on rv32im or rv64im (`ARCH=rv64`) under QEMU | `qemu-eest-blockchain.yml`, `qemu-eest-blockchain-rv64.yml` |
| `cd prover/prover_airbender && make eest` | the JSON fixtures on the Airbender simulator | `airbender-eest.yml` |

The fixtures a runner is known to get wrong are listed in `zilk_core/dev/eest-known-failures.txt`
(native and SP1, registered `WILL_FAIL` by `zilk_core/dev/cli/CMakeLists.txt`) and
`prover/prover_airbender/eest-known-failures.txt` (Airbender).

The `*-json` targets (`eest-blockchain-tests-json`, `eest-prover-test-json`, `tests-json`) run the
unconverted JSON fixtures through the EJSN path; CI runs the MFBD path.

**Bump the EEST release.** Edit the `eest_stable` entry of `test-fixtures.json`: set `url` to the
new release asset and `sha256` / `size` to its published digest (for example from
`gh api repos/<org>/<repo>/releases/tags/<tag> --jq '.assets[]|{name,size,digest}'`). Then:

```bash
make eest-mfbd-build   # downloads + verifies the new tarball, converts into a new mfbd-<new-sha>/ tree
git add test-fixtures.json && git commit
```

The old `mfbd-<old-sha>/` tree is left in place. Update the known-failures lists if the failing
set shifts.

## 5. Wire-format changes

If a change alters the byte layout of any `reinterpret_cast`'d wire POD, bump `kFlatBundleVersion`
(`zilk_core/core/types_zz/flat_bundle.hpp`) in the same commit and regenerate both fixture sets.

`load_flat_bundle()` checks only the version field. A layout change without a bump leaves the
bundles on disk with a matching version: they pass the check and are cast with the new struct
definition, which yields wrong roots and no error.

| Wire-significant struct | File (under `zilk_core/core/`) |
| --- | --- |
| `FlatBundleHeader` | `types_zz/flat_bundle.hpp` |
| `PreStateMeta`, `Slot`, `AddrHashEntry`, `BlockHashEntry` | `state_zz/pre_state.hpp` |
| `Account` | `types_zz/account.hpp` |
| `MphfMapHeader`, `MphfCollisionEntry` | `common_zz/mphf_map.hpp` |
| `FlatKv` layout (`kPayloadOffset` / `kKeySize`) | `types_zz/flat_kv.hpp` |

The Rust encoder `prover/stateless_validator/src/mfbd.rs` mirrors the wire constants and the key8
functions and must change with them.

```bash
# 1. In the same commit as the layout change: bump kFlatBundleVersion in flat_bundle.hpp.
# 2. Regenerate EEST (automatic, since the converter binary changed):
make eest-mfbd-build
# 3. Regenerate the benchmark corpus (it has no staleness check):
make sp1-benchmark-corpus
```

| Change | Benchmark corpus | EEST fixtures |
| --- | --- | --- |
| Wire-POD layout change (with the `kFlatBundleVersion` bump) | `make sp1-benchmark-corpus` | `make eest-mfbd-build` |
| Converter logic change (how bytes are written) | `make sp1-benchmark-corpus` | automatic (the converter sha changes the manifest) |
| New EEST release pin | | edit `test-fixtures.json`, `make eest-mfbd-build` |
| New or different benchmark blocks | add the `.bin`, `make sp1-benchmark-corpus` | |

## 6. Validation after regenerating

```bash
make eest-blockchain-tests                                                        # leg 1
tools/scripts/release_state_root_check.sh --dir temp/200_benchmark_blocks_mfbd_v2 # leg 2
make sp1-benchmark                                                                # leg 3 (rebuilds the guest)
```

Pass: ctest green, `State root mismatches: 0`, and no failed block in the benchmark with
`gas_used` unchanged. A skipped version bump or a stale corpus shows up here as state-root or gas
mismatches.
