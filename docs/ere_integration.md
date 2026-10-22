<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

Zilkworm is integrated as a stateless-validation execution client in the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). The same canonical EEST benchmark fixtures are executed inside SP1 using the Zilkworm guest, validated against their expected public values, and (optionally) compared with Reth by SP1 estimated prover cost.

The current integration targets **Amsterdam / Sepolia** with the
**tests-zkevm v21.0.1** stateless schema, on **ere v0.18.1 / ere-guests v0.18.0**. The ERE guest is the HashState
build of the hypercube guest (`make ere-bin`), which takes the canonical EEST `statelessInputBytes` unchanged; see
[hashstate.md](hashstate.md). The MFBD host adapter in [`prover/stateless_validator`](../prover/stateless_validator)
serves the DirectState guest and is no longer on the ERE path.

## Branches and repository layout

The ere-guests and benchmark changes live on `erigontech` forks until merged upstream.
Until then the three repos must sit **as siblings** in the same parent directory: the
benchmark fork's `[patch]` and path deps use relative paths (`../ere-guests_fork`,
`../z6m`), so the Zilkworm checkout must be named `z6m/`:

```
<workspace>/
├── z6m/                            # clone of erigontech/zilkworm (guest)
├── ere-guests_fork/                # clone of erigontech/ere-guests
└── zkevm-benchmark-workload_fork/  # clone of erigontech/zkevm-benchmark-workload
```

| Repo | Branch | Based on | Carries |
|---|---|---|---|
| `erigontech/zilkworm` | `release/0.1.0-alpha.4` | `v0.1.0-alpha.3` | Guest (`zilk_core` + ZVM1 submodule `34cc5a71`, zvm1 `release/0.1.0-alpha.4`) with the stateless new-payload and witness checks, and the host adapter `prover/stateless_validator` (SIOB→MFBD): tests-zkevm v21.0.1 schema, EIP-8282 builder-requests fix, chain id 1 → Amsterdam, Sepolia network config, ERE make targets/docs/fetch script, `eest_runner` cycle metrics, the `ERE Benchmark` workflow and its release hookup. |
| `erigontech/ere-guests` | `canepat/zilkworm_mfbd` | `main` (`d31055c`, v0.18.0) | One commit mirroring the Nimbus addition (upstream PR #88): `StatelessValidatorKind::Zilkworm` (catalog ID 4), the `zilkworm` entry in `artifact-registry.json` (sp1, `zkvm_version` v6.6.0), the catalog/downloader/test-crate tests, and the README. The guest runs on the fixtures' `statelessInputBytes` like every other guest; `elf_url` names the `z6m_guest_hypercube_slib` assets of a Zilkworm release. |
| `erigontech/zkevm-benchmark-workload` | `canepat/zilkworm_mfbd` | `master` (`274070c`, ere-guests v0.18.0) | The `zilkworm` execution client (`ExecutionClient::Zilkworm`, on the raw `statelessInputBytes` path), the `[patch]` taking the ere-guests catalog from the erigontech fork, and the cross-file EEST fixture-name dedup with its regression test. |

The benchmark's workspace `[patch]` takes `stateless-validator-catalog` from the
erigontech ere-guests fork (the Zilkworm kind); the other ere-guests crates stay
on the upstream tag.

## Reference environment

| Component | Version |
|---|---|
| OS | macOS, Darwin 25.5.0, arm64 |
| Container engine | Docker 29.4.0 |
| Rust | 1.95.0 (pinned in `rust-toolchain.toml`) |
| ERE harness | `eth-act/ere` tag `v0.18.1` (rev `20e87aa`), image `ghcr.io/eth-act/ere/ere-server-sp1:20e87aa` |
| ere-guests | `v0.18.0` (via the benchmark `[patch]` to `../ere-guests_fork`) |
| SP1 | v6.6.0 (ere v0.18.1) |
| Guest artifacts | zilkworm `local-dev`, reth `0.1.0-rc.4`, ethrex `29.0.0` (all sp1 v6.6.0) |
| Fixtures | Sepolia block export (Amsterdam since timestamp 1791294816), chainId `0xaa36a7` (11155111), 100-block batches |

The SP1 host runs in an x86_64 container; on Apple Silicon it executes under
emulation. Cycle counts are host-independent and valid; wall-clock timings are
not representative.

## Quick start

Two `Makefile` targets drive the ERE harness. Both run `ere-hosts` inside `$(ERE_WORKLOAD_DIR)`:

```sh
# Validate Zilkworm against a fixture folder
make ere-validate \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin

# Estimate cost (SP1 gas model) for Zilkworm and Reth and print the comparison
make ere-compare \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin
```

`ERE_WORKLOAD_DIR` must point at the **benchmark fork** (it has the `zilkworm`
client and the local `[patch]`); upstream `master` does not. It is not changed
in the Makefile default — pass it on the command line as shown.

### Tunable variables

```
ERE_IMAGE_REGISTRY ?= ghcr.io/eth-act/ere   # registry for ere's prebuilt zkVM images (see note)
ERE_WORKLOAD_DIR   ?= temp/zkevm-benchmark-workload   # pass ../zkevm-benchmark-workload_fork
ERE_INPUT_FOLDER   ?= $(FIXTURES_CACHE)/ere-sepolia/eest_batch  # ere-hosts --input-folder
ERE_BIN_PATH       ?=                        # local guest ELF dir; empty => download the published guest
ERE_RETH_ARTIFACT_URL ?= <derived from the ere-guests resolved by $(ERE_WORKLOAD_DIR): reth sp1 elf_url dirname>
ERE_GEN_FIXTURES   ?=                        # non-empty => (re)generate EEST fixtures first (opt-in)
ERE_TIMEOUT        ?= 60m                    # per-action timeout
```

- **`ERE_IMAGE_REGISTRY`** is folded into `ERE_RUN_ENV` and prepended to ere's
  image names so `docker pull` fetches the prebuilt `ere-server-sp1:20e87aa`
  from ghcr. Without it, ere has no default registry and falls back to building
  the images from source. Overridable.
- **`ERE_BIN_PATH`** (optional): a relative value is resolved against z6m via
  `$(abspath …)` (the recipe `cd`s into the workload dir first). Empty => the
  target downloads the published guest ELF named in `artifact-registry.json`.
  Build/stage the local guest with `make ere-bin`: the HashState build
  (`z6m_guest_slib`), which takes the fixtures' `statelessInputBytes` unchanged
  (outputs `build/ere-bin/stateless-validator-zilkworm-sp1.{elf,vk}`). ere-hosts loads
  `<bin-path>/stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}`, so
  both targets first run `ere-bin-link`, which symlinks the unversioned files
  under the version the workload's ere resolves (`tools/ere_workload.py
  <workload> sp1-sdk-version`, mirroring ere-catalog's build script: currently
  `v6.6.0`). The VK must exist but ere-hosts does not read it.
- **`ERE_RETH_ARTIFACT_URL`**: base URL of the reth guest artifacts, passed as
  `--guest-artifact-base-url` on the reth leg of `ere-compare`. Temporary while
  the workload `[patch]`es ere-guests. Derived at make time by navigating the
  workload's own dependency graph: `cargo metadata` in `ERE_WORKLOAD_DIR` gives
  the `manifest_path` of the resolved `stateless-validator-downloader` crate, and
  the registry that crate embeds sits at `../../artifact-registry.json` from
  there (the `[patch]` checkout today, the git checkout once upstreamed); the
  value is the dirname of the reth sp1 `elf_url` (`tools/ere_workload.py
  <workload> reth-artifact-url`). No sibling-folder assumption;
  override it to point elsewhere. Why it is needed: the benchmark's
  `build.rs` derives the guest download source (release tag or commit) from the
  `stateless-validator-downloader` entry's git source in `Cargo.lock`; under the
  `[patch]` that crate is a path dependency with no git source, so ere-hosts
  compiles with an unknown download source and its default downloader (ere-guests
  release assets) bails. The flag bypasses it. If the URL cannot be derived the
  flag is omitted and the default downloader runs.
- **`ERE_INPUT_FOLDER`**: the fixture folder passed to `ere-hosts --input-folder`
  (required for `--action execute`). Defaults to the cached Sepolia first batch;
  point it at a larger extracted set for a full run.
- **`ere-fixtures` is opt-in**: set `ERE_GEN_FIXTURES=1` to regenerate EEST
  fixtures via `witness-generator-cli` before running. By default the targets run
  directly against `ERE_INPUT_FOLDER` (no generation).

### `--force-rerun` is always on

`ere-hosts` writes one result JSON per fixture under
`$(ERE_WORKLOAD_DIR)/zkevm-metrics/<client>-<ver>/<zkvm>-<sdk>/`, and by default
**skips** any fixture that already has a result there. That silently reuses stale
results from a previous guest. Both targets therefore pass `--force-rerun`
unconditionally so validate/compare always re-execute against the current guest.

### Actions and metrics (ere ≥ v0.17)

Since ere v0.17 / benchmark master (#310, #312) the per-fixture record written
by `--action execute` carries only `output_matched` and `execution_duration`:
**no cycle count**. Cost data comes from `--action estimate-cost`, which stores
`cost_estimation.success.cost`, a per-component map (`opcode`, `syscall`,
`system`) from SP1's estimated prover-cost model, plus `peak_heap_bytes`.
Accordingly:

- `ere-validate` runs `--action execute` and gates on `output_matched`.
- `ere-compare` runs `--action estimate-cost` for reth and zilkworm and compares
  the summed components. Records are merged per fixture file, so a compare run
  keeps the `execution` block written by a preceding validate run.
- `tools/ere_compare.py` reports one comparison per metric kind and never sums
  legacy execution cycles (results from ere ≤ v0.16) with estimated cost.

## Fixtures: Sepolia

The stateless fixtures are published as an R2 block export (not the generated EEST
corpus):

```
base:    https://pub-afa6b160acfb4919bda1d0e2a00b5b77.r2.dev/testnets/sepolia
catalog: <base>/batches.jsonl        # 100-block batches
batches: <base>/exports/batches/<start>-<end>.tar.zst   # each holds blockchain_tests_engine/**/*.json
```

Each fixture carries one `engineNewPayloads` entry whose `statelessInputBytes` use the
tests-zkevm v21.0.1 layout. The earlier glamsterdam-devnet-8 export uses the v0.8.4
layout, which the v21 decoder rejects.

They are cached under `test-fixtures-cache/ere-sepolia/` (gitignored):
`batches8.jsonl` (catalog), `archives/*.tar.zst` (downloads), `eest_batch/` (first
batch extracted), `latest/` (latest batches extracted), `all_blocks/` (every batch extracted).

### Download and extract to the cache

Use [`tools/ere-fetch-fixtures.sh`](../tools/ere-fetch-fixtures.sh) — it fetches the
catalog + manifest, caches the first batch to `eest_batch/`, with `all`
downloads every batch (sha256-verified against the catalog) and extracts it to
`all_blocks/`, and with `latest N` extracts only the N latest batches to
`latest/` (the selection used by CI):

```sh
tools/ere-fetch-fixtures.sh            # first batch only
tools/ere-fetch-fixtures.sh latest 1   # latest batch (100 blocks)
tools/ere-fetch-fixtures.sh all        # full corpus
```

The R2 base URL (catalog root, or its `index.html` / `manifest.json` URL) and cache dir
are overridable via `ERE_FIXTURES_BASE` / `ERE_FIXTURES_CACHE`. Then run the extracted
batches through the make target:

```sh
make ere-validate \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin \
    ERE_INPUT_FOLDER=$(pwd)/test-fixtures-cache/ere-sepolia/latest
```

To run the general EEST corpus instead, pass `ERE_GEN_FIXTURES=1` (and set
`ERE_INPUT_FOLDER` to the generated tree).

## CI

[`.github/workflows/ere-benchmark.yml`](../.github/workflows/ere-benchmark.yml) runs
`make ere-validate` (and optionally `make ere-compare`) on the latest batches of an
R2 catalog, mirroring the upstream `eest-r2-stateless-inputs.yml` selection with the
Zilkworm guest in place of the EEST spec guest.

- **Triggers:** push to `release/*` branches, `workflow_dispatch` on any branch, and `workflow_call` from
  [`release.yml`](../.github/workflows/release.yml) after a `v*` release is
  published (a release created with `GITHUB_TOKEN` emits no `release` event).
- **Guest source:** `build` runs `make ere-bin` at the run's ref; `release`
  downloads `stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}` of `release_tag`, verified against
  the release `SHA256SUMS.txt`. A release publishes both hypercube guests:
  `z6m_guest_hypercube_mfbd` (DirectState, MFBD bundles) and the handbook-named
  `stateless-validator-zilkworm-sp1-<SP1 SDK version>` (HashState, the ERE guest).
- **Inputs:** `guest_source`, `release_tag`, `catalog_url` (default Sepolia),
  `batch_count` (default 1), `compare` (default off; on for releases),
  `workload_ref` / `ere_guests_ref` (default `canepat/zilkworm_mfbd` on the
  erigontech forks).
- **Layout:** `z6m/`, `zkevm-benchmark-workload_fork/` and `ere-guests_fork/` are
  checked out as siblings, as the workload's path dependency and `[patch]` require.
  The ere job runs on the runner host: ere-hosts reaches `ere-server-sp1` on
  `127.0.0.1:4175`.
- **Output:** the step summary records the three commits, the guest ELF sha256,
  the block range and the `ere_compare.py` report; `zkevm-metrics/` is uploaded.

Once the zilkworm client and registry entry are upstreamed, the ere-guests
checkout and the workload `[patch]` go away.

## Results

Full per-fixture metrics live under `$(ERE_WORKLOAD_DIR)/zkevm-metrics/`.

### Sepolia (current)

Local run of `make ere-validate` and `make ere-compare` through the forks on
`canepat/zilkworm_mfbd` (raw `statelessInputBytes` path), latest batch (blocks
11905100..11905199), `--action estimate-cost`, SP1 v6.6.0, ere v0.18.1. Zilkworm
guest: the HashState build (`make ere-bin`), ELF sha256
`267cd6486004e386a736fc8f205ad9974051fcf820f3141c264ef2189d667d84`; Reth guest `0.1.0-rc.4`.

| Client | Completed | output_matched | Mismatches |
|---|---|---|---|
| Zilkworm | 100/100 | 100 | 0 |
| Reth | 100/100 | 98 | 2 (blocks 11905160, 11905186) |

| Metric | Value |
|---|---|
| Total estimated cost — Reth | 15,498,357,778,963 |
| Total estimated cost — Zilkworm | 7,397,962,138,984 |
| Ratio Z/R (total) | **0.477** (Reth = 2.09× Zilkworm) |
| Per-fixture Z/R | median 0.473, mean 0.503, min 0.403, max 2.186 |
| Zilkworm cheaper | 98 / 100 |

Components (Reth / Zilkworm): `opcode` 12,983,896,897,645 / 5,501,284,818,016,
`syscall` 1,679,793,866,158 / 1,524,988,700,636, `system` 834,667,015,160 / 371,688,620,332.
The two blocks where Reth is cheaper are its two mismatches: it stops early on a
block it gets wrong. On the 98 blocks both validate, Z/R stays within 0.403..0.484.

The alpha.4 DirectState guest with the MFBD host adapter, run locally on this batch,
totals 7,653,392,292,202 (Z/R 0.494); the HashState guest on the raw input is 3.3%
cheaper on the same blocks.

### tests-zkevm v21.0.6

The ere-guests `stateless-validator-test` crate (`executes_registered_guest`, SP1) feeds
the HashState guest each fixture's `statelessInputBytes` unchanged: **33,854 of 33,854
fixtures succeed**, no expected failures (every case the other guests list as expected
failures passes, Reth's three `eip7928` BAL cases included). Three gaps were found and
closed on the way:

- the raw path lacked the EIP-7934 block-RLP cap, so
  `test_block_at_rlp_size_limit_boundary[max_rlp_size_plus_1_byte]` was accepted; `run_sib`
  now rejects a block whose canonical RLP exceeds `kMaxRlpBlockSize` from Osaka, as the
  JSON and MFBD paths do on the RLP they receive;
- the trie sweep skipped a node whose path runs past the 64-nibble key instead of failing
  the build (`test_witness_state_rejects_overlength_secured_trie_path`, a v21.0.6 rule);
  such a witness is now `BuildStatus::kMalformed` and the block is rejected;
- an EIP-7702 marker written inside a transaction lives in evmone's state until the diff,
  so a same-transaction read of another account holding that marker, with the bytes omitted
  from the witness, was a fail-closed miss (`test_witness_codes_delegation_same_marker_*`);
  the processor now keeps each authorization's marker by hash before the transaction runs
  (`note_created_code`), which is sound by the hash binding.

The test resolves the guest through `artifact-registry.json`, so until a release
publishes `stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}` it runs with the registry pointed at a
local copy (an `http://127.0.0.1` URL served from `build/ere-bin`, the HTTPS check in
`registry.rs` relaxed locally; neither edit is committed). Run it alone: it and
`make ere-validate`/`ere-compare` both drive an ere-server on port 4175, and a
concurrent run answers with the other guest's results.

### Previous stack (tests-zkevm v0.8.4 layout, ere v0.17.0, SP1 v6.4.0)

Zilkworm guest built from `canepat/ere_benchmark_workflow` (`266b94e`, ZVM1 `3ddf2bdf`), ELF sha256
`1962dd4dbfbae8400f7fed4726ec159027ac114ab71faa5a9ab7623121d07fef`; Reth guest `0.1.0-rc.3`.

#### Validation — glamsterdam-devnet-8

| Client | Completed | output_matched | Mismatches |
|---|---|---|---|
| Zilkworm | 72,732/72,732 | 72,732 | 0 |

`make ere-validate` over the full catalog (72,732 fixtures, blocks 93300..257519) reports
`RESULT: PASS` (total 72732, completed 72732, output_matched 72732, incomplete 0, mismatched 0).

#### Estimated cost — glamsterdam-devnet-8 batch

10 blocks (93300..93309), `--action estimate-cost`, both clients 10/10 `output_matched`:

| Metric | Value |
|---|---|
| Total estimated cost — Reth | 244,559,852,848 |
| Total estimated cost — Zilkworm | 120,970,645,141 |
| Ratio Z/R (total) | **0.495** (Reth = 2.02× Zilkworm) |
| Per-fixture Z/R | median 0.499, min 0.463, max 0.502 |
| Zilkworm cheaper | 10 / 10 |

Components (Reth / Zilkworm): `opcode` 167,896,301,578 / 67,435,147,093,
`syscall` 61,924,881,056 / 44,689,339,322, `system` 14,738,670,214 / 8,846,158,726.

#### Estimated cost — tests-zkevm-benchmark v0.8.2

3464 generated fixtures, `--action estimate-cost`. Zilkworm completes 3464/3464 `output_matched`;
Reth completes 3444/3444, and its remaining 20 (`test_modexp`) hit the 60-minute timeout, so they
are excluded from the comparison.

| Metric | Value |
|---|---|
| Total estimated cost — Reth | 1,032,071,340,802,973 |
| Total estimated cost — Zilkworm | 265,634,675,644,496 |
| Ratio Z/R (total) | **0.257** (Reth = 3.89× Zilkworm) |
| Per-fixture Z/R | median 0.617, mean 0.771, min 0.002, max 70.2 |
| Zilkworm cheaper | 3019 / 3444 (88%) |

Components over the 3444 compared (Reth / Zilkworm): `opcode` 990,878,872,734,653 /
223,787,360,806,176, `syscall` 38,219,353,538,426 / 38,166,577,234,012, `system`
2,973,114,529,894 / 3,680,737,604,308.

By test family (Z/R total estimated-cost ratio; <1 = Zilkworm cheaper):

```
test_modexp                 0.02  test_storage                0.65
test_alt_bn128              0.42  test_blake2f                0.68
test_identity               0.44  test_log                    0.68
test_system                 0.46  test_bitwise                0.71
test_point_evaluation       0.49  test_block_access_list      0.72
test_comparison             0.53  test_bls12_381              0.74
test_stack                  0.54  test_call_context           0.81
test_control_flow           0.54  test_memory                 0.82
test_transaction_types      0.60  test_mix_operations         0.82
test_account_query          0.61  test_ecrecover              0.90
test_sha256                 0.63  test_keccak                 0.99
test_arithmetic             0.64  ----- Reth cheaper below -----
                                  test_ripemd160              1.08
                                  test_block_context          1.13
                                  test_tx_context             1.14
                                  test_p256verify            12.94
```

## Interpretation

- **Correctness:** Zilkworm produces **100% correct** stateless-validation outputs on the latest Sepolia batch (100/100), where Reth rc.4 mismatches 4 blocks, and matches 33,635 of 33,637 tests-zkevm v21.0.1 fixtures, failing only on 2 that Reth is also expected to fail. On the previous stack it matched the full glamsterdam-devnet-8 corpus (72,732/72,732) and the generated tests-zkevm-benchmark v0.8.2 corpus (3464/3464).
- **Efficiency:** on Sepolia blocks, estimated prover cost is 0.500× Reth rc.4's (98/100 cheaper). On the previous stack it was 0.495× Reth rc.3's on devnet-8 blocks and 0.257× on the v0.8.2 corpus, excluding the 20 `test_modexp` fixtures where Reth times out.
- **Reth cheaper:** on Sepolia only on two blocks Reth fails to match; on the v0.8.2 corpus `test_p256verify` (12.94×) dominates, while `test_ripemd160`, `test_block_context` and `test_tx_context` are within 1.15×.
