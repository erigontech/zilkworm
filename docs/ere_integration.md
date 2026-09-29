<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

Zilkworm is integrated as a stateless-validation execution client in the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). The same canonical EEST benchmark fixtures are executed inside SP1 using the Zilkworm guest, validated against their expected public values, and (optionally) compared cycle-for-cycle against other guests (Reth, Ethrex).

> 🚧 **WIP:** needs revision after landing on public Zilkworm repo.

The current integration targets **Amsterdam / glamsterdam-devnet-8** with the
**tests-zkevm v0.8.2** stateless schema, on **ere v0.17.0 / ere-guests v0.17.1**. The host adapter decodes the canonical
EEST `statelessInputBytes` into the Zilkworm MFBD envelope; see
[`prover/stateless_validator`](../prover/stateless_validator).

> 🚧 The three branches below are pushed to the `erigontech/*` forks but are not yet merged upstream;
> `[patch]` and path deps still point at local sibling checkouts and must be changed before publishing.

## Branches and repository layout

The integration spans three repos, which at the moment must sit **as siblings** in the same
parent directory — the benchmark fork's `[patch]` and path deps use relative
paths (`../ere-guests_fork`, `../z6m`):

```
<workspace>/
├── z6m/                            # this repo (guest + host adapter)
├── ere-guests_fork/                # clone of erigontech/ere-guests
└── zkevm-benchmark-workload_fork/  # clone of erigontech/zkevm-benchmark-workload
```

| Repo | Branch (pushed) | Based on | Carries |
|---|---|---|---|
| `erigontech/z6m` | `canepat/ere_stateless_input` | `glamsterdam-devnet-8` (`a128f910`) | Guest (`zilk_core` + evmone submodule `a14dfc9b`) and the host adapter `prover/stateless_validator` (SIOB→MFBD). On top of devnet-8: tests-zkevm v0.8.2 schema, EIP-8282 builder-requests fix, chain id 1 → Amsterdam, ERE make targets/docs/fetch script, `eest_runner` cycle metrics. |
| `erigontech/ere-guests` | `canepat/zilkworm_mfbd` | `main` (`daec35a`, v0.17.1) | One commit mirroring the Nimbus addition (upstream PR #88): `StatelessValidatorKind::Zilkworm` (catalog ID 4), the `zilkworm` entry in `artifact-registry.json` (sp1, `zkvm_version` v6.4.0), the catalog/downloader/test-crate tests, and the README. `elf_url` is a `local-dev` placeholder until a z6m release is published; the registry and README are updated with that release before upstreaming. |
| `erigontech/zkevm-benchmark-workload` | `canepat/zilkworm_mfbd` | `master` (`6802450`, ere-guests v0.17.1) | The `zilkworm` execution client (`ExecutionClient::Zilkworm`, host transform via `from_ere_eest`), the `[patch]` redirecting ere-guests deps to `../ere-guests_fork`, the z6m host-adapter path dep (`stateless-validator-zilkworm = ../z6m/prover/stateless_validator`), and the cross-file EEST fixture-name dedup with its regression test. |

The z6m host adapter pins `stateless-validator-common` at ere-guests rev
`eaa3f46` (tests-zkevm v0.8.2), but the benchmark's workspace `[patch]` overrides
all ere-guests deps to `../ere-guests_fork`, so the actual crates used are the
fork's (v0.17.1).

## Reference environment

| Component | Version |
|---|---|
| OS | macOS, Darwin 25.5.0, arm64 |
| Container engine | Docker 29.4.0 |
| Rust | 1.95.0 (pinned in `rust-toolchain.toml`) |
| ERE harness | `eth-act/ere` tag `v0.17.0` (rev `5023513`), image `ghcr.io/eth-act/ere/ere-server-sp1:5023513` |
| ere-guests | `v0.17.1` (via the benchmark `[patch]` to `../ere-guests_fork`) |
| SP1 | v6.4.0 (ere v0.17.0 pins `sp1-sdk`/`sp1-verifier` v6.4.0) |
| Guest artifacts | zilkworm `local-dev`, reth `0.1.0-rc.3`, ethrex `27.0.0` (all sp1 v6.4.0) |
| Fixtures | glamsterdam-devnet-8 block export (Amsterdam), chainId `0x1a6a8cc6e` (7091047534), 644 batches / 6478 blocks (93300..99749) |

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
ERE_INPUT_FOLDER   ?= $(FIXTURES_CACHE)/ere-glamsterdam-devnet-8/eest_batch  # ere-hosts --input-folder
ERE_BIN_PATH       ?=                        # local guest ELF dir; empty => download the published guest
ERE_RETH_ARTIFACT_URL ?= <derived from the ere-guests resolved by $(ERE_WORKLOAD_DIR): reth sp1 elf_url dirname>
ERE_GEN_FIXTURES   ?=                        # non-empty => (re)generate EEST fixtures first (opt-in)
ERE_TIMEOUT        ?= 60m                    # per-action timeout
```

- **`ERE_IMAGE_REGISTRY`** is folded into `ERE_RUN_ENV` and prepended to ere's
  image names so `docker pull` fetches the prebuilt `ere-server-sp1:8961a4e`
  from ghcr. Without it, ere has no default registry and falls back to building
  the images from source. Overridable.
- **`ERE_BIN_PATH`** (optional): a relative value is resolved against z6m via
  `$(abspath …)` (the recipe `cd`s into the workload dir first). Empty => the
  target downloads the published guest ELF named in `artifact-registry.json`.
  Build/stage the local guest with `make ere-bin` (outputs
  `build/ere-bin/stateless-validator-zilkworm-sp1.{elf,vk}`). ere-hosts loads
  `<bin-path>/stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}`, so
  both targets first run `ere-bin-link`, which symlinks the unversioned files
  under the version the workload's ere resolves (`tools/ere_workload.py
  <workload> sp1-sdk-version`, mirroring ere-catalog's build script: currently
  `v6.4.0`). The VK must exist but ere-hosts does not read it.
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
  (required for `--action execute`). Defaults to the cached devnet-8 first batch;
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

## Fixtures: glamsterdam-devnet-8

The devnet-8 stateless fixtures are published as an R2 block export (not the
generated EEST corpus):

```
base:    https://pub-760ad8b3dd9547539f829c1ea30f18b5.r2.dev/devnets/glamsterdam-devnet-8
catalog: <base>/batches.jsonl        # 644 batches x 10 blocks, 93300..99749
batches: <base>/exports/batches/<start>-<end>.tar.zst   # each holds blockchain_tests/**/*.json
```

They are cached under `test-fixtures-cache/ere-glamsterdam-devnet-8/` (gitignored):
`batches8.jsonl` (catalog), `archives/*.tar.zst` (downloads), `eest_batch/` (first
batch extracted), `all_blocks/` (all 6478 extracted). See that dir's `README.txt`.

### Download and extract to the cache

Use [`tools/ere-fetch-fixtures.sh`](../tools/ere-fetch-fixtures.sh) — it fetches the
catalog + manifest, caches the first batch to `eest_batch/`, with `all`
downloads every batch (sha256-verified against the catalog) and extracts it to
`all_blocks/`, and with `latest N` extracts only the N latest batches to
`latest/` (the selection used by CI):

```sh
tools/ere-fetch-fixtures.sh            # first batch only (10 blocks, quick smoke)
tools/ere-fetch-fixtures.sh latest 10  # 10 latest batches (100 blocks)
tools/ere-fetch-fixtures.sh all        # full corpus (7247 batches, ~24 GB download as of 2026-09)
```

The catalog kept growing after the 644-batch sweep below. The R2 base URL (catalog
root, or its `index.html` / `manifest.json` URL) and cache dir are overridable via
`ERE_FIXTURES_BASE` / `ERE_FIXTURES_CACHE`. Then run the full corpus through the make target (point
`ERE_INPUT_FOLDER` at the extracted `all_blocks/`):

```sh
make ere-validate \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin \
    ERE_INPUT_FOLDER=$(pwd)/test-fixtures-cache/ere-glamsterdam-devnet-8/all_blocks
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
  downloads `z6m_guest_hypercube.{elf,vk}` of `release_tag`, verified against the
  release `SHA256SUMS.txt`. The host adapter is compiled from the same z6m ref
  (the release tag in `release` mode), so adapter and guest always match.
- **Inputs:** `guest_source`, `release_tag`, `catalog_url` (default devnet-8),
  `batch_count` (default 10), `compare` (default off; on for releases),
  `workload_ref` / `ere_guests_ref` (default `canepat/zilkworm_mfbd` on the
  erigontech forks).
- **Layout:** `z6m/`, `zkevm-benchmark-workload_fork/` and `ere-guests_fork/` are
  checked out as siblings, as the workload's path dependency and `[patch]` require.
  The ere job runs on the runner host: ere-hosts reaches `ere-server-sp1` on
  `127.0.0.1:4175`.
- **Output:** the step summary records the three commits, the guest ELF sha256,
  the block range and the `ere_compare.py` report; `zkevm-metrics/` is uploaded.

Once the zilkworm client and registry entry are upstreamed, the ere-guests
checkout goes away and the host adapter git dependency is redirected to the z6m
checkout with `cargo --config 'patch."<zilkworm git url>".z6m_stateless_validator.path=…'`.

## Results

Full per-fixture metrics live under `$(ERE_WORKLOAD_DIR)/zkevm-metrics/`.

### Validation — glamsterdam-devnet-8 (current)

| Client | Completed | output_matched | Mismatches |
|---|---|---|---|
| Zilkworm `canepat/ere_stateless_input` (sp1 v6.4.0) | 6478/6478 | 6478 | 0 |

`make ere-validate` over all 6478 blocks reports `RESULT: PASS`
(`ere_compare.py --validate 'zilkworm-*'`: total 6478, completed 6478,
output_matched 6478, incomplete 0, mismatched 0). Every block validates,
including the 17 request-carrying blocks fixed by folding the EIP-8282 builder
deposit/exit requests (types 0x03/0x04) into `requests_hash`. That full-corpus run
was on ere v0.16.2; on the v0.17.0 / ere-guests v0.17.1 stack the 10-block
`eest_batch` smoke re-validates 10/10 (`RESULT: PASS`).

### Estimated cost — glamsterdam-devnet-8 batch (current, `make ere-compare`)

10 blocks (93300..93309), `--action estimate-cost`, SP1 v6.4.0, reth `0.1.0-rc.3`:

| Metric | Value |
|---|---|
| Total estimated cost — Reth | 244,559,852,848 |
| Total estimated cost — Zilkworm | 127,834,309,954 |
| Ratio Z/R (total) | **0.523** (Reth = 1.91× Zilkworm) |
| Per-fixture Z/R | median 0.528, min 0.489, max 0.530 |
| Zilkworm cheaper | 10 / 10 |

Components (Reth / Zilkworm): `opcode` 167,896,301,578 / 74,212,170,226,
`syscall` 61,924,881,056 / 44,689,339,322, `system` 14,738,670,214 / 8,932,800,406.

### Cycle comparison — tests-zkevm-benchmark v0.8.2 (ere v0.16.2, legacy cycles)

3464 generated fixtures, both clients 3464/3464 `output_matched`:

| Metric | Value |
|---|---|
| Total cycles — Reth | 9,012,226,526,812 |
| Total cycles — Zilkworm | 1,475,310,960,304 |
| Ratio Z/R (total) | **0.164** (Reth = 6.11× Zilkworm) |
| Per-fixture Z/R | median 0.663, mean 0.726 |
| Zilkworm fewer cycles | 3205 / 3464 (93%) |

### Cycle comparison — historical (Osaka 10M, ere v0.11 / SP1 v6.1)

> 🚧 The tables below are from the earlier Osaka run (1077 fixtures,
> `tests-benchmark@v0.0.9`, ere v0.11.0/SP1 v6.1.0, Reth v2.1.0). They predate
> the Amsterdam/devnet-8 + tests-zkevm v0.8.2 + SP1 v6.4.0 stack and are kept for
> reference only. Regenerate current numbers with `make ere-compare`.

| Metric | Value |
|---|---|
| Total cycles — Reth | 301,864,477,725 |
| Total cycles — Zilkworm | 158,037,964,869 |
| Ratio Z/R (total) | **0.524** (Reth = 1.91× Zilkworm) |
| Per-fixture Z/R | median 0.655, mean 0.742 |
| Zilkworm fewer cycles | 913 / 1077 (84%) |

By test family (Z/R total-cycle ratio; <1 = Zilkworm cheaper):

```
test_modexp                 0.15      test_account_query    0.72
test_bls12_381              0.24      test_stack            0.73
test_comparison             0.24      test_blake2f          0.73
test_transaction_types      0.38      test_unchunkified_bc  0.75
test_alt_bn128              0.46      test_log              0.78
test_control_flow           0.49      test_keccak           0.84
test_identity               0.51      test_call_context     0.85
test_sha256                 0.54      test_memory           0.98
test_system                 0.54      ----- Reth cheaper below -----
test_arithmetic             0.60      test_mix_operations   1.04
test_storage                0.62      test_ripemd160        1.12
test_bitwise                0.64      test_ecrecover        1.51
test_point_evaluation       0.67      test_tx_context       1.74
                                      test_block_context    1.97
                                      test_p256verify      16.13
```

## Interpretation

- **Correctness:** Zilkworm produces **100% correct** stateless-validation outputs on the full glamsterdam-devnet-8 corpus (6478/6478, ere v0.16.2) and on the generated tests-zkevm-benchmark v0.8.2 corpus (3464/3464); re-validated on the v0.17 stack.
- **Efficiency:** on the generated v0.8.2 corpus Zilkworm needs 0.164× Reth's cycles overall (93% of fixtures cheaper); on real devnet-8 blocks, estimated prover cost is 0.523× Reth's (10/10 cheaper). The devnet-8 figure is from a 10-block batch; extend `ERE_INPUT_FOLDER` to `all_blocks/` for the full-corpus number.
