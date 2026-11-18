<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

**Backend: HashState.** Zilkworm is a stateless-validation execution client in the
[ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). The ERE guest is the
HashState build of the SP1 guest (`make ere-bin`), which takes a fixture's `statelessInputBytes`
unchanged ([hashstate.md](hashstate.md#raw-statelessinput-dispatch)); ere-hosts runs it inside SP1,
compares its public values with the fixture's `statelessOutputBytes`, and costs it with SP1's
prover-cost estimate, optionally next to Reth. Per-release results are in
[`../CHANGELOG.md`](../CHANGELOG.md).

The MFBD host adapter in [`prover/stateless_validator`](../prover/stateless_validator) (`ere_eest.rs`,
`mfbd.rs`) converts an ERE input for the DirectState guest and is not on the ERE path.

## Repositories and pins

The Zilkworm client and its registry entry live on `erigontech` forks until they are merged
upstream.

| Repo | Carries | Pinned by |
|---|---|---|
| `erigontech/zkevm-benchmark-workload` | The `zilkworm` execution client (`ExecutionClient::Zilkworm`, on the raw `statelessInputBytes` path) and a workspace `[patch]` that takes the ere-guests catalog, common and downloader crates from the erigontech fork at one rev. | `workload_ref` in [`ere-benchmark.yml`](../.github/workflows/ere-benchmark.yml) |
| `erigontech/ere-guests` | `StatelessValidatorKind::Zilkworm` and the `zilkworm` entry of `artifact-registry.json`, which names a release's `stateless-validator-zilkworm-sp1-<SP1 version>.{elf,vk}` assets and their sha256. | `ere_guests_ref` in the workflow; the workload's `[patch]` pins the rev that is built |
| ere, and the SP1 it resolves | | whatever the workload resolves; `make ere-bin-link` checks it against `ERE_SP1_SDK_VERSION` |

The workload's `[patch]` takes all three ere-guests crates from the fork at one rev; patching the
catalog alone leaves a second `ere-catalog` in the build. Locally the examples assume the workload
fork is a sibling checkout, `../zkevm-benchmark-workload_fork`.

The SP1 host runs in an x86_64 container; on Apple Silicon it executes under emulation. Cycle
counts and cost estimates are host-independent, wall-clock timings are not.

## Quick start

Three `Makefile` targets drive the ERE harness. All run `ere-hosts` inside `$(ERE_WORKLOAD_DIR)`:

```sh
# Validate Zilkworm against a fixture folder
make ere-validate \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin

# Estimate Zilkworm's SP1 cost and print the cost report
make ere-cost \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin

# ere-cost, then Reth's SP1 cost and the comparison
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
  image names so `docker pull` fetches the prebuilt `ere-server-sp1` image
  from ghcr. Without it, ere has no default registry and falls back to building
  the images from source. Overridable.
- **`ERE_BIN_PATH`** (optional): a relative value is resolved against z6m via
  `$(abspath …)` (the recipe `cd`s into the workload dir first). Empty => the
  target downloads the published guest ELF named in `artifact-registry.json`.
  Build/stage the local guest with `make ere-bin`: the HashState build
  (`z6m_guest_slib`), which takes the fixtures' `statelessInputBytes` unchanged
  (outputs `build/ere-bin/stateless-validator-zilkworm-sp1.{elf,vk}`). ere-hosts loads
  `<bin-path>/stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}`, so
  `ere-validate` and `ere-cost` first run `ere-bin-link`, which symlinks the unversioned files
  under the version the workload's ere resolves (`tools/ere_workload.py
  <workload> sp1-sdk-version`, mirroring ere-catalog's build script). It stops
  unless that equals `ERE_SP1_SDK_VERSION`, the `sp1-sdk` tag `derive_vk` builds against
  (`prover/stateless_validator/Cargo.toml`). The VK must exist but ere-hosts does not read it.
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
results from a previous guest. The targets therefore pass `--force-rerun`
unconditionally so every run re-executes against the current guest.

### Actions and metrics

The per-fixture record written by `--action execute` carries only `output_matched`
and `execution_duration`, no cycle count. Cost data comes from `--action estimate-cost`, which stores
`cost_estimation.success.cost`, a per-component map from SP1's estimated
prover-cost model (`peak_heap_bytes` is null since ere v0.19). The unit is
`3 × trace area + chip complexity`; SP1's own gas is that over 10, and its
`ExecutionReport::gas()`, which `sp1_benchmark` reports as prover gas, is the
estimate over 191. The components (ere `crates/prover/sp1`):

| Component | Rows charged |
|---|---|
| `opcode` | plain RISC-V instructions (the total minus the other two) |
| `syscall` | syscalls, including the precompile chips they invoke |
| `system` | chips every program runs, such as memory |

Accordingly:

- `ere-validate` runs `--action execute` and gates on `output_matched`.
- `ere-cost` runs `--action estimate-cost` for zilkworm and prints
  `ere_compare.py --table`, one column per client with the ere version,
  completed, output_matched, incomplete and estimated cost in G, then
  `ere_compare.py --cost`: total estimated cost and its prover-gas equivalent,
  per-fixture mean and median, component and test-family totals, and the
  heaviest fixtures. It fails only when no fixture has an estimate.
- `ere-compare` runs `ere-cost`, then `--action estimate-cost` for reth, prints
  the table with a reth column, and compares the summed components.
  `make ere-compare -o ere-cost` skips the zilkworm leg when `ere-cost` already
  ran, as CI does.
- Records are merged per fixture file, so an estimate-cost run keeps the
  `execution` block written by a preceding validate run. `--validate` decides
  on that block when a record has one, so a `--validate` after `ere-cost`
  (the CI summary's) still reports the execute results.
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
layout [hashstate.md](hashstate.md#wire-layout) decodes.

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

## The ere-guests corpus test

The ere-guests `stateless-validator-test` crate (`executes_registered_guest`, SP1) feeds the guest
every fixture of the `tests-zkevm` corpus unchanged and compares the outputs. It resolves the guest
through `artifact-registry.json`, so it runs a published release. To run an unreleased guest, point
the registry at a local copy: an `http://127.0.0.1` URL served from `build/ere-bin`, with the HTTPS
check in `registry.rs` relaxed locally (neither edit is committed).

Run it alone: it and `make ere-validate` / `ere-compare` both drive an ere-server on port 4175, and
a concurrent run answers with the other guest's results.

## CI

[`.github/workflows/ere-benchmark.yml`](../.github/workflows/ere-benchmark.yml) runs
`make ere-validate` and `make ere-cost`, and optionally the Reth leg of `make ere-compare`, on the
latest batches of an R2 catalog.

- **Triggers:** push to `release/*` branches, `workflow_dispatch` on any branch, and `workflow_call`
  from [`release.yml`](../.github/workflows/release.yml) after a `v*` release is published (a
  release created with `GITHUB_TOKEN` emits no `release` event).
- **Inputs:** `guest_source` (`build` runs `make ere-bin` at the run's ref; `release` downloads the
  ERE guest assets of `release_tag`, verified against the release's `SHA256SUMS.txt`),
  `release_tag`, `catalog_url` (default Sepolia), `batch_count` (default 1), `compare` (Reth's cost
  and the comparison; default off, and off in `release.yml`), `workload_ref`, `ere_guests_ref`.
- **Layout:** `z6m/`, `zkevm-benchmark-workload_fork/` and `ere-guests_fork/` are checked out as
  siblings. The ere-guests checkout only feeds the step summary. The ere job runs on the runner
  host: ere-hosts reaches `ere-server-sp1` on `127.0.0.1:4175`.
- **Output:** the step summary opens with the `--table --markdown` table (a Reth column with
  `compare`), then records the three commits, the guest ELF sha256, the block range, the
  `--validate` result and the Zilkworm cost report (`--cost`), plus the Reth comparison with
  `compare`; `zkevm-metrics/` is uploaded.

Once the Zilkworm client and registry entry are upstreamed, the ere-guests checkout and the
workload `[patch]` go away.
