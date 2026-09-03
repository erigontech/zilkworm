<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

Zilkworm is integrated as a stateless-validation execution client in the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). The same canonical EEST benchmark fixtures are executed inside SP1 using the Zilkworm guest, validated against their expected public values, and (optionally) compared cycle-for-cycle against other guests (Reth, Ethrex).

> 🚧 **WIP:** needs revision after landing on public Zilkworm repo.

The current integration targets **Amsterdam / glamsterdam-devnet-8** with the
**tests-zkevm v0.8.2** stateless schema. The host adapter decodes the canonical
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
| `erigontech/z6m` | `canepat/ere_stateless_input` | `glamsterdam-devnet-8` (`a128f910`) | Guest (`zilk_core` + evmone submodule `a14dfc9b`) and the host adapter `prover/stateless_validator` (SIOB→MFBD). Two commits on top of devnet-8: tests-zkevm v0.8.2 schema support + the EIP-8282 builder-requests fix. |
| `erigontech/ere-guests` | `canepat/zilkworm_mfbd` | merged `main` (`d5a6451`, includes `jsign-upgrade-v0.8.2`) | The `StatelessValidatorKind::Zilkworm` catalog kind and the `zilkworm` entry in `artifact-registry.json` (sp1, `zkvm_version` v6.4.0; `elf_url` is a `local-dev` placeholder until a real z6m release is published). |
| `erigontech/zkevm-benchmark-workload` | `canepat/zilkworm_mfbd` | `jsign-specs-8` (`b793c87`) | The `zilkworm` execution client (`ExecutionClient::Zilkworm`, host transform via `from_ere_eest`), the `[patch]` redirecting ere-guests deps to `../ere-guests_fork`, and the z6m host-adapter path dep (`stateless-validator-zilkworm = ../z6m/prover/stateless_validator`). |

The z6m host adapter pins `stateless-validator-common` at ere-guests rev
`eaa3f46` (tests-zkevm v0.8.2), but the benchmark's workspace `[patch]` overrides
all ere-guests deps to `../ere-guests_fork`, so the actual crates used are the
fork's.

## Reference environment

| Component | Version |
|---|---|
| OS | macOS, Darwin 25.5.0, arm64 |
| Container engine | Docker 29.4.0 |
| Rust | 1.95.0 (pinned in `rust-toolchain.toml`) |
| ERE harness | `eth-act/ere` tag `v0.16.2`, image `ghcr.io/eth-act/ere/ere-server-sp1:8961a4e` |
| SP1 | v6.4.0 (ere v0.16.2 pins `sp1-verifier` v6.4.0) |
| Guest artifacts | zilkworm `local-dev`, reth `0.1.0-rc.2`, ethrex `26.0.0-rc.2` (all sp1 v6.4.0) |
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

# Run Zilkworm and Reth and print the cycle comparison
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
  Build/stage the local guest with `make ere-bin` (outputs `build/ere-bin`).
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
catalog + manifest, caches the first batch to `eest_batch/`, and with `all`
downloads every batch (sha256-verified against the catalog) and extracts all 6478
blocks to `all_blocks/`:

```sh
tools/ere-fetch-fixtures.sh          # first batch only (10 blocks, quick smoke)
tools/ere-fetch-fixtures.sh all      # full corpus (~3 GB download, ~17 GB extracted)
```

The R2 base URL and cache dir are overridable via `ERE_FIXTURES_BASE` /
`ERE_FIXTURES_CACHE`. Then run the full corpus through the make target (point
`ERE_INPUT_FOLDER` at the extracted `all_blocks/`):

```sh
make ere-validate \
    ERE_WORKLOAD_DIR=../zkevm-benchmark-workload_fork \
    ERE_BIN_PATH=build/ere-bin \
    ERE_INPUT_FOLDER=$(pwd)/test-fixtures-cache/ere-glamsterdam-devnet-8/all_blocks
```

To run the general EEST corpus instead, pass `ERE_GEN_FIXTURES=1` (and set
`ERE_INPUT_FOLDER` to the generated tree).

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
deposit/exit requests (types 0x03/0x04) into `requests_hash`.

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

- **Correctness:** Zilkworm produces **100% correct** stateless-validation outputs on the full glamsterdam-devnet-8 corpus (6478/6478).
> 🚧 - **Efficiency:**  on the historical 10M Osaka fixture set, Zilkworm was ~1.91× more cycle-efficient than Reth overall and won 84% of fixtures. *TBD: we must re-run `make ere-compare` to measure the current Amsterdam stack*.
