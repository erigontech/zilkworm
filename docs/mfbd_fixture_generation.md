# MFBD Fixture Generation & Update — Operations Guide

How the MFBD (flat-bundle) fixtures consumed by the benchmarks and the EEST
blockchain tests are produced, and exactly how to regenerate them. For the
on-wire byte layout itself see [`flat_witness_bundle.md`](flat_witness_bundle.md);
for the EEST CI cache keys see [`../tools/README.md`](../tools/README.md); the
wire-format discipline rule lives in [`../tools/claude/AGENTS.md`](../tools/claude/AGENTS.md).

---

## 0. TL;DR

```bash
# EEST fixtures (auto-keyed; regenerates only when the submodule or converter changed)
make eest-mfbd-build           # third_party/eest-fixtures/*.json -> third_party/eest-fixtures-mfbd/dev-<sha>/**/*.mfbd
make eest-blockchain-tests     # build + run the ctest suite against those .mfbd

# Benchmark corpus (MANUAL — never auto-regenerates)
make sp1-benchmark-corpus      # temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin -> temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd
make sp1-benchmark             # rebuild guest+prover, run the 200-block prover sweep
```

**The one rule you must never break:** if you change the byte layout of any
`reinterpret_cast`'d wire POD (see §6.1), bump `kFlatBundleVersion`
(`zilk_core/core/types_zz/flat_bundle.hpp:54`, currently **13**) **in the same
commit** AND regenerate **both** fixture sets. Skipping this is the iter03
silent-corruption bug (§6.1).

---

## 1. What an MFBD fixture is

An `.mfbd` file is an **MFBD envelope** (`magic 'MFBD'`, version, `n_bundles`)
wrapping one or more **FlatBundle** (`'FBND'`) blobs. Each FlatBundle is a
self-contained, stateless block-execution witness: genesis RLP, the block(s) to
execute, ancestor headers, the pre-state (`direct_state` blob: addr-map MphfMap +
code store + addr/block hashes), and the trie node store. Every encoder stamps
`kFlatBundleVersion` into the FlatBundle header; `load_flat_bundle()` rejects any
bundle whose version differs (`flat_bundle.cpp:123-125`). Full layout:
[`flat_witness_bundle.md`](flat_witness_bundle.md).

There are **two fixture sets**:

| Set | Lives in | Source of truth | Regenerates |
| --- | --- | --- | --- |
| **Benchmark corpus** (200 mainnet blocks) | `temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd` | `temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin` (raw legacy RLP) | **manually**, via `make sp1-benchmark-corpus` |
| **EEST fixtures** | `third_party/eest-fixtures-mfbd/dev-<sha>/blockchain_tests/**/*.mfbd` | `third_party/eest-fixtures/blockchain_tests/**/*.json` (git submodule) | **automatically** (SHA-keyed), via `make eest-mfbd-build` |

> Note: `temp/200_benchmark_blocks/<N>/` holds **both** the raw `.bin` (the regen
> source) and a `.mfbd` copy. `release_state_root_check.sh` reads the `.mfbd`
> (`release_state_root_check.sh:107`), so it can run against either
> `temp/200_benchmark_blocks` or `temp/200_benchmark_blocks_mfbd_v2`.

---

## 2. The three encoders (`zilk_core/dev/cli/`)

All three call `build_flat_bundle()`, which stamps `kFlatBundleVersion`. Built in
the host `build/` (Release): `cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S . && cmake --build build --target <tool>`.

| Tool | Invocation | Input | Output |
| --- | --- | --- | --- |
| `legacy_to_flat_bundle` | `legacy_to_flat_bundle <in.bin> <out.mfbd>` | one legacy 5-item RLP bundle (genesis, block, pre-state, ancestors, pre-trie) | one `.mfbd` |
| `eest_to_flat_bundle` | `bulk-convert --input-dir <D> --output-dir <D>` (or `emit --json <f> --index <i>` → stdout) | EEST `blockchain_tests` JSON tree | mirrored `.mfbd` tree (one `.mfbd` per JSON, all subtests inside) |
| `json_witness_to_flat_bundle` | `json_witness_to_flat_bundle < witness.json > out.mfbd` | a JSON witness (`block`, `headers`, `state`, `codes`, `keys`) on stdin | one `.mfbd` on stdout |

`legacy_to_flat_bundle` drives the **benchmark corpus**; `eest_to_flat_bundle`
drives the **EEST fixtures**; `json_witness_to_flat_bundle` is the ad-hoc path for
a single witness captured elsewhere.

---

## 3. Benchmark corpus

### 3.1 Layout
```
temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin   # raw source (legacy RLP)
temp/200_benchmark_blocks/<N>/flatWitnessBundle<N>.mfbd        # converted (host check uses this)
temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd # canonical benchmark corpus (BENCH_CORPUS_DIR)
```
Makefile knobs: `BENCH_SRC_DIR ?= temp/200_benchmark_blocks`, `BENCH_CORPUS_DIR ?= temp/200_benchmark_blocks_mfbd_v2` (Makefile:117-118).

### 3.2 Generate the corpus from the raw blocks
```bash
make sp1-benchmark-corpus
```
This builds `legacy_to_flat_bundle` and, for each `temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin`,
writes `temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd` (Makefile:122-133).
It is a plain `for` loop — **no manifest, no staleness check**: it always
re-converts whatever `.bin` files are present.

### 3.3 Consume the corpus
- **Prover sweep (guest):** `make sp1-benchmark` → `python3 tools/scripts/sp1_benchmark.py --dir temp/200_benchmark_blocks_mfbd_v2`. Depends on `z6m_prover` + `sp1-benchmark-corpus`. Output: `temp/benchmarks/benchmark_<timestamp>/`.
- **Host state-root check:** `tools/scripts/release_state_root_check.sh --dir temp/200_benchmark_blocks` → builds `state_transition` (Release), runs each `flatWitnessBundle<N>.mfbd`, reports `State root mismatches`.

### 3.4 Acquire NEW benchmark blocks
The raw `.bin` blocks are fetched from a mainnet RPC. Use the **fetch-blocks**
skill, or directly drive the fetcher (writes `temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin`):
```bash
make z6m_prover
prover/target/release/z6m_prover --service \
  --rpc-url <MAINNET_RPC_URL> \
  --data-dir temp/200_benchmark_blocks \
  --save-all-responses \
  --start-block <FIRST> --end-block <LAST>
```
Then `make sp1-benchmark-corpus` to convert the new `.bin` into the corpus.
(Verify the exact fetcher flags against the fetch-blocks skill before relying on them.)

---

## 4. EEST fixtures

### 4.1 Source
`third_party/eest-fixtures` — git submodule, remote
`https://github.com/erigontech/eest-fixtures`, containing
`blockchain_tests/**/*.json` (per-fork dirs: `frontier/`, `paris/`, `osaka/`, …).
Current pin: `373eebed796c`.

### 4.2 Generate the MFBD tree (auto-keyed)
```bash
make eest-mfbd-build
```
Steps (Makefile:74-87):
1. Build `eest_to_flat_bundle` (Release).
2. `EEST_SHA = git -C third_party/eest-fixtures rev-parse --short=12 HEAD`; output dir `EEST_MFBD_DIR = third_party/eest-fixtures-mfbd/dev-<EEST_SHA>`.
3. **Skip-if-fresh:** if `dev-<sha>/manifest.json` already records the current converter binary's SHA, do nothing.
4. Otherwise `eest_to_flat_bundle bulk-convert --input-dir third_party/eest-fixtures/blockchain_tests --output-dir dev-<sha>/blockchain_tests`, then write `manifest.json = {"eest_sha":…,"converter_sha":…}`.

**Double-keyed auto-invalidation:** the output dir is keyed by the **EEST submodule
SHA** (so a fixture bump lands in a fresh `dev-<sha>/`), and the manifest is keyed
by the **converter binary SHA** (so editing any converter source —
`eest_to_flat_bundle.cpp`, `direct_state_builder.cpp`, `flat_bundle.*`, etc. —
forces a rebuild within the same `dev-<sha>/`). You rarely regen EEST by hand;
just run a target that depends on it.

### 4.3 Consume
- **C++ ctest suite:** `make eest-blockchain-tests` (configures `build/eest` with `-DEEST_MFBD_DIR=...`, registers each `.mfbd` as a ctest case, runs `ctest --parallel`). This is leg 1 of the 3-leg validation.
- **Prover against EEST:** `make eest-prover-test` → `z6m_prover --test-service --test-dir dev-<sha>/`.

### 4.4 Bump to a newer EEST release
```bash
git submodule update --remote third_party/eest-fixtures   # or: git -C third_party/eest-fixtures fetch && checkout <tag>
git -C third_party/eest-fixtures rev-parse --short=12 HEAD # confirm new sha
make eest-mfbd-build                                       # creates a new dev-<new-sha>/ tree
git add third_party/eest-fixtures                          # commit the new submodule pointer
```
The old `dev-<old-sha>/` tree is left in place (cheap rollback / parallel runs).
Expect the known-failing test set to shift with a new release — re-baseline the
"2 known failures" if it does.

---

## 5. End-to-end: who reads what

```
                 fetch-blocks skill / z6m_prover --service
                              │  (RPC)
                              ▼
        temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin   (raw)
                              │  make sp1-benchmark-corpus (legacy_to_flat_bundle)
                              ▼
   temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd
                 │                                   │
   make sp1-benchmark (guest)            release_state_root_check.sh (host)
   sp1_benchmark.py                      state_transition


   third_party/eest-fixtures/blockchain_tests/**/*.json   (submodule)
                              │  make eest-mfbd-build (eest_to_flat_bundle bulk-convert)
                              ▼
   third_party/eest-fixtures-mfbd/dev-<sha>/blockchain_tests/**/*.mfbd
                              │  make eest-blockchain-tests
                              ▼
                         ctest (build/eest)
```

---

## 6. Updating / regenerating fixtures

### 6.1 ⚠️ Wire-format changes — bump the version AND regenerate (the iter03 rule)

From `tools/claude/AGENTS.md`:
> if your patch reorders fields of a `reinterpret_cast`'d POD inside the flat
> bundle (PreAccount, MphfKvMeta, FlatWithdrawal, etc.), you MUST bump
> `kFlatBundleVersion` in `zilk_core/types_zz/flat_bundle.hpp` in the SAME commit
> AND regenerate the 200 bundles via `legacy_to_flat_bundle`. The iter03
> silent-corruption bug (2026-05) was exactly this failure mode: a layout change
> without a version bump caused every bench bundle on disk to mis-decode,
> producing wrong roots for ~5 days before discovery.

**Wire-significant PODs** (changing field order / size / alignment of any of these
requires a version bump + regen):

| Struct | File |
| --- | --- |
| `FlatBundleHeader` | `core/types_zz/flat_bundle.hpp` |
| `PreStateMeta` | `core/state_zz/pre_state.hpp` |
| `Account` | `core/types_zz/account.hpp` |
| `Slot` | `core/state_zz/pre_state.hpp` |
| `AddrHashEntry`, `BlockHashEntry` | `core/state_zz/pre_state.hpp` |
| `MphfMapHeader`, `MphfCollisionEntry` | `core/common_zz/mphf_map.hpp` |
| `FlatKv` layout (`kPayloadOffset`/`kKeySize`) | `core/types_zz/flat_kv.hpp` |

> Why it's silent: `load_flat_bundle()` only checks the *version* field. If you
> change a layout but don't bump the version, the old on-disk bundles still have
> the matching (old) version number, pass the check, and get `reinterpret_cast`
> with the new struct definition → garbage fields → wrong roots, no error.

**Procedure for a wire-format change:**
```bash
# 1. In the SAME commit as the layout change:
#    edit zilk_core/core/types_zz/flat_bundle.hpp  ->  kFlatBundleVersion = 14 (next)
# 2. Regenerate EEST (auto, since the converter binary changed):
make eest-mfbd-build
# 3. Regenerate the benchmark corpus (MANUAL — it has no staleness check):
make sp1-benchmark-corpus
#    Optional but recommended: bump the corpus dir name to track the format era,
#    e.g. set BENCH_CORPUS_DIR=temp/200_benchmark_blocks_mfbd_v3 in the Makefile
#    and regenerate into it (the _vN suffix is a human convention, not auto).
# 4. Validate all three legs (a stale-corpus mismatch is the symptom this catches):
make eest-blockchain-tests
tools/scripts/release_state_root_check.sh --dir temp/200_benchmark_blocks_mfbd_v2
make sp1-benchmark
```

### 6.2 Regeneration trigger matrix

| Change | Benchmark corpus | EEST fixtures |
| --- | --- | --- |
| Wire-POD layout change (+ `kFlatBundleVersion` bump) | **must** `make sp1-benchmark-corpus` | **must** `make eest-mfbd-build` |
| Converter logic change (how bytes are written) | **must** `make sp1-benchmark-corpus` | auto (converter SHA changes manifest) |
| New EEST submodule release | — | bump submodule + `make eest-mfbd-build` |
| New / different benchmark blocks | fetch `.bin` + `make sp1-benchmark-corpus` | — |

### 6.3 Key asymmetry to remember
- **EEST regen is automatic** — keyed by submodule SHA *and* converter binary SHA;
  any target that depends on `eest-mfbd-build` rebuilds it when stale.
- **The benchmark corpus regen is manual** — `sp1-benchmark-corpus` has no manifest
  and no staleness check, and nothing ties the `_v2` suffix to `kFlatBundleVersion`.
  After any wire-format or converter change you must run it yourself, or the
  benchmark/host-check will silently run stale bundles.

---

## 7. Validate after regenerating (the 3-leg)

Always run the full 3-leg after regenerating fixtures or bumping the version:

```bash
make eest-blockchain-tests                                              # leg 1
tools/scripts/release_state_root_check.sh --dir temp/200_benchmark_blocks  # leg 2
make z6m_prover && make sp1-benchmark                                   # leg 3 (rebuilds the guest)
```
Pass criteria: EEST shows only the known pre-existing failures; `State root
mismatches: 0` over 200 blocks; `gas_mismatches: 0` (and `gas_used` unchanged) in
the benchmark. A regen mistake (skipped version bump, stale corpus) surfaces here
as state-root / gas mismatches.

---

## 8. Quick file/path reference

| Thing | Path |
| --- | --- |
| Version constant | `zilk_core/core/types_zz/flat_bundle.hpp:54` (`kFlatBundleVersion`) |
| Version write / check | `flat_bundle.cpp:74` / `flat_bundle.cpp:123-125` |
| Encoders | `zilk_core/dev/cli/{legacy_to,eest_to,json_witness_to}_flat_bundle.cpp` |
| Make targets | `Makefile`: `eest-mfbd-build` (74), `eest-blockchain-tests` (89), `sp1-benchmark-corpus` (122), `sp1-benchmark` (136) |
| Benchmark raw source | `temp/200_benchmark_blocks/<N>/unifiedBlockAndStateRlp<N>.bin` |
| Benchmark corpus | `temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd` |
| EEST JSON | `third_party/eest-fixtures/blockchain_tests/**/*.json` |
| EEST MFBD | `third_party/eest-fixtures-mfbd/dev-<sha>/blockchain_tests/**/*.mfbd` |
| Host check script | `tools/scripts/release_state_root_check.sh` |
| Benchmark driver | `tools/scripts/sp1_benchmark.py` |
| Format spec | `docs/flat_witness_bundle.md` |
| Wire discipline rule | `tools/claude/AGENTS.md` |
