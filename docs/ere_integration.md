<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

Zilkworm is integrated as a stateless-validation execution client in the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). This allows the same EEST benchmark fixtures be executed inside SP1 using Zilkworm as guest program and compare the resulting cycle counts with other guests.

> 🚧 **WIP:** needs revision after landing on public Zilkworm repo.

The initial ERE integration landed on `canepat/ere_benchmark_integration` branch and was tagged `v0.1.0-alpha.2-ere`, matching upstream workload changes merged via PR [#291](https://github.com/eth-act/zkevm-benchmark-workload/pull/291).
The numbers below reflect the current `canepat/ere_benchmark_integration` branch tip, sitting on top of the new `MFBD` wire format for Zilkworm's guest input and candidate to be merged into main. The upstream ERE benchmark changes are on `canepat/zilkworm_mfbd` branch of [our ERE benchmark fork](https://github.com/erigontech/zkevm-benchmark-workload).

The following instructions describe how to reproduce the ERE fixture set used for validation and Zilkworm vs Reth cycle comparison.

## Reference Environment

The results below were produced on:

| Component | Version |
|---|---|
| OS | macOS 26.5 (build 25F71), Darwin 25.5.0, arm64 |
| CPU / RAM | Apple M1 Max, 10 cores / 64 GiB |
| Container engine | OrbStack 2.1.3 (Docker 29.4.0) |
| OrbStack VM | 52 GiB RAM, 10 CPU |
| Rust | rustc/cargo 1.93.1 |
| ERE harness | `eth-act/ere` tag `v0.11.0`, image `ere-server-sp1:e1d345c` |
| SP1 | v6.1.0 (from the ERE SP1 image) |
| Reth | v2.1.0 |
| Zilkworm | branch `canepat/ere_benchmark_integration` @ `a5bf541` |
| Fixtures | workload-pinned default (`tests-benchmark@v0.0.9`), filtered for 10M gas Osaka fork by `--include 10M` (1077 fixtures)|

The SP1 host runs as an x86_64 container. On Apple Silicon it executes under
emulation: SP1 cycle counts are host-independent and remain valid, but
wall-clock timings are not representative.

Some notes on setup:
- _Disk_: the raw EEST benchmark archive is ~1 GiB; the generated fixtures and metrics
  add a few GiB.
- _Memory_: some fixtures (e.g. BLS12-381 and blake2f) are memory-heavy under SP1. Reaching 1077/1077 for Reth requires giving the container engine ample RAM (52 GiB on this setup) and/or limiting fixture concurrency. Zilkworm completes all fixtures within far smaller footprints (32GiB RAM are enough).

## Quick Start

Two targets in the zilkworm `Makefile` drive the ERE workload harness using the filtered ERE fixture set:

```sh
# Validate Zilkworm
make ere-validate

# Run both Zilkworm and Reth clients and print the cycle comparison
make ere-compare
```

Tunable variables with their defaults:
```
ERE_WORKLOAD_DIR    ?= temp/zkevm-benchmark-workload   # gitignored scratch dir
ERE_WORKLOAD_BRANCH ?= master                          # changing this may be helpful during future developement cycles
ERE_FIXTURE_FILTER  ?= 10M                             # 10M-gas subset; set empty for the full upstream set
ERE_TIMEOUT         ?= 60m                             # per-fixture action timeout
```

Fixture concurrency is left to rayon's default (= host logical CPUs). If a run is killed by the OOM killer —
not seen with Zilkworm on the 10M set, but it happens with Reth on the memory-heavy precompiles (BLS12-381/blake2f)
and on the larger gas tiers — cap concurrency by passing `RAYON_NUM_THREADS` in the environment:

```sh
RAYON_NUM_THREADS=2 make ere-compare     # or =1 for the heaviest tiers
```

## Testing Scope

The upstream benchmark applies no run-time filter and the generation default (no
`--include`) is the **full** set: all gas values (including 100M) and every fork in
the release. The `--include 10M` we use is our scoping choice for tractable local runs.
To mirror the full upstream set, set `ERE_FIXTURE_FILTER=`(empty) — note this may need
some tweaks in the fixture generation at least for ERE fixtures in _legacy_ format.

## Results

> 🚧 **WIP:** needs revision after landing on public Zilkworm repo.

Full per-fixture metrics live under the `$(ERE_WORKLOAD_DIR)/zkevm-metrics/` directory.

### Validation

| Client | Completed | output_matched | Mismatches |
|---|---|---|---|
| Zilkworm `canepat/ere_benchmark_integration @ a5bf541d` (sp1 v6.1.0) | 1077/1077 | 1077 | 0 |
| Reth v2.1.0 (sp1 v6.1.0) | 1077/1077 | 1077 | 0 |

Both clients produce matching public outputs on every fixture. The Zilkworm
guest commits the raw `block_used_gas` as an 8-byte little-endian u64.

### Cycle comparison (SP1 `total_num_cycles`, all 1077)

| Metric | Value |
|---|---|
| Total cycles — Reth | 301,864,477,725 |
| Total cycles — Zilkworm | 158,037,964,869 |
| Ratio Z/R (total) | **0.524** (Reth = 1.91× Zilkworm) |
| Per-fixture Z/R | median 0.655, mean 0.742 |
| Zilkworm fewer cycles | 913 / 1077 (84%) |

> Note: the benchmark harness regenerates the per-fixture `ExecutionWitness` on each run, and that generation is not byte-deterministic (the accessed trie nodes are serialized in unordered-set order). Every variant is a valid witness, but absolute cycle counts shift by ~0.01% run-to-run. Treat the totals as representative to ~3–4 significant figures; the ratio and per-family/best-worst breakdowns are stable.

### By test family (Z/R total-cycle ratio; <1 = Zilkworm cheaper)

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

### Best 10 for Zilkworm (lowest Z/R)

All are `modexp` — Zilkworm's `u256x2048` multiply syscall cuts ~1.2B cycles to
~26M (≈48×):

```
fixture                                    reth      zilkworm       z/r
modexp mod_even_32b_exp_256       1,255,858,733    26,214,839     0.021
modexp mod_vul_zkevm_worst_case   1,236,968,391    26,019,400     0.021
modexp mod_odd_32b_exp_256        1,228,928,620    26,019,639     0.021
modexp mod_vul_example_1          1,227,777,401    26,027,438     0.021
modexp uncachable mod_odd_32b_256 1,229,678,244    26,276,408     0.021
modexp mod_1360_gas_balanced      1,208,061,809    26,029,482     0.022
modexp mod_vul_example_2          1,180,329,289    25,750,575     0.022
modexp mod_vul_common_1360n1      1,056,200,269    23,744,338     0.023
modexp mod_vul_common_1360n2        975,685,174    22,671,160     0.023
modexp mod_vul_common_1349n1        962,442,010    22,810,498     0.024
```

### Worst 10 for Zilkworm (highest Z/R)

Dominated by P256 (RIP-7212 secp256r1) — no SP1 accelerator wired in evmone —
`bls12_g2msm` uncachable, and a cluster of block-context / tx-context
micro-benchmarks (BASEFEE, CHAINID, GASPRICE, BLOBBASEFEE, CALLVALUE) that pay
one `intx::be::load` byteswap per opcode invocation:

```
fixture                                        reth      zilkworm         z/r
p256verify x_coord_exceeds_n             159,380,175   2,663,050,785    16.709
p256verify                               153,856,223   2,551,035,614    16.581
p256verify uncachable                    152,351,386   2,518,504,182    16.531
bls12_381 uncachable g2msm                35,406,830     457,840,938    12.931
block_context_ops BASEFEE                184,502,732     973,328,441     5.275
block_context_ops CHAINID                184,508,449     973,328,645     5.275
callvalue_from_call value_False          185,200,433     956,162,180     5.163
callvalue_from_call value_True            47,430,676     235,622,255     4.968
call_frame_context_ops GASPRICE          217,563,903     968,613,931     4.452
block_context_ops BLOBBASEFEE            241,190,203     973,327,729     4.036
```

## Interpretation

- **Correctness:** Zilkworm produces **100% correct** stateless-validation outputs on the entire fixture set.
- **Efficiency:** Zilkworm is **~1.91× more cycle-efficient** overall and wins **84%** of fixtures versus Reth.
