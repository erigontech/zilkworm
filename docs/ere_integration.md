<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ERE Benchmark Integration

Zilkworm is integrated as a stateless-validation execution client in the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload). This allows the same EEST benchmark fixtures be executed inside SP1 using Zilkworm as guest program and compare the resulting cycle counts with other guests.

Currently, Zilkworm supports ERE integration in `canepat/ere_benchmark_integration` branch with tag `v0.1.0-alpha.2-ere`. Such integration required changes also into the [ERE benchmark](https://github.com/eth-act/zkevm-benchmark-workload) repository, merged via PR [#291](https://github.com/eth-act/zkevm-benchmark-workload/pull/291). 

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
| Zilkworm | tag `v0.1.0-alpha.2-ere` |
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

Full per-fixture metrics live under the `$(ERE_WORKLOAD_DIR)/zkevm-metrics/` directory.

### Validation

| Client | Completed | output_matched | Mismatches |
|---|---|---|---|
| Zilkworm `v0.1.0-alpha.2-ere` (sp1 v6.1.0) | 1077/1077 | 1077 | 0 |
| Reth v2.1.0 (sp1 v6.1.0) | 1077/1077 | 1077 | 0 |

Both clients produce matching public outputs (`success_flag || block_used_gas`) on
every fixture.

### Cycle comparison (SP1 `total_num_cycles`, all 1077)

| Metric | Value |
|---|---|
| Total cycles — Reth | 301,880,882,267 |
| Total cycles — Zilkworm | 159,156,117,864 |
| Ratio Z/R (total) | **0.527** (Reth = 1.90× Zilkworm) |
| Per-fixture Z/R | median 0.654, mean 0.755 |
| Zilkworm fewer cycles | 906 / 1077 (84%) |

> Note: the benchmark harness regenerates the per-fixture `ExecutionWitness` on each run, and that generation is not byte-deterministic (the accessed trie nodes are serialized in unordered-set order). Every variant is a valid witness, but absolute cycle counts shift by ~0.01% run-to-run. Treat the totals as representative to ~3–4 significant figures; the ratio and per-family/best-worst breakdowns are stable.

### By test family (Z/R total-cycle ratio; <1 = Zilkworm cheaper)

```
test_modexp                 0.15      test_account_query    0.72
test_bls12_381              0.23      test_stack            0.73
test_comparison             0.24      test_blake2f          0.74
test_transaction_types      0.39      test_log              0.78
test_alt_bn128              0.47      test_keccak           0.84
test_control_flow           0.49      test_point_evaluation 0.84
test_identity               0.51      test_call_context     0.85
test_sha256                 0.54      test_memory           0.98
test_system                 0.54      ----- Reth cheaper below -----
test_unchunkified_bytecode  0.56      test_mix_operations   1.04
test_storage                0.59      test_ecrecover        1.51
test_arithmetic             0.60      test_tx_context       1.74
test_bitwise                0.64      test_block_context    1.97
                                      test_ripemd160        3.06
                                      test_p256verify      16.13
```

### Best 10 for Zilkworm (lowest Z/R)

All are `modexp` — Zilkworm's `u256x2048` multiply syscall cuts ~1.2B cycles to
~26M (≈48×):

```
fixture                                    reth      zilkworm       z/r
modexp mod_even_32b_exp_256       1,255,877,685    26,246,256     0.021
modexp mod_vul_zkevm_worst_case   1,236,986,771    26,045,894     0.021
modexp mod_odd_32b_exp_256        1,228,947,125    26,046,246     0.021
modexp mod_vul_example_1          1,227,795,928    26,055,971     0.021
modexp uncachable mod_odd_32b_256 1,229,696,394    26,349,892     0.021
modexp mod_1360_gas_balanced      1,208,080,015    26,056,220     0.022
modexp mod_vul_example_2          1,180,347,961    25,778,835     0.022
modexp mod_vul_common_1360n1      1,056,218,389    23,771,034     0.023
modexp mod_vul_common_1360n2        975,693,714    22,697,983     0.023
modexp mod_vul_common_1349n1        962,459,811    22,837,507     0.024
```

### Worst 10 for Zilkworm (highest Z/R)

Dominated by P256 (RIP-7212 secp256r1) and `bls12_g2msm`, plus a few light blocks:

```
fixture                                  reth        zilkworm         z/r
p256verify x_coord_exceeds_n      159,398,972   2,663,062,565      16.707
p256verify                        153,883,847   2,551,047,641      16.578
p256verify uncachable             152,370,018   2,518,559,504      16.529
bls12_381 uncachable g2msm         35,424,872     442,240,901      12.484
block_context_ops CHAINID         184,527,753     973,438,887       5.275
block_context_ops BASEFEE         184,530,544     973,438,535       5.275
callvalue_from_call value_False   185,219,535     956,173,269       5.162
callvalue_from_call value_True     47,448,988     235,624,323       4.966
ripemd160                          97,287,283     457,429,015       4.702
call_frame_context_ops GASPRICE   217,592,864     968,723,868       4.452
```

## Interpretation

- **Correctness:** Zilkworm produces **100% correct** stateless-validation outputs on the entire fixture set.
- **Efficiency:** Zilkworm is **~1.9× more cycle-efficient** overall and wins **84%** of fixtures versus Reth.
