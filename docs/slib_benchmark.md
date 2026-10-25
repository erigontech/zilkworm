# HashState/slib SP1 cycle benchmark

Measure SP1 guest cycle counts for the **HashState/slib** state backend (the
`statelessInputBytes` / SSZ read-side path) on the curated Amsterdam compute
benchmark fixtures, so our numbers can be compared against the reth baseline
(the reth side is produced externally and compared via dashboards; these targets
only emit **our** cycle numbers).

## Prerequisite: Amsterdam EVM support

The benchmark fixtures are Amsterdam `statelessInputBytes` blocks, so both the
guest ELF and the host need the full Amsterdam EVM semantics: the zilk_core
Amsterdam fork plumbing (glamsterdam-devnet-8) and the matching evmone
submodule.

## Running locally

```bash
# 1. Download + extract the 30M-gas benchmark fixtures (~150 MiB, idempotent).
#    Needs the `gh` CLI authenticated (GH_TOKEN / `gh auth login`).
make zkevm-benchmark-fixtures

# 2. Build the flag-ON guest + prover, run every case, summarize. This target
#    also runs step 1 as a prerequisite, so it is the single entry point.
make slib-benchmark
```

What `make slib-benchmark` does:

1. `zkevm-benchmark-fixtures` — `gh release download tests-zkevm-benchmark@v21.0.5`
   (asset `fixtures_zkevm-benchmark_0030M.tar.gz`; the release ships one tarball
   per gas budget, `ZKEVM_BENCH_ASSET` selects it), extracted under
   `test-fixtures-cache/zkevm_benchmark/`.
2. `z6m_guest_slib` — configures/builds the guest with `-DZ6M_HASH_STATE=ON` in a
   **dedicated** build tree (`prover/guest_hypercube/build-slib`) so the normal
   OFF build cache is never contaminated.
3. `z6m_prover_slib` — builds the prover with `Z6M_GUEST_ELF` naming that tree's
   ELF; `prover_hypercube/build.rs` embeds it in place of
   `prover/guest_hypercube/build/z6m_guest.elf`, which is left untouched, so the
   next `make z6m_prover` relinks and embeds the DirectState guest as usual.
4. Splits each multi-case fixture JSON into one-case-per-file
   (`tools/scripts/slib_split_fixtures.py`) — necessary because
   `execute --is-test --file-name` **sums cycles across all cases in a file**, so
   one case per invocation is required for a per-block cycle number.
5. Runs each case with `z6m_prover execute --is-test --file-name <json>`, records
   the `cycles=` value, and writes both a per-case CSV and a
   `cycle_stats.py`-format log.
6. Summarizes with `tools/stats/cycle_stats.py` (needs `matplotlib` + `scipy`; if
   they are absent the raw per-case numbers are still in the CSV).

### Outputs

- `temp/slib_benchmark/per_case.csv` — `case,gas_used,cycles,prover_gas,syscall_count`
  (one row per block).
- `temp/slib_benchmark/execution.log` — `cycle_stats.py`-format log.
- `temp/slib_benchmark/cycle_stats.png` — summary plots.

## Results — tests-zkevm-benchmark@v21.0.5, 30M budget

The 30M tarball holds 122 fixture files, 1203 cases (one block each). The run
is `make slib-benchmark`'s per-case command (`z6m_prover execute --is-test`)
over `slib_split_fixtures.py`'s cases; the loop was run 8-wide with `xargs -P`
instead of sequentially (the per-case cycle count is deterministic, the
sequential loop takes ~1 min per 30M case). Guest: HashState.

These totals are not the production `statelessInputBytes` path. `execute
--is-test` ships the whole fixture JSON to the guest (`build_stdin_from_eth_tests`,
`prover/prover_hypercube/src/stdin_builders.rs:16-28`), which `run_ejsn` parses
with nlohmann (`zilk_core/dev/blockchain_test_runner.cpp:676`) before
hex-decoding each block's `statelessInputBytes`. Production input is the raw SSZ
`statelessInputBytes`, dispatched to `run_sib`
(`zilk_core/dev/state_transition.cpp:760-766`) with no JSON in the guest. On
main the in-guest JSON parse is about 45% of sampled cycles, so a per-case
number here is roughly half harness; the ERE estimator run below measures the
production path.

**1200 of 1203 cases report cycles.** The other three are zero-gas blocks
(`test_empty_block`, and the two `test_contract_creation[contract_size_max-*]`
cases, whose block carries no transaction), which the prover reports as
`FAILED (gas_used=0)` by its success criterion; the guest accepts them.

Cycle distribution (per case = per block, raw SP1 cycles):

| n | min | median | mean | max |
|---|-----|--------|------|-----|
| 1200 | 4.9M | 259.6M | 334.1M | 8.00B |

Grand total: **400,868,140,263 cycles (~0.40T)** over 49.4G gas (8.1
cycles/gas; the gas sums every block of a case, setup blocks included).

- **Heaviest families:** `p256verify` (median 6.09B, no SP1 acceleration, pure
  software), `blake2f` (median 4.23B; its 8.00B case is the largest single
  block), `selfbalance` (1.76B), `block_context_ops` and
  `call_frame_context_ops` (1.53B).
- **Lightest families:** `create` (median 10.3M), `selfdestruct_initcode`
  (9.0M), `nested_frame_state_access` (8.9M).
- Against the v0.8.2 30M budget (median 319.4M): the corpus content changed,
  so the figures are indicative only.

### The same corpus through ERE's cost estimator

`ere-hosts --action estimate-cost` runs the guest on the raw
`statelessInputBytes` (the production path, no JSON in the guest) under SP1's
gas-estimating executor; its unit is SP1's prover-cost model (trace-area
weighted charges, split into `opcode`, `syscall` and `system`), about 160× the
raw cycle count of the same case. All 1203 cases ran and every output matched
`statelessOutputBytes`; 1109 reports survive, as the harness truncates long
case names and the rest collide.

| n | min | median | mean | max |
|---|-----|--------|------|-----|
| 1109 | 349.5M | 36.06B | 59.26B | 1441.2B |

Total **65.72T** (opcode 54.37T, syscall 10.09T, system 1.26T) over 32.6G gas
(2013 units/gas); peak guest heap 35.3 MB. Heaviest families by median:
`p256verify` 980B, `point_evaluation` 237B, `keccak` 235B, `tx_context` 202B,
`blake2f` 155B (max 1441B), `bls12_381` 126B; lightest: `log` 2.65B, `system`
5.4B, `mix_operations` 16.5B, `storage` 17.0B.

This run found `test_blockhash[block_1]` at **4.12T**, 75× the next
`BLOCKHASH` case: the ancestor walk ran its 255 lookups on every call, and a
header-map lookup costs ~15k units under the estimator. `HashState::get_block_hash`
now memoizes the run of ancestors per block, as `DirectState` does; the case is
47.0B (`block_256`: 47.5B), and the corpus total went from 69.81T to 65.72T.

## Previous results — tests-zkevm-benchmark@v0.8.2

Completed full run against **tests-zkevm-benchmark@v0.8.2** (the latest release;
v0.8.3+ do not exist): **3464 cases** (339 fixture files × the 10M/30M/60M
gas-budget dirs), **3464/3464 guest passed**.

Overall cycle distribution (per case = per block):

| n | min | median | mean | max |
|---|-----|--------|------|-----|
| 3464 | 4.04M | 277M | 538M | 16.21B |

Grand total: **1,864,870,513,045 cycles (~1.86T)** — by budget: 10M = 209.53B,
30M = 562.77B, 60M = 1,092.57B. Median cycles per budget: **119.8M / 319.4M /
608.4M** (10M / 30M / 60M).

Notable points:

- **Heaviest family: `precompile/p256verify`** (median 5.13B cycles) — there is
  no SP1 acceleration for P-256 yet, so it runs as pure software.
- **Largest single block: 16.21B cycles** (a 60M `blake2f` case).
- **Lightest family: `instruction/log`** (median 37M cycles).

Splitter fix: `tools/scripts/slib_split_fixtures.py` used to truncate output
filenames at 180 chars, which dropped the distinguishing `value_10M/30M/60M`
tail of long pytest node ids — the same stem exists in all three budget dirs, so
655 of the 3464 cases silently overwrote each other. The slug now appends a
short digest of the full name when truncating, so distinct cases always produce
distinct files.

> **Comparability caution:** the published reth total of **301.88B cycles** is
> for the **Osaka convert-first** workload — a different fork and fixture
> pipeline — and is **not comparable** to these Amsterdam v0.8.2 numbers.

### Knobs (Makefile variables)

- `ZKEVM_BENCH_ASSET` — the release tarball to fetch, one per gas budget
  (default `fixtures_zkevm-benchmark_0030M.tar.gz`).
- `ZKEVM_BENCH_JSON_DIR` — override the fixtures dir (default under
  `test-fixtures-cache/zkevm_benchmark/fixtures/blockchain_tests`).
- `SLIB_BENCH_WORK` — output/work dir (default `temp/slib_benchmark`).
- `FIXTURES_CACHE` — root cache dir (default `./test-fixtures-cache`).

## CI

`.github/workflows/hypercube-slib-benchmark.yml` runs `make slib-benchmark` and
uploads the log + CSV + plot as an artifact plus a job summary. It is
**`workflow_dispatch` (manual) only and non-blocking** — deliberately not wired
to push/PR, and its run step is `continue-on-error`, so it never gates CI.

## Guest build flag

The guest is a separate CMake project, so the top-level `Z6M_HASH_STATE` option
does not reach it. `prover/guest_hypercube/CMakeLists.txt` therefore defines its
own `option(Z6M_HASH_STATE ... OFF)`. Default **OFF** ⇒ the normal guest build
keeps DirectState and carries no HashState code; the define is only added when the
option is `ON`.
