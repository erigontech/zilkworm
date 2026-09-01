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
# 1. Download + extract the benchmark fixtures (~495 MiB, idempotent).
#    Needs the `gh` CLI authenticated (GH_TOKEN / `gh auth login`).
make zkevm-benchmark-fixtures

# 2. Build the flag-ON guest + prover, run every case, summarize. This target
#    also runs step 1 as a prerequisite, so it is the single entry point.
make slib-benchmark
```

What `make slib-benchmark` does:

1. `zkevm-benchmark-fixtures` — `gh release download tests-zkevm-benchmark@v0.8.2`
   (asset `fixtures_zkevm-benchmark.tar.gz`), extracted under
   `test-fixtures-cache/zkevm_benchmark/`.
2. `z6m_guest_slib` — configures/builds the guest with `-DZ6M_HASH_STATE=ON` in a
   **dedicated** build tree (`prover/guest_hypercube/build-slib`) so the normal
   OFF build cache is never contaminated, then stages the ELF at the path
   `prover_hypercube/build.rs` embeds (`prover/guest_hypercube/build/z6m_guest.elf`).
3. `z6m_prover_slib` — builds the prover (via `cargo` directly, so it embeds the
   staged slib ELF rather than rebuilding the OFF guest).
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

### Knobs (Makefile variables)

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
own `option(Z6M_HASH_STATE ... OFF)`. Default **OFF** ⇒ the normal guest build is
byte-identical to today; the define is only added when the option is `ON`.
