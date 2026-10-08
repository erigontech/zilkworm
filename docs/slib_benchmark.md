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

## Results — full run, tests-zkevm-benchmark@v0.8.2

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

- `ZKEVM_BENCH_JSON_DIR` — override the fixtures dir (default under
  `test-fixtures-cache/zkevm_benchmark/fixtures/blockchain_tests`).
- `SLIB_BENCH_WORK` — output/work dir (default `temp/slib_benchmark`).
- `FIXTURES_CACHE` — root cache dir (default `./test-fixtures-cache`).

## Mainnet blocks

`make slib-mainnet-benchmark` runs the mainnet blocks the DirectState benchmark
(`make sp1-benchmark`) uses through the HashState guest, so the two backends can
be compared block for block.

```bash
# Convert the raw witness files into HashState fixtures, then run them.
make slib-mainnet-corpus BENCH_SRC_DIR=<dir of <N>/unifiedBlockAndStateRlp<N>.bin>
make slib-mainnet-benchmark BENCH_SRC_DIR=<same dir>
```

- `legacy_to_slib_fixture` turns each `unifiedBlockAndStateRlp<N>.bin` into
  `$(SLIB_MAINNET_DIR)/<N>/statelessInput<N>.slib` (default
  `temp/200_benchmark_blocks_slib`), a binary SLIB envelope:
  `[magic "SLIB"][version][network length][block RLP length][network][block RLP][statelessInputBytes]`.
  The network is `Mainnet`, and `statelessInputBytes` is built from the file's
  state nodes, codes and ancestor headers. Given an output path ending in
  `.json`, the tool writes a one-block blockchain-test JSON instead.
- The guest reads a SLIB envelope with no JSON parse and no hex decode, the way
  it reads MFBD. It takes the pre-state root from the parent header, which must
  be among the witness headers, and otherwise runs the JSON runner's HashState
  arm's checks and execution. It has no skip outcome (an unknown network fails),
  and it applies the EIP-7934 block-size cap from Osaka on, as the MFBD runner
  does, where the JSON arm skips any oversize block before decoding it.
- The `statelessInputBytes` is a benchmark encoding, not a spec-valid one. It
  carries the full witness but an empty `new_payload_request` and no public keys,
  which HashState does not read; the block executes from its RLP. Other EIP-8025
  tools would reject it.
- The run uses `sp1_benchmark.py --slib`, which passes `--slib` to
  `z6m_prover --test-service`, so each block is read from
  `statelessInput<N>.slib` instead of `flatWitnessBundle<N>.mfbd`. Logs,
  chunking and the summary are the same as for `make sp1-benchmark`, keyed by
  block number. `--prover <path>` picks the binary when both builds are kept side
  by side.
- A block the guest rejects comes back as the failure sentinel (`u64::MAX`, see
  "Public output" in [architecture.md](architecture.md)). `--test-service` logs
  it as `FAILED` with `gas_used=0`, and `sp1_benchmark.py` leaves such blocks
  out of its summary and prints how many it dropped. On a JSON run the guest
  reports the gas of every block it accepts, because a gas of 0 also counts as
  a failed block.

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
