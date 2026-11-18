# HashState SP1 cycle benchmark

**Backend: HashState.** `make slib-benchmark` measures the SP1 cycle count of the HashState guest
on the curated Amsterdam compute benchmark fixtures, one block per case. The targets emit this
project's numbers only; a Reth comparison on the same inputs is `make ere-compare`
([ere_integration.md](ere_integration.md)). Per-release results are in
[`../CHANGELOG.md`](../CHANGELOG.md).

## Corpus

The `tests-zkevm-benchmark` release of `ethereum/execution-specs` that the Makefile pins as
`ZKEVM_BENCH_RELEASE_VERSION`, one tarball per gas budget (`ZKEVM_BENCH_ASSET`, the 30M tarball by
default). The fixtures are Amsterdam `statelessInputBytes` blocks with the wire schema of the
`eest-zkevm-tests` corpus.

## Running

```bash
# 1. Download + extract the benchmark fixtures (idempotent).
#    Needs the `gh` CLI authenticated (GH_TOKEN / `gh auth login`).
make zkevm-benchmark-fixtures

# 2. Build the flag-ON guest + prover, run every case, summarize. This target
#    also runs step 1 as a prerequisite, so it is the single entry point.
make slib-benchmark
```

What `make slib-benchmark` does:

1. `zkevm-benchmark-fixtures`: `gh release download` of the pinned tarball, extracted under
   `test-fixtures-cache/zkevm_benchmark-$(ZKEVM_BENCH_RELEASE_VERSION)/`.
2. `z6m_guest_slib` and `z6m_prover_slib`: the flag-on guest in its own build tree and a prover
   that embeds it ([hashstate.md](hashstate.md#build-flag-and-test-targets)).
3. Splits each multi-case fixture JSON into one case per file
   (`tools/scripts/slib_split_fixtures.py`). `execute --is-test --file-name` sums the cycles of
   every case in a file, so one case per invocation is what gives a per-block number.
4. Runs each case with `z6m_prover execute --is-test --file-name <json>` and rewrites the
   prover's `Executed block N (gas_used=..., cycles=..., prover_gas=..., syscall_count=...)` line
   into the `block N executed, ...` line `cycle_stats.py` parses, with a running index as the
   block number (every benchmark block is chain block 1).
5. Summarizes with `tools/stats/cycle_stats.py` (needs `matplotlib` and `scipy`; without them the
   per-case numbers are still in the CSV).

The loop is sequential. The per-case cycle count is deterministic, so the cases can also be run
in parallel by hand.

## What the number is

`execute --is-test` ships the whole fixture JSON to the guest in an EJSN envelope
(`build_stdin_from_eth_tests`), and the guest parses it (`run_ejsn`) before hex-decoding each
block's `statelessInputBytes`. The production input is the raw SSZ blob, dispatched to `run_sib`
with no JSON in the guest. A per-case number therefore includes the JSON harness.
`ere-hosts --action estimate-cost` measures the production path, in SP1's prover-cost unit
([ere_integration.md](ere_integration.md#actions-and-metrics)).

A zero-gas block (an empty block, a block with no transaction) is reported by the prover as
`FAILED (gas_used=0)` by its success criterion and gets no cycle line; the guest accepts it.

## Outputs

- `temp/slib_benchmark/per_case.csv`: `case,gas_used,cycles,prover_gas,syscall_count`, one row
  per block.
- `temp/slib_benchmark/execution.log`: the `cycle_stats.py`-format log.
- `temp/slib_benchmark/cycle_stats.png`: summary plots.

## Knobs (Makefile variables)

- `ZKEVM_BENCH_ASSET`: the release tarball to fetch, one per gas budget.
- `ZKEVM_BENCH_JSON_DIR`: the fixtures directory.
- `SLIB_BENCH_WORK`: the output and work directory (default `temp/slib_benchmark`).
- `FIXTURES_CACHE`: the cache root (default `./test-fixtures-cache`).

## CI

`.github/workflows/hypercube-slib-benchmark.yml` runs `make slib-benchmark` and uploads the log,
CSV and plot as an artifact plus a job summary. It is `workflow_dispatch` only, and its run step
is `continue-on-error`, so it never gates CI.
