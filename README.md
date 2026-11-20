

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo_224_80_white.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo_224_80.svg">
    <img alt="Project Logo" src="assets/logo_224_80.svg" width="320">
  </picture>
</p>

<p align="center">
    <strong>A fast, modular, optimized ZKEVM core written in C++</strong>
</p>


🚧 [ALPHA STAGE: This is in pre-release. Functional for block execution and proof generation, but not yet production-ready.] 🚧


Zilkworm is a prototype ZKEVM (Zero-Knowledge Ethereum Virtual Machine): it generates ZK proofs
that an Ethereum block was executed correctly, so the block can be verified without re-executing it.

Zilkworm is written in C++, with a Rust orchestration layer, building on Silkworm and evmone. The
block validator is compiled to bare-metal RISC-V and runs as the guest of a zkVM: Succinct's SP1
Hypercube (rv64im) and zksync-airbender (rv32im).

## Documentation

**Start at [docs/README.md](docs/README.md)**, the index of the repository: the two state backends,
their inputs, code paths, guests, make targets, tests, corpora and benchmarks, then the shared
parts, the build, the provers, the ERE integration and the release process.

Two state backends ship today:

| Backend | Input | Guests |
|---|---|---|
| **DirectState** (default) | MFBD flat witness bundles | the SP1 guest that `z6m_prover` embeds, and the Airbender guest |
| **HashState** (`-DZ6M_HASH_STATE=ON`) | the EIP-8025 SSZ `statelessInputBytes` | the SP1 guest the ERE benchmark runs |

## High-Level Workflow

1. _Fetch_ — Retrieve a block and its execution witness from an Ethereum RPC node (Reth/Geth)
2. _Execute_ (dry-run) — Run the block validator inside the zkVM without proof generation
3. _Prove_ — Generate a ZK proof of correct block execution
4. _Verify_ — Verify a previously generated proof
5. _Service_ — Continuously poll a node and prove blocks as they arrive

A ZK prover takes an Ethereum block and its pre-state witness, re-executes all transactions inside a
zkVM and produces a proof that the execution was done correctly. Anyone can verify the proof cheaply
without re-executing the block, which also enables light clients, bridges and rollup verification.
Zilkworm differs from other ZKEVM provers by running a C++ EVM inside the zkVM instead of a Rust one.

## How to Run

Building from source needs the RISC-V GCC toolchain and the SP1 toolchain (see
[docs/README.md](docs/README.md#build-and-toolchain)). The pre-built docker image is the quick way:

```
$ docker run somnergy/z6m_prover --help
```

`z6m_prover` is the SP1 host. Every subcommand and option has `--help`.

| Command | Does |
|---|---|
| `z6m_prover fetch --rpc-url <URL> --block-number <N> --data-dir <dir>` | Fetch a block and its witness; writes `<dir>/blocks/<N>/flatWitnessBundle<N>.mfbd` |
| `z6m_prover execute --block-number <N> --data-dir <dir>` | Execute the guest on a fetched block, without proving |
| `z6m_prover execute --file-name <bundle.mfbd>` | Execute the guest on a bundle file (`--is-test` for an EEST JSON fixture) |
| `z6m_prover prove --block-number <N> --data-dir <dir>` | Prove a block (`--proof-type core, compressed, groth16, plonk`) |
| `z6m_prover --service --rpc-url <URL>` | Follow the chain: fetch, execute and prove as blocks arrive |
| `z6m_prover --test-service ...` | Execute a range of blocks, or a fixture tree, from disk |

The `setup` and `verify` subcommands are accepted but do nothing at present: their bodies are
commented out in `prover/prover_hypercube/src/main.rs`.

### Test service (offline batch execution)

Execute a range of blocks from disk without RPC or prover key setup:

```bash
z6m_prover --test-service \
  --data-dir /path/to/witness_blocks \
  --start-block 24490786 --end-block 24490805 \
  --execute-every 1
```

Blocks are read from `<data-dir>/blocks/<block_number>/flatWitnessBundle<block_number>.mfbd`. Missing blocks are skipped with a warning. Results are appended to `<data-dir>/executionLogs.log`.

### Cycle stats

Install the Python dependencies first:

```bash
pip install -r requirements.txt
```

Plot execution metrics from the log file:

```bash
python3 tools/stats/cycle_stats.py \
  -i /path/to/executionLogs.log \
  -o /path/to/results_plot.png \
  --no-display
```

## NVIDIA CUDA Accelerated proving

Install the NVIDIA drivers and the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html), then:

```
docker run --gpus all --rm --network host \
  -v "$PWD:/work:rw" -v /var/run/docker.sock:/var/run/docker.sock -w /work \
  -e SP1_PROVER=cuda \
  somnergy/z6m_prover prove --file-name /work/flatWitnessBundle<N>.mfbd
```

The Airbender prover has its own image and service; see
[docs/airbender-docker-service.md](docs/airbender-docker-service.md).

## Testing

```bash
# Unit tests
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
cmake --build build --target zilkworm.tests
ctest --test-dir build --output-on-failure --parallel

# EEST blockchain tests, native (downloads the pinned fixtures and converts them to MFBD)
make eest-blockchain-tests

# One bundle or one EEST JSON fixture through the native runner
build/zilk_core/dev/cli/state_transition path/to/flatWitnessBundle<N>.mfbd
```

Every test target, with its corpus and what it checks, is in [docs/README.md](docs/README.md).

## Acknowledgements
We thank the hard work done by the teams and people behind
1. Silkworm
2. EVMOne (especially @chfast)
3. Succinct (for SP1 and rsp)
4. RISCV
5. C++ Conglomerate
6. The Rust community

