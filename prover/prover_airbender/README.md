# z6m Airbender Prover

GPU-accelerated ZK prover for Ethereum blocks on the [zksync-airbender](https://github.com/matter-labs/zksync-airbender) RISC-V zkVM, "v3" stack (`prover_pipeline`, GKR/WHIR circuits, 100-bit security).

Compiles a C++ EVM implementation (zilk_core/evmone) to RISC-V, runs it on Airbender's simulator, and proves its execution on GPU down to one final unified recursion proof, which it writes in the format Ethproofs and its verifier take.

## Architecture

```
Ethereum block (MFBD flat witness bundle)
        |
        v
  z6m guest binary (rv32im, no signed mul/div)   <-- C++ EVM compiled to RISC-V
        |
        v
  base layer      unrolled circuits, full-unsigned machine (the guest itself)
        |
        v
  unrolled recursion layers   fsv_unrolled_* verifier programs, while the next verifier
        |                     would still cost >= 52M cycles (RECURSION_UNIFIED_SWITCH_CYCLES)
        v
  bridge          the unrolled verifier proved in unified mode
        |
        v
  final           fsv_unified_recursion_layer, repeated until 1 unified + 1 delegation proof
        |
        v
  proof.bin       gzip(EPROOF01 v2): the final verifier's input word stream (~1 MB)
```

### Key components

- **Guest binary** (`guest_airbender/build/z6m_guest.{bin,text}`): the EVM execution engine compiled to RISC-V. Takes an MFBD flat witness bundle (or an EEST JSON test) as input, validates the blocks, and commits the hash of the last block it validated as its 32-byte public output (registers a0..a7). Uses CSR-delegated acceleration for keccak, blake2s and bigint operations.

- **Machine**: the base layer proves the guest on Airbender's *full-unsigned* machine: RV32IM without `mulh`, `mulhsu`, `div` and `rem`. The guest's build checks that it contains none of them (`guest_airbender/cmake/check_unsigned_muldiv.cmake`), and `execute` decodes the guest as the prover does, so a binary that executes one fails there too.

- **Simulator** (`execute`): Airbender's RISC-V interpreter, with the UART output of the guest.

- **Prover** (`prover_pipeline::ProgramProver`): precomputes the setups of the guest and of the recursion verifier programs once, then proves any number of blocks. It runs on a thread of its own with a 1 GiB stack; a panic while proving fails the block and the prover is rebuilt.

- **Recursion verifier programs** (`fsv_*_sec_100_blake2_with_compression.{bin,text}`): loaded at run time from `FSV_DIR` (default: `tools/gkr_verifier` of the zksync-airbender checkout the prover was built from). They and the guest determine the verification key. `prover/docker/fsv.sha256` records their hashes.

### Proof and verification key

- `proof.bin`: gzip of the bincode-2 `EncodedProof { magic: "EPROOF01", version: 2, security: 100, proof_words }`, where `proof_words` is `build_unified_stream` of the final recursion proof. These are the bytes posted to Ethproofs (base64).
- `vk.bin`: bincode-2 `EncodedVerificationKey { magic: "EVKEY001", version: 2, security: 100, app_bin_keccak, app_text_keccak, expected_chain_hashes }`. A proof verifies against it if the final unified verifier accepts its word stream and its output[8..16], the recursion chain over the layers' setups and exit PCs, is one of the three `expected_chain_hashes` (zero, one, or two and more unrolled recursion layers).
- The proof's output[0..8] is the guest's public output: `verify` also requires it to be the hash of the block the proof must cover.

Both formats are matter-labs/ethereum-prover's (`proof_format.rs`, `verification_key_format.rs`), so its JS/WASM verifier accepts our proofs with our key.

### Run-time environment

| Variable | Value | Why |
|---|---|---|
| `FSV_DIR` | directory with the six `fsv_*` files | the recursion verifier programs; required when the build's cargo checkout is not on the machine (e.g. in the image) |
| `RISCV_MERGE_WINDOW` | `0` (set by the prover when unset) | the guest jumps into runs of word stores (keccak.c, memset), which the JIT's word-run fusion assumes never happens |
| `RECURSION_UNROLLED_BLAKE`, `RECURSION_BRIDGE_BLAKE`, `RECURSION_FINAL_BLAKE` (legacy `RECURSION_UNIFIED_BLAKE`) | unset or `blake2_with_compression` | they select the recursion verifier programs and so the verification key; the prover refuses anything else |
| `RUST_MIN_STACK` | `1073741824` in the image | the prover thread has a 1 GiB stack of its own; this covers threads the pipeline spawns |

## Prerequisites

- NVIDIA GPU with >= 32 GB VRAM, CUDA 13.1+ toolkit and driver (all visible GPUs prove one block together)
- About 24 GB of pinned host memory per GPU (the GPU prover's host buffers), and `ulimit -l unlimited` or a sufficient memlock limit
- Rust nightly-2026-08-09 (`rust-toolchain.toml`; rustup installs it)
- riscv-none-elf-gcc 15.2.0 (for guest compilation)

## Building

```bash
# From this directory (prover/prover_airbender/)
# GPU is the default feature; CUDAARCHS selects the GPU architectures (e.g. "89;90;120"),
# its default "native" needs a GPU at build time
CUDAARCHS="80;89;90;120" cargo build --release

# Without GPU (execute, vk, verify, CPU proving)
cargo build --release --no-default-features
```

The guest binary must be built separately:
```bash
cd ../guest_airbender && make z6m_guest
```

This produces `build/z6m_guest.bin` (ROM image) and `build/z6m_guest.text` (instruction section). Both are required: the prover takes a path without extension (`--guest-bin`, default `prover/guest_airbender/build/z6m_guest` from the project root) and expects both files.

## Commands

### `execute` — run a block without proving

Executes the guest on the simulator and reports gas used, cycle count and execution time. No GPU required. The run must end at the guest's exit point and its public output must equal the hash of the input's last valid block header; otherwise the command fails. A run over 1,073,741,822 cycles (the prover's limit) still succeeds, with a warning that it cannot be proved.

```bash
z6m_prover_airbender execute --file-name path/to/flatWitnessBundle12345.mfbd
z6m_prover_airbender execute --is-test --file-name path/to/eest_fixture.json
```

`--flamegraph out.svg` writes a flamegraph (slower). `--cycles` sets the simulator's limit (default 5,000,000,000).

### `vk` — write the verification key

Computes the guest's verification key from the guest and the recursion verifier programs in `FSV_DIR` (on the CPU; it recomputes their setups) and writes it.

```bash
z6m_prover_airbender vk --output vk.bin
```

Publish it with the proofs: it is what a verifier checks them against. It changes with the guest binary and the recursion verifier programs, not with the block.

### `prove` — prove a single block

Runs the block on the simulator first (it must succeed within the prover's cycle limit), then proves it to the final unified recursion layer, checks that the proof's public output is the block's hash, and writes `proof.bin`.

```bash
z6m_prover_airbender prove \
  --file-name path/to/flatWitnessBundle12345.mfbd \
  --output-dir ./proofs            # writes ./proofs/proof.bin
```

`--backend cpu` proves on the CPU (`--backend gpu` is the default): very slow, and it needs about 96 GB of RAM. The prover is built per invocation (setup precomputation, tens of seconds); the service and `bench` build it once.

### `verify` — verify a proof

Verifies `proof.bin` against `vk.bin` (CPU only, no guest needed), then checks the proof's public output against the block it must cover: the input file (`--file-name`) or the block hash (`--block-hash`). A proof binds its block only through that output, so one of the two is required.

```bash
z6m_prover_airbender verify \
  --proof ./proofs/proof.bin \
  --vk vk.bin \
  --file-name path/to/flatWitnessBundle12345.mfbd
```

### `bench` — prove one block repeatedly

Builds the prover once, then proves the block `--iterations` times (default 5) and prints the time of each and their min/median/max.

```bash
z6m_prover_airbender bench --file-name path/to/flatWitnessBundle12345.mfbd --iterations 5
```

### `--service` — continuous proving service

Builds the GPU prover **once** at startup and reuses it for every block (it is rebuilt only after a panic). Fetches blocks and execution witnesses over RPC, converts them to MFBD bundles, and executes and/or proves them.

```bash
z6m_prover_airbender --service --gpu \
  --rpc-url http://<execution-client>:8545 \
  --prove-every 100 \
  --data-dir ./temp \
  --output-dir ./proofs
```

- `--prove-every N`: prove blocks whose number is a multiple of N (needs `--gpu`)
- `--execute-every N`: execute (without proof) the other blocks that are multiples of N
- `--start-block`/`--end-block`: the range (default: from the chain's tip, onwards)
- `--ws-url`: a WebSocket endpoint for newHeads (otherwise the service polls)
- Proofs are written to `<output-dir>/<block>/proof.bin`; one line per block goes to `<data-dir>/provingLogs.log`

Every proved block is first run on the simulator (the preflight, with the prover's machine and cycle limit). A proof is written and posted only if that run ended at the guest's exit point and both the run and the proof commit the block's hash. The preflight runs concurrently with proving by default; `Z6M_SERIAL_PREFLIGHT=1` runs it first, so that a block that fails it (for example one over the cycle limit) is skipped without being proved.

#### Ethproofs

```bash
z6m_prover_airbender --service --gpu --rpc-url ... \
  --ethproofs-endpoint https://staging--ethproofs.netlify.app/api/v0 \
  --ethproofs-token YOUR_TOKEN \
  --ethproofs-cluster-id 42
```

The service posts `queued` when a block enters its queue, `proving` when proving starts, and `proved` with `{block_number, cluster_id, proving_time, proving_cycles, proof}`: `proving_time` in ms covers witness generation (the witness-to-MFBD conversion and the guest's input) and proving, not fetching; `proving_cycles` is the guest's cycle count; `proof` is `proof.bin` in standard base64.

### `--test-service` — batch execution from disk

Executes blocks from local files without proving.

```bash
z6m_prover_airbender --test-service --start-block 24808100 --end-block 24808500 --data-dir ./temp
```

## Docker

See [docs/airbender-docker-service.md](../../docs/airbender-docker-service.md): the image `ghcr.io/erigontech/zilkworm-airbender:<commit>` runs the service from environment variables, computes the verification key into its data directory, and carries the recursion verifier programs at `/opt/z6m/fsv`.

## File structure

```
prover/prover_airbender/
  src/
    main.rs          — CLI: execute, vk, prove, verify, bench, service, test-service
    guest.rs         — the guest on Airbender's simulator (full-unsigned decoding)
    prove.rs         — ProgramProver on its own thread, rebuilt after a panic
    proof_format.rs  — proof.bin: gzip(EPROOF01 v2)
    vk.rs            — vk.bin (EVKEY001 v2) and proof verification
    public_output.rs — the block hash an input's proof must commit
    service.rs       — continuous proving service with a persistent prover
  Cargo.toml         — zksync-airbender v3 (somnergy/zksync-airbender at bd0d5153) from git
  rust-toolchain.toml — nightly-2026-08-09
```
