# z6m Airbender Prover

GPU-accelerated ZK prover for Ethereum blocks using [zksync-airbender](https://github.com/matter-labs/zksync-airbender) RISC-V zkVM.

Compiles a C++ EVM implementation (zilk_core/evmone) to RISC-V, then generates STARK proofs of correct block execution on GPU. The proving pipeline produces a fully recursed proof (~1.2 MB) in ~30-100s per block on an RTX 5090, depending on block gas usage.

## Architecture

```
Ethereum block (unified RLP)
        |
        v
  z6m guest binary (rv32im)     <-- C++ EVM compiled to RISC-V
        |
        v
  riscv_transpiler               <-- JIT-compiles RISC-V to x86-64, traces execution
        |
        v
  GPU prover (CUDA)              <-- STARK proof generation on GPU
        |
        v
  Unrolled recursion (2-4 rounds) <-- Reduces proof count
        |
        v
  Unified recursion (2 rounds)   <-- Converges to 1 family proof + 1 delegation
        |
        v
  proof.bin (~1.2 MB, bincode)
```

### Key components

- **Guest binary** (`guest_airbender/build/z6m_guest.{bin,text}`): The EVM execution engine compiled to RISC-V (rv32im). Takes a unified RLP encoding of block + state as input, executes all transactions, and returns gas_used. Uses CSR-delegated acceleration for keccak, blake2s, and bigint operations.

- **riscv_transpiler**: JIT-compiles the guest binary to native x86-64 for fast trace generation. Multiple CPU workers re-execute the program in parallel to produce witness data. Supports the full RV32IM ISA including signed mul/div (mulh, mulhsu, div, rem).

- **GPU prover (CUDA)**: Takes witness traces and generates STARK proofs on GPU. The `ExecutionProver` manages GPU memory, thread pools, and host buffer caches. Binaries are registered once and reused across blocks.

- **Recursion layers**: Two layers reduce the proof to a constant size:
  - **Unrolled recursion**: Verifies base proofs using the `ReducedRiscVMachine` (no byte access, no mul/div, MOPs enabled). Each round reduces proof count by ~4-8x.
  - **Unified recursion**: Further compresses to 1 family proof + 1 delegation proof. This is the final output.

### Machine types

The z6m guest runs on `MachineType::Full` (`IMStandardIsaConfig`) because:
- libsecp256k1's modular inverse uses `int32_t` arithmetic that GCC compiles to `mulh`
- evmone's memory growth and gas calculations use signed C++ types
- GCC's division-by-constant optimization generates `mulh` for `x / constant` patterns

This required adding a new verification op code (`OP_VERIFY_FULL_MACHINE_BASE_LAYER = 3`) to the recursion verifier binary, since the signed `mul_div` circuit has different column counts (3493) than the unsigned `mul_div_unsigned` circuit (2490).

## Prerequisites

- NVIDIA GPU with CUDA 13.1+ (tested: RTX 5090, 32GB VRAM)
- CUDA Toolkit 13.1
- Rust nightly-2026-02-10
- riscv-none-elf-gcc 15.2.0 (for guest compilation)

### System requirements

- GPU VRAM: 30+ GB recommended
- Host RAM: 16+ GB (8 GB used for pinned host buffers)
- `ulimit -l unlimited` or sufficient memlock limit for CUDA pinned memory

## Building

```bash
# From this directory (prover/prover_airbender/)
# GPU is the default feature — no need for --features gpu
cargo build --release

# Without GPU (execution only, no proving)
cargo build --release --no-default-features
```

The guest binary must be built separately:
```bash
cd ../guest_airbender && make z6m_guest
```

This produces `build/z6m_guest.bin` (ROM image) and `build/z6m_guest.text` (instruction section). Both are required — the prover takes a path without extension and expects both files.

## Commands

### `execute` — Run a block without proving

Executes the guest binary in the RISC-V VM and reports gas_used, cycle count, and execution time. No GPU required.

```bash
z6m_prover_airbender execute \
  --file-name path/to/unifiedBlockAndStateRlp12345.bin \
  --block-number 12345
```

### `setup` — Precompute circuit setup

Computes circuit layouts, Merkle tree setups, and recursion chain data. This is the expensive one-time step (~50s) that only depends on the guest binary and proof target level.

```bash
z6m_prover_airbender setup \
  --setup-dir ./temp \
  --until unified
```

Produces `./temp/setup.bin` (~24.6 MB for unified level). Reuse this across all prove/service invocations for the same guest binary.

Setup levels:
- `base` (~10 MB, ~20s): Only base layer setups
- `unrolled` (~16 MB, ~35s): Base + unrolled recursion setups
- `unified` (~24.6 MB, ~50s): Base + unrolled + unified recursion setups

### `prove` — Prove a single block

```bash
# With cached setup (recommended)
z6m_prover_airbender prove \
  --file-name path/to/unifiedBlockAndStateRlp12345.bin \
  --block-number 12345 \
  --gpu \
  --until unified \
  --setup-dir ./temp \
  --output-dir ./proofs

# Without cached setup (computes setup on the fly, ~50s slower)
z6m_prover_airbender prove \
  --file-name path/to/unifiedBlockAndStateRlp12345.bin \
  --block-number 12345 \
  --gpu \
  --until unified \
  --output-dir ./proofs
```

Proof targets:
- `base`: Base STARK proofs only (no recursion). Produces many proofs depending on cycle count.
- `unrolled`: Base + unrolled recursion. Reduces to ~4 family proofs + 1 delegation.
- `unified`: Full pipeline. Produces 1 family proof + 1 delegation proof (~1.2 MB bincode).

Output: `proofs/proof.bin` (bincode-serialized `UnrolledProgramProof`).

### `--service` — Continuous proving service

Initializes the GPU prover **once** at startup and reuses it across all blocks. Fetches blocks from RPC or proves from cached files on disk.

```bash
z6m_prover_airbender --service \
  --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY \
  --start-block 24808100 \
  --end-block 24808500 \
  --prove-every 100 \
  --gpu \
  --until unified \
  --setup-dir ./temp \
  --data-dir ./temp \
  --output-dir ./proofs
```

Service mode features:
- GPU prover persisted in memory via `Arc<UnrolledProver>` — no reinit between blocks
- `--prove-every N`: Only prove blocks where `block_number % N == 0`
- `--execute-every N`: Execute (without proof) for remaining blocks
- `--setup-dir`: Load precomputed setup instead of recomputing at startup
- Proofs written to `output-dir/{block_number}/proof.bin`
- If unified RLP file already exists on disk, skips RPC fetch

#### Ethproofs integration

```bash
z6m_prover_airbender --service \
  --rpc-url https://... \
  --gpu --until unified \
  --setup-dir ./temp \
  --ethproofs-endpoint https://ethproofs.example.com \
  --ethproofs-token YOUR_TOKEN \
  --ethproofs-cluster-id 42
```

Proof bytes (bincode) are base64-encoded and posted to the ethproofs API after each block.

### `--test-service` — Batch execution from disk

Executes blocks from local files without proving. Useful for benchmarking VM execution speed.

```bash
z6m_prover_airbender --test-service \
  --start-block 24808100 \
  --end-block 24808500 \
  --data-dir ./temp
```

## Performance

Tested on NVIDIA RTX 5090 (170 SMs, 32 GB VRAM), Ubuntu 24.04, CUDA 13.1.

### Single block (24835560, 642M cycles, 0 gas — validation error block)

| Stage | Time |
|-------|------|
| Setup (one-time, cached to disk) | 50s |
| GPU init + binary insertion | 28s |
| Base layer (46 family proofs) | 12.5s |
| Unrolled recursion (2 rounds) | 4.9s |
| Unified recursion (2 rounds) | 1.3s |
| **Total with cached setup** | **~48s proving** |

### Service mode (3 blocks, prover persisted)

| Block | Gas Used | Cycles | Proving Time |
|-------|----------|--------|-------------|
| 24808100 | 54.9M | 4.8B | 107s |
| 24808200 | 18.2M | 1.2B | 32s |
| 24808300 | 41.7M | 2.0B | 49s |

GPU init (41s) happens once at startup. Subsequent blocks go straight to proving.

### Proof sizes

| Format | Size |
|--------|------|
| Bincode (current) | ~1.2 MB |
| JSON (deprecated) | ~9.3 MB |

Proof size is constant regardless of block complexity — unified recursion converges to the same shape.

## Docker

```bash
# Build from repo root
docker build --target airbender -t somnergy/z6m_prover:airbender -f prover/Dockerfile .

# Run
docker run --gpus all somnergy/z6m_prover:airbender \
  --service --rpc-url https://... --gpu --until unified
```

The image includes the guest binary at `/opt/z6m/z6m_guest.{bin,text}`. The entrypoint automatically sets `--guest-bin /opt/z6m/z6m_guest`.

Base image: `nvidia/cuda:13.1.0-runtime-ubuntu24.04`. Dependencies are fetched from `somnergy/zksync-airbender` dev branch at build time.

## Upstream changes (somnergy/zksync-airbender dev branch)

The following changes were made to the zksync-airbender fork to support z6m:

1. **Signed M-extension instructions**: Added `mulh`, `mulhsu`, `div`, `rem` to the VM interpreter, x86-64 JIT compiler, and witness replayer. These are standard RV32IM instructions that the upstream dev branch had not yet implemented.

2. **Full-machine recursion verification**: Added `OP_VERIFY_FULL_MACHINE_BASE_LAYER = 3` to the recursion verifier, with a new verification path using `FULL_MACHINE_UNROLLED_CIRCUITS_VERIFICATION_PARAMETERS`. Rebuilt the verifier binaries.

3. **Unknown instruction handling**: Changed the transpiler to treat unknown CSRs (0xC00, 0xC22) and non-CSRRW system instructions (ebreak) as illegal instructions instead of panicking at compile time.

4. **Serde derives**: Added `Serialize`/`Deserialize` to `UnrolledProverLevel` and `UnrolledProverLevelData` for setup caching. Added `base_is_full_machine` flag to `UnrolledProver`.

## File structure

```
prover/prover_airbender/
  src/
    main.rs       — CLI entry point: execute, setup, prove, service
    prove.rs      — GPU prover: setup cache, UnrolledProver creation, proof generation
    service.rs    — Continuous proving service with persistent GPU prover
  Cargo.toml      — Dependencies (zksync-airbender from git), GPU default feature
  rust-toolchain.toml — nightly-2026-02-10

prover/guest_airbender/
  src/
    main.cpp              — Guest entry: reads oracle, runs EVM block execution
    include/
      airbender_csr.hpp   — CSR interface: I/O, blake2s, bigint, keccak, exit sequence
  build/
    z6m_guest.bin          — Flat binary (ROM image)
    z6m_guest.text         — Instruction text section
```
