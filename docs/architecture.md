# Architecture

Z6M (Zilkworm) is a modular ZKEVM that proves Ethereum block execution inside a RISC-V zkVM. RISC-V is a free, open-source
Instruction Set Architecture (ISA) based on RISC principles, standardized by [RISC-V International](https://riscv.org/).

The architecture has three main layers: a **Rust prover host** that orchestrates proof generation, a **RISC-V guest program**
that runs inside the zkVM, and a **C++ EVM core** that performs the actual block execution.

![Z6M Architecture Diagram](architecture.svg)

## Components

### Prover Host (Rust)

The host process runs natively (e.g. on x86_64 or ARM). It fetches block data and witness from an Ethereum full node, encodes it, and submits it to the SP1 prover.

| Module | Role |
|--------|------|
| **Fetcher** | Calls `eth_getBlockByNumber`, `debug_getRawBlock`, and `debug_executionWitness` via JSON-RPC to retrieve block data and state witness. |
| **RLP Methods** | Encodes block headers and pre-state into a unified RLP binary that the guest can consume. |
| **Service** | Orchestrates fetch → execute → prove → verify workflow. Manages SP1 prover client lifecycle. |
| **EthProofs Client** | Posts completed proofs to the ethproofs aggregation service. |

### Guest Program (RISC-V ELF)

Compiled to a RISC-V target (rv64im or rv32im). This is the program whose execution is proven by the zkVM.

| Module | Role                                                                                 |
|--------|--------------------------------------------------------------------------------------|
| **Guest Main** | Entry point in Rust. Reads SP1 stdin, calls into C++ via bridge.                     |
| **Precompiles** | Replaces expensive crypto precompiles with SP1 syscalls (accelerated in the prover). |

### Zilk Core (C++ static library)

A fork of Silkworm's core, compiled both natively (for testing) and cross-compiled to RISC-V (for the guest).

| Module | Path | Role |
|--------|------|------|
| **Execution** | `zilk_core/core/execution/` | EVM interpreter integration, transaction processor, precompile dispatch. |
| **State** | `zilk_core/core/state/` | `IntraBlockState` for in-block state transitions; `InMemoryState` for the full state tree. |
| **Protocol** | `zilk_core/core/protocol/` | Consensus rule sets, block validation, intrinsic gas calculation. |
| **Trie** | `zilk_core/core/trie/` | Merkle Patricia Trie hash builder and prefix set for state root computation. |
| **RLP** | `zilk_core/core/rlp/` | Recursive Length Prefix encode/decode for all Ethereum types. |
| **Types** | `zilk_core/core/types/` | Core data types: Block, Transaction, Account, Receipt, Withdrawal, etc. |

### Third-Party Libraries

| Library | Path | Role |
|---------|------|------|
| **zEVMOne** | `third_party/evmone/` | EVM bytecode interpreter (fork of evmone with ZK-friendly modifications). |
| **intx** | `third_party/intx/` | Header-only 256-bit integer arithmetic. |
| **blst** | (fetched at build time) | BLS12-381 cryptographic operations for the BLS precompile. |
| **nlohmann/json** | (fetched at build time) | JSON parsing for test fixtures and configuration. |

### SP1 Hypercube SDK

| Component | Role |
|-----------|------|
| **sp1-sdk** | Host-side prover client. Manages ELF loading, stdin/stdout, proof requests. |
| **sp1-core-executor** | RISC-V interpreter that executes the guest ELF and records the execution trace. |
| **sp1-prover** | Converts the execution trace into a cryptographic proof (compressed, Groth16, or PLONK). |

### CLI / Dev Tools

| Tool | Path | Role |
|------|------|------|
| **state_transition** | `zilk_core/dev/cli/` | Native CLI that runs EEST blockchain test fixtures or unified RLP block files through zilk_core without the zkVM. Used for development and testing. |
| **qemu_runner** | `qemu_runner/` | Runs the RISC-V guest ELF under QEMU (rv32im or rv64im) for debugging without the full prover. |

## Data Flow

1. **Fetch**: The prover host calls Geth/Reth JSON-RPC to retrieve the target block, its parent, and the execution witness (state trie nodes + bytecodes needed for execution).
2. **Encode**: Block and pre-state are RLP-encoded into a single binary blob and written to SP1's stdin.
3. **Execute**: The SP1 executor runs the guest ELF. The guest decodes the input, calls into zilk_core via FFI, and the C++ EVM executes every transaction in the block.
4. **Prove**: The SP1 prover converts the execution trace into a succinct proof.
5. **Verify**: The proof can be verified on-chain or off-chain using the SP1 verifying key.

## Input Format

Canonical byte layout fed as input to every Zilkworm STF runner (native, QEMU rv32/rv64,
SP1 hypercube, ...).

All multi-byte integers expressing encoded lengths are **little-endian**, except RLP uses its own
length encoding (big-endian per the Ethereum spec).

### Per-subtest unified RLP

One subtest = one outer RLP list. Version is auto-detected by the first byte of the outer-list payload:

| First byte    | Version | Layout |
|---------------|---------|--------|
| `0x01`        | v1      | `[VERSION_V1, fork_name, prev_block, blocks_list, pre_state, headers, pre_trie, post_state_hash]` |
| `0xb8..0xbf`  | v0 legacy | `[prev_block, block, pre_state, headers, pre_trie]` — Mainnet only, single block. |

Fork-name short strings encode as `0x80..0xb7`, so the ranges never collide.

**v1 fields:**
- `blocks_list` = `[[block_rlp, ei], ...]` where `ei` is `0x01` (expect-invalid) or `0x80` (expect-valid).
- `post_state_hash` = 32 bytes; zero hash means "skip the check".

**`pre_state` sub-layout:** `[accounts, storage, codes]`
- `accounts`: `[[addr, nonce, balance, code_hash, storage_root], ...]`
- `storage`:  `[[addr, [k, v, k, v, ...]], ...]`
- `codes`:    flat sequence of `[code_hash, code]` pairs (no per-pair wrapper).

### Bundle format

N per-subtest blobs concatenated, length-prefixed. Used even for N=1.

```
<u32 N> <u32 len_0> <rlp_0> ... <u32 len_{N-1}> <rlp_{N-1}>
```

Produced by `encode_rlp_bundle` and `z6m_eest_convert bulk-convert`.

### Transport variants

The bundle bytes are identical across runners; only the surrounding transport differs.

| Runner             | Transport |
|--------------------|-----------|
| SP1 hypercube      | Bundle on SP1 stdin. |
| Native `.rlp`      | Bundle in the file. |
| Native `.json`     | EEST JSON, parsed in-process; bundle never materialised. |
| QEMU               | `stdin_payload.bin`: `<1 byte tag><payload>`. Tag `'R'` = bundle, `'J'` = raw JSON. |

The QEMU tag is prepended by `qemu_run_rlp.sh` / `qemu_run_json.sh`.

### Public output

SP1 guest writes to public values:

```
<u32 N> <u64 result_0> ... <u64 result_{N-1}>
```

Each `result_i` is `cumulative_gas_used`, or a sentinel:

| Sentinel       | Value          | Meaning |
|----------------|----------------|---------|
| `kRunFailure`  | `UINT64_MAX`   | Failed. |
| `kRunSkipped`  | `UINT64_MAX-1` | Skipped. |

Native + QEMU translate the same sentinels into ctest exit codes:
**1** = any failure, **2** = all skipped (ctest `SKIP_RETURN_CODE`), **0** = otherwise.
