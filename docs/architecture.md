# Architecture

Z6M (Zilkworm) is a modular ZKEVM that proves Ethereum block execution inside a RISC-V zkVM. RISC-V is a free, open-source
Instruction Set Architecture (ISA) based on RISC principles, standardized by [RISC-V International](https://riscv.org/).

The architecture has three main layers: a **Rust prover host** that orchestrates proof generation, a **RISC-V guest program**
that runs inside the zkVM, and a **C++ EVM core** that performs the actual block execution.

(NOTE:  MULTI-BLOCK ONLY SUPPORTS EEST FULL-STATE MPT re-calculation with `silkworm::Hashbuildier` at the moment)

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
| **intx** | `third_party/evmone/third_party/intx/` | Header-only 256-bit integer arithmetic (vendored inside the evmone submodule). |
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
SP1 hypercube, and others). The first 4 bytes provide the magic identifier as follows

| Magic    | Meaning |
|----------|---------|
| `MFBD`   | FlatBundle envelope: `<u32 "MFBD"><u32 ver><u64 N>` followed by N FlatBundle blobs (each 8-aligned). |
| `EJSN`   | EEST JSON envelope: `<u32 "EJSN"><u32 ver>` followed by raw EEST `blockchain_test` JSON. |
| `URLP`, `SFBD`, `STBD` | Reserved for UnifiedRLP, SingleFlatBundle, SingleTransactionBundle (no code path yet). |

For the full FlatBundle / MFBD byte layout, see
[`docs/flat_witness_bundle.md`](flat_witness_bundle.md)

### Transport variants

The envelope bytes are identical across runners; only the surrounding transport differs.

| Runner             | Transport |
|--------------------|-----------|
| SP1 hypercube      | Envelope on SP1 stdin. |
| Native `.mfbd`     | MFBD envelope in the file. |
| Native `.json`     | EEST JSON file; the native runner wraps it with an `EJSN` header before invoking StateTransition. |
| QEMU               | Envelope passed verbatim through the `stdin_payload.bin` file input |

### Public output

The SP1 hypercube guest writes a fixed 112-byte output to public values:

| Offset | Size | Field             | Notes |
|--------|------|-------------------|-------|
| 0      | 8    | `gas_used`        | u64 LE; cumulative across bundles, or a sentinel (below). |
| 8      | 32   | `pre_state_root`  | parent state root the proof starts from i.e. the validation anchor. |
| 40     | 32   | `post_state_root` | state root of the (last) proven block. |
| 72     | 32   | `block_hash`      | hash of the (last) proven block. |
| 104    | 8    | `chain_id`        | u64 LE. |

`gas_used` stays at offset 0 so existing readers are unaffected; it carries a sentinel on the
failure/empty paths:

| Sentinel       | Value          | Meaning |
|----------------|----------------|---------|
| `kRunFailure`  | `UINT64_MAX`   | Failed. |
| `kRunSkipped`  | `UINT64_MAX-1` | Skipped. |

The roots, block hash, and chain ID bind the proof to a concrete state transition. The SP1 hypercube host currently parses and logs them.

The Airbender guest's public output is 32 bytes, the output registers a0..a7: the `block_hash` above
(the hash of the last validated block), its bytes in order as little-endian words, or zero when the run
validated no block: an EJSN success, or an MFBD whose every block is flagged expected-invalid (a skipped
run ends at `finish_error` and commits nothing). The hash binds that block's chain: StateTransition reads a
bundle's pre-state root from the header that its first block's parent hash names (headers are stored
under their own hash), requires every later block of the bundle to extend the one validated before it,
and checks each header's state root and gas used against the execution. The bundles of an envelope are
independent chains (the EEST conversions pack one test per bundle), so with several bundles the output
covers the last validated block's bundle only. `z6m_prover_airbender` derives the expected value from
the input (keccak256 of the last valid block's RLP header) and fails on a mismatch in `execute`,
`prove`, `verify`, `--test-service` and `--service`.

## Runners

### Dispatch

Entry point: `StateTransition::run()` in
`zilk_core/dev/state_transition.cpp`. The leading 4 bytes are read and matched
against `kInputMagicEJSN` / `kInputMagicMFBD`:

```cpp
switch (magic) {
    case kInputMagicEJSN: return run_ejsn();
    case kInputMagicMFBD: return run_mfbd();
    default: sys_println("ERROR: unsupported input magic"); return kRunFailure;
}
```

### EJSN envelope

**EJSN** (`EEST JSON`) — 8-byte header followed by raw EEST `blockchain_test`
JSON bytes (no inner length prefix — body runs to envelope end):

```
+0   u32  magic   == 'EJSN' (0x4E534A45)
+4   u32  version == 1
+8   <JSON bytes …>
```

Only `MFBD` and `EJSN` are declared in code today (`flat_bundle.hpp`). A few
other four-character codes are *conventions referenced in prose only* — they are
**not** defined as constants anywhere and the dispatch does not handle them:

| Code | Hex | Status |
|---|---|---|
| `URLP` | `0x504C5255` | Legacy Unified RLP (pre-FlatBundle); not in code |
| `SFBD` | `0x44424653` | Notional "single FlatBundle" — use MFBD with `n_bundles=1`; not in code |
| `STBD` | `0x44425453` | Notional future single-transaction proving; not in code |

### EJSN path

`run_ejsn()` strips the 8-byte envelope header, parses the body as an EEST
`blockchain_test` JSON document, and runs each test sub-object via the
`blockchain_test()` helper (which constructs an in-memory `DirectState` from the
test's `pre` block and exercises one `Blockchain::insert_block` per entry in
`blocks`). Exit codes mirror the legacy EEST contract:

- `0` — all passed
- `1` — any failed
- `2` — any skipped (no failures)

### SP1 input building

The Rust prover host builds an `SP1Stdin` carrying exactly one envelope per
proof request. See `prover/prover_hypercube/src/stdin_builders.rs` (and the
equivalent `prover_turbo` variant):

```rust
const INPUT_MAGIC_EJSN: u32 = 0x4E534A45;
const INPUT_VERSION_EJSN: u32 = 1;

pub fn build_stdin_from_eth_tests(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read_to_string(path)?;
    let minified = serde_json::to_string(&serde_json::from_str::<Value>(&raw)?)?;
    let json_bytes = minified.as_bytes();

    let mut envelope = Vec::with_capacity(8 + json_bytes.len());
    envelope.extend_from_slice(&INPUT_MAGIC_EJSN.to_le_bytes());
    envelope.extend_from_slice(&INPUT_VERSION_EJSN.to_le_bytes());
    envelope.extend_from_slice(json_bytes);
    stdin.write_vec(envelope);
    Ok(stdin)
}

pub fn build_stdin_from_mfbd(path: &Path) -> Result<SP1Stdin> {
    let mut stdin = SP1Stdin::new();
    let raw = fs::read(path)?;        // file is already MFBD-wrapped on disk
    stdin.write_vec(raw);
    Ok(stdin)
}
```

The MFBD path slurps the on-disk bundle file unmodified — the converters
(`json_witness_to_flat_bundle`, `legacy_to_flat_bundle`, `eest_to_flat_bundle`)
write the MFBD envelope at file-write time, so no re-wrapping is required.

`SP1Stdin` layout is a single `Vec<u8>`. The guest does ONE `read_vec_raw()` and
hands the bytes straight to `StateTransition`
(`prover/guest_hypercube/src/main.cpp`):

```cpp
ReadVecResult input_buf = read_vec_raw();
std::span<uint8_t> envelope{input_buf.ptr, input_buf.len};
auto st = silkworm::cmd::state_transition::StateTransition(envelope);
uint64_t result = st.run();
```

Note: the Rust constants are an independent mirror of the C++ values in
`flat_bundle.hpp`. They are kept in sync by convention; a future binding
generator could collapse them.

### Native run

The native runner is `zilk_core/dev/cli/runner.cpp` (built as the
`state_transition` executable). It accepts either a file or a directory:

- **`.json`** — `run_json_test_file()` reads the file, wraps it in an in-memory
  EJSN envelope, constructs `StateTransition`, and returns the run's exit code
  (0/1/2 per EEST semantics).
- **`.bin` / unknown** — `run_flat_bundle_file()` reads the file straight into a
  vector. The on-disk file is already MFBD-wrapped (the converters emit it that
  way), so the bytes pass through unmodified into `StateTransition`. The runner
  prints `Cumulative Gas Used: <n>` and returns 0.
- **Directory** — iterates recursively, dispatching per file extension.

The runner is the same binary the EEST harness (`make eest-blockchain-tests`)
drives via ctest.

### QEMU run

`qemu_runner/` cross-compiles `zilk_core` to a RISC-V target (rv32im or rv64im)
and runs the resulting binary under QEMU semihosting. Used for cycle-accurate
instruction profiling without paying SP1 prover overhead.

`qemu_runner/src/main.cpp` reads the envelope file via semihosting into a static
200 MB buffer:

```cpp
static char ENV_BUF[200 * 1024 * 1024];

int h = sh::open_file_read("stdin_payload.bin");
// chunked read into ENV_BUF until EOF …
std::string envelope_str(ENV_BUF, ENV_BUF + total);
const uint64_t res = sample_run_wrapped(envelope_str);
sh::exit(static_cast<int>(res));
```

`qemu_runner/src/cppextern.cpp::sample_run_wrapped` constructs a
`std::span<uint8_t>` over the envelope bytes and hands them to
`StateTransition::run()` — the magic dispatch chooses MFBD or EJSN exactly as in
the SP1 guest. The wire format is the same `stdin_payload.bin` that the prover
host would have written for an SP1 run.

### EEST JSON tests

The EEST corpus on disk lives at
`test-fixtures-cache/eest_stable/fixtures/blockchain_tests/` (populated by
`make test-fixtures` from the `test-fixtures.json` pin).
Two harness paths consume it:

- **Native runner** — `runner.cpp::run_json_test_file` reads a `.json` file
  byte-for-byte, prepends an 8-byte EJSN header in memory, and feeds the
  envelope to `StateTransition`. EEST JSON files on disk are never re-encoded.
- **SP1 prover via `.mfbd`** — `eest_to_flat_bundle bulk-convert` converts the
  EEST corpus into a parallel `.mfbd` tree. Freshness is managed by the
  `Makefile` (not the converter binary): `make eest-blockchain-tests` writes a
  `manifest.json` recording both the fixture submodule SHA (`eest_sha`) and the
  converter SHA (`converter_sha`), and re-runs `bulk-convert` only when that
  manifest is absent or its `converter_sha` no longer matches. The SP1 prover
  then ingests the `.mfbd` files via the MFBD path.

Both paths land in the same `StateTransition::run()` magic dispatch.
