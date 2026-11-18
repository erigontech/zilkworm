# Architecture

What is common to both state backends: the layers, the input dispatch, the runners and the public
outputs. The backends themselves are in [directstate.md](directstate.md) (MFBD bundles) and
[hashstate.md](hashstate.md) (`statelessInputBytes`); the index of everything is [README.md](README.md).

Zilkworm proves Ethereum block execution inside a RISC-V zkVM. A **Rust prover host** fetches a
block and its witness and drives the zkVM, a **RISC-V guest** runs inside it, and the guest is a
thin entry point over **zilk_core**, the C++ block validator (a fork of Silkworm's core) with
**zvm1** (a fork of evmone) as its EVM.

![Z6M Architecture Diagram](architecture.svg)

## Components

### Prover host (Rust)

| Crate | Path | Role |
|---|---|---|
| `z6m_prover` | `prover/prover_hypercube/` | SP1 Hypercube host: `fetch`, `execute`, `prove`, `verify`, `--service`, `--test-service` (`main.rs`, `service.rs`); builds the guest's stdin (`stdin_builders.rs`); embeds the guest ELF (`build.rs`). |
| `z6m_prover_airbender` | `prover/prover_airbender/` | Airbender host: simulator, GPU prover, verification key, service. See [airbender_architecture.md](airbender_architecture.md). |
| common | `prover/common/` | `fetcher.rs` (block, raw block RLP and `debug_executionWitness` over JSON-RPC, converted to an MFBD bundle), `ethproofs_client.rs`. |
| witness FFI | `prover/witness_ffi/` | Links the C++ witness JSON to MFBD converter (`zilk_core/dev/witness_converter.{hpp,cpp}`) into the Rust hosts. |
| `z6m_stateless_validator` | `prover/stateless_validator/` | `derive_vk` (the SP1 verifying key of a guest ELF) and the MFBD host adapter for ERE inputs; see [ere_integration.md](ere_integration.md). |

### Guests

| Guest | Path | Target | Backend |
|---|---|---|---|
| SP1 Hypercube | `prover/guest_hypercube/` (`src/main.cpp`, `src/sp1_runtime.cpp`, `src/include/sp1_syscalls.hpp`) | rv64im, `cmake/riscv64im-sp1.cmake` | DirectState by default, HashState with `-DZ6M_HASH_STATE=ON` |
| Airbender | `prover/guest_airbender/` (`src/main.cpp`, `src/include/airbender_csr.hpp`) | rv32im without signed mul/div | DirectState |

Both are C++ and call `StateTransition::run()` on the one input blob they read.
`prover/guest_common/src/mem_builtins.cpp` holds the memory builtins they share.

### zilk_core (C++ static library)

Compiled natively for tests and cross-compiled into each guest.

| Module | Path | Role |
|---|---|---|
| Execution | `zilk_core/core/execution/` | `ExecutionProcessor` (transactions, system calls, the evmone host), precompile dispatch. |
| State backends | `zilk_core/core/state_zz/` | `DirectState`, `HashState`, the `ActiveState` alias that selects one, and the `statelessInputBytes` parser. |
| Protocol | `zilk_core/core/protocol/` | Rule sets, block and transaction validation, intrinsic gas. |
| Trie | `zilk_core/core/trie_zz/`, `zilk_core/core/trie/` | `GridMPT` (the witness-backed root recompute) and `HashBuilder` (leaf-to-root). |
| Flat bundle types | `zilk_core/core/types_zz/` | `FlatBundle`, `Account`, `FlatKv`, the witness trie walk of the converters. |
| Indexes and SSZ | `zilk_core/core/common_zz/` | `MphfMap` / `MphfBuilder`, `HashIndex`, the key8 functions, SSZ reading and merkleization. |
| RLP, types | `zilk_core/core/rlp/`, `zilk_core/core/types/` | RLP codec; Block, Transaction, Receipt, Withdrawal. |
| Runner | `zilk_core/dev/` | `StateTransition` (`state_transition.{hpp,cpp}`), the EEST runner (`blockchain_test_runner.cpp`), the HashState accept check (`check_root_hashstate.hpp`), the CLIs in `cli/`. |

### Third-party

| Library | Path | Role |
|---|---|---|
| zvm1 | `third_party/evmone/` (submodule, `erigontech/zvm1`) | EVM interpreter and precompiles, with the SP1 and Airbender syscall paths. |
| intx | `third_party/evmone/third_party/intx/` | 256-bit integers. |
| blst | fetched by `third_party/evmone/cmake/blst.cmake` | BLS12-381. |
| nlohmann/json, magic_enum, Catch2 | CMake `FetchContent` | JSON fixtures, enum names, unit tests. |

### Dev tools

| Tool | Path | Role |
|---|---|---|
| `state_transition` | `zilk_core/dev/cli/runner.cpp` | Native runner: one input file or a directory, no zkVM. The binary ctest drives. |
| converters | `zilk_core/dev/cli/*_to_flat_bundle.cpp` | Produce MFBD bundles; see [mfbd_fixture_generation.md](mfbd_fixture_generation.md#2-the-three-converters). |
| `qemu_runner` | `qemu_runner/` | Runs zilk_core cross-compiled to rv32im or rv64im under QEMU semihosting. |

## Data flow

1. **Fetch.** The host gets the block, its raw RLP and the execution witness from an execution
   client (`prover/common/src/fetcher.rs`).
2. **Encode.** The witness is converted to an MFBD flat bundle (`json_witness_to_flat_bundle`,
   linked in through `prover/witness_ffi`). An ERE harness skips steps 1 and 2 and hands the guest a
   fixture's `statelessInputBytes`.
3. **Execute.** The guest reads the input in one piece, `StateTransition::run()` dispatches on its
   first bytes, and the backend validates the block against the parent state root.
4. **Prove.** The zkVM turns the execution trace into a proof.
5. **Verify.** The proof is checked against the guest's verifying key and its public output.

## Input format and dispatch

`StateTransition::run()` (`zilk_core/dev/state_transition.cpp`) looks at the first bytes of the
input. The magics are declared in `zilk_core/core/types_zz/flat_bundle.hpp`.

| First bytes | Constant | Input | DirectState build | HashState build (`Z6M_HASH_STATE`) |
|---|---|---|---|---|
| `MFBD` (u32 LE `0x4442464D`) | `kInputMagicMFBD` | flat witness bundle envelope | `run_mfbd`: [directstate.md](directstate.md#mfbd-run) | rejected, run fails |
| `EJSN` (u32 LE `0x4E534A45`) | `kInputMagicEJSN` | EEST `blockchain_test` JSON | `run_ejsn`: state built from the test's `pre` | `run_ejsn`: each block's own `statelessInputBytes`, [hashstate.md](hashstate.md#slib-arm) |
| `15 01` (u16 BE) | `kInputMagicSIB` | raw `statelessInputBytes` | rejected, run fails | `run_sib`: [hashstate.md](hashstate.md#raw-statelessinput-dispatch) |
| anything else | | | "unsupported input magic", run fails | `run_sib`, which answers the all-zero result |

The MFBD envelope and the bundle inside it are laid out in
[flat_witness_bundle.md](flat_witness_bundle.md#21-input-envelope-outer); the `statelessInputBytes`
wire layout is in [hashstate.md](hashstate.md#wire-layout).

### EJSN envelope

An 8-byte header followed by the JSON, which runs to the end of the input:

```
+0   u32  magic   == 'EJSN' (0x4E534A45)
+4   u32  version == 1   (kInputVersionEJSN)
+8   <JSON bytes …>
```

`run_ejsn` (`zilk_core/dev/blockchain_test_runner.cpp`) parses the JSON and runs every test in it.
The run's result follows the EEST convention the native runner turns into its exit code: 0 all
passed, 1 any failed, 2 none failed and at least one skipped.

## Runners

Every runner hands the same bytes to `StateTransition::run()`; only the transport differs.

| Runner | Source | Transport |
|---|---|---|
| SP1 host | `prover/prover_hypercube/src/stdin_builders.rs` | One `SP1Stdin::write_vec`. `build_stdin_from_mfbd` passes an `.mfbd` file unchanged; `build_stdin_from_eth_tests` (`--is-test`) minifies a JSON fixture and prepends the EJSN header. The guest does one `read_vec_raw()` (`prover/guest_hypercube/src/main.cpp`). |
| ERE (`ere-hosts`) | [ere_integration.md](ere_integration.md) | The fixture's `statelessInputBytes`, unchanged, on the guest's stdin. |
| Native `state_transition` | `zilk_core/dev/cli/runner.cpp` | A `.json` file is wrapped in an EJSN header in memory (`run_json_test_file`); any other file is passed as it is (`run_flat_bundle_file`) and the run prints `Cumulative Gas Used`. A directory is walked recursively for `.json` and `.bin` files. |
| QEMU | `qemu_runner/src/main.cpp`, `cppextern.cpp` | `stdin_payload.bin`, read through semihosting into a static 200 MB buffer, then `sample_run_wrapped`. |
| Airbender | `prover/guest_airbender/src/include/airbender_input.hpp` | The CSR `0x7C0` oracle: the byte count, then the bytes as little-endian u32 words. |

The Rust EJSN constants in `stdin_builders.rs` mirror `flat_bundle.hpp` by hand.

## Public output

### SP1 guest, MFBD or EJSN input

A fixed 112 bytes:

| Offset | Size | Field             | Notes |
|--------|------|-------------------|-------|
| 0      | 8    | `gas_used`        | u64 LE; cumulative across bundles, or a sentinel (below). |
| 8      | 32   | `pre_state_root`  | parent state root the proof starts from, the validation anchor. |
| 40     | 32   | `post_state_root` | state root of the (last) proven block. |
| 72     | 32   | `block_hash`      | hash of the (last) proven block. |
| 104    | 8    | `chain_id`        | u64 LE. |

`gas_used` carries a sentinel on the failure and empty paths (`state_transition.hpp`):

| Sentinel       | Value          | Meaning |
|----------------|----------------|---------|
| `kRunFailure`  | `UINT64_MAX`   | Failed. |
| `kRunSkipped`  | `UINT64_MAX-1` | Skipped. |

The roots, block hash and chain ID bind the proof to a concrete state transition. The SP1 host
parses and logs them (`prover/prover_hypercube/src/service.rs`).

### SP1 guest, raw `statelessInputBytes` input

The 43-byte SSZ `StatelessValidationResult`, and nothing else:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0  | 32 | `new_payload_request_root` | `hash_tree_root(NewPayloadRequest)`. |
| 32 | 1  | `successful_validation`    | 1 when the block was accepted. |
| 33 | 8  | `chain_id`                 | u64 LE. |
| 41 | 2  | `schema_id`                | u16 LE. |

A rejected block is a result with `successful_validation` 0, not a failed run. Only an input that
does not decode leaves the result all zero. ere-hosts compares these bytes with the fixture's
`statelessOutputBytes`.

### Airbender guest

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
