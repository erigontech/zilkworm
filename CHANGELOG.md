# Changelog

## v0.1.0-alpha.2-ere - ERE zkEVM benchmark integration

Pre-release equivalent to v0.1.0-alpha.2 plus integration into the ERE zkEVM benchmark workload.

## v0.1.0-alpha.2 - More performance more testing and more stability

### Highlights

Many tests, benchmakrs and performance related improvments introduced in this release.

#### Tests and Benchmarks: 
- Now introduces SP1 Hypercube EEST run workflow, and a 200-block benchmark. This ensures the whole EEST suite can be run inside of the prover and any problems tracked down. It is a stronger check for proving blocks as running EESTs on native hardware uses a different code-path and build.
- EEST JSONs are now converted to the unifiedRLP input format used for running blocks inside the provers. This means EESTs now share the same code-path as actual blocks, resulting in stronger checks.

#### Improvments and Fixes
- Close to 10% improved proving time, notable improvements:
  - MPT optimizations for post state root calculation
  - Faster ECC with MSM (Gauss-Shamir)
- Fixes introduced for prover build

#### ZVM1/EVMone changes

ZVM1 (now corresponds to evmone v0.21.0)
- EVMC merge: All of EVMC is now in a sub-directory of ZVM1 repository (history retained) making code easier to maintian and ship
- Many Amsterdam and Instruction related changes in upstream, please check the changelog and upstream EVMOne for more context

### Contributors

| Author | Commits |
|---|---|
| Somnath Banerjee | 11 |
| Paweł Bylica | 4 |
| canepat | 2 |

### Commit Log by Category (17 non-merge commits since v0.1.0-alpha.1)

#### Core EVM & Execution

- `d26a0b61` drop call-path bailout and refund options (#92) (Paweł Bylica)
- `f3defa53` Merge EVMC submodule into evmone (upstream PR #1499) (#85) (Paweł Bylica)
- `9ac3838a` Use --wrap for memcpy and memmove implementations (#72) (Paweł Bylica)

#### Merkle Patricia Trie

- `54d85257` core/trie_zz: Use first 8 bytes hash for FlatNodeStore and fast rlp (#76) (Somnath Banerjee)

#### Tests, Benchmarks & EESTs

- `929c7d7d` Convert EEST JSON fixtures to unified RLP (#88) (canepat)
- `65d5bb37` prover, workflows: Concurrent EEST runner and CI workflow for SP1 Hypercube (#84) (Somnath Banerjee)
- `e8dd6edb` Add SP1 200-block benchmark CI (#81) (Somnath Banerjee)
- `dee84782` Add SP1 benchmark script (#79) (Somnath Banerjee)
- `258b4cbf` Add HyperCube EEST CI workflow (Somnath Banerjee)

#### CI/CD & Workflows

- `5f8079d0` workflows: add RISC-V and Rust to CI image, use it in SP1 benchmark (#87) (Somnath Banerjee)
- `8184fc40` workflows: Use pre-built image at ghcr, necessary files only from eest-fixtures (#86) (Somnath Banerjee)
- `def81782` ci: set RUSTUP_HOME/CARGO_HOME in CI image (Somnath Banerjee)

#### Build System & Toolchain

- `56856115` Don't use Cable buildinfo (#67) (Paweł Bylica)
- `246a6425` Unify CMakeLists for qemu_runner (#78) (Somnath Banerjee)
- `16200fc5` Fix build (Somnath Banerjee)

#### Documentation & Tooling

- `6d5aa9c8` Improve README formatting and and clarity (#74) (canepat)
- `5dbe3db0` Add Copyright to files in bulk (Somnath Banerjee)


## v0.1.0-alpha.1 - First Public Alpha

> A native C++ EVM that runs inside a zkVM and generates cryptographic proofs of Ethereum block execution.

Zilkworm is a ZKEVM focussed on performance: the entire EVM execution, state management, and Merkle Patricia Trie computation are implemented in **C++23**, compiled to a bare-metal **RISC-V ELF**, and executed inside Succinct's **SP1 Hypercube** zkVM. The Rust layer exists only for proof orchestration. This release represents **225 commits**, **204 files changed**, and months of focused engineering.

### Diversity with C++ zkVM Guest

Major ZKEVM provers in the ecosystem runs a Rust EVM (mostly revm) inside the zkVM. Zilkworm runs **evmone**, a battle-tested C++ EVM interpreter with 5+ years of production history. This gives us:

- Direct control over memory layout, allocation patterns, and instruction selection, critical when every CPU cycle becomes part of the cryptographic proof
- Zero overhead from Rust runtime abstractions, trait dispatch, or alloc crate; the guest optimizes memory footprint and fragmentation
- A proven EVM implementation trusted by the Ethereum ecosystem

---

### Highlights

#### Pure C++ Guest Program, Zero Rust in the Proof

The guest program that executes inside the zkVM is written entirely in C++ and assembly. It boots from a 26-line RISC-V assembly entry point (`sp1_entrypoint.S`), initializes a bump-pointer heap, runs C++ global constructors, then calls directly into evmone via zilk_core. The SP1 runtime (`sp1_runtime.cpp`) implements all zkVM syscalls in C++ using inline `ecall` instructions. No Rust FFI bridge, no cxx-bridge, no overhead.

#### SP1 Syscall Acceleration for Cryptographic Precompiles

Every expensive EVM precompile is accelerated through SP1's syscall mechanism, converting thousands of RISC-V cycles into single `ecall` instructions:

| Precompile | Acceleration |
|---|---|
| Keccak-256 | `syscall_keccak_permute` |
| SHA-256 | `syscall_sha256_compress` + `extend` |
| BN254 add/double | `syscall_bn254_add` / `double` |
| BLS12-381 add/double | `syscall_bls12381_add` / `double` |
| secp256k1 add/double | `syscall_secp256k1_add` / `double` |
| MULMOD (256-bit) | `syscall_uint256_mulmod` |
| MODEXP (big-int) | `syscall_u256x2048_mul` |
| KZG point evaluation | SP1 precompile |

All syscalls use zero-overhead `always_inline` macros that compile to a single `ecall` instruction at the call site.

#### Memory-Optimized Stateless Merkle Patricia Trie (GridMPT)

A new MPT implementation (`trie_zz/`) designed from scratch for zkVM memory constraints. `GridMPT` uses grid-based stack folding/unfolding: trie nodes are decoded from RLP as needed and hashed as soon as they're unreachable. When updates are sorted by key, the algorithm achieves **linear-time complexity** because it never revisits left subtrees. 1,428 lines of implementation with a 647-line test suite.

Key design decisions:
- `GridLine` union type packs Branch/Extension/Leaf nodes in a single stack entry
- `DeletionEnabled` template parameter for compile-time removal of deletion code when not needed (acc trie)
- `FlatNodeStore` for O(log n) lookups without hash-map overhead
- Static thread-local buffers and FastHash to eliminate allocation thrashing

#### Computed Goto EVM Dispatch

The evmone fork enables computed goto for the EVM interpreter dispatch loop, replacing switch-case with a jump table. This eliminates branch misprediction overhead for opcode dispatch, a measurable win when every cycle counts inside the zkVM.

#### Optimized memcpy for RISC-V zkVM

A 552-line hand-tuned `memcpy` derived from musl libc, compiled to RISC-V by Clang and embedded as GCC inline assembly. Necessary because GCC's codegen emits unaligned loads that crash in SP1 (which requires 8-byte aligned `ld`/`sd`). Clang's register allocation produces tighter code for misaligned copy paths.

#### Dual Architecture: RISC-V 64IM + 32IM

The guest targets **rv64im** for SP1 Hypercube, with **rv32im** supported for legacy SP1 Turbo and QEMU testing. Both architectures have dedicated assembly entry points, linker scripts, and CI workflows.

#### SP1 Hypercube v6.0.2 Integration

Full integration with SP1 Hypercube via `erigontech/sp1` fork. The prover supports:
- CPU proving via `CpuProver`
- **NVIDIA CUDA GPU acceleration** via `CudaProver`
- Proof modes: Core, Compressed, Groth16, PLONK
- Dynamic prover selection at runtime
- Proof with cycles: Allowing prover to return cycles during proving

#### C++23 and Modern Build System

The entire C++ codebase uses C++23 (`std::expected`, `std::optional`, `std::format`, `std::bit_cast`, `[[assume]]` and so on). Dependencies managed via CMake FetchContent. No Conan, no vcpkg, no system package dependencies beyond a C++23 compiler and CMake 3.28.

#### Ethereum Protocol Support

Full **Osaka** hardfork support via the evmone fork (`erigontech/zvm1`), validated against the EEST blockchain test suite.

Osaka EIPs:
- EIP-7918: Blob base fee calculation changes
- EIP-7934: MAX_RLP_BLOCK_SIZE
- EIP-7939: CLZ instruction
- EIP-7883: Updated modexp precompile costs
- EIP-7823: Modexp exponent limit
- EIP-7825: Max transaction gas limit enforcement
- EIP-7840: BlobSchedule
- EIP-7594: Blob count limit per transaction (PeerDAS)
- EIP-7892: BPO forks

Pectra EIPs:
- EIP-7702: Set-code transactions
- EIP-7685: General-purpose execution layer requests
- EIP-7691: Blob throughput increase
- EIP-7623: Increase calldata cost
- EIP-6110: Supply validator deposits on chain
- EIP-7002 / EIP-7251: Withdrawal and consolidation requests
- EIP-2935: Historical block hashes from state

Precompiles (native implementations in evmone):
- EIP-2537: BLS12-381 (g1add, g1mul, g2add, g2mul, MSM, pairing, map-to-curve)
- Full native modexp (replaced stubs/GMP)
- P256verify (secp256r1 signature verification)
- KZG proof verification
- BN254 ecmul optimization with field endomorphism

#### Testing: EESTs on Three Architectures

Zilkworm runs the Ethereum Execution Spec Tests (EESTs) on three architectures in CI. When running something inside a zkVM, testing as close to the actual environment as possible matters more than coverage on a comfortable host.

**Native x86_64 (every push + PR)**
The full EEST blockchain test suite compiled with GCC 15 on Ubuntu 25.10. zilk_core linked against evmone, each JSON test fixture executed via `ctest` in parallel. Fast feedback for protocol correctness.

**QEMU rv32im (every 3 days + push)**
zilk_core and evmone cross-compiled to bare-metal RISC-V 32IM (`-march=rv32im -mabi=ilp32`) with the xpack `riscv-none-elf-gcc` toolchain, custom linker script, and QEMU semihosting entry point. `ctest` launches hundreds of `qemu-system-riscv32` instances, each processing one EEST fixture. This architecture exposes:
- 32-bit narrowing and truncation bugs (pointers, offsets, size calculations)
- Alignment violations (rv32im is less forgiving than x86_64)
- Accidental dependencies on atomics (A) or floating-point (F/D) extensions
- Instruction-count blowups where a path acceptable on x86_64 becomes a performance cliff on a proving target

**QEMU rv64im (every 3 days + push)**
Cross-compiled to RISC-V 64IM (`-march=rv64im -mabi=lp64`), the actual ISA that SP1 Hypercube executes. This is the closest-to-production test without running the full prover. It validates that the guest ELF, with its `sp1_entrypoint.S` boot sequence, bump-pointer heap, and `-nostdlib` linking, produces correct EVM results on the real target architecture.

All three enforce a failure threshold (<=5). Test logs and ctest reports uploaded as CI artifacts with 30-day retention.

### evmone Fork Summary (third_party/evmone, branch release/0.1.0-alpha.1)

The evmone fork (erigontech/zvm1) carries the full Osaka hardfork implementation plus SP1-specific optimizations. Key areas of work by contributors Pawel Bylica, rodiazet, pdobacz, Andrei Maiboroda, and Saw-mon & Natalie:

**Osaka EIPs**: EIP-7918 (blob base fee), EIP-7934 (MAX_RLP_BLOCK_SIZE), EIP-7939 (CLZ instruction), EIP-7883/7823 (modexp cost and exponent limit), EIP-7825 (max tx gas limit), EIP-7840 (BlobSchedule), EIP-7594 (blob count limit per tx, PeerDAS), EIP-7892 (BPO forks). EOF was moved to Osaka then removed from the current implementation.

**Pectra EIPs**: EIP-7702 (set-code transactions), EIP-7691 (blob throughput increase), EIP-7685 (execution layer requests), EIP-7623 (calldata cost increase), EIP-6110 (validator deposits on chain), EIP-7002/7251 (withdrawal and consolidation requests), EIP-2935 (historical block hashes from state).

**Precompiles**: Full EIP-2537 BLS12-381 suite (g1add, g1mul, g2add, g2mul, multi-scalar multiplication, pairing check, map-to-curve). Native modexp implementation replacing stubs/GMP for all input sizes. KZG proof verification. P256verify (secp256r1). BN254 ecmul optimized with field endomorphism.

**Crypto optimizations**: ecrecover using Montgomery form hash reduction, point-at-infinity checks in non-affine coordinates, Shamir trick multi-scalar multiplication for ecrecover and p256verify.

#### CLI Workflow

```
z6m_prover fetch    --block-number <N> --rpc-url <URL>   # Fetch block + witness
z6m_prover execute  --file-name <block.bin>               # Dry-run (cycle count)
z6m_prover prove    --file-name <block.bin>               # Generate ZK proof
z6m_prover --service --rpc-url <URL>                      # Continuous proving
```

### Known Limitations

- No on-chain verifier contract included
- `verify` subcommand is scaffolded but not fully wired
- `--service` mode with ethproofs posting is functional but lightly tested
- BLST library requires patching for SP1 (included in evmone fork)

### Dependencies

| Component | Version |
|---|---|
| SP1 Hypercube SDK | v6.0.2 (erigontech/sp1) |
| evmone (zvm1 fork) | 0.18+ |
| intx | 0.15.0 |
| Rust toolchain | 1.88.0 |
| CMake | >= 3.28 |
| C++ Standard | C++23 |
| RISC-V toolchain | riscv-none-elf-gcc (xpack 15.2.0) |

---

### Contributors

| Author | Commits |
|---|---|
| Somnath Banerjee | 120 |
| Pawel Bylica | 89 |
| canepat | 9 |

### Commit Log by Category (218 non-merge commits)

#### Core EVM & Execution

- `a98205e` evmone: Update blst SP1 patch to use inline SP1 ecalls (#62) (Pawel Bylica)
- `668d8f3` Inline SP1 ecalls for syscalls used by evmone (#60) (Pawel Bylica)
- `d8d8939` evmone: Call SP1 precompile for keccak directly with ECALL (#57) (Pawel Bylica)
- `22fef6d` evmone: Use BLST patched for SP1 (#56) (Pawel Bylica)
- `3a60105` evmone: Enable computed goto for EVM interpreter dispatch (#55) (Pawel Bylica)
- `554e228` Bypass journal in apply_state_diff (#51) (Pawel Bylica)
- `f3ae667` Use evmone system contract functions (#50) (Pawel Bylica)
- `8e17065` evmc: Use __has_include for dlfcn.h detection (#45) (Pawel Bylica)
- `a49c2f4` evmc: Remove gas_cost, restore asserts, optimize for SP1 Hypercube (#43) (Pawel Bylica)
- `0fca9b9` Update evmone to v0.19.0 (#37) (Pawel Bylica)
- `747f3ec` Upgrade zevmone and intx, better mulmod syscall (#30) (Pawel Bylica)
- `0c35eb3` Update evmone (Somnath Banerjee)
- `92d10ab` Update evmone module (Somnath Banerjee)
- `f8a42b9` Upgrade evmone (Pawel Bylica)
- `c510900` Fix system contracts with requests (#22) (Pawel Bylica)
- `da480a6` Fix system contracts with requests (#22) (Pawel Bylica)
- `60b8e8c` evmone: Use SP1 syscall to implement ADDMOD (#19) (Pawel Bylica)
- `2d4530c` evmone: Use SP1 syscall to implement MULMOD (#18) (Pawel Bylica)
- `80b6233` evmone: Use SP1 syscall to implement MULMOD (#18) (Pawel Bylica)
- `80fd35a` evmc: Optimize address and bytes32 for riscv32 (#17) (Pawel Bylica)
- `f89a92a` Add memmove forwarding to optimized memcpy (#66) (Pawel Bylica)
- `e2f6746` Add optimized memcpy from musl libc for SP1 zkVM (#65) (Pawel Bylica)
- `dd2a1e9` Update evmone (Somnath Banerjee)
- `b8d063e` Use Mainnet config for the STF (Pawel Bylica)
- `f53a4c4` Don't capture output in StateTransition, use std::cout (Pawel Bylica)
- `93452bc` Cleanup state_transition (Pawel Bylica)
- `92b4160` state_transition: return error code on exception (Pawel Bylica)
- `dd582e3` Extract running bin file to a function (Pawel Bylica)
- `0cc56e6` cli/state_transition: Execute also .bin blocks in a dir (#31) (Pawel Bylica)
- `6e2ca24` Improve state_transition CLI (Pawel Bylica)
- `1b8796c` cli: improve JSON test logging (Pawel Bylica)
- `d0c7d38` cli: run all tests in a dir (Pawel Bylica)
- `d77ac7e` Return error code (Pawel Bylica)
- `e74423a` Add --execution-log-file and --test-service batch execution (#34) (Somnath Banerjee)
- `bda6a41` Pass storage_size to state interface to fix EESTs (Somnath Banerjee)
- `91ba675` Pass storage_size to state interface to fix EESTs (Somnath Banerjee)
- `feaa57b` evmmax err (Somnath Banerjee)

#### Merkle Patricia Trie

- `2817dc5` feat: Memory-optimized stateless Merkle tree update implementation (#2) (Somnath Banerjee)

#### SP1 Prover Integration

- `19e8d2d` Replace SP1 submodule with git dependencies in Cargo.toml (canepat)
- `f3252ae` Update SP1 to v6.0.2 via erigontech/sp1 submodule (canepat)
- `c615ddd` Drop -fno-builtin flag from the SP1 guest build (#71) (Pawel Bylica)
- `4282e7c` Use pure cpp/cmake based build of the guest program (#69) (Somnath Banerjee)
- `7ad9565` Clean up Hypercube guest main.rs (#38) (Pawel Bylica)
- `51ee7ac` Rebase on latest sp1 (#26) (Somnath Banerjee)
- `0cc41a8` Separate out proving service and fetcher (#27) (Somnath Banerjee)
- `86a8c0d` Move prover stuff to prover dir (Somnath Banerjee)
- `8bd471f` Accelerated decompress (Somnath Banerjee)
- `8990c37` wip: rv64 (Somnath Banerjee)
- `2f04118` Small prover fix (Somnath Banerjee)
- `d8883c6` Uncomment fetch block (Somnath Banerjee)
- `024ab38` Vscode native runner, fix to secp (Somnath Banerjee)
- `fc17dc4` Temp (Somnath Banerjee)
- `5cf16cd` Dirty test fire (Somnath Banerjee)
- `cff9dd2` Interim (Somnath Banerjee)
- `d61a37b` Small tweaks (Somnath Banerjee)
- `cb98273` Build WIP (Somnath Banerjee)
- `33ffedb` Build success (Somnath Banerjee)
- `ec549c3` Update build script (Somnath Banerjee)
- `713fd97` Update sw (Somnath Banerjee)
- `8480f8d` Update sw (Somnath Banerjee)

#### Build System & Toolchain

- `0c77bbf` CMakeLists for nlohmann issue (Somnath Banerjee)
- `fa3ff07` Clean up C++ build flags (#58) (Pawel Bylica)
- `d8ee783` Drop dependency on conan package manager (#21) (Pawel Bylica)
- `01e90fe` Upgrade nlohmann_json and migrate to FetchContent (#20) (Pawel Bylica)
- `64f2fae` Upgrade magic_enum and migrate to FetchContent (#19) (Pawel Bylica)
- `87b97e9` Drop the ms-gsl dependency (#12) (Pawel Bylica)
- `7bea6b4` Don't expose conan includes to guest build (#17) (Pawel Bylica)
- `d44b30c` Clean up conanfile.py (#11) (Pawel Bylica)
- `009feb0` Require C++23 (#7) (Pawel Bylica)
- `673cfb6` Change `tl::expected` -> `std::expected` (#8) (Pawel Bylica)
- `6b4b6f4` Update conan to cpp23-gcc15 (Somnath Banerjee)
- `2516d4b` Add zilk core and third parties (Somnath Banerjee)
- `b0cd632` Update (Somnath Banerjee)
- `a17ad8b` Update (Somnath Banerjee)
- `b26a4d8` Temp rename (Pawel Bylica)
- `76fe775` Rename to zilk_core 2 (Somnath Banerjee)
- `b069c60` Rename to zilk_core 1 (Somnath Banerjee)
- `289d1b7` Rename back (Somnath Banerjee)
- `bc39f72` Update gitmodules (Somnath Banerjee)

#### Protocol & Consensus

- `e3804ae` Add Osaka config for Ethereum Mainnet and public testnets (Pawel Bylica)
- `3ba8aee` Add configuration for BPOs (Pawel Bylica)
- `95b5afe` Implement tx blob limit (PeerDAS) (Pawel Bylica)
- `d0b3fff` Implement EIP-7918: blob reserve price (Pawel Bylica)
- `de4e07f` Refactor calc_excess_blob_gas (Pawel Bylica)
- `3d7e02a` Implement EIP-7934: RLP Execution Block Size Limit for tests (Pawel Bylica)
- `dfac795` Implement EIP-7825: Transaction Gas Limit Cap (Pawel Bylica)
- `f60bf06` Osaka related changes (Pawel Bylica)
- `12fe1e0` core: fix terminal total difficulty config (Pawel Bylica)

#### CI/CD & Testing

- `67d825e` Fix qemu runner workflows (Somnath Banerjee)
- `136e469` ci: Enable EEST workflow for release/* branches (canepat)
- `6f56203` feat: Add rv64im runner for qemu and gh workflow (#22) (Somnath Banerjee)
- `be9a8fb` feat: Add rv64im runner for qemu and gh workflow (#22) (Somnath Banerjee)
- `7f50d4c` qemu_runner: Add a printline quirk to fix runner (#25) (Somnath Banerjee)
- `b5248a3` qemu_runner: Add a printline quirk to fix runner (#25) (Somnath Banerjee)
- `764e5ea` workflows: Fix CI (Somnath Banerjee)
- `6046d6a` Use Release build for qemu_runner EEST (#18) (Somnath Banerjee)
- `5078cff` Use Release build for qemu_runner EEST (#18) (Somnath Banerjee)
- `b54cd9e` workflows and qemu_runner: Sync with public repo (#14) (Somnath Banerjee)
- `65142f9` feat: Add QEMU runner and EESTs for rv32im (Somnath Banerjee)
- `4b585df` Add EEST workflow (Somnath Banerjee)
- `8d90843` Add qemu-eest-workflow (Somnath Banerjee)
- `d4c2273` Fix cron job for qemu (Somnath Banerjee)
- `cbf95e1` Schedule cron every 3 days (Somnath Banerjee)
- `2abe98f` Add back tee output and result parsing (Somnath Banerjee)
- `204f6be` Working act run (Somnath Banerjee)
- `e5e0983` Use direct file read (Somnath Banerjee)
- `0c21949` Try something (Somnath Banerjee)
- `c50b0c4` Download more RAM (Somnath Banerjee)
- `bf66274` Bring back on push (Somnath Banerjee)
- `15d24db` Try verbose (Somnath Banerjee)
- `428d1f0` Add sed to replace paths (Somnath Banerjee)
- `ebe4809` Fix ctest relative path caching (Somnath Banerjee)
- `d2beb29` Try split build-run (Somnath Banerjee)
- `5e175d7` Use bash in last 2 (Somnath Banerjee)
- `510a989` Fix (Somnath Banerjee)
- `85a10d0` Fix bash issue (Somnath Banerjee)
- `3b891cd` Fix (Somnath Banerjee)
- `0969fd8` Use ubuntu 25.10 (Somnath Banerjee)
- `a701f70` Add EEST make directive and fix test run (Somnath Banerjee)
- `7910fd2` Add EEST make directive and fix test run (Somnath Banerjee)
- `a153bfe` Add qemu semihosting exit call (Somnath Banerjee)
- `49d03a7` Add rv32im runner with qemu (Somnath Banerjee)
- `8fe7099` Add eest make and submodule (Somnath Banerjee)
- `e5845ec` ctest (Pawel Bylica)
- `e27ee2f` No ignorelist (Pawel Bylica)
- `daafe3c` Add ctest (Pawel Bylica)
- `4f195e6` Improve running tests with Makefile (Pawel Bylica)
- `08753a3` Improve running tests with Makefile (Pawel Bylica)
- `1e75894` Improve running tests with Makefile (Pawel Bylica)
- `42bc331` Add eest_debug config for vscode (Somnath Banerjee)

#### Repository Cleanup

- `c00cd96` Delete tools/monitor_proving.sh (Somnath Banerjee)
- `fe10d73` Delete tools/globs directory (Somnath Banerjee)
- `156b150` Delete tools/scripts directory (Somnath Banerjee)
- `7758b8c` Delete tools/claude directory (Somnath Banerjee)
- `2cb671f` Remove stale files not present in z6m (canepat)
- `e64764c` Remove unused CallTracer (#29) (Pawel Bylica)
- `85c0dc3` Remove incarnation (#23) (Somnath Banerjee)
- `c58f60b` Remove unused code in StateTransition and hide JSON from public headers (#15) (Pawel Bylica)
- `5aa20d2` Remove unused dev/common utilities (#6) (Pawel Bylica)
- `ebcff7b` Remove third_party/ethereum-tests (#5) (Pawel Bylica)
- `403ab56` Cleanup unused gmp, libff, secp256k1 (Somnath Banerjee)
- `b469219` Remove editorconfig (Somnath Banerjee)
- `7c59470` Cleanup (Somnath Banerjee)
- `624b662` Cleanup and update (Somnath Banerjee)
- `b1f23cc` Cleanup (Somnath Banerjee)
- `95f36f7` Undo ai (Somnath Banerjee)
- `2686257` Remove unused variable pre_state_rlp in zilk_core (#73) (canepat)

#### Documentation & Tooling

- `5e0320f` Update SP1-benchmark skill (Somnath Banerjee)
- `7a7274d` Add Claude skills for fetching and executing blocks (#63) (canepat)
- `4c6c279` Add Python dependencies for cycle stats scripts (#61) (canepat)
- `69ea453` Move cycle_stats scripts to tools/stats (#49) (Somnath Banerjee)
- `a4b32bf` docs: add architecture description (#39) (canepat)
- `efe7928` Add test-service and execution docs to README (#52) (Somnath Banerjee)
- `606012b` Update tools/claude orchestrator configs (#47) (Somnath Banerjee)
- `42039aa` Add .claude config files (#46) (Somnath Banerjee)
- `4a306b3` Move Claude orchestrator from .claude-workspace to tools/claude (Somnath Banerjee)
- `a93901e` Orchestrator (Somnath Banerjee)
- `0c9fcbf` Refresh Hypercube build instructions (#10) (Pawel Bylica)
- `fc2094f` readme: Add native build testing instruction (Pawel Bylica)
- `8fafa74` Add instructions how to execute unified block files (Pawel Bylica)
- `38defb6` Update Instructions.md (Somnath Banerjee)
- `e7ddf91` Update test instructions (Somnath Banerjee)
- `5a4f7ba` Update (Somnath Banerjee)
- `8797ff0` Update (Somnath Banerjee)
- `5f9947d` Small adjustments (Somnath Banerjee)

#### Docker & Deployment

- `a0f069e` Add new builder dockerfiles (Somnath Banerjee)

#### Bug Fixes

- `86bff79` Fix order of guest program link libraries (#70) (Pawel Bylica)
- `de85692` Fix SP1 secp256k1 ecrecover crash on zero points (#42) (Pawel Bylica)
- `6c02278` Fix rv32im (Somnath Banerjee)
- `4c1f3ac` Fix qemu debug build (Pawel Bylica)
- `8eedf43` Fix qemu-eest run (Somnath Banerjee)
- `f993235` Fix the config issue (Somnath Banerjee)
- `fb528bc` Fix (Somnath Banerjee)
- `e2e08ec` Fix (Somnath Banerjee)

#### RPC

- `ca501aa` rpc: add support for Geth debug_executionWitness (#41) (canepat)

