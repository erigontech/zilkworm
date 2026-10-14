# Z6M Airbender Guest Architecture

## 1. Guest Program Build

### Toolchain
- **Compiler**: `riscv-none-elf-gcc` / `riscv-none-elf-g++` (xPack GCC 15.2.0)
- **ISA**: `rv32im_zicsr` — 32-bit RISC-V with integer multiply/divide and CSR instructions, less
  `mulh`, `mulhsu`, `div` and `rem`: Airbender's proving machine has only the unsigned M
  instructions, and a post-link check (`cmake/check_unsigned_muldiv.cmake`) fails the build on a
  signed one outside two library functions that only run on a failing guest
- **ABI**: `ilp32` — 32-bit int, long, pointer
- **Optimization**: `-O3 -fno-builtin -fipa-pta -funroll-loops`
- **C++ mode**: `-fno-exceptions -fno-rtti -fno-threadsafe-statics`
- **Linking**: `-nostdlib -Wl,-e,_start -Wl,--gc-sections`

### Memory Layout (from `memory.x` and `link.x`)

| Region | Address | Size | Contents |
|--------|---------|------|----------|
| ROM | `0x000000` | 4 MB | `.text` (code), LMA of `.rodata` and `.data` |
| Stack | `0x400000` | 64 MB | Grows downward from `_sstack` |
| .rodata | ~`0x4400000` | ~256 KB | Read-only data (VMA, copied from ROM at startup) |
| .data | ~`0x4440000` | ~48 KB | Initialized data (VMA, copied from ROM at startup) |
| .bss | ~`0x444C000` | varies | Zero-initialized data |
| Heap | after .bss | 896 MB | Bump allocator (`operator new`) |

### Two-Phase Build (`prover/guest_airbender/Makefile`)

**Phase 1 — Zilkworm library build:**
```bash
cmake -B build/zilkworm -S ../.. \
    -DCMAKE_TOOLCHAIN_FILE=cmake/riscv32im.cmake \
    -DAIRBENDER=ON
cmake --build build/zilkworm --target install
```
Cross-compiles the full zilk_core (silkworm fork), evmone and blst for rv32im. Installs headers and static libraries to `build/zilkworm-install/`.

**Phase 2 — Guest ELF link:**
```bash
cmake -B build -S .    # configures guest binary
cmake --build build     # links against installed libraries
```
Produces `z6m_guest.elf`, then `objcopy -O binary` creates `z6m_guest.bin` (flat binary for the simulator).

### Source Files

| File | Role |
|------|------|
| `start.S` | Entry point (`_start`): sets gp, sp, calls `_start_rust` |
| `airbender_runtime.cpp` | Memory init (copies .rodata/.data from ROM to RAM), calls `main()` |
| `main.cpp` | Application: reads input via CSR, runs block execution |
| `simple_allocator.cpp` | Bump allocator for `operator new` / `operator delete` |
| `mem_builtins.c` | Word-aligned `memcpy`, `memmove`, `memset`, `memcmp` |
| `runtime_stubs.c` | Stubs for `floor`, `fegetround`, `__dso_handle` |
| `airbender_csr.hpp` | All CSR operations: read/write, UART, blake2s, bigint, keccak, finish |

---

## 2. Runtime Invocation Flow

### Boot Sequence
```
_start (start.S)
  → sets gp = __global_pointer$
  → sets sp = _sstack (top of 64MB stack)
  → jumps to _start_rust

_start_rust (airbender_runtime.cpp)
  → init_memory(): copies .rodata and .data from ROM (LMA) to RAM (VMA)
  → calls main()

main (main.cpp)
  → airbender::read_input_from_csr()  — reads block data from CSR oracle
  → run_unified_rlp(ByteView)         — executes the block
  → airbender::finish_success(out)    — writes result to registers, halts
```

### Input Reading Protocol (`airbender::read_input_from_csr`)
1. Read first u32 from CSR 0x7C0 → `num_bytes` (total input size)
2. Allocate raw buffer via `operator new(num_bytes)` — no zero-fill
3. Read `num_bytes/4` words from CSR, store directly as u32 (word-aligned, LE)
4. Handle trailing 0-3 bytes individually
5. Return `{buffer_ptr, num_bytes}` as a `ByteView`

The input is a **unified block-and-state RLP** binary: genesis block + target block + pre-state accounts/storage/code + pre-trie nodes, all concatenated as a single RLP list.

### Block Execution (`StateTransition::run_rlp`)
```
run_rlp(unified_rlp_)
  → RLP decode: genesis block, target block, pre-state, headers
  → read_pre_state_from_rlp(): populate InMemoryState with accounts, storage, code
  → Blockchain::insert_block(block):
      → validate_block_header()
      → pre_validate_block_body()
      → execute_block() → ExecutionProcessor::execute_block_no_post_validation()
          → For each transaction:
              evmone::state::transition() → Host::call() → EVM dispatch loop
      → apply_state_diff()
  → check_root(): GridMPT verification against expected state root
  → Return gas_used
```

---

## 3. Binary Input (vs JSON)

The original zksync-airbender `runner.rs` was hardcoded to load `../zksync-os/zksync_os/app.bin` with no CLI arguments and no input file support. The zilkworm guest needs a **binary RLP input** (not JSON), fed through the CSR non-determinism oracle.

### Changes to zksync-airbender (`risc_v_simulator/bin/runner.rs`)
- Added CLI argument parsing: `--bin <path>`, `--input-file <path>`, `--cycles <N>`
- Added `build_oracle()`: reads the input file bytes, prepends a u32 byte-count word, packs into LE u32 words
- Feeds the oracle to `QuasiUARTSource::new_with_reads(oracle)` which the simulator delivers via CSR reads
- Made `RunResultMeasurements` fields public and `Debug`-derivable for cycle reporting

### Why binary, not JSON
The z6m witness format is a compact RLP encoding of the full block context (genesis + block + pre-state + trie). This is ~6-16 MB per block. JSON would be 10-50x larger and require a JSON parser in the guest (nlohmann/json adds ~200KB of code). The binary format is parsed directly via `rlp::decode_header` / `rlp::decode` which are lightweight pointer-advancing operations.

---

## 4. Precompile Acceleration

### Keccak-f[1600] via CSR 0x7CB

Ethereum uses Keccak-256 for everything: address derivation, storage slot hashing, MPT node hashing, transaction hashing. Without acceleration, the pure-C `keccakf1600_implementation` in `keccak.c` runs ~300 lines of bit manipulation per permutation.

**Hook**: In `third_party/evmone/lib/evmone_precompiles/keccak.c`, the `AIRBENDER` preprocessor path defines `syscall_keccak_permute()`, which permutes the state through `keccak_permute_buf()` and its CSR 0x7CB delegation. It is selected as `keccakf1600_best`.

**Protocol**: The keccak CSR (0x7CB) uses a delegation model:
1. Copy 25 u64 state words to a 256-byte-aligned buffer (+ 6 scratch words)
2. Set x10=0 (control, auto-bumped by hardware), x11=buffer pointer
3. Execute 649 contiguous `csrrw x0, 0x7CB, x0` instructions (`.rept 649`, not a loop: the transpiler recognizes exactly 649 contiguous CSR writes, runs the whole permutation on the first and moves the PC past the rest)
4. Copy 25 u64 words back from buffer

Each CSR write performs one micro-step of the Keccak-f permutation. The simulator implements the full 24-round Keccak-f across these 649 calls.

### BigInt U256 via CSR 0x7CA

The bigint CSR provides hardware-accelerated 256-bit arithmetic. Operations are triggered by setting x10=mut_ptr, x11=immut_ptr, x12=operation_mask, then executing `csrrw x0, 0x7CA, x0`.

| Mask | Operation | Description |
|------|-----------|-------------|
| 0x01 | ADD | mut += immut |
| 0x02 | SUB | mut -= immut |
| 0x04 | SUB_NEG | mut = immut - mut |
| 0x08 | MUL_LOW | mut = low256(mut * immut) |
| 0x10 | MUL_HIGH | mut = high256(mut * immut) |
| 0x20 | EQ | x12 = (mut == immut) |
| 0x80 | MEMCOPY | mut = immut |

Both pointers must be 32-byte aligned and point to RAM (>= 0x400000).

### ecrecover

The EVM `ecrecover` precompile (address 0x01) and transaction sender recovery use evmone's
built-in secp256k1 code, which on AIRBENDER runs its field arithmetic through the BigInt CSR
and computes u1*G + u2*R with a GLV-decomposed MSM over precomputed G / phi(G) tables
(see zvm1 `lib/evmone_precompiles/secp256k1.cpp`). An earlier libsecp256k1-based path was
dropped once this became faster.

---

## 5. Building and Running

### Prerequisites
- xPack `riscv-none-elf-gcc` 15.2.0 (or compatible) in PATH
- Rust nightly toolchain (for prover_airbender)
- CMake 3.20+, GNU Make

### Build Guest
```bash
cd /path/to/z6m
make z6m_guest_airbender
```
Output: `prover/guest_airbender/build/z6m_guest.bin`

### Build Prover
```bash
make z6m_prover_airbender
```
Output: `prover/prover_airbender/target/release/z6m_prover_airbender`

### Execute a Block
```bash
prover/prover_airbender/target/release/z6m_prover_airbender execute \
    --file-name /path/to/unifiedBlockAndStateRlp<N>.bin
```

Options:
- `--guest-bin <path>` — override guest binary (default: `prover/guest_airbender/build/z6m_guest.bin`)
- `--cycles <N>` — max cycle limit (default: 5,000,000,000)

### Batch Execution
```bash
prover/prover_airbender/target/release/z6m_prover_airbender execute \
    --test-service \
    --start-block 24522000 --end-block 24522010 \
    --data-dir /mnt/nodes_wd_8tb/benchmark_blocks
```

### Running EEST Test Fixtures

Ethereum Execution Specification Tests (EEST) are JSON fixtures that validate EVM correctness across forks.

The guest runs EEST *blockchain* tests. Fetch the pinned fixtures (`test-fixtures.json`) from the repo root first:
```bash
tools/test-fixtures.sh test-fixtures.json test-fixtures-cache eest_stable
```

**Single test:**
```bash
prover/prover_airbender/target/release/z6m_prover_airbender execute \
    --is-test \
    --file-name test-fixtures-cache/eest_stable/fixtures/blockchain_tests/for_osaka/istanbul/eip152_blake2/blake2_delegatecall/blake2_precompile_delegatecall.json
```

**Batch EEST via Makefile:**
```bash
cd prover/prover_airbender
make selftest                               # one blake2 test
make -j"$(nproc)" eest                      # all blockchain tests (slow)
make -j"$(nproc)" eest TESTS_SUBDIR=for_osaka   # one fixture directory
```

A test passes only if its log has the guest's `run successful` line and no `CRASHED!` line, which the Makefile appends when `execute` exits non-zero. `execute` exits non-zero unless the run ended at the guest's exit point (`finish_success`): a failure, a skipped test (unknown network, block over the RLP size limit) and a run cut off at the cycle limit all fail. CI fails on any failure outside `eest-known-failures.txt`.

**Oracle protocol**: The oracle is the input's byte count followed by its bytes, packed into little-endian u32 words. The guest reads them from CSR 0x7C0 and dispatches on the input's leading 4-byte magic: `MFBD` (a flat witness bundle, as converted on disk) or `EJSN` (an EEST JSON test). With `--is-test`, the Rust prover minifies the JSON fixture and wraps it in the `EJSN` envelope.

### Example Output
```
Loading guest binary: prover/guest_airbender/build/z6m_guest.bin (3.2 MB)
Loading input: unifiedBlockAndStateRlp24522000.bin (15.8 MB)
UART: `[state_transition] run successful, gas used: 59681801`
Took 2213982219 cycles to finish
Executed block 24522000 (gas_used=59681801, cycles=2213982219, time=14.27s, freq=155M cycles/s, reached_end=true)
```

---

## 6. Proving (Airbender v3)

`z6m_prover_airbender` proves with zksync-airbender's v3 stack (`prover_pipeline`, pinned to
bd0d5153), always to the final unified recursion layer at 100-bit security. See
`prover/prover_airbender/README.md` for the commands and `docs/airbender-docker-service.md` for
the image and service.

### Pipeline

| Layer | Program | Machine |
|-------|---------|---------|
| base | the guest (`z6m_guest.{bin,text}`) | unrolled circuits, full-unsigned ISA (RV32IM without signed mul/div) |
| unrolled recursion (0 or more) | `fsv_unrolled_base_layer` / `fsv_unrolled_recursion_layer` | unrolled circuits, reduced ISA; repeated while the next verifier would cost ≥ 52M cycles |
| bridge | the unrolled verifier again | unified circuit |
| final | `fsv_unified_recursion_layer` (repeated until 1 unified + 1 delegation proof) | unified circuit |

The `fsv_*` verifier programs are binaries shipped in zksync-airbender's `tools/gkr_verifier`; the
prover loads them from `FSV_DIR`. The guest's run is limited to 1,073,741,822 cycles (the prover's
JIT keeps timestamps in 32 bits), and `RISCV_MERGE_WINDOW=0` must turn off the JIT's fusion of
word load/store runs, because the guest jumps into such runs (keccak's `buf_zero_state_from`,
`memset`'s jump table).

### Statement and public output

Every layer's verifier outputs 16 words. Words 0..7 are the guest's registers a0..a7 at its exit
(the hash of the last block it validated, carried unchanged through the recursion). Words 8..15
are the recursion chain: a Blake2s hash chain over each distinct layer's end parameters, the
hash of its exit PC and setup commitments. The chain binds a proof to the guest binary and the
verifier programs; the output binds it to a block.

### Proof and verification key formats

The formats are matter-labs/ethereum-prover's, which Ethproofs and its JS/WASM verifier take:

- **Proof** (`proof.bin`, posted to Ethproofs in base64): gzip of the bincode-2 (standard config)
  encoding of `{ magic: "EPROOF01", version: 2, security: 100, proof_words: Vec<u32> }`, where
  `proof_words` is the final unified verifier's input stream (`build_unified_stream` of the last
  proof and its setups).
- **Verification key** (`vk.bin`, from `z6m_prover_airbender vk`): bincode-2 of
  `{ magic: "EVKEY001", version: 2, security: 100, app_bin_keccak, app_text_keccak,
  expected_chain_hashes: [[u32; 8]; 3] }`: the keccak256 of the guest's `.bin` and `.text`, and the
  recursion chain hashes recomputed from the guest and the verifier programs for zero, one, and
  two or more unrolled recursion layers.
- **Verification**: run `verify_unified_circuit_recursion_layer_sec_100` over `proof_words`
  (every word consumed), require output words 8..15 to equal one of `expected_chain_hashes`, and
  output words 0..7 to commit the expected block hash.

The key depends on the guest binary, the verifier programs and the `RECURSION_*_BLAKE` modes
(the prover only accepts the defaults), not on the block.
