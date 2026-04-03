# Z6M Airbender Guest Architecture

## 1. Guest Program Build

### Toolchain
- **Compiler**: `riscv-none-elf-gcc` / `riscv-none-elf-g++` (xPack GCC 15.2.0)
- **ISA**: `rv32im_zicsr` — 32-bit RISC-V with integer multiply/divide and CSR instructions
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
| Heap | after .bss | 768 MB | Bump allocator (`operator new`) |

### Two-Phase Build (`prover/guest_airbender/Makefile`)

**Phase 1 — Zilkworm library build:**
```bash
cmake -B build/zilkworm -S ../.. \
    -DCMAKE_TOOLCHAIN_FILE=cmake/riscv32im.cmake \
    -DAIRBENDER=ON
cmake --build build/zilkworm --target install
```
Cross-compiles the full zilk_core (silkworm fork), evmone, blst, libsecp256k1 for rv32im. Installs headers and static libraries to `build/zilkworm-install/`.

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

**Hook**: In `third_party/evmone/lib/evmone_precompiles/keccak.c`, the `AIRBENDER` preprocessor path defines `syscall_keccak_permute()` which delegates to the `airbender::keccak_f1600_delegate()` CSR function. This is selected via the `keccakf1600_best` function pointer.

**Protocol**: The keccak CSR (0x7CB) uses a delegation model:
1. Copy 25 u64 state words to a 256-byte-aligned buffer (+ 6 scratch words)
2. Set x10=0 (control, auto-bumped by hardware), x11=buffer pointer
3. Execute 649 sequential `csrrw x0, 0x7CB, x0` instructions (loop)
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

Both pointers must be 32-byte aligned and point to RAM (>= 0x200000).

### libsecp256k1 for ecrecover

The EVM `ecrecover` precompile (address 0x01) recovers a public key from an ECDSA signature. The default evmone implementation uses generic Montgomery field arithmetic which is very slow on rv32.

**Hook**: When `AIRBENDER=ON`, `third_party/CMakeLists.txt` fetches libsecp256k1 v0.7.1 (bitcoin-core, BSD-2-Clause) via FetchContent, cross-compiles it for rv32im (no ASM, pure C), and links it into evmone. In `zilk_core/core/crypto/ecdsa.cpp`, the `EVMONE_PRECOMPILES_LIBSECP256K1` path calls `secp256k1_ecdsa_recover()` + keccak256 to produce the address.

This gave a **67% cycle reduction** for ecrecover-heavy blocks.

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

**Single test:**
```bash
prover/prover_airbender/target/release/z6m_prover_airbender execute \
    --is-test \
    --file-name third_party/eest-fixtures/state_tests/istanbul/eip152_blake2/test_blake2b.json
```

**Batch EEST via Makefile:**
```bash
cd prover/prover_airbender
make eest-blake2          # just blake2 tests
make eest-istanbul        # all istanbul fork tests
make eest                 # all state_tests (slow)
make eest TESTS_SUBDIR=cancun  # specific fork
```

**Oracle protocol**: When `--is-test` is used, the Rust prover prepends a u32 dispatch word to the oracle before the byte count. The dispatch value selects the guest code path: `1` = JSON test (`run_json_test()`), `0` = RLP block (`run_unified_rlp()`). The C++ guest reads this first word from CSR 0x7C0 and branches accordingly.

**Available test suites**: Fixtures live under `third_party/eest-fixtures/state_tests/` organized by fork: `frontier`, `istanbul`, `berlin`, `shanghai`, `cancun`, `prague`, and others.

### Example Output
```
Loading guest binary: prover/guest_airbender/build/z6m_guest.bin (3.2 MB)
Loading input: unifiedBlockAndStateRlp24522000.bin (15.8 MB)
UART: `[state_transition] run successful, gas used: 59681801`
Took 2213982219 cycles to finish
Executed block 24522000 (gas_used=59681801, cycles=2213982219, time=14.27s, freq=155M cycles/s, reached_end=true)
```
