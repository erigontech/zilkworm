---
name: zisk-execute
description: Use to build the ZisK guest and execute blocks / EEST fixtures under ziskemu or z6m_prover_zisk
allowed-tools: Bash, Read, Glob
---

# Execute Blocks and EEST Fixtures on the ZisK Guest

## Overview
The ZisK guest (`prover/guest_zisk`, ZisK v1.3.1-alpha) is built with `make z6m_guest_zisk` and runs under `ziskemu`, the ZisK emulator, or under the host prover `z6m_prover_zisk` (`prover/prover_zisk`, zisk-sdk 1.3.1-alpha). The guest commits the same 112-byte public values as the SP1 guest to the ZisK output slots, so `ziskemu -o out.bin` writes them to `out.bin[0:112]` (`out.bin[112:256]` stays zero). `tools/scripts/zisk_execute.py` runs a whole corpus or EEST tree through either one and compares each result byte-for-byte with the native `state_transition` runner's `Public Values: 0x…` line.

## Command Syntax

### Build the guest
```bash
make z6m_guest_zisk [ZISK_GCC_BIN=<xPack bin dir>] [ZISK_BUILD_DIR=prover/guest_zisk/build]
```
The ELF is written to `prover/guest_zisk/build/z6m_guest.elf`.

### Run one block
```bash
$ZISKEMU -e prover/guest_zisk/build/z6m_guest.elf --legacy-inputs <file.mfbd> -o temp/runtime/out.bin -m
xxd -l 112 -c 8 temp/runtime/out.bin
```
`-m` prints `process_rom() steps=<N> duration=… tp=… Msteps/s …` after the guest's UART output. The `xxd` rows are laid out as follows:

| Row | Field |
|---|---|
| 0 | `gas_used`, u64 LE (`ff…ff` = failed, `fe ff…ff` = skipped) |
| 1-4 | `pre_state_root` |
| 5-8 | `post_state_root` |
| 9-12 | `block_hash` |
| 13 | `chain_id`, u64 LE |

The native reference is `build/zilk_core/dev/cli/state_transition <file.mfbd>`, which prints `Public Values: 0x<224 hex>`.

### Compare a corpus or EEST tree with native
```bash
python3 tools/scripts/zisk_execute.py --elf ELF (--input F.mfbd | --dir CORPUS | --eest-dir DIR [--filter REGEX])
    [--native BIN] [--ziskemu "CMD"] [-j 8] [--timeout 900] [--max-steps N] [--log-dir temp/zisk_execute] [--stats] [--legacy-inputs]
    [--prover BIN [--threads N]]
```
For the 200-block corpus there is also `make zisk-emu-check BENCH_CORPUS_DIR=temp/runtime/zisk_corpus ZISKEMU=$ZISKEMU`.

### Host prover (`z6m_prover_zisk`)
```bash
make z6m_prover_zisk        # builds the guest, then prover/prover_zisk/target/release/z6m_prover_zisk
Z=prover/prover_zisk/target/release/z6m_prover_zisk
$Z execute --file-name <file.mfbd> [--is-test] [--save-input temp/runtime/in.bin]
$Z --test-service --data-dir temp/mainnet --start-block <START> --end-block <END> --execution-log-file=temp/mainnet/logs/<feature>_<commit>.log
$Z --test-service --test-dir <mfbd>/blockchain_tests/<subdir>
make zisk-eest [ZISK_EXECUTOR=ziskemu] [ZISK_EEST_FLAGS="--filter for_osaka --max-parallel 4"]
make zisk-benchmark BENCH_CORPUS_DIR=temp/runtime/zisk_corpus [ZISK_EXECUTOR=ziskemu]
```
The CLI matches `z6m_prover` (hypercube): the same global flags, `execute`/`fetch`/`prove`/`verify`/`setup` subcommands and `executionLogs.log` format, so `eest_runner.py --prover $Z` and `sp1_benchmark.py --prover $Z` work unchanged. `execute` prints `Executed|FAILED|SKIPPED block N (… cycles=<steps> …)` and `Public Values: 0x<224 hex>`, and exits 1 on a failed or aborted run. `cycle_count` in the logs is ZisK steps; `prover_gas` is 0 (execute-only has no cost model).

ZisK-only flags (before the subcommand):
- `--executor emulator|assembly|ziskemu` (or `Z6M_ZISK_EXECUTOR`):
  - `emulator` (default) is the zisk-sdk execute-only path: it emulates on 16 threads, then counts and plans, so it costs 20-30x the CPU of ziskemu. Cap it with `RAYON_NUM_THREADS`.
  - `ziskemu` runs the same engine as the `ziskemu` CLI in-process on one thread. Steps and public values are identical, and it sees the halt-with-error flag. It is execute-only.
  - `assembly` needs ziskup's `~/.zisk/zisk/emulator-asm` tree and `ulimit -l unlimited`.
- `--elf PATH`: run this ELF instead of the one embedded at build time.
- `--proving-key DIR`, `--remote URL`: only for `setup`/`prove`/`--prove-every`.

### Proving (needs the proving key)
```bash
ziskup --version 1.3.1-alpha --provingkey      # ~5 GB download into ~/.zisk/provingKey; 25-64 GB RAM
$Z setup                                       # ROM setup + program VK (cached in ~/.zisk/cache)
$Z prove --file-name <file.mfbd> [--proof-type compressed|minimal|plonk] [--proof-path P]
$Z verify --proof-path P
```
Without a key, `setup`/`prove` stop with `ZisK proving key not found at …` before loading anything. `--remote URL` sends setup and prove to a ZisK coordinator instead. `prove` verifies the new proof before saving it (default `<data-dir>/<N>/proof<N>.bin`) and appends to `provingLogs.log`. `verify` binds the proof to this ELF's program VK, so run `setup` once first.

### Profile one block
```bash
$ZISKEMU -e prover/guest_zisk/build/z6m_guest.elf --legacy-inputs <file.mfbd> -X --sdk --opcodes --profile-tags --top-functions -S
```

## Flags (`zisk_execute.py`)

- `--elf`: the ZisK guest ELF (required)
- `--input` / `--dir` / `--eest-dir`: one `.mfbd` file, a corpus of `<N>/flatWitnessBundle<N>.mfbd`, or an EEST tree that is walked for `*.mfbd` (exactly one is required)
- `--filter`: a regex matched against each input's path relative to its root
- `--native`: the native `state_transition` binary. Without it, inputs are only classified by the gas sentinel.
- `--ziskemu`: a command prefix. The default is `$ZISKEMU`, then `temp/runtime/zisk_target/release/ziskemu`, then `ziskemu` on PATH.
- `--timeout`: per-run limit in seconds (default 900)
- `--max-steps`: passed to ziskemu as `-n`. ziskemu's default is 2^36−1 (about 68.7 G steps); a run that hits it ends in `EmulationNoCompleted` (rc 1, ERROR).
- `--stats`: passes `-X` and puts the stats report in each `.log`
- `--legacy-inputs`: hands the raw file to ziskemu (`--legacy-inputs F`). By default the script frames the file itself (`[u64 LE len][raw][pad to 8]`) and passes `-i`.
- `--prover`: runs each input as `BIN --elf ELF execute --file-name F` instead of ziskemu, and reads `Public Values:` and `cycles=` from its output. `--ziskemu`, `--max-steps`, `--stats` and `--legacy-inputs` do not apply. Set `Z6M_ZISK_EXECUTOR` to pick the host executor.
- `--threads`: with `--prover`, sets `RAYON_NUM_THREADS` for each host process. Keep `-j × --threads` within the cores you can use (for example `-j 2 --threads 7`).

## Results

| Status | Meaning |
|---|---|
| PASS / FAIL / SKIP | Classified by the gas sentinel, and in agreement with native |
| MISMATCH | The 112 bytes or the class differ from native. The reason names the differing fields. |
| ERROR | ziskemu rc ≠ 0, a timeout, a halt with error, a missing, all-zero or non-zero-tail `.out`, or no native `Public Values:` line |

The output directory (`--log-dir`) holds:
- `results.tsv` (`file status gas steps pv_hex native_pv_hex`), which is the steps baseline;
- `summary.log`;
- `<name>.out`, `<name>.log` (the ziskemu command and output) and `<name>.native.log` for each input.

The last stdout line is `Total: X, Passed: Y, Failed: Z, Skipped: W, Mismatch: M, Error: E`. The script exits 1 if M + E > 0.

## Important Considerations

### Before Running
1. **ziskemu v1.3.1-alpha**: set `ZISKEMU` to a local build (`cargo build --release -p ziskemu` in a v1.3.1-alpha checkout), or install it with `cargo install --locked --git https://github.com/0xPolygonHermez/zisk --tag v1.3.1-alpha ziskemu`. Either way it needs `libgmp-dev nlohmann-json3-dev nasm libsodium-dev libomp-dev libopenmpi-dev`.
2. **Guest ELF**: `make z6m_guest_zisk`.
3. **Native runner**: `cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S . && cmake --build build --target state_transition`.
4. **Fresh MFBD inputs**: `load_flat_bundle: bad version` means the corpus is stale. Regenerate it with `make sp1-benchmark-corpus BENCH_SRC_DIR=<raw blocks dir> BENCH_CORPUS_DIR=temp/runtime/zisk_corpus`.

### Notes
- Never use `/tmp`. Run `export TMPDIR=$PWD/temp/runtime/tmp` first. `zisk_execute.py` sets `TMPDIR=<log-dir>/tmp` for its child processes.
- **memlock.** `ziskemu` is the Rust emulator. It does not lock memory and has **no `-u` flag** (it rejects `-u`). Only the ASM emulator needs `-u/--unlock-mapped-memory` or `ulimit -l unlimited`; that means `cargo-zisk execute -a`, or the SDK's `.assembly()` in `z6m_prover_zisk`.
- **Docker fallback:** `--ziskemu "docker run --rm -v $PWD:$PWD -w $PWD z6m-ziskemu:v1.3.1 ziskemu"`. Inputs are framed into `--log-dir`, so only the ELF and the log dir have to be under `$PWD`. A timeout kills the docker client but not the container.
- **Failure semantics:**
  - A failed block is still a provable run with `gas_used = 0xFFFF_FFFF_FFFF_FFFF`. Classify it by the sentinel, never by `gas == 0`.
  - Unrecoverable states (OOM, `fatal()`, traps) end in the ZisK halt-with-error word. ziskemu still exits 0, but prints `Emu::run_fast() finished with error at step=N pc=0x…` on stderr, and the run cannot be proven. `zisk_execute.py` reports this as ERROR.
  - SP1 handles this differently: it commits partial public values with exit code 1.
- **Run time:** a 200-block corpus or the 8615-file EEST tree takes a long time, so run it in the background (`run_in_background: true`).
- **Host prover quirks** (zisk-sdk 1.3.1-alpha):
  - The SDK emulator runs the guest on 16 threads, so guest UART lines appear up to 16 times on stdout.
  - On a halted-with-error run (OOM, `fatal()`) the SDK's count phase panics. The host catches the panic, reports the run as FAILED / `execution failed`, rebuilds its executor and continues. `--executor ziskemu` reports the same run as `FAILED … (guest aborted …)` instead.
  - `TMPDIR` matters for the SDK as well: keep it on disk.

## Workflow

When the user wants to run blocks or EEST fixtures on the ZisK guest:

1. **Confirm parameters**
    - Ask what to run (one block, a corpus dir, or an EEST tree) if it is not already known from context
2. **Check prerequisites**
    - `ZISKEMU` (or `z6m_prover_zisk` for `--prover`), the guest ELF and the native runner exist; build whatever is missing
3. **Run command**
4. **Report**
    - Give the summary line, every MISMATCH/ERROR with its reason, and the `results.tsv` path

## Examples

### Example 1: One Block, Then Compare With Native
```bash
$ZISKEMU -e prover/guest_zisk/build/z6m_guest.elf --legacy-inputs temp/runtime/zisk_corpus/24491136/flatWitnessBundle24491136.mfbd -o temp/runtime/out.bin -m
xxd -l 112 -c 8 temp/runtime/out.bin
build/zilk_core/dev/cli/state_transition temp/runtime/zisk_corpus/24491136/flatWitnessBundle24491136.mfbd
```

### Example 2: 200-Block Corpus vs Native
```bash
python3 tools/scripts/zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf --dir temp/runtime/zisk_corpus --native build/zilk_core/dev/cli/state_transition --log-dir temp/runtime/zisk_corpus_check
```

### Example 3: 200-Block Corpus Through the Host Prover vs Native
```bash
python3 tools/scripts/zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf --dir temp/runtime/zisk_corpus --native build/zilk_core/dev/cli/state_transition --prover prover/prover_zisk/target/release/z6m_prover_zisk -j 2 --threads 7 --log-dir temp/runtime/zisk_corpus_host
```

### Example 4: EEST Fixtures vs Native
```bash
python3 tools/scripts/zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf --eest-dir test-fixtures-cache/mfbd-<sha>/blockchain_tests --native build/zilk_core/dev/cli/state_transition -j 16 --log-dir temp/runtime/zisk_eest
```

## Tips

- Use `--filter` to rerun only the failing inputs, for example `--filter '^24498847/'` or `--filter 'call1024'`.
- Heavy EEST BLS12-381 MSM fixtures (software BLS; `bls12_g2msm/valid` takes about 85 G steps) need `--max-steps 1099511627775 --timeout 7200`.
- For a GCC A/B check, build each ELF into its own `ZISK_BUILD_DIR` and run the same corpus against both into separate `--log-dir`s. The `pv_hex` columns must be identical.
