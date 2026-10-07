<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# ZisK Backend: Status and GPU Proving Guide

Zilkworm runs on [ZisK](https://github.com/0xPolygonHermez/zisk) **v1.3.1-alpha** as a second zkVM
next to SP1 Hypercube. The guest, the accelerators, the host prover and CI are in place, the whole
stack is validated in **execute-only** mode, and the 200-block corpus has been **proven and verified
on one GPU** (compressed proofs, §5.1). The `minimal` and `plonk` proof types, the `assembly`
executor, `--remote` and the CI image are still untested.

This guide covers setting up a fresh Linux machine with an NVIDIA GPU, checking that execution
reproduces the reference results, and running the proofs.

## 1. Status

| | |
|---|---|
| zilkworm branch | `som/zisk-impl` on `erigontech/zilkworm` |
| evmone branch | `som/zisk-impl` on `erigontech/zvm1` (submodule `third_party/evmone` @ `6f35e0a0`, 9 commits on top of `oss` @ `b10a25a4`) |
| ZisK pin | v1.3.1-alpha (`306a9c934`): guest linker script, `ziskemu`, `zisk-sdk` crates, proving key |
| Guest compiler | xPack `riscv-none-elf-gcc` 14.2.0-3.1 (what the Makefile picks, see §3.2) |

| Commit | Content |
|---|---|
| `8c9ef3367` | `ZISK` build seams, native `Public Values:` line |
| `ad9a724ab` | guest, `zisk_execute.py`, skill |
| `1e0b27001` | mem ops through DMA precompiles |
| `d7c3b4819` | precompile shims, keccak |
| `19e3e028d` | sha256, ADDMOD/MULMOD, modexp, secp256k1, bn254 |
| `1ad2de5df` | BLS12-381/KZG, blake2f, p256verify |
| `93bcdac28` | host prover, Make targets, CI, skill update |

### Done

- **Guest** (`prover/guest_zisk`): freestanding C++ guest (own `_start`, newlib, vendored ZisK
  linker script). It commits the same 112-byte public values as the SP1 guest to ZisK output slots
  0–27 (see [architecture.md](architecture.md)).
- **Host** (`prover/prover_zisk`): `z6m_prover_zisk` on `zisk-sdk` 1.3.1-alpha. It has the same CLI
  and log formats as `z6m_prover` (`setup`, `fetch`, `execute`, `prove`, `verify`, `--test-service`,
  `--service`), plus `--executor emulator|assembly|ziskemu`, `--elf`, `--proving-key` and `--remote`.
- **Tooling and CI**: Make targets, `tools/scripts/zisk_execute.py`, `--prover` support in
  `eest_runner.py` and `sp1_benchmark.py`, the CI image and two execute-only workflows (§6).
- **Accelerators**: raw CSR precompiles. Every free-input (fcall) hint is verified in the guest,
  which halts with error on a bad hint.

| Area | ZisK precompiles |
|---|---|
| keccak-f | `0x800` |
| sha256 | `0x805` |
| ADDMOD / MULMOD, modexp with operands ≤ 32 B | `arith256_mod` `0x802` |
| ecrecover (secp256k1) | `0x802`, `0x803`/`0x804`, fcall 3 (sqrt), fcall 2 (inverse) |
| bn254 ecadd / ecmul / ecpairing | `0x802`, `0x806`/`0x807`, `0x808`–`0x80A` |
| BLS12-381 (EIP-2537) and KZG point evaluation (patched blst) | `0x80B`, `0x80E`–`0x810`, fcall 10 (inverse) |
| blake2f | `0x819` |
| p256verify | `0x802`, `0x817`/`0x818`, fcall 5 (inverse) |
| memcpy / memmove / memset / memcmp | DMA `0x813` / `0x814` / `0x816` |

Still in software: ripemd160 (no ZisK precompile), identity, modexp with operands > 32 B, the
MUL/EXP/DIV/MOD opcodes, and blst's 256-bit Fr arithmetic and curve formulas.

### Validated (execute-only, ZisK guest sha256 `4fa5aa2bc92c9ebaad1110976ddfa4b0a05b2945e4197bdf1a8cbf1328d638da`)

- **200-block mainnet corpus**: 200/200 public values byte-identical to native `state_transition`.
  The `ziskemu` CLI, the host's SDK emulator and the host's `--executor ziskemu` all agree, with
  identical step counts.
- **EEST** (`eest_stable`, tests@v20.0.1, 8615 fixtures): 8613/8615 pass with public values equal to
  native. The 2 failures are platform OOMs, not guest bugs:
  `for_cancun/…/static_call1_mb1024_calldepth` and `for_prague/…/static_call1_mb1024_calldepth`
  (`ported_static/stStaticCall`). They need about 575 MB natively, which is more than ZisK's fixed
  512 MiB of RAM. The guest halts with error, which cannot be proven and never yields a wrong output.
- **Precompile suites** (all pass): sha256 89, modexp 110, addmod 6, mulmod 6, ecrecover 179,
  ecadd 20, ecmul 20, ecpairing 110, bls12 106, KZG 20, blake2 41, p256verify 15.
- **Adversarial tests**:
  - the standalone curve test passes 105/105 (P == ±Q, identity, the Q == −P MSM regression);
  - the standalone blst test passes 79/79;
  - every forged fcall hint (secp256k1 sqrt and inverse, BLS Fp inverse, P-256 inverse) halts with
    error, both in the standalone tests and in the real guest.
- **SP1 unaffected**: the SP1 guest ELF is byte-identical on every commit, and all three legs pass (§9).
- **GPU proving** (2026-10-08, one RTX 5090): 200/200 corpus blocks proved with the default
  `compressed` proof type and verified; every proof's step count equals the `ziskemu` run. Numbers in §5.1.

Latest step totals (`ziskemu`, raw; the corpus row is after the intx bump in `e97f0823`):

| Set | total | min | median | max |
|---|---|---|---|---|
| Corpus, 200 blocks | 21688407462 | 4477139 | 105580700 | 234814444 |
| EEST, 8613 passing fixtures | 51978949913 | 66624 | 366517 | 1711581893 |

### Not done

- `--proof-type minimal` and `plonk`; multi-GPU / `mpirun`.
- The `assembly` executor, `--remote` with a coordinator, and `--service` against a live RPC.
- The CI image `zilkworm-ci-zisk` has not been built, so no ZisK workflow has run yet.

## 2. Layout

| Path | What it is |
|---|---|
| `prover/guest_zisk/` | Guest: CMake build, toolchain file `cmake/riscv64im-zisk.cmake`, vendored `zisk.ld`, `src/` runtime and DMA stubs (`src/dma/*.s`) |
| `prover/guest_zisk/tools/zisk_postlink.py` | Post-link step: `ebreak` rewrite plus ISA, layout and memory-map checks (§7) |
| `prover/guest_zisk/src/include/zisk_precompiles.hpp` | Shim header: CSR precompile and fcall wrappers with hint verification, included by evmone |
| `prover/guest_zisk/src/include/zisk_syscalls.hpp` | Memory map, UART print, halt |
| `prover/prover_zisk/` | Host `z6m_prover_zisk`: a standalone crate with its own `Cargo.lock` and `target/` |
| `third_party/evmone/cmake/patch_blst_zisk.sh` | blst patch for BLS12-381 Fp/Fp2 and the inverse (lives in the evmone submodule) |
| `tools/scripts/zisk_execute.py` | Runs ziskemu or the host over a file, corpus or EEST tree and compares with native |
| `tools/scripts/eest_runner.py`, `tools/scripts/sp1_benchmark.py` | Take `--prover prover/prover_zisk/target/release/z6m_prover_zisk` |
| `.claude/skills/zisk-execute/SKILL.md` | Skill with the execute and profiling recipes |
| `.github/docker/zisk-ci.Dockerfile`, `.github/workflows/ci-image.yml` | CI image `ghcr.io/erigontech/zilkworm-ci-zisk` (job `build-and-push-zisk`) |
| `.github/workflows/zisk-eest.yml`, `.github/workflows/zisk-benchmark.yml` | Execute-only CI (§6) |

Make targets: `z6m_guest_zisk`, `zisk-emu-check`, `z6m_prover_zisk`, `zisk-eest` and `zisk-benchmark`.

## 3. GPU Machine Setup

Every command below runs from the repository root unless it says otherwise. The reference
environment is Ubuntu 25.10, the same as the CI image (`.github/docker/ci.Dockerfile`). ZisK itself
requires Ubuntu 22.04 or newer. The native build needs CMake ≥ 3.28 and a C++23 compiler at
`/usr/bin/g++` (validated with GCC 15.2). Older compilers are unverified.

The ziskup, GPU-build and proving commands (§3.6, §3.7, §5) were run once, on the machine in §5.1
(Ubuntu 25.10, no sudo). The CI-image commands (§6) have never been run; treat them as unverified.

### 3.1 Clone

```sh
git clone https://github.com/erigontech/zilkworm.git && cd zilkworm
git checkout som/zisk-impl
git submodule update --init --recursive
git submodule status --recursive   # evmone 6f35e0a0…, intx 0306b495… (v0.15.0); no '+' or '-'
```

The evmone pin exists only on `erigontech/zvm1` branch `som/zisk-impl`, not yet on `oss`.
`.gitmodules` already points at zvm1, so the plain update works. If the update fails with
`not our ref`, a local `submodule.evmone.url` override is pointing somewhere else. Fix it with
`git -C third_party/evmone fetch https://github.com/erigontech/zvm1.git som/zisk-impl` and run
the update again.

### 3.2 Packages and toolchains

```sh
# Repo build deps (cf. ci.Dockerfile) plus the full ZisK list from its install guide
sudo apt-get install -y build-essential cmake ninja-build git git-lfs python3 curl nodejs npm \
  pkg-config libssl-dev protobuf-compiler libprotobuf-dev time \
  xz-utils jq qemu-system libomp-dev libgmp-dev nlohmann-json3-dev uuid-dev libgrpc++-dev \
  libsecp256k1-dev libsodium-dev libpqxx-dev nasm libopenmpi-dev openmpi-bin openmpi-common \
  libclang-dev clang gcc-riscv64-unknown-elf

# Rust; prover/ and prover/prover_zisk/ pin 1.93.1 in rust-toolchain.toml
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Guest cross-compiler: xPack riscv-none-elf-gcc 14.2.0-3.1
sudo npm install --global xpm@latest
xpm install @xpack-dev-tools/riscv-none-elf-gcc@14.2.0-3.1 --global --verbose
ls ~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/   # 14.2.0-3.1
```

The Makefile prepends the **first** directory under `~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/`
to `PATH`. With 14.2.0-3.1 installed it wins even next to 15.2.0-1.1, and the reference hashes
(the ZisK ELF above and the SP1 ELF in §9) were produced with it. Installing 15.2.0-1.1 as well is
optional; use it for the GCC A/B through `ZISK_GCC_BIN` (§8).

The ZisK subset strictly needed to build the host is `libgmp-dev nlohmann-json3-dev nasm
libsodium-dev libomp-dev libopenmpi-dev clang libclang-dev`, as in `.github/docker/zisk-ci.Dockerfile`.
The host link line also needs `libiomp5.so` (from `libomp-dev`), `libcrypto.so` (`libssl-dev`) and
`libmpi.so` (`libopenmpi-dev`, searched in `/usr/lib/x86_64-linux-gnu/openmpi/lib`).

**Without sudo.** The §5.1 run was done on a box where none of this could be installed. The same
packages were fetched with `apt-get download …` (plus the runtime libs `libgmp10 libsodium23
libopenmpi40 libhwloc15 libpmix2t64 libevent-core-2.1-7t64 libevent-pthreads-2.1-7t64 libnuma1`),
unpacked with `dpkg -x <deb> <prefix>`, and used through `CPATH`, `LIBRARY_PATH`,
`LD_LIBRARY_PATH` (both `<prefix>/usr/lib/x86_64-linux-gnu` and `…/openmpi/lib`) and `PATH`
(`<prefix>/usr/bin` for `nasm`; symlink `mpicc -> mpicc.openmpi` and `libiomp5.so -> libomp.so.5`
by hand). Set `OPAL_PREFIX=<prefix>/usr` so the `mpicc` wrapper finds its data files.

### 3.3 NVIDIA driver and CUDA

- **Driver:** 525.60.13 or newer. This is the version ziskup checks before it auto-selects GPU binaries.
- **CUDA Toolkit:** 12.9 or newer, which ZisK requires to build the `zisk-sdk` crate with GPU support.
- **Install location:** the proofman build script looks for `/usr/local/cuda/bin/nvcc` (or `nvcc` on
  `PATH`) and links `/usr/local/cuda/lib64`, so install CUDA there.

```sh
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv
nvcc --version
```

### 3.4 Locked memory

ZisK expects an unlimited memlock. The ASM emulator locks its shared-memory mappings under `/dev/shm`.

```sh
ulimit -l   # must print: unlimited
```

If it does not, follow the ZisK install guide: add `DefaultLimitMEMLOCK=infinity` to
`/etc/systemd/system.conf` and reboot. For SSH logins, also add these lines to
`/etc/security/limits.conf` and log in again:

```
*  soft  memlock  unlimited
*  hard  memlock  unlimited
```

The default `emulator` executor and the GPU prover do not need it: the §5.1 run was done with a
hard limit of 8192 kB. Only the `assembly` executor locks memory.

### 3.5 Disk, RAM, TMPDIR

| Item | Size |
|---|---|
| Proving key `zisk-provingkey-1.3.1-alpha.tar.gz` | 5.1 GB download; larger once extracted and after constant-tree generation (not measured) |
| PLONK key (optional, `ziskup setup_snark`) | 21.9 GB download, about 50 GB on disk (ZisK docs) |
| RAM | ~25 GB per prover process (ZisK docs). The ASM emulator reserves a 32 GB trace mapping and needs ≥ 64 GB physical RAM; the Rust emulator needs ≥ 32 GB. |
| VRAM | Not documented upstream; record it (§5) |
| Inputs | 1.1 GB benchmark tarball, 423 MB EEST tarball, plus the converted fixtures |

Keep temporary files on disk. `/tmp` is often tmpfs, and both ziskup (`mktemp -d`) and the SDK write
temporary files there.

```sh
export TMPDIR=$PWD/temp/runtime/tmp && mkdir -p "$TMPDIR"   # temp/ is gitignored
```

### 3.6 ZisK v1.3.1-alpha via ziskup

The upstream one-liner (`install.sh`) always fetches `ziskup` from ZisK's `main` branch. To pin the
installer as well, fetch the tagged script into the place `install.sh` would put it:

```sh
mkdir -p ~/.zisk/bin
curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/v1.3.1-alpha/ziskup/ziskup -o ~/.zisk/bin/ziskup
chmod +x ~/.zisk/bin/ziskup

cd temp/runtime                      # the proving-key tarball is downloaded into the current dir
~/.zisk/bin/ziskup --version 1.3.1-alpha --gpu --provingkey
cd - && source ~/.bashrc             # ziskup appends ~/.zisk/bin to PATH
```

What ziskup does:

1. Installs the v1.3.1-alpha binary bundle (`cargo-zisk`, `cargo-zisk-dev`, `ziskemu`, the
   `emulator-asm` sources, …) into `~/.zisk`. `--gpu` keeps the GPU builds.
2. Installs the `zisk` rustup toolchain.
3. Downloads and md5-checks `zisk-provingkey-1.3.1-alpha.tar.gz`, and extracts it to
   `~/.zisk/provingKey`. This first deletes `~/.zisk/{provingKey,verifyKey,cache}`.
4. Generates the constant trees with `cargo-zisk-dev check-setup --proving-key ~/.zisk/provingKey -a --gpu`.
   This step is slow.

Always pass `--version`. Without it ziskup installs the latest release, whose key and binaries no
longer match the `zisk-sdk =1.3.1-alpha` that the host links.

Two things went wrong on Ubuntu 25.10:

- The prebuilt binaries are linked against `libpsm2.so.2`, `libfabric.so.1` and UCX
  (`libucp/libucs/libucm/libuct.so.0`), which are not installed by default. ziskup then dies at
  `cargo-zisk toolchain install` right after extracting the bundle. Install `libpsm2-2 libfabric1
  libucx0` (or unpack them as in §3.2) before running ziskup. `UCX_VFS_ENABLE=n` silences UCX's
  `inotify_add_watch … No space left on device` warning on every start.
- ziskup runs `check-setup … -a`, and in v1.3.1-alpha `-a` means **`--no-aggregation`**, so the
  recursive setups are not checked. Run it yourself once the key is in place:
  `cargo-zisk-dev check-setup --proving-key ~/.zisk/provingKey --gpu` (55 s on the §5.1 machine;
  the key grows from 15 GB to 21 GB).

If ziskup dies before the key step, finish by hand: download
`https://storage.googleapis.com/zisk-setup/zisk-provingkey-1.3.1-alpha.tar.gz` and its `.md5`
(5.1 GB), `md5sum -c`, then `tar --no-same-owner -xf … -C ~/.zisk` (about a minute), and run
`check-setup` as above. The ZisK Rust toolchain that ziskup installs is only needed for Rust
guests; the C++ guest does not use it.

Check the result:

```sh
cargo-zisk --version                            # 1.3.1-alpha [gpu] (…)
ziskemu --version                               # ziskemu 1.3.1-alpha (306a9c9 …)
cat ~/.zisk/.zisk-bundle                        # version=1.3.1-alpha, variant=gpu
ls ~/.zisk/provingKey/pilout.globalInfo.json    # the file z6m_prover_zisk checks for
```

Optional: run `ziskup setup_snark` for `--proof-type plonk`. It installs `~/.zisk/provingKeySnark`.

You do not need to build ZisK from source: the bundle's `ziskemu` and GPU `cargo-zisk` are enough.
If you do build it, ZisK's guide describes `cargo build --release` in a v1.3.1-alpha checkout. That
build auto-detects CUDA, and `CUDA_ARCHS` pins the GPU architectures. See §7 for the libffi pitfall.

### 3.7 Host prover with GPU support

`make z6m_prover_zisk` builds the default **CPU-only** host (crate feature `cpu-only`). For GPU,
build the guest first, then the host with the `gpu` feature. With that feature the host calls
`.gpu()` on the SDK client.

```sh
make z6m_guest_zisk
(cd prover/prover_zisk && CUDA_ARCHS=120 cargo build --release --no-default-features --features gpu)
# CUDA_ARCHS: optional, defaults to the local GPU (89 = Ada, 90 = Hopper, 120 = RTX 50xx)
```

Verified with CUDA 13.2, g++ 15.2 as the nvcc host compiler and `CUDA_ARCHS=120` (about 3 minutes
for `pil2-stark`, 55 s for the Rust side). Cargo hides build-script output of registry crates, so
the `[BUILD INFO] STARKS compiled with GPU support` line is not on the terminal; read it from
`prover/prover_zisk/target/release/build/proofman-starks-lib-c-*/output`, and check that
`~/.cargo/registry/src/*/proofman-starks-src-1.3.1-alpha/.cuda_arch_stamp` names your arch
(`pil2-stark` is built in place inside the registry checkout). If the output says
`CPU-only support (CUDA not detected)`, cargo did not find `nvcc`. Both builds write the same
`prover/prover_zisk/target/release/z6m_prover_zisk`, and running `make z6m_prover_zisk` again
replaces the GPU binary with the CPU one.

## 4. Build and Execute Sanity

Reproduce the reference results before proving.

```sh
export TMPDIR=$PWD/temp/runtime/tmp && mkdir -p "$TMPDIR"

# Inputs: the 200-block corpus (raw RLP -> MFBD) and the EEST fixtures
curl -L -o temp/200_benchmark_blocks.tar.gz \
  https://github.com/erigontech/zilkworm-testdata/releases/download/benchmark-200-spread/200_benchmark_blocks.tar.gz
tar xzf temp/200_benchmark_blocks.tar.gz -C temp && rm temp/200_benchmark_blocks.tar.gz
make sp1-benchmark-corpus   # -> temp/200_benchmark_blocks_mfbd_v2/<N>/flatWitnessBundle<N>.mfbd
make eest-mfbd-build        # -> test-fixtures-cache/mfbd-3586193db06d/blockchain_tests (8615 .mfbd)

# Guest and native reference
make z6m_guest_zisk         # postlink prints "ebreak->halt: 16" and the heap range
sha256sum prover/guest_zisk/build/z6m_guest.elf   # 4fa5aa2bc92c9ebaad1110976ddfa4b0a05b2945e4197bdf1a8cbf1328d638da
cmake -DCMAKE_BUILD_TYPE=Release -B build -G Ninja -S . && cmake --build build --target state_transition
```

A different compiler gives a different ELF hash and different step counts. The public values must
still match native.

Three blocks under `ziskemu` (smallest, first, heaviest):

```sh
python3 tools/scripts/zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf \
  --dir temp/200_benchmark_blocks_mfbd_v2 --filter '^(24545295|24491136|24521911)/' \
  --native build/zilk_core/dev/cli/state_transition --ziskemu ziskemu -j 3 --log-dir temp/runtime/zisk_sanity
```

Expect `Total: 3, Passed: 3, … Mismatch: 0, Error: 0`. The steps in
`temp/runtime/zisk_sanity/results.tsv` should be 4477295, 163598878 and 234804852.

Full runs:

```sh
make zisk-emu-check                       # 200 blocks, ziskemu from PATH: 200/200 PASS
python3 tools/scripts/zisk_execute.py --elf prover/guest_zisk/build/z6m_guest.elf \
  --eest-dir test-fixtures-cache/mfbd-3586193db06d/blockchain_tests \
  --native build/zilk_core/dev/cli/state_transition --ziskemu ziskemu -j "$(nproc)" --log-dir temp/runtime/zisk_eest
# expect Passed: 8613, Error: 2 (the two static_call1_mb1024_calldepth OOMs; the script exits 1)
```

Host prover (CPU or GPU build, execute needs no key):

```sh
P=prover/prover_zisk/target/release/z6m_prover_zisk
$P --executor ziskemu execute --file-name temp/200_benchmark_blocks_mfbd_v2/24545295/flatWitnessBundle24545295.mfbd
# "Executed block 0 (gas_used=1056239, cycles=4477295, …)" and a "Public Values: 0x…" line
# (with --file-name, execute prints the block number as 0)
make zisk-eest ZISK_EXECUTOR=ziskemu      # EEST via eest_runner.py; skips fixtures > 20 MB like the SP1 runner
make zisk-benchmark ZISK_EXECUTOR=ziskemu # 200 blocks via sp1_benchmark.py
```

The full-tree `make zisk-eest` has not been run yet. A 200-fixture sample gave 198/200, and the 2
failures were the OOM fixtures.

## 5. Proving

`prove` runs setup itself, verifies the new proof before saving it, and appends a line to
`<data-dir>/provingLogs.log` (default `temp/provingLogs.log`). `verify` needs the program VK from
the setup cache (`~/.zisk/cache`), so run `setup` once per ELF. Each `prove` process loads the
proving key again (about 20 s and 21 GB of RSS before the first proof), so prove a corpus with the
offline loop in §5.1 rather than one process per block.

```sh
export TMPDIR=$PWD/temp/runtime/tmp RUST_LOG=info   # info shows "ZisK setup done in …s"
P=prover/prover_zisk/target/release/z6m_prover_zisk
mkdir -p temp/proofs

$P setup                                             # ROM setup + program VK

# 1. Tiny EEST fixture (352240 steps)
F=test-fixtures-cache/mfbd-3586193db06d/blockchain_tests/for_osaka/ported_static/stExample/add11/add11.mfbd
/usr/bin/time -v $P prove --file-name $F --proof-path temp/proofs/add11.bin 2>&1 | tee temp/proofs/add11.log
$P verify --proof-path temp/proofs/add11.bin

# 2. Mainnet blocks, smallest to heaviest: 24545295 (4.5M steps), 24491136 (164M), 24521911 (235M)
for N in 24545295 24491136 24521911; do
  /usr/bin/time -v $P prove --file-name temp/200_benchmark_blocks_mfbd_v2/$N/flatWitnessBundle$N.mfbd \
    --proof-path temp/proofs/$N.bin 2>&1 | tee temp/proofs/$N.log
  $P verify --proof-path temp/proofs/$N.bin
done
```

### 5.1 First GPU run: 200-block corpus (2026-10-08)

Machine: 1× NVIDIA GeForce RTX 5090 (32607 MiB), driver 595.71.05, CUDA 13.2, AMD Ryzen 9 7945HX
(32 threads), 103 GB RAM, Ubuntu 25.10, memlock 8192 kB; `cargo-zisk 1.3.1-alpha [gpu]`; guest
ELF `c2c1490f…` (xPack GCC 14.2.0-3.1, tree `e97f0823` + this commit); host built as in §3.7.

The offline loop proves every bundle under `<data-dir>/blocks/<N>/` in one process:

```sh
mkdir -p temp/zisk_gpu_run && ln -sfn ../200_benchmark_blocks_mfbd_v2 temp/zisk_gpu_run/blocks
RUST_LOG=info /usr/bin/time -v $P --test-service --data-dir temp/zisk_gpu_run \
  --start-block 24491136 --end-block 24640322 --prove-every 1
# proofs: temp/zisk_gpu_run/<N>/proof<N>.bin; log: temp/zisk_gpu_run/provingLogs.log
for f in temp/zisk_gpu_run/*/proof*.bin; do $P verify --proof-path $f; done
```

Blocks missing from the range are skipped; a failed proof is logged (`FAILED to prove block N`)
and the loop goes on. Result, default `compressed` proofs:

| | |
|---|---|
| Proved / verified | 200 / 200, 0 failures; steps identical to `ziskemu` on all 200 |
| Total steps, gas | 21,688,407,462 steps; 6,036,444,409 gas |
| Proving time (`proving_ms`, excludes verify) | 6524 s total; min 8.4 s, median 31.5 s, max 75.4 s (block 24498438, 218 M steps) |
| Throughput | 3.32 M steps/s, 0.93 M gas/s, 32.6 s per block |
| Wall clock (200 blocks, one process) | 1 h 49 min 33 s; 520 % CPU |
| Setup | ROM setup 1.6 s; key load about 20 s |
| Peak RSS / VRAM | 32.2 GB / 31.6 GB of 32.6 GB (mean 29.9 GB, GPU utilisation 82 %) |
| Proof size | 415,300 bytes each (415,298 on one block) |
| `verify` | 0.3 s per proof (200 in 49 s) |

The smallest block alone (24545295, 4.48 M steps) takes 8.8 s of proving and 30.5 s wall in a
fresh `prove` process. VRAM sits at the card's limit on every block (the prover sizes its stream
pool to the card), so an input much heavier than the corpus may need `max_streams` or
`minimal_memory` (`zisk_sdk::EmbeddedOpts`), neither of which the host exposes yet.

Variants, in this order (not run yet):
- `--proof-type minimal` (smaller proof, slower) and `--proof-type plonk` (needs `ziskup setup_snark`).
  The default is `compressed`, which is VadcopFinal.
- `--executor assembly`, a global flag placed before the subcommand. It uses ziskup's
  `~/.zisk/zisk/emulator-asm` and needs ≥ 64 GB RAM. The host passes `unlock_mapped_memory` for it.
  Untested.
- `--remote URL`, which proves on a ZisK coordinator. Untested.

Cross-check with the stock CLI on the same input. `--save-input` writes the framed stdin, which
`cargo-zisk` and `ziskemu -i` both read:

```sh
$P --executor ziskemu execute --file-name $F --save-input temp/proofs/add11.in
cargo-zisk prove -e prover/guest_zisk/build/z6m_guest.elf -i temp/proofs/add11.in -o temp/proofs/add11.cli.bin -y -g
cargo-zisk verify -p temp/proofs/add11.cli.bin
```

`-g` (GPU) exists only in the GPU build of `cargo-zisk`.

**What to record** for each input:

| Field | Source |
|---|---|
| steps | `cycles=` in the `Proved block …` line |
| proving time | `proving_ms=` in the same line, plus wall time from `time -v` |
| setup time | `ZisK setup done in …s` (`RUST_LOG=info`) |
| peak RAM | `Maximum resident set size` from `time -v` |
| peak VRAM | `nvidia-smi --query-gpu=memory.used --format=csv,noheader -l 1` running alongside |
| proof size | `ls -l temp/proofs/*.bin`, per `--proof-type` |
| machine | GPU model, driver, CUDA version, CPU, RAM, `cargo-zisk --version` |

**Expected failure modes:**

| Symptom | Cause and fix |
|---|---|
| `ZisK proving key not found at …/provingKey` | The host checks for `pilout.globalInfo.json` before it loads the SDK. Install the key (§3.6) or pass `--proving-key DIR`. `execute` and `--test-service` need no key. |
| Errors about the setup or key version | ZisK v1.3.1 checks setup artifacts against the installed key version. Reinstall with `ziskup --version 1.3.1-alpha --provingkey`. |
| Failures locking or mapping memory, mostly with `assembly` | `ulimit -l` is not unlimited (§3.4). |
| `program VK unavailable (…); run z6m_prover_zisk setup` | `verify` ran before `setup` for this ELF. |
| `EmulationNoCompleted` / `did not finish within N steps` | The default step cap is 2^36−1 (about 68.7 G). The heaviest input today is 1.71 G steps, so this should not trigger. For `zisk_execute.py`, raise the cap with `--max-steps N`, which is passed as `ziskemu -n`. |
| Panic or `FAILED` on a guest abort (OOM, bad hint, `fatal()`) | On execute, zisk-sdk's count phase panics and poisons its client. The host catches the panic, reports `FAILED`/`execution failed`, rebuilds the client and continues. `--executor ziskemu` reports `guest aborted` instead. The prove path does not catch this (unverified), so never prove the 2 OOM fixtures. |
| `--executor ziskemu` with `prove` exits 1 | That executor is execute-only. Prove with `emulator` (the default) or `assembly`. |

The guest's input copy may read up to 7 bytes past the payload, inside the zero padding of the last
u64 of the `[u64 len][payload][pad8]` record. This is harmless. The Rust emulator loads the whole
record, and the ASM emulator rounds the input-ready address down to a u64 and waits for that whole
word (`wait_for_input_ready`).

## 6. CI

1. **Build the image.** `ci-image.yml` exists on `master` with `workflow_dispatch`, so it can run
   from this branch's version:

   ```sh
   gh workflow run ci-image.yml --repo erigontech/zilkworm --ref som/zisk-impl
   ```

   - Job `build-and-push` rebuilds `ghcr.io/erigontech/zilkworm-ci:latest` from `ci.Dockerfile`,
     which is unchanged from `master`.
   - Job `build-and-push-zisk` then builds `ghcr.io/erigontech/zilkworm-ci-zisk:latest` from
     `zisk-ci.Dockerfile`: the base image plus the ZisK apt deps, Rust 1.93.1 and
     `cargo install --git … --tag v1.3.1-alpha ziskemu`.
   - This image has never been built. If the ZisK workflows later cannot pull it, check the
     package's Actions access settings on GHCR (unverified).
2. **Run the ZisK workflows.** They trigger on push and pull requests to `master`, `main` and
   `release/*` (path-filtered), and on `workflow_dispatch` once they exist on the default branch.
   The simplest first run is a (draft) PR from `som/zisk-impl` to `master`. The branch is based on
   `dev`, so that PR also carries `dev`'s commits. Both workflows fail until `zilkworm-ci-zisk` exists.

| Workflow | What it does |
|---|---|
| `zisk-eest.yml` | `make z6m_prover_zisk`; prepares **`eest_devnet`** MFBD fixtures (same corpus as `hypercube-eest.yml`); runs `eest_runner.py --prover … --stagger 15 --fail-threshold 5` with `Z6M_ZISK_EXECUTOR=ziskemu`. Only `eest_stable` has been validated locally, so the devnet failure count is unknown. |
| `zisk-benchmark.yml` | `make z6m_prover_zisk`; downloads the raw 200 blocks from `zilkworm-testdata`, regenerates the corpus, and runs `sp1_benchmark.py --prover … --ram-per-instance 16` through the SDK emulator. It fails on any FAILED or SKIPPED block or a short count. |

Both workflows are **execute-only**: they download no proving key, use no GPU and generate no proofs.
The CI image has only GCC 15.2.0-1.1, so CI's ZisK ELF differs from a local GCC 14 build. Public
values are identical across the two compilers (§8).

## 7. Known Issues and Gotchas

- **`ebreak` is a no-op on ZisK** (and `unimp` is not a trap). `zisk_postlink.py` rewrites every
  `ebreak` in the linked ELF to `0xFFFFFFFF`, ZisK's halt-with-error word. The current ELF has 16
  sites. It also checks ISA, layout and memory-map symbols, and on a violation it renames the ELF to
  `*.rejected` and fails the build. The guest's own aborts emit `0xFFFFFFFF` directly.
- **Re-patching blst.** ExternalProject does not track `patch_blst_zisk.sh`. After editing it, run
  `rm -rf prover/guest_zisk/build/deps/src/blst*` (`blst`, `blst-stamp`, `blst-build`), because
  otherwise a stale unpatched blst builds silently. Check that
  `grep -c ZISK prover/guest_zisk/build/deps/src/blst/src/vect.h` is non-zero.
- **ziskemu quirks:**
  - it has no `-u` flag; only the ASM emulator (`cargo-zisk … -a -u`) has one;
  - a halt-with-error still **exits 0**. Check stderr for
    `Emu::run_fast() finished with error at step=N pc=0x…`; the guest's OOM path prints
    `[zisk] out of memory` on stdout first. `zisk_execute.py` already classifies these runs as ERROR.
- **512 MiB RAM.** The heap is 507.2 MiB. Heap peaks were 28.4 MB on the corpus and 72.2 MB on EEST.
  The 2 OOM fixtures are the only inputs above the limit.
- **4 MiB fixed stack.** The worst case is `create2_recursive` at about 3.19 MB, leaving 24% headroom.
  An overflow writes below `0xA0000000`, and ziskemu panics loudly (rc 101) rather than failing
  silently. The heap and stack numbers predate the accelerators (§8).
- **SDK execute cost.** The SDK emulator runs the guest on 16 threads and then counts and plans,
  which costs 20–30× the CPU of `--executor ziskemu`. On a 942 M-step block it took 25.6 s wall,
  218 s CPU and 4.0 GB RSS, against 10.9 s, 10.6 s and 0.46 GB. Use `ziskemu` for bulk execution,
  and cap the SDK with `RAYON_NUM_THREADS`. The SDK path also prints guest UART lines up to 16 times.
- **libffi-sys when building ZisK crates from source.** On hosts whose `mkdir`/`cp` are uutils
  (Ubuntu 25.10), libffi's configure fails with `../install-sh: Permission denied`. Set
  `MKDIR_P="mkdir -p"`. `prover/prover_zisk/.cargo/config.toml` and the CI Dockerfile already do.
- **`-march`.** Keep `-march=rv64im_zicsr_zba_zbb_zbs_zbkb`: with xPack GCC, `rv64ima*` selects a
  libgcc multilib without M.
- **Memory map drift.** On a ZisK bump, re-vendor `zisk.ld` and `src/dma/*.s`. A stale memory map
  produces an all-zero output silently, which `zisk_execute.py` reports as ERROR.
- **`make zisk-emu-check` builds the native runner in the shared `build/` directory.**

## 8. Remaining Backlog

1. **Proving benchmarks.**
   - `compressed` on the 200-block corpus is done (§5.1). Repeat per proof type (`minimal`, `plonk`)
     and record proving time, peak RAM/VRAM and proof size the same way.
   - Expose `max_streams` / `minimal_memory` on the host for cards with less than 32 GB.
   - Then try `--executor assembly`, multi-process `mpirun`, and the `--remote` coordinator.
2. **Compiler and flag sweep.**
   - GCC 15.2 vs 14.2 gave identical public values on all 8815 inputs, with −1.69% steps on the
     corpus and −4.0% on EEST. That was measured before the accelerators, so re-measure.
   - Build an A/B ELF with
     `make z6m_guest_zisk ZISK_GCC_BIN=$HOME/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/15.2.0-1.1/.content/bin ZISK_BUILD_DIR=prover/guest_zisk/build-gcc15`.
   - Also try `-mtune=size`, `-funroll-loops` and the inline parameters.
3. **Optional accelerators.**
   - MUL/EXP via `arith256` (`0x801`).
   - DIV/MOD via fcall 19; the verified `zisk::udivrem` is already in the shim.
   - evmc word-load `==` and hash gates in `evmc.hpp`, after profiling.
   - Plain-form instead of Montgomery blst, which would halve the `0x80B` calls.
4. **Stack headroom.**
   - Re-measure heap and stack on the accelerated guest. Heap stats come from
     `-DZ6M_ZISK_HEAP_STATS=ON` (a CMake option of `prover/guest_zisk`).
   - Make the stack paint an in-tree option.
5. **EF zkvm-standards C API.** Later, consider moving from raw CSR shims to ZisK's
   `libziskos_staticlib.a` (`zkvm_io.h` / `zkvm_accelerators.h`).
6. **Upstreaming.** Upstream the 9 evmone ZisK commits (`b10a25a4..6f35e0a0`) from zvm1
   `som/zisk-impl` to `oss`, then repoint the submodule.
7. **Smaller items.**
   - Service mode against a live RPC.
   - ethproofs posting (deferred, because `verifier_id` is SP1-specific).
   - Handling the 2 OOM fixtures (exclusion list, or evmone memory retention).
   - ZisK binaries in `release-artifacts`.

## 9. Validation Policy

Every commit runs the legs below, including docs-only and ZisK-only commits. Run them sequentially,
because legs 1 and 2 both reconfigure `build/`. Rebuild the guest and prover first so that leg 3
never measures a stale guest. After any evmone bump, run `git -C third_party/evmone checkout <pinned sha>`
before building.

```sh
make z6m_prover                                         # SP1 guest + host, fresh
sha256sum prover/guest_hypercube/build/z6m_guest.elf    # leg 0: 68b32dcaebca9c0bd8bf9ca6d911d108271d250c4e919c604878860097b5f676
make eest-blockchain-tests                              # leg 1: 8654/8654 (8615 EEST fixtures + 39 unit tests)
tools/scripts/release_state_root_check.sh --dir temp/200_benchmark_blocks_mfbd_v2 -l temp/runtime/leg2
                                                        # leg 2: 200/200, 0 state-root mismatches
python3 tools/scripts/sp1_benchmark.py --dir temp/200_benchmark_blocks_mfbd_v2
                                                        # leg 3: 200 records, 0 failed blocks
```

- **Leg 0** needs xPack GCC 14.2.0-3.1. ZisK code sits behind `ZISK` gates, so the SP1 ELF must not
  change.
- **Leg 3 totals at `e97f0823`:** cycles 26,575,390,325; prover gas 50,563,817,864;
  gas_used 6,036,444,409. The intx bump in `e97f0823` changed the SP1 ELF (it was
  `e8e7201c…` through `93bcdac28`, with 26,617,248,718 cycles and 50,605,949,665 prover gas).
- **Stale compiler cache.** `make z6m_guest` reuses `prover/guest_hypercube/build/CMakeCache.txt`,
  including the compiler path cached on the first configure. With 15.2.0-1.1 installed first and
  14.2.0-3.1 added later, delete that directory once; otherwise leg 0 silently builds with GCC 15
  (ELF `aee426fa…`, 26,132,211,190 cycles, which is −1.7%).
- **Commits that touch the ZisK guest, shims or evmone ZisK code** must also pass `make zisk-emu-check`
  (200/200) and the full EEST `zisk_execute.py` run from §4 (8613 PASS, the 2 known OOMs). Report
  the raw step totals.
