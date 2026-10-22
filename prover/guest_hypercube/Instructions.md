# Instructions on building Zilkworm-Hypercube

## Toolchains

1. Install `protoc` needed by SP1 CLI from-source build. E.g. `sudo apt install protobuf-compiler`.
2. SP1-Hypercube toolchain
   Before installing SP1 hypercube toolchain, make sure older toolchains (cargo-prove) are removed. You can clear out ~/.sp1 safely too.
   In order to install the toolchain clone the repo https://github.com/succinctlabs/sp1-wip.
3. Install `cargo prove` (see official instructions: https://docs.succinct.xyz/docs/sp1/getting-started/install#option-2-building-from-source):
   ```
   (cd sp1-wip/crates/cli && cargo install --locked --path .)
   ```
4. Install SP1 toolchain:
   ```
   cargo prove install-toolchain
   ```
   For the purpose of zilkworm we will not be using the packaged c-toolchain. Therefore, doing `sp1up --c-toolchain` isn't useful. However it's something to keep in mind for resolving issues.
   (Note: If you want to use NVIDIA CUDA for proving, you must also have sp1-gpu-server built from sp1-gpu/crates/server/ in the erigontech/sp1 repository)
5. GCC compiler for rv64-im
   We will use the latest version from https://xpack-dev-tools.github.io/riscv-none-elf-gcc-xpack/docs/install/
   ```
   npm install --location=global xpm@latest
   xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global --verbose
   ```
   The directories inside `~/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*` would contain all the downloaded libs and binaries.
6. Std libraries
   The ones provided by xpack build should work mostly. There can be some clashes with symbols coming from SP1's builder during the linking phase. It's recommended to get the following libraries to use for linking instead:
   ```
   wget https://github.com/erigontech/z6m/releases/download/prelibs/prelibs64.tar.xz
   ```
   Extract it in `prover` directory.

(Probably outdated)
At the moment of writing this there was only one clash - `memcpy` for which I just removed memcpy object from libc
```
ar d libc.a libc_a-memcpy.o
```
The libc for this build is located at ls $HOME/.local/xPacks/\@xpack-dev-tools/riscv-none-elf-gcc/15.2.0-1.1/.content/riscv-none-elf/lib/rv64im/lp64/


## Setting up cargo-prove
cargo-prove binary must be accessible in the path (from Toolchains instructions, see above)
(Probably not needed)
The following env must be set for cargo prove to work properly
```
export RUSTC_LINKER=riscv-none-elf-ld 
export CC_riscv64im_succinct_zkvm_elf=/usr/bin/riscv-none-elf-g++
export CXX_riscv64im_succinct_zkvm_elf=/usr/bin/riscv-none-elf-g++
export CONAN_PROFILE_HOST=riscv64-baremetal
```

## Building
The zilkworm-hypercube integration source is in `./prover/hypercube` directory
You can use the makefile directives to build
```
make z6m_guest
make z6m_prover
```


## Other stuff
AMD AVX
```



RUSTFLAGS="-C target-cpu=znver3" RUST_BACKTRACE=full RUST_LOG=info cargo run --release --manifest-path ../prover/Cargo.toml -- --prove
```

```
SP1_PROVER=cuda RUST_BACKTRACE=full RUST_LOG=info cargo run --release -- --prove

```
