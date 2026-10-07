# Profile-guided optimization of the Airbender guest

The guest is compiled with GCC's instrumented profile-guided optimization: `-fprofile-use` with the
profile in `profile/`, on every translation unit that the training reaches, except the interpreter
(`third_party/evmone/lib/evmone/baseline_execution.cpp`) and `vm.cpp`. With a profile,
`dispatch_cgoto` spills and costs about 900M more cycles on the corpus, so the interpreter stays
unprofiled. The rules are in `../cmake/z6m_pgo.cmake`; the measurements are below.

## Build modes: `Z6M_PGO`

| Mode | Effect | Used by |
| --- | --- | --- |
| `OFF` | No profile flag, source, macro or link change: the guest of a tree without this directory. | `cmake` run directly, or an explicit opt-out |
| `GEN` | Instrumented guest: `gcov_dump.c` prints the arc counters over the UART at the end of `main`. | Regenerating the profile |
| `USE` | The committed profile. Configuring fails unless the profile matches the build exactly. | `prover/Dockerfile`, the Airbender CI workflows |
| `AUTO` | `USE` if the profile matches, otherwise `OFF` with a warning that names what differs. | The default of `prover/guest_airbender/Makefile` |

`make z6m_guest_airbender Z6M_PGO=USE` (root Makefile) and `make -C prover/guest_airbender z6m_guest
Z6M_PGO=USE` pass the mode to both CMake projects: the zilkworm subbuild (evmone, silkworm_core,
silkworm_dev, silkworm_types_zz) and the guest (z6m_guest). Each prints
`Z6M_PGO=<mode>: building <zilkworm|guest> with the committed profile` when it uses it. The profile
is recorded with `USE_HASH_KEY=OFF`; with `ON` the flags differ, so `AUTO` builds without it.

## When the profile applies

At configure time each project compares the build with `manifest.txt` and `flags-<project>.txt`:

- the SHA-256 of every file that a profiled translation unit includes: its source, every project
  and fetched header, and every toolchain header (`src` and `sys` lines);
- the compiler: its version line and the SHA-256 of `cc1` and `cc1plus` (xPack riscv-none-elf-gcc
  15.2.0-1, which is what xpm installs as 15.2.0-1.1);
- the list of profiled sources and their profile files (`tu` lines);
- the compile flags of those sources as configured: `CMAKE_<LANG>_FLAGS`, target, directory and
  source properties and the usage requirements of linked targets (`flags-*.txt`).

Any difference makes `AUTO` build without the profile and warn, and makes `USE` stop. An edit to a
profiled file therefore never breaks a default build, while CI (`USE`) fails until the profile is
regenerated. GCC's own checks would not be enough: they miss an inverted condition that keeps the
lines and the control-flow shape, skip a new function without a word, and only warn about a
profile from another compiler version.

The profile does not depend on where the tree or the toolchain is installed, so Docker, CI and any
checkout build the same image:

- Both stages pass `--param=profile-func-internal-id=1`, so a `.gcda` file names each function by
  its position in the translation unit. GCC's default name for a function with internal linkage
  hashes the absolute path of its source and object files. `-fprofile-prefix-map` (and
  `-ffile-prefix-map`, which implies it) only rewrites the file names written to `.gcno` notes, and
  `-fprofile-prefix-path` only where `.gcda` files are looked for.
- The other field that depends on the path, each function's line checksum (a hash of its line and
  the absolute name of its file), is zeroed by `mkprofile.py`, and `USE` passes
  `-Wno-coverage-mismatch` so that GCC does not compare it. That flag also silences GCC's
  control-flow checksum check, which the exact manifest check replaces.
- `mkprofile.py` also zeroes the time stamp and object checksum, so the profile's bytes depend only
  on the GEN guest and the training runs, not on where or when the GEN guest was built.
- Each project copies the files of `profile/` next to its objects, where GCC looks for them. They
  have flat names (`+` for `/`) because `.gitignore` skips every `CMakeFiles` path.

## Training set

- The 100 blocks of `train_blocks.txt`: every other block of the 200-block benchmark corpus. The
  other 100 blocks are the held-out half.
- Half of the EEST blockchain tests: those whose path below `for_<fork>/` has a SHA-256 with an even
  first byte (`eest_training` in `mkprofile.py`), so that a test and its copies for other forks fall
  in the same half. The other half is held out.

A block and an EEST test count the same, and the summary records a single run, so that only code
no training run reached counts as never executed. Trained on the blocks alone, the profile made the
cold paths that mainnet blocks rarely take markedly slower (below); the EEST half covers them.

## Measurements

When the profile was recorded (unprofiled guest 3,218,592 bytes, profiled 3,095,712, GEN 4,115,512):

| | Unprofiled | Blocks + EEST (committed) | Blocks only |
| --- | --- | --- | --- |
| 200-block corpus, cycles | 33,509,676,732 | 33,146,481,070 (-1.084%) | 33,119,379,148 (-1.165%) |
| Held-out 100 blocks | | -1.082% | -1.147% |
| EEST, 8,595 passing tests | 249,412,538,851 | -0.805% | +0.396% |
| EEST tests more than 1% / 5% slower | | 0 / 0 | 505 / 100 |
| Slowest EEST test against the unprofiled guest | | +0.54% | +16.32% (`create_oog_from_call_refunds`) |
| The 100 most expensive EEST tests | | -0.565%, worst +0.09% | +0.505%, worst +5.55% |
| Held-out EEST half (4,382 tests) | | -0.671%, worst +0.54% | +0.377%, worst +16.32% |
| BigInt / Keccak delegation calls (corpus) | 1,544,638,171 / 9,790,986,634 | 1,544,556,763 / equal | 1,544,555,525 / equal |

Gas and status match on all 200 blocks and the same 8,595 EEST tests pass. Every Keccak permutation
in the image is still one run of 649 `csrrw`.

Other trainings of the same tree gave, against the unprofiled guest (corpus, EEST, slowest EEST
test, BigInt calls):

| Training | Corpus | EEST | Slowest test | BigInt calls |
| --- | --- | --- | --- | --- |
| EEST weight 1, code outside the hottest 99.9% (not 99%) optimized for size | -1.341% | -0.941% | +0.39% | +1,248,805 |
| EEST weight 1, 99.5% / 99.8% / 100% | -1.25% / -1.27% / -1.32% | about -0.9% | under +0.6% | +56,232 / +19,338 / +72,326 |
| EEST weight 0.3 / 0.5 / 2 / 3, 99.9% | -1.43% / -1.28% / -1.09% / -1.26% | about -0.9% | +1.27% to +1.78% | +1.35M / +1.29M / -6,667 / +1.24M |
| EEST weight 2, 99% | -0.851% | -0.747% | +1.27% | +93,740 |

The BigInt count moves with the stack layout: `ModArith` takes a path with one more delegation call
when an operand on the stack happens to be 32-byte aligned. The guest trained with EEST weight 0.5
and 99% rejected deposit requests (EIP-6110: 3 corpus blocks and 9 EEST tests failed with
`kRequestsProcessingFailure`); the same profile with `-fno-strict-aliasing` passes everything, so the
profile's inlining exposed undefined behaviour on that path. Every new profile has to pass the
checks of step 8 below.

## Regenerating the profile

The profile goes stale with any change to a profiled input: a source or header under `zilk_core/`,
`third_party/evmone/` or `third_party/intx/`, a guest source, a compile flag, or the compiler. It
also has to be regenerated after a rebase onto a base that changed one of them. Regenerate it in the
change that makes it stale, since CI builds with `USE`:

1. Check out exactly the tree to commit, without uncommitted changes to profiled inputs, with the
   pinned toolchain on `PATH` and Python 3.
2. Build the prover first (the root Makefile's `z6m_prover_airbender` would rebuild the guest):
   `(cd prover/prover_airbender && cargo build --release)`.
3. Build the instrumented guest:
   `make -C prover/guest_airbender z6m_guest Z6M_PGO=GEN`. Its `z6m_guest.bin` must stay below
   4 MiB (4,194,304 bytes); the cold files listed in `z6m_pgo.cmake` are left out for that reason.
4. Get the inputs: the benchmark corpus
   (`make sp1-benchmark-corpus BENCH_SRC_DIR=<raw blocks> BENCH_CORPUS_DIR=<corpus>`, raw blocks
   from the `benchmark-200-spread` release of erigontech/zilkworm-testdata) and the EEST fixtures
   (`tools/test-fixtures.sh test-fixtures.json test-fixtures-cache eest_stable`).
5. Run the training (a few minutes on 32 cores):
   `prover/guest_airbender/pgo/train.sh prover/prover_airbender/target/release/z6m_prover_airbender prover/guest_airbender/build/z6m_guest <corpus> test-fixtures-cache/eest_stable/fixtures/blockchain_tests <logs>`
6. Write the profile: `prover/guest_airbender/pgo/mkprofile.py prover/guest_airbender/build <logs>`.
   It rewrites `profile/`, `manifest.txt` and `flags-*.txt`, and refuses inputs that changed after
   the GEN build compiled them.
7. Build with `Z6M_PGO=USE`: both projects must print `building ... with the committed profile`.
8. Check the profiled guest against the unprofiled one (`Z6M_PGO=OFF`) before committing `pgo/`:
   gas and status equal on all 200 blocks, the same EEST tests passing, no EEST test markedly slower,
   and no more BigInt (CSR 0x7ca) or Keccak (CSR 0x7cb) delegation calls over the corpus.
