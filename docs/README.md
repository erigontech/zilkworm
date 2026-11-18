# Zilkworm repository index

Zilkworm is a C++ Ethereum block validator that runs as a zkVM guest (SP1 Hypercube, Airbender).
This page is the map of the repository: one line per topic, with the doc section that explains it,
the source that implements it and the make target that runs it. Start here; open a doc for the
detail and the source only when the doc does not answer.

Conventions:

- Every fact has one home. A line here points at it and does not restate it.
- Versions are not written in prose. [Version pins](#version-pins) names the variable or file
  that sets each one.
- Make targets are in the root `Makefile` unless a directory is given.

## State backends

Two state backends ship. `ActiveState` (`zilk_core/core/state_zz/active_state.hpp`) selects one at
compile time with the CMake option `Z6M_HASH_STATE`: [hashstate.md](hashstate.md#backend-selection).

| | DirectState | HashState (slib) |
|---|---|---|
| Build flag | `Z6M_HASH_STATE=OFF` (default) | `Z6M_HASH_STATE=ON` |
| Input | MFBD flat witness bundle | EIP-8025 SSZ `statelessInputBytes` |
| Pre-state | read in place from the bundle, checked by `sanitize()` and the root recompute | derived in the guest by walking the witness trie from the parent state root |
| Guests | SP1 `z6m_guest` (released as `z6m_guest_hypercube_mfbd`, embedded in `z6m_prover_hypercube`); Airbender guest | SP1 `z6m_guest_slib` (released as `stateless-validator-zilkworm-sp1-<SP1 version>`, the ERE guest) |
| Public output | 112 bytes (SP1), block hash in a0..a7 (Airbender) | 43-byte `StatelessValidationResult` |
| Doc | [directstate.md](directstate.md) | [hashstate.md](hashstate.md) |

### DirectState (MFBD bundles)

- **Input format and dispatch**
  - Dispatch on the `MFBD` magic to `run_mfbd` — [architecture.md](architecture.md#input-format-and-dispatch) — `zilk_core/dev/state_transition.cpp`
  - MFBD envelope and FlatBundle (`FBND`) layout — [flat_witness_bundle.md §2.1–2.2](flat_witness_bundle.md#21-input-envelope-outer) — `zilk_core/core/types_zz/flat_bundle.{hpp,cpp}`
  - `direct_state` blob: accounts, slots, address and block hashes, code store — [flat_witness_bundle.md §2.3](flat_witness_bundle.md#23-direct_state-internals) — `zilk_core/core/state_zz/pre_state.hpp`, `zilk_core/core/types_zz/account.hpp`
  - `MphfMap`, the minimal-perfect-hash index of the three stores, and its validation — [flat_witness_bundle.md §2.4](flat_witness_bundle.md#24-mphfmap-the-minimal-perfect-hash-map) — `zilk_core/core/common_zz/mphf_map.hpp`
  - `MphfBuilder`, the host-side construction and the sidecar invariant — [flat_witness_bundle.md §2.5](flat_witness_bundle.md#25-mphfbuilder-how-the-sidecar-gets-populated) — `zilk_core/core/common_zz/mphf_builder.{hpp,cpp}`
  - `node_store`, the witness trie nodes — [flat_witness_bundle.md §2.6](flat_witness_bundle.md#26-node_store--read-only-mpt-proof-nodes-a-peer-section) — `zilk_core/core/state_zz/direct_state.hpp`
  - Normative format spec: what a conforming verifier MUST check, lookup function, rationale — [mfbd_design_specs.md](mfbd_design_specs.md)
- **Code paths**
  - One bundle, start to finish (`run_mfbd`, `load_flat_bundle`, `run_one_bundle`) — [directstate.md](directstate.md#mfbd-run) — `zilk_core/dev/state_transition.cpp`
  - `sanitize()`: what an untrusted bundle must prove before execution — [directstate.md](directstate.md#sanitize-the-threat-model) — `zilk_core/core/state_zz/direct_state.cpp`
  - Account reads never return nothing; the created/existing hash clash — [directstate.md](directstate.md#account-reads-never-return-nothing) — `zilk_core/core/state_zz/direct_state.{hpp,cpp}`
  - Root check: block 0 by `GridMPT` recompute, later blocks by `HashBuilder` — [directstate.md](directstate.md#root-check) — `zilk_core/dev/state_transition.cpp`
  - Known open gaps of the checks — [directstate.md](directstate.md#open-gaps)
  - Node-store recovery for witness preimage gaps (`USE_HASH_KEY`) — [directstate.md](directstate.md#node-store-recovery-use_hash_key) — `zilk_core/core/state_zz/direct_state.cpp`
  - Fetched witness to bundle (`json_witness_to_flat_bundle`) — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#2-the-three-converters) — `zilk_core/dev/witness_converter.{hpp,cpp}`, `prover/witness_ffi/`, `prover/common/src/fetcher.rs`
- **Guests and make targets**
  - SP1 guest (rv64im) — [architecture.md](architecture.md#guests) — `prover/guest_hypercube/` — `make z6m_guest` (ELF in `prover/guest_hypercube/build/`), `make z6m_guest_vk`
  - SP1 prover with the guest embedded — [../README.md](../README.md#how-to-run) — `prover/prover_hypercube/` — `make z6m_prover`
  - Airbender guest (rv32im) — [airbender_architecture.md](airbender_architecture.md#1-guest-program-build) — `prover/guest_airbender/` — `make z6m_guest_airbender`, `make z6m_prover_airbender`
- **Tests and corpora**
  - Unit tests — the whole core (RLP, protocol, precompiles, trie, state) plus account-read spoofing and honest reads — [directstate.md](directstate.md#tests) — `zilkworm.tests` (`CMakeLists.txt`) — `cmake -B build -G Ninja -DBUILD_TESTING=ON && cmake --build build --target zilkworm.tests && ctest --test-dir build` — CI `unit-tests.yml`
  - EEST blockchain tests, native — corpus: `eest_stable` of `test-fixtures.json`, converted to MFBD; checks every fixture's blocks against their expected roots and exceptions — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#4-eest-fixtures) — `make eest-blockchain-tests` — CI `eest-blockchain-tests.yml`
  - EEST under the SP1 executor — same corpus through the guest — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#4-eest-fixtures) — `make eest-prover-test`, `make selftest` — CI `hypercube-eest.yml`
  - EEST under QEMU, rv32im and rv64im — same corpus, cross-compiled zilk_core — `qemu_runner/` — `cd qemu_runner && make rerun-ctest` (`ARCH=rv64`) — CI `qemu-eest-blockchain.yml`, `qemu-eest-blockchain-rv64.yml`
  - EEST on the Airbender simulator — the JSON fixtures through the EJSN path — [airbender_architecture.md](airbender_architecture.md#4-building-and-running) — `cd prover/prover_airbender && make eest` — CI `airbender-eest.yml`
  - Known-failure lists — `zilk_core/dev/eest-known-failures.txt`, `prover/prover_airbender/eest-known-failures.txt`
  - Fixture generation, the converter-keyed cache, bumping the EEST pin — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#4-eest-fixtures), CI cache keys in [../tools/README.md](../tools/README.md) — `make test-fixtures`, `make eest-mfbd-build`
  - Wire-format changes: bump `kFlatBundleVersion`, regenerate both sets — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#5-wire-format-changes)
- **Benchmarks**
  - 200 mainnet blocks, SP1 cycles — corpus: legacy witness blocks converted to MFBD — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#3-benchmark-corpus) — `tools/scripts/sp1_benchmark.py` — `make sp1-benchmark-corpus`, `make sp1-benchmark` — CI `sp1-benchmark.yml`
  - The same corpus on Airbender — `tools/scripts/airbender_benchmark.sh` — CI `airbender-benchmark.yml`
  - Host state-root check of the corpus — [mfbd_fixture_generation.md](mfbd_fixture_generation.md#6-validation-after-regenerating) — `tools/scripts/release_state_root_check.sh`

### HashState (`statelessInputBytes`)

- **Input format and dispatch**
  - Dispatch on the `15 01` schema prefix to `run_sib`; the EJSN slib arm — [architecture.md](architecture.md#input-format-and-dispatch), [hashstate.md](hashstate.md#raw-statelessinput-dispatch) — `zilk_core/dev/blockchain_test_runner.cpp`
  - `StatelessInput` SSZ wire layout and its validation — [hashstate.md](hashstate.md#statelessinputbytes-parsing) — `zilk_core/core/state_zz/slib_input.{hpp,cpp}`
  - `NewPayloadRequest`: decoding, hash tree root, rebuilding the block — [hashstate.md](hashstate.md#the-payload) — `zilk_core/core/state_zz/slib_payload.{hpp,cpp}`
  - Output: the 43-byte `StatelessValidationResult` — [architecture.md](architecture.md#public-output) — `prover/guest_hypercube/src/main.cpp`
- **Code paths**
  - Node and code stores, built in the guest from the witness — [hashstate.md](hashstate.md#node-and-code-stores) — `zilk_core/core/state_zz/hash_state.{hpp,cpp}`
  - Deriving accounts and storage by sweeping the trie from the parent root — [hashstate.md](hashstate.md#building-state-from-the-trie) — `hash_state.cpp` (`build_state_from_trie`, `sweep`)
  - Fail-closed policy and read-miss confirmation (`confirm_absent`) — [hashstate.md](hashstate.md#fail-closed-policy), [hashstate.md](hashstate.md#read-miss-confirmation) — `hash_state.cpp`
  - Witness headers and BLOCKHASH — [hashstate.md](hashstate.md#block-headers-and-blockhash) — `hash_state.{hpp,cpp}`
  - Write overlay and its two divergences from DirectState — [hashstate.md](hashstate.md#write-overlay) — `hash_state.cpp`
  - `HashIndex`, the open-addressed index of the stores and caches — [hashstate.md](hashstate.md#hash-index) — `zilk_core/core/common_zz/hash_index.hpp`
  - Accept check: fold the block's writes over the parent root, require every read confirmed — [hashstate.md](hashstate.md#accept-check) — `zilk_core/dev/check_root_hashstate.hpp`
  - One block, start to finish (`run_sib_block`) — [hashstate.md](hashstate.md#slib-arm) — `zilk_core/dev/blockchain_test_runner.cpp`
- **Guests and make targets**
  - Build flag in the host and guest CMake projects — [hashstate.md](hashstate.md#build-flag-and-test-targets) — `CMakeLists.txt`, `prover/guest_hypercube/CMakeLists.txt`
  - SP1 guest (rv64im), built in its own tree — `prover/guest_hypercube/` — `make z6m_guest_slib` (ELF in `prover/guest_hypercube/build-slib/`)
  - SP1 prover with the HashState guest embedded — `prover/prover_hypercube/build.rs` (`Z6M_GUEST_ELF`) — `make z6m_prover_slib`
  - ERE guest, ELF and verifying key — [ere_integration.md](ere_integration.md) — `make ere-bin` (in `build/ere-bin/`), `make derive_vk`
- **Tests and corpora**
  - Unit tests, flag on — stores, sweep, absence walk, fold, accept check, SSZ front end — [hashstate.md](hashstate.md#tests) — `zilk_core/dev/cli/hash_state_test.cpp`, `hash_index_test.cpp` — configure with `-DZ6M_HASH_STATE=ON`, target `zilkworm.tests` — CI `unit-tests.yml` (`unit-tests-hashstate`)
  - tests-zkevm corpus, native — corpus: `tests-zkevm@$(ZKEVM_RELEASE_VERSION)`; checks every witnessed block, with witness-validation negatives passing only if rejected — [slib_corpus_validation.md](slib_corpus_validation.md#runs) — `make zkevm-fixtures`, `make eest-zkevm-tests` — no CI
  - How negatives and waived labels are scored — [hashstate.md](hashstate.md#scoring-witness-validation-negatives), [hashstate.md](hashstate.md#expected-invalid-label-relaxation) — `zilk_core/dev/blockchain_test_runner.cpp`
  - Guest against `statelessOutputBytes` — corpus: Sepolia block batches from an R2 catalog — [ere_integration.md](ere_integration.md#fixtures-sepolia) — `make ere-validate` — CI `ere-benchmark.yml`
  - Guest against the whole tests-zkevm corpus — the ere-guests test crate — [ere_integration.md](ere_integration.md#the-ere-guests-corpus-test)
- **Benchmarks**
  - SP1 cycles per block — corpus: `tests-zkevm-benchmark@$(ZKEVM_BENCH_RELEASE_VERSION)`; includes the JSON harness — [slib_benchmark.md](slib_benchmark.md) — `tools/scripts/slib_split_fixtures.py`, `tools/stats/cycle_stats.py` — `make zkevm-benchmark-fixtures`, `make slib-benchmark` — CI `hypercube-slib-benchmark.yml` (manual)
  - SP1 prover-cost estimate on the raw input, alone and against Reth — [ere_integration.md](ere_integration.md#actions-and-metrics) — `tools/ere_compare.py` — `make ere-cost`, `make ere-compare` — CI `ere-benchmark.yml`

## Shared parts

- **Layers and components** — host, guests, zilk_core, third-party — [architecture.md](architecture.md#components)
- **Input dispatch** — which first bytes go to which path under which build — [architecture.md](architecture.md#input-format-and-dispatch) — `StateTransition::run()` in `zilk_core/dev/state_transition.cpp`
- **EJSN (EEST JSON) path** — accepted by both backends — [architecture.md](architecture.md#ejsn-envelope) — `zilk_core/dev/blockchain_test_runner.cpp`
- **Runners and transports** — SP1 stdin, ERE, native, QEMU, Airbender oracle — [architecture.md](architecture.md#runners) — `zilk_core/dev/cli/runner.cpp`, `prover/prover_hypercube/src/stdin_builders.rs`, `qemu_runner/src/`
- **Public outputs** — all three guests — [architecture.md](architecture.md#public-output) — `prover/guest_hypercube/src/main.cpp`, `prover/guest_airbender/src/main.cpp`
- **EVM (zvm1, a fork of evmone)** — submodule `third_party/evmone`, wired in by `third_party/CMakeLists.txt`; driven by `ExecutionProcessor` (`zilk_core/core/execution/processor.{hpp,cpp}`) through the per-transaction views `DirectStateView` / `HashStateView` — [hashstate.md](hashstate.md#per-transaction-state-view)
- **SSZ** — offset-table reading (`zilk_core/core/common_zz/ssz_read.hpp`) and merkleization of progressive containers and lists (`ssz_merkle.{hpp,cpp}`); used by HashState only — [hashstate.md](hashstate.md#statelessinputbytes-parsing)
- **GridMPT / trie** — the witness-backed root recompute, templated on the backend — [directstate.md](directstate.md#root-check), [hashstate.md](hashstate.md#trie-fold-under-hashstate) — `zilk_core/core/trie_zz/` (`mpt.hpp`, `grid_mpt.cpp`, `fold_unfold.hpp`, `rlp_sw.hpp`), tests in `zilk_core/core/trie_zz/test/`; `HashBuilder` in `zilk_core/core/trie/`
- **key8 functions** — the 64-bit index keys shared by `MphfMap` and `HashIndex` — [hashstate.md](hashstate.md#index-key) — `zilk_core/core/common_zz/index_key.hpp`
- **Precompiles and syscalls**
  - Precompile dispatch — `zilk_core/core/execution/precompile.{hpp,cpp}`; implementations in `third_party/evmone/lib/evmone_precompiles/`
  - SP1 syscalls — `prover/guest_hypercube/src/include/sp1_syscalls.hpp`, runtime in `prover/guest_hypercube/src/sp1_runtime.cpp`; host test of evmone's SP1 secp256k1 path over a software stand-in for the syscalls in `tests/sp1_secp256k1/` (`CMakeLists.txt`). No doc section.
  - Airbender CSR delegations (keccak, bigint, ecrecover) — [airbender_architecture.md](airbender_architecture.md#3-precompile-acceleration) — `prover/guest_airbender/src/include/airbender_csr.hpp`; host differential tests of the guest's blst patches in `tests/blst_cyclotomic/`, `tests/blst_mont384/`
  - Memory builtins shared by the guests — `prover/guest_common/src/mem_builtins.cpp`
- **Protocol** — rule sets, validation, intrinsic gas — `zilk_core/core/protocol/`; chain configs by network name in `zilk_core/core/common/test_util.hpp` (`kNetworkConfig`)
- **Code style** — [code_style.md](code_style.md) — `zilk_core/.clang-format`, `zilk_core/.clang-tidy`

## Build and toolchain

- **Submodules** — `git submodule update --init --recursive` (zvm1 is `third_party/evmone`)
- **Host build** — CMake and Ninja; dependencies come from the submodule and `FetchContent` — `CMakeLists.txt` — `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build`
- **CMake options** — `Z6M_HASH_STATE` ([hashstate.md](hashstate.md#build-flag-and-test-targets)), `USE_HASH_KEY` ([directstate.md](directstate.md#node-store-recovery-use_hash_key)), `BUILD_TESTING`, `EEST_MFBD_DIR` / `EEST_JSON_DIR` (register fixtures as ctest cases, `zilk_core/dev/cli/CMakeLists.txt`)
- **RISC-V toolchain** — xPack `riscv-none-elf-gcc`; the Makefile adds a global xPack install to `PATH` — `prover/guest_hypercube/cmake/riscv64im-sp1.cmake` (SP1 flags), [airbender_architecture.md](airbender_architecture.md#1-guest-program-build) (Airbender flags)
- **SP1 toolchain setup** — [`../prover/guest_hypercube/Instructions.md`](../prover/guest_hypercube/Instructions.md) (partly outdated, marked so in the file)
- **Build trees** — `build/` (host), `build/zkevm/` (host, flag on), `prover/guest_hypercube/build/` (DirectState guest), `prover/guest_hypercube/build-slib/` (HashState guest), `prover/guest_airbender/build/`, `build/ere-bin/` (staged ERE guest); `make clean` removes the hypercube guest tree and `prover/target`
- **Docker** — `Dockerfile` (SP1 prover image), `prover/Dockerfile` (targets `airbender` and `hypercube`), `.github/docker/ci.Dockerfile` (CI image, `ci-image.yml`)
- **QEMU runner** — [`../qemu_runner/README.md`](../qemu_runner/README.md) — `qemu_runner/Makefile`
- **Legacy SP1 Turbo guest and prover (rv32im)** — `prover/guest_turbo/`, `prover/prover_turbo/` — `make z6m_guest_turbo`, `make z6m_prover_turbo`; not in CI

## Provers and services

- **`z6m_prover` (SP1 Hypercube host)** — `fetch`, `execute`, `prove`, `--service`, `--test-service` (`setup` and `verify` parse but do nothing) — [../README.md](../README.md#how-to-run) — `prover/prover_hypercube/src/main.rs`, `service.rs` — `make z6m_prover`
- **Fetcher and Ethproofs client** — [architecture.md](architecture.md#prover-host-rust) — `prover/common/src/fetcher.rs`, `ethproofs_client.rs`
- **`z6m_prover_airbender`** — simulator, GPU prover, verification key, service — [`../prover/prover_airbender/README.md`](../prover/prover_airbender/README.md) — `prover/prover_airbender/src/`
- **Airbender proving pipeline, proof and key formats** — [airbender_architecture.md](airbender_architecture.md#5-proving-airbender-v3)
- **Airbender image and proving service** — configuration, host requirements, behavior, known limitations — [airbender-docker-service.md](airbender-docker-service.md) — `prover/Dockerfile`, `prover/docker/airbender-entrypoint.sh` — CI `airbender-image.yml`
- **Agent skills** — fetch blocks, execute blocks, run the SP1 benchmark — `.claude/skills/`
- **Witness checks against a node** — `tools/witness/`

## ERE integration

HashState only; the ERE guest is `make ere-bin`.

- **Forks and what pins them** — [ere_integration.md](ere_integration.md#repositories-and-pins)
- **Validate, cost, compare** — [ere_integration.md](ere_integration.md#quick-start) — `tools/ere_compare.py`, `tools/ere_workload.py` — `make ere-validate`, `make ere-cost`, `make ere-compare`
- **Variables** — [ere_integration.md](ere_integration.md#tunable-variables) — the `ERE_*` variables of the `Makefile`
- **Fixtures** — [ere_integration.md](ere_integration.md#fixtures-sepolia) — `tools/ere-fetch-fixtures.sh` — `make ere-fixtures` (opt-in generation)
- **CI** — [ere_integration.md](ere_integration.md#ci) — `.github/workflows/ere-benchmark.yml`
- **MFBD host adapter (DirectState, not on the ERE path)** — `prover/stateless_validator/src/ere_eest.rs`, `mfbd.rs`

## Release

- **Steps: version, CHANGELOG section, tag** — [release.md](release.md#steps) — `.github/workflows/release.yml`
- **Published guests and their names** — [release.md](release.md#hypercube-guests) — `RELEASE_BINS` in the `Makefile` — `make release-artifacts`
- **Airbender image and assets** — [release.md](release.md#airbender-image-and-assets) — `tools/scripts/airbender_release_assets.sh`
- **Release notes and per-release results** — [`../CHANGELOG.md`](../CHANGELOG.md)

## Version pins

| What | Set by |
|---|---|
| Zilkworm version | `PROJECT_VERSION` in `CMakeLists.txt` |
| tests-zkevm corpus (HashState tests) | `ZKEVM_RELEASE_VERSION` in the `Makefile` |
| tests-zkevm-benchmark corpus and gas budget | `ZKEVM_BENCH_RELEASE_VERSION`, `ZKEVM_BENCH_ASSET` in the `Makefile` |
| EEST corpus (DirectState tests) | the `eest_stable` entry of `test-fixtures.json` |
| SP1, prover host | the `sp1-*` dependencies of `prover/prover_hypercube/Cargo.toml` |
| SP1, ERE guest key and asset name | the `sp1-sdk` tag in `prover/stateless_validator/Cargo.toml`, read into `ERE_SP1_SDK_VERSION` by the `Makefile` |
| ere, ere-guests, benchmark workload | `workload_ref` and `ere_guests_ref` in `.github/workflows/ere-benchmark.yml` |
| zvm1 | the `third_party/evmone` submodule commit |
| zksync-airbender | the `rev` in `prover/prover_airbender/Cargo.toml` |
| MFBD format | `kFlatBundleVersion` (`flat_bundle.hpp`), `kMphfMapVersion` (`mphf_map.hpp`), `kVersion` (`pre_state.hpp`) |
| Rust | `rust-toolchain.toml`, `prover/rust-toolchain.toml`, `prover/prover_airbender/rust-toolchain.toml` |
| RISC-V GCC | `.github/docker/ci.Dockerfile`, `RISCV_GCC_VERSION` in `prover/Dockerfile` |

## CI workflows

All in `.github/workflows/`.

| Workflow | Backend | Runs |
|---|---|---|
| `unit-tests.yml` | both | `zilkworm.tests` three ways: default, `-DZ6M_HASH_STATE=ON`, and `-DUSE_HASH_KEY=ON` under ASan and UBSan (the rv32 paths) |
| `eest-blockchain-tests.yml` | DirectState | `make eest-blockchain-tests` |
| `hypercube-eest.yml` | DirectState | EEST through the SP1 guest |
| `qemu-eest-blockchain.yml`, `qemu-eest-blockchain-rv64.yml` | DirectState | EEST under QEMU |
| `airbender-eest.yml` | DirectState | EEST on the Airbender simulator |
| `sp1-benchmark.yml`, `airbender-benchmark.yml` | DirectState | the 200-block corpus |
| `hypercube-slib-benchmark.yml` | HashState | `make slib-benchmark`, manual |
| `ere-benchmark.yml` | HashState | `make ere-validate`, `make ere-cost` |
| `release.yml` | both | builds and publishes a tag |
| `airbender-image.yml`, `ci-image.yml` | | the Airbender prover image, the CI image |

## Documents

| Doc | Backend | Content |
|---|---|---|
| [architecture.md](architecture.md) | both | components, dispatch, runners, public outputs |
| [directstate.md](directstate.md) | DirectState | the backend: checks, reads, root check |
| [flat_witness_bundle.md](flat_witness_bundle.md) | DirectState | MFBD byte layout, `MphfMap`, `MphfBuilder` |
| [mfbd_design_specs.md](mfbd_design_specs.md) | DirectState | normative MFBD spec |
| [mfbd_fixture_generation.md](mfbd_fixture_generation.md) | DirectState | converters, fixtures, corpora, format bumps |
| [hashstate.md](hashstate.md) | HashState | the backend: parsing, state derivation, accept check, runner, tests |
| [slib_corpus_validation.md](slib_corpus_validation.md) | HashState | running and reading the tests-zkevm corpus |
| [slib_benchmark.md](slib_benchmark.md) | HashState | the SP1 cycle benchmark |
| [ere_integration.md](ere_integration.md) | HashState | the ERE harness |
| [airbender_architecture.md](airbender_architecture.md) | DirectState | the Airbender guest and proving pipeline |
| [airbender-docker-service.md](airbender-docker-service.md) | DirectState | the Airbender image and service |
| [release.md](release.md) | both | release process |
| [code_style.md](code_style.md) | both | C++ style |
