# Changelog

## v0.1.0-alpha.7 - SP1 v6.9.0

> **Draft.** Still to come before the tag: the ERE fork moves to ere v0.19.5, any further PRs, Contributors and the Commit Log.

### Highlights

This release moves Zilkworm from SP1 v6.6.0 to SP1 v6.9.0. The prover builds on `erigontech/sp1` `erigon/patches-v6.9.0`: v6.9.0 plus `prove_with_cycles`, the one commit `erigon/patches-v6.6.0` carried, cherry-picked unchanged. The ERE leg (`derive_vk` and the published ERE guest) builds on the upstream `v6.9.0` tag, the SP1 that ere v0.19.5 resolves.

The guests are unchanged. The C++ guest issues its own `ecall`s and links no SP1 crate, and nothing it depends on in SP1 moved between v6.6.0 and v6.9.0. The verifying keys did change: SP1 v6.9.0 loads a guest ELF's initial memory correctly where v6.6.0 zeroed up to four bytes of it (succinctlabs/sp1#2981), and both Zilkworm guests hit the case. Keys published for alpha.6 do not verify alpha.7 proofs.

### SP1 v6.9.0

#### No guest ABI change

The 26 syscall codes the guest emits are byte-identical in v6.6.0, v6.9.0 and the erigontech fork, as are the ecall handlers (`executor/src/vm`, `minimal/ecall.rs`), the core machine circuits, `crates/zkvm` (entrypoint, memory layout) and the linker script. The guest's own constants (stack top `0x78000000`, 2^37 bytes of memory, the 2^34 input region, public values on fd 13) still hold. The fork's commit touches the SDK, prover and verifier only, none of the syscall surface.

#### Verifying keys (succinctlabs/sp1#2981)

When a loadable segment's file bytes end in the middle of an 8-byte word and the segment runs on past them (`memsz > filesz`, the `.data`/`.bss` boundary), v6.6.0 zeroed that whole word while laying out the `.bss` tail, dropping the last file bytes before it; v6.9.0 keeps them. The same ELF therefore has a different initial memory image, and a different program vkey, on the two versions. In both Zilkworm guests the dropped bytes are newlib's `numempty` locale sentinel (`{CHAR_MAX, 0}`). Zeroing those two bytes in the ELF gives the same key on v6.6.0 and v6.9.0, so the loader fix is the whole difference.

| ELF (sha256) | vkey on SP1 v6.6.0 | vkey on SP1 v6.9.0 |
|---|---|---|
| alpha.6 release `z6m_guest_hypercube_mfbd.elf` (`4bd40149`) | `0x005b7a791175720074007c3dffd34964652682c54cba11e7b03030d7fbb880e2` (published) | `0x003e1145d16c1e8db31ad51dd670b1f8a8eb21cc35eb5b9b50d148cda172cd3f` |
| alpha.6 release `stateless-validator-zilkworm-sp1-v6.6.0.elf` (`e94aecf0`) | `0x004af2d21b4670e678cce8ae27e26fbb35095443a7fbdf119eb4321310029938` (published) | `0x001cf4a8d52aff25605e5b3e3dd0ae48651150ff56e3dbf209493814ab28f6fe` |
| MFBD guest, local build of this release (`2182f5eb`) | `0x00f127ca1769db44b449b402dc0781b2b1fc56271144ce43a50e19b780e48151` | `0x0007f3f8b341b7489c0f1a25087c9270a8536ced378590a579f23af4581913a2` |
| SLIB guest, local build of this release (`2efd9b3b`) | `0x001fa54aad5bc91d189302b592069034edd7cf5bcd8eca8cf264cd685e1654cf` | `0x00f8816137237db3715e99509c8b88ab5cd276958ae38a0e63dc72d9fd39151f` |

The keys of the alpha.7 release assets are the ones its workflow derives; a local build has different bytes and keys.

#### Pins

| Where | v0.1.0-alpha.6 | v0.1.0-alpha.7 |
|---|---|---|
| `prover/prover_hypercube` (sp1-sdk, sp1-prover, sp1-cuda, sp1-core-executor, sp1-zkvm, sp1-build) | `erigontech/sp1` `erigon/patches-v6.6.0` (`e4fa2f0`) | `erigontech/sp1` `erigon/patches-v6.9.0` (`d6eb0ae`) |
| `prover/stateless_validator` sp1-sdk (`derive_vk`) | `succinctlabs/sp1` `v6.6.0` | `succinctlabs/sp1` `v6.9.0` |
| `Dockerfile` SP1 GPU server | `erigon/patches-v6.6.0` | `erigon/patches-v6.9.0` |
| ERE guest assets | `stateless-validator-zilkworm-sp1-v6.6.0.{elf,vk}` | `stateless-validator-zilkworm-sp1-v6.9.0.{elf,vk}` |

`prover/Cargo.lock` moves the 49 SP1 crates and `Cargo.lock` the 47 SP1 crates to 6.9.0; no other dependency changes. `make ere-bin-link` refuses a workload whose ere still resolves SP1 v6.6.0 (ere v0.18.1): the ERE workload needs ere v0.19.5.

#### Validation

- `make eest-blockchain-tests`: 12705/12705
- `tools/scripts/release_state_root_check.sh` on the 200-block mainnet corpus: 200/200, 0 state-root mismatches
- SP1 benchmark on the same corpus (`z6m_prover` on the v6.9.0 fork, local build): 200/200 blocks, gas used equal to the host's on every block; 17.75B cycles, 40.91B prover gas

## v0.1.0-alpha.6 - Native statelessInputBytes with the HashState backend

### Highlights

This release makes the SP1 Hypercube guest consume the canonical EEST stateless input directly. A second read-side state backend, **HashState** (Somnath Banerjee @somnergy, with @canepat), takes the EIP-8025 `statelessInputBytes` the ERE zkEVM benchmark feeds every guest: it decodes the SSZ `StatelessInput` (tests-zkevm v21 schema), rebuilds the pre-state from the witness trie nodes keyed by their keccak, runs the block fail-closed on it, and commits the 43-byte `StatelessValidationResult`. The MFBD host adapter of alpha.4 is no longer on the ERE path.

Releases now publish two Hypercube guests: `z6m_guest_hypercube_mfbd` (DirectState, MFBD bundles, the one `z6m_prover_hypercube` embeds) and `z6m_guest_hypercube_slib` (HashState, `statelessInputBytes`, the ERE guest). On the Sepolia batch the ERE benchmark runs, the HashState guest validates 100/100 blocks and costs 3.3% fewer SP1 cost units than the alpha.4 guest with its adapter; against Reth 0.1.0-rc.4 it is at Z/R 0.477. On the ere-guests corpus for tests-zkevm v21.0.6 it passes 33,854 of 33,854 fixtures.

ZVM1/evmone got Paweł Bylica's SP1 series: shared word-wise memory builtins, the size cost table, reviewed byte-order conversions, the jump and JUMPDEST analysis, and the batched ecrecover with GLV on the SP1 syscalls. Hypercube guest cycles on the 200-block mainnet corpus went from 23.21B at alpha.5 to 17.44B (-24.9%); the Airbender guest from 27.86B to 27.65B (-0.8%).

### HashState backend and statelessInputBytes

#### Reading the witness

`HashState` (`zilk_core/core/state_zz/hash_state.*`, built with `-DZ6M_HASH_STATE=ON`; `ActiveState` names the backend the execution surface runs on) holds the witness's trie nodes and codes in open-addressed stores keyed by keccak. `build_state_from_trie` sweeps the account trie from the parent's state root, then each account's storage trie from its root, and caches every leaf it reaches. A read the sweep cannot settle is walked as a claim of absence down the trie; a read neither cached nor proven absent counts as unconfirmed, and the accept gate rejects the block. Code is resolved by hash from the witness or from code the block itself derives (contract creations, EIP-7702 markers), so a witness may omit any code the block reproduces.

A trie path longer than the 64-nibble key, or a referenced node that does not decode, makes the witness malformed and rejects the block (a tests-zkevm v21.0.6 rule). Clearing an EIP-7702 delegation keeps the authority's storage, as on DirectState. BLOCKHASH walks the parent hashes back from the block's own header through the witness headers, memoized per block: an ancestor is never found by its number, and a header the walk does not reach is an unconfirmed read.

#### Executing and accepting a block

`run_sib` decodes the `NewPayloadRequest` (Gloas shape: `ExecutionPayloadV4`, versioned hashes, parent beacon block root, EIP-7685 request lists), takes its hash tree root, rebuilds the block (transactions and withdrawals roots, requests hash with EIP-8282 builder requests, block access list hash) and checks its hash and versioned hashes against the request, as the MFBD path does. The witness headers must chain by parent hash and end at the block's parent, whose state root anchors the pre-state. From Osaka a block whose canonical RLP exceeds `MAX_RLP_BLOCK_SIZE` (EIP-7934) is rejected. After execution, `check_root_hashstate` folds the block's writes over the parent root with `GridMPT` and accepts only a block whose root matches with every read confirmed.

The guest dispatches on the input's first bytes: `MFBD`, `EJSN`, or the `0x1501` schema prefix of a raw stateless input (`kInputMagicSIB`). An input that does not decode yields the all-zero result, as the spec requires. The public values are `{new_payload_request_root, successful_validation, chain_id, schema_id}`, compared by ere-hosts with the fixture's `statelessOutputBytes`.

#### Corpus results

- ere-guests `executes_registered_guest` on tests-zkevm v21.0.6 (SP1): 33,854/33,854, no expected failures; the cases the other guests list as expected failures pass.
- `make eest-zkevm-tests` (the JSON corpus through the HashState runner): 3450/3450 files, 124 skipped for lacking a witness. The witness-validation negatives (deliberately broken witnesses on valid blocks) are scored pass iff rejected; an expected-invalid label is waived only when the witness pruned an account a validation gate reads.
- SSZ merkleization is checked against the ere-guests reference roots; the sample fixture test rebuilds a v21 block from its payload and matches its `statelessOutputBytes`.

Documentation: `docs/hashstate.md` (design), `docs/slib_corpus_validation.md`, `docs/slib_benchmark.md`.

### ERE integration

- `make ere-bin` stages the HashState guest under the name ere-hosts loads; `z6m_guest_vk` derives the MFBD guest's key; `release-artifacts` publishes both guests. The `ERE Benchmark` workflow runs the SLIB guest, from the ref or from a release's `z6m_guest_hypercube_slib` assets.
- The erigontech forks of `zkevm-benchmark-workload` and `ere-guests` (`canepat/zilkworm_mfbd`) feed Zilkworm the raw `statelessInputBytes` like every other guest; the adapter crate and its dependencies are gone from them.
- Sepolia, blocks 11905100..11905199, `estimate-cost` (SP1 v6.6.0, ere v0.18.1):

| Client | output_matched | Total estimated cost | Z/R |
|---|---|---|---|
| Zilkworm (HashState guest) | 100/100 | 7,397,962,138,984 | **0.477** (median 0.473; cheaper on 98/100) |
| Reth 0.1.0-rc.4 | 98/100 | 15,498,357,778,963 | |
| Zilkworm v0.1.0-alpha.4 (DirectState guest + adapter) | 100/100 | 7,653,392,292,202 | 0.494 |

  Reth's two mismatched blocks are the only ones where it is cheaper: it stops early on them.
- tests-zkevm-benchmark v21.0.5, 30M-gas blocks, through ERE's cost estimator: 1109 cases, median 36.06B, total 65.72T; the `make slib-benchmark` route (raw SP1 cycles) covers 1200 of its 1203 cases, median 259.6M. The run found the unmemoized BLOCKHASH walk (`test_blockhash[block_1]`, 4.12T → 47B).

### Fixes and improvements

#### ZVM1/EVMone and the guests

- Calldata non-zero bytes counted per aligned word on both guests (#119)
- SP1 built with `-mtune=size` (and `-mstrict-align`), Airbender with `-mbranch-cost=1`: GCC's default cost table prices branches, multiplies and divides as the rocket core does, while both zkVMs charge one cycle per instruction (#120)
- One set of memcpy, memmove, memset and memcmp for both guests, working in aligned machine words (#121)
- evmone (erigontech/zvm1) with reviewed byte-order conversions: MLOAD/MSTORE word loads, PUSH data and CALLDATALOAD assembled big-endian in place, SP1 converting byte order as Airbender does (#122); the jump and JUMPDEST analysis: code run in place on SP1 with a lazy JUMPDEST byte map, fused PUSH2 JUMP/JUMPI and comparison jumps (#123, #125); the SP1 ecrecover with the batch's shared inversion, the GLV split and scalar arithmetic on the `uint256_mulmod` syscall (#124)

Guest cycles on the 200-block mainnet corpus (`Hypercube 200-block Bench`, `Airbender 200-block Bench`), exact cycle counts and gas parity on all 200 blocks:

| After | Hypercube cycles | Change | Airbender cycles | Change |
|---|---|---|---|---|
| v0.1.0-alpha.5 (`ba41c7c`; evmone v0.25.0, #114) | 23.21B |  | 27.86B |  |
| Calldata non-zero bytes per aligned word (#119) | 23.16B | -0.2% | 27.85B | ±0.0% |
| SP1 `-mtune=size`, Airbender `-mbranch-cost=1` (#120) | 23.06B | -0.4% | 27.80B | -0.2% |
| Shared word-wise memcpy/memmove/memset/memcmp (#121) | 22.16B | -3.9% | 27.71B | -0.3% |
| evmone: reviewed byte-order conversions (#122) | 20.12B | -9.2% | 27.69B | -0.1% |
| evmone: jump and JUMPDEST analysis (#123, #125) | 18.61B | -7.5% | 27.65B | -0.2% |
| evmone: SP1 ecrecover batch, GLV, syscall arithmetic (#124) | 17.44B | -6.3% | 27.65B | ±0.0% |
| HashState backend and statelessInputBytes path (#32) | 17.44B | ±0.0% | 27.65B | ±0.0% |
| Two Hypercube guests, ERE on SLIB (#130) | 17.44B | ±0.0% | 27.65B | ±0.0% |

Over the release: Hypercube 23.21B → 17.44B (-24.9%), Airbender 27.86B → 27.65B (-0.8%). The HashState backend and the release plumbing leave the DirectState guests these benches run cycle-neutral.

#### Airbender service

- Every fetch is bounded (`--fetch-timeout`, default 60 s; 10 s for `eth_blockNumber` and the newHeads subscription), so a witness request past reth's 300 s read-transaction limit no longer stalls the service for 75 minutes per block; the service stays near the chain tip instead of working through a backlog (#127)

#### Tests and CI

- EEST fixtures pinned to tests@v21.0.1 for every job (#116); `tx_invalid_first_in_block` is a known failure of the DirectState runner, which runs a test's blocks on one witness in place, and passes on the HashState arm
- `Unit Tests` builds and runs the HashState backend (`unit-tests-hashstate`); `make eest-zkevm-tests` runs the tests-zkevm corpus (v21.0.6, version-keyed cache) through it, `make slib-benchmark` the benchmark corpus
- The release workflow builds the guest twice and publishes both; the ERE benchmark takes the SLIB one

### Contributors

| Author | Commits |
|---|---|
| Paweł Bylica @chfast | 8 |
| Somnath Banerjee @somnergy | 3 |
| @canepat | 1 |

### Commit Log by Category (12 non-merge commits since v0.1.0-alpha.5)

#### HashState & ERE

- `25b9ee2` Add HashState backend and direct StatelessInputBytes input path (#32) (Somnath Banerjee @somnergy, with @canepat)
- `ceafbf8` ci: publish the MFBD and SLIB hypercube guests, ERE on SLIB (#130) (@canepat)

#### ZVM1/EVMone & Guests

- `8bcc9b8` common_zz: count calldata non-zero bytes per aligned word on both guests (#119) (Paweł Bylica @chfast)
- `6ce7618` guest: build SP1 with -mtune=size, Airbender with -mbranch-cost=1 (#120) (Paweł Bylica @chfast)
- `d5deb51` guest: one set of memcpy, memmove, memset and memcmp for both guests (#121) (Paweł Bylica @chfast)
- `a78cbcc` third_party: evmone with reviewed byte-order conversions for both guests (#122) (Paweł Bylica @chfast)
- `9c4327a` third_party: evmone with the jump and JUMPDEST analysis changes (#123) (Paweł Bylica @chfast)
- `d6152d0` third_party: evmone with the jump destination kept whole on 32-bit builds (#125) (Paweł Bylica @chfast)
- `a6ed4df` third_party: evmone with the SP1 ecrecover batch, GLV and syscall arithmetic (#124) (Paweł Bylica @chfast)

#### Airbender Service

- `46caa9f` Airbender service: bound block fetches and stay near the chain tip (#127) (Somnath Banerjee @somnergy)

#### Tests, CI/CD & Release

- `19fc573` eest: bump fixtures to tests@v21.0.1 (#116) (Paweł Bylica @chfast)
- `2b4bd5f` Bring the v0.1.0-alpha.5 release notes into main (#128) (Somnath Banerjee @somnergy)

## v0.1.0-alpha.5 - Real-time proving with Airbender v3

### Highlights

This release introduces support for Airbender ([ZKsync Airbender](https://github.com/matter-labs/zksync-airbender) v3, rv32im) as Zilkworm's second zkVM, next to SP1 Hypercube: an rv32 guest whose precompiles and 256-bit arithmetic run on Airbender's delegation circuits, a 32-bit build of ZVM1/evmone, a GPU prover on the Airbender v3 stack and a published Docker image.

The latest result with Ethproofs provenance is a median proving time of 3.4 s with 2x RTX 5090 on a single node: 200 consecutive mainnet blocks, all proved, the slowest in 6.1 s (Matter Labs' on-prem cluster, 15 October 2026). On 4x RTX 5090 the same guest proves at a 2.58 s median.

This is real-time, same-slot proving territory: a block is proved well inside its 12-second slot, even with network and witness generation delays included.

### Airbender path

#### Precompiles

The guest uses two Airbender v3 delegations: BigInt (256-bit add, subtract, multiply, compare and copy on aligned operands) and keccak_f1600 (one Keccak permutation). Every precompile that does modular arithmetic does it on BigInt, and everything that hashes does so on keccak_f1600; the curve and scalar logic around them stays RISC-V code in ZVM1/evmone.

| Precompile | Delegation | Code path |
|---|---|---|
| ECRECOVER (0x01), and the sender recovery of every transaction | BigInt | evmone's secp256k1 with Montgomery field arithmetic on BigInt; a GLV-split MSM over precomputed tables; a block's senders recovered as one batch with shared inversions |
| SHA256 (0x02), RIPEMD160 (0x03), IDENTITY (0x04), BLAKE2F (0x09) | none | plain rv32 code |
| MODEXP (0x05) | BigInt | Montgomery exponentiation on BigInt for 256-bit base and modulus; the generic path otherwise |
| ECADD, ECMUL, ECPAIRING (0x06..0x08) | BigInt | bn254 field arithmetic on BigInt; ECMUL by signed-digit tables of the GLV halves |
| POINT_EVALUATION (0x0a), BLS12-381 (0x0b..0x11) | BigInt | blst, patched at build time so its 384-bit Montgomery multiplication runs as a few BigInt calls; KZG point evaluation with one Miller loop |
| P256VERIFY (0x100) | BigInt | evmone's generic Montgomery field template, whose rv32 paths are on BigInt |
| KECCAK256, and every hash the guest computes (trie nodes, transactions, receipts, addresses, code) | keccak_f1600 | one delegation run per permutation, replacing the heavier KeccakSpecial5 circuit; KECCAK256 inputs memoized per block and trie hashing resumed from a saved sponge state |

The EVM's own 256-bit add, subtract and multiply, and its 32-byte copies, use the BigInt delegation as well. The keccak_f1600 delegations alone cut the median proving time on 2x RTX 5090 by 21% (5.14 s to 4.06 s on 200 mainnet blocks).

#### 32-bit optimizations

The guest (`prover/guest_airbender`) is a bare-metal rv32im program in a 4 MiB ROM with a bump heap, fed through the CSR oracle. It commits the hash of the last block it validated, which binds the parent's state root and the block's post-state root, gas used and receipts root (#39). A post-link check rejects the instructions Airbender v3 cannot run.

Zilkworm and ZVM1/evmone were written for 64-bit hosts, so the rv32 build got its own paths, all under `AIRBENDER`:
- EVM memory in a big-endian word layout, so MLOAD, MSTORE and CALLDATALOAD copy words instead of reversing bytes; byte order is converted once at each boundary (code, calldata, logs, hashes, precompile inputs)
- 256-bit values loaded and stored word by word, and 256-bit division done on 32-bit words
- The interpreter charges gas and checks bounds in 32 bits, does shifts, ADDMOD, SIGNEXTEND and power-of-two EXP on words, and fuses common opcode pairs (PUSH with arithmetic and jumps, comparisons with the jump they decide)
- Fewer copies on the hot path: call frames, environment values, LOG topics and receipts handled in place
- Witness and trie code that hashes nodes straight from the witness, patches branches in place and compares keys by words
- Inline memcpy/memset fast paths and a pointer-bump allocator; word accesses through may_alias types with a build guard

Guest cycles on the 200-block mainnet corpus (`Airbender 200-block Bench`), each step measured with exact cycle counts and gas parity on all 200 blocks:

| After | Cycles | Change |
|---|---|---|
| Airbender integration (#28) | 54.23B | |
| Guest performance (#31) | 39.21B | -27.7% |
| Round 4 (#34) | 33.51B | -14.5% |
| Witness soundness fixes and follow-ups (#35..#90, #108) | 34.10B | +1.8% |
| Round 5: 35 optimizations (#105) | 32.19B | -5.6% |
| `USE_HASH_KEY` recovery on by default (#112) | 32.76B | +1.8% |
| keccak_f1600 delegations, keccak prefix resumes, KECCAK256 memos, BLOCKHASH cache (#113) | 28.00B | -14.5% |
| evmone v0.25.0 (#114) | 27.86B | -0.5% |

#### Proving pipeline and service

`prover/prover_airbender` is the Airbender prover, on the same v3 stack as Matter Labs' [ethereum-prover](https://github.com/matter-labs/ethereum-prover) and with the same proof and verification-key formats, so Ethproofs verifies its proofs with its standard Airbender verifier. It has `execute`, `vk`, `prove`, `bench` and `verify` commands. A preflight run must commit the block's hash before the block is proved, and the proof must commit the same hash; a block the guest rejects is skipped instead of aborting the prover (#111).

The z6m prover service got an Airbender code path as well (`--service`): it follows the chain tip, converts each block's witness to MFBD in-process, proves every N-th block and reports `queued`, `proving` and `proved` to Ethproofs, retrying a failed `proved` post (#113).

Igor Borodin (@hatemosphere) wrote the prover's first `verify` and `bench` commands, its Ethproofs envelopes, the service's tip-following latency work, and the node-store recovery of storage slots whose preimage the witness omits.

The Docker image `ghcr.io/erigontech/zilkworm-airbender` is public and runs as is on A100, Ada, Hopper and RTX 50xx GPUs, on your own hardware or on vast.ai; it is configured through environment variables (see `docs/airbender-docker-service.md`). It is tagged per commit on main and per release, and each release attaches its guest and verification key. A new guest means a new key, so an Ethproofs cluster that moves to this release needs this release's key before its proofs show as verified.

### Fixes and improvements

#### Witness and state validation

Every value the guest reads from the witness, and every claim that an account or storage slot is absent, is now checked against the parent block's state root. This applies to both guests:
- Failed trie walks and claimed values at absent keys reject the block (#35, #36)
- Storage is checked against the account's storage root, including the slots of accounts the block wipes, and every slot starts from its verified value (#37, #38, #51)
- Reads of accounts and slots the witness leaves out are walked as claims of absence (#69); EIP-7610 collisions are decided by the verified storage root (#53)
- A bundle of blocks must carry the whole state and each block must follow the one before it (#39, #63); BLOCKHASH is checked against the chain of parent hashes (#71)
- Malformed witnesses are rejected (#70, #77)
- GridMPT: a wrong root on an honest witness when a branch collapses to a single child is fixed (#59), plus smaller trie fixes (#60..#62)

#### Execution (all guests)

Less copying and re-encoding on the hot path: transaction hashes and the transactions root reuse the canonical RLP, receipts are encoded in one pass, transaction data goes to the EVM as a view, and ecrecover copies only what it reads (#16, #17, #18, #67, #88).

#### ZVM1/EVMone changes

- ZVM1 now corresponds to upstream evmone v0.25.0 (Amsterdam) plus the zkVM work, up from v0.24.0 (#114). The Airbender precompile and rv32 work above lives in evmone (erigontech/zvm1) and its vendored intx
- intx is vendored inside evmone instead of being a submodule (#107)
- Fixes in gas and MODEXP length arithmetic and in CALLDATALOAD at the end of the input; see the upstream evmone changelog for everything else

#### Tests and CI

- The pinned EEST blockchain tests (tests@v20.0.1) now also run through the Airbender guest: 8595 of 8618 pass, the 23 others hit known resource limits, and any new failure fails CI
- `Airbender 200-block Bench` tracks the guest's exact cycles on the 200-block corpus
- `Airbender Prover Image` builds and publishes the GPU image; the release workflow tags it with the release and attaches the guest and verification key
- The rv32 paths are tested under ASan and UBSan (#108)

### Contributors

| Author | Commits |
|---|---|
| Somnath Banerjee @somnergy | 45 |
| Igor Borodin @hatemosphere | 2 (on `release/airbender`, landed on main in #28) |
| Paweł Bylica @chfast | 2 |
| @canepat | 1 |

### Commit Log by Category (48 non-merge commits since v0.1.0-alpha.4, plus the 2 from `release/airbender` squashed into #28)

#### Airbender: Guest, Prover & Service

- `253e1b3` Airbender integration: rv32 guest, GPU prover and service (#28) (Somnath Banerjee @somnergy)
- `ee068e9` prover_airbender: verify/bench subcommands, tip-following latency, ethproofs envelopes (#11 on `release/airbender`, in #28) (Igor Borodin @hatemosphere)
- `96cf016` fix(state): recover storage slots from node-store when witness omits the preimage (#12 on `release/airbender`, in #28) (Igor Borodin @hatemosphere)
- `56c1a7f` Airbender rv32 guest performance: −27.7% cycles on the 200-block corpus (#31) (Somnath Banerjee @somnergy)
- `df31566` Airbender rv32 guest performance, round 4: −14.5% cycles on the 200-block corpus (#34) (Somnath Banerjee @somnergy)
- `ba48a7b` Round 5: 35 more rv32 guest optimizations (34.10B -> 32.19B cycles) (#105) (Somnath Banerjee @somnergy)
- `a015aff` Airbender v3: prover on the v3 stack, GPU image published to GHCR (#109) (Somnath Banerjee @somnergy)
- `3dfc681` Airbender: report the prover's own proving time, preflight before proving (#111) (Somnath Banerjee @somnergy)
- `6227575` guest_airbender: build with node-store account recovery (USE_HASH_KEY) by default (#112) (Somnath Banerjee @somnergy)
- `cc2f0b3` Airbender perf: keccak_f1600, keccak prefix resumes, memos, BLOCKHASH cache (#113) (Somnath Banerjee @somnergy)
- `3e4553a` guest_airbender: commit the last block's hash and check it on the host (#39) (Somnath Banerjee @somnergy)
- `d24c2b9` guest_airbender: guard the gp window in the linker script, relink on its change (#41) (Somnath Banerjee @somnergy)
- `e6f772e` prover: take CMake 3.31.6 from Kitware in the Airbender Docker image (#83) (Somnath Banerjee @somnergy)

#### Witness Format, State & Pre-Trie Validation

- `b81b96f` dev: check the storage walk of an unmodified account against its root (#37) (Somnath Banerjee @somnergy)
- `b5f5ef5` state_zz: start every witness slot at its initial value (#38) (Somnath Banerjee @somnergy)
- `ef0c726` dev: check the witness slots of an account the block wipes against its root (#51) (Somnath Banerjee @somnergy)
- `2dc4c04` state_zz: decide create collisions by the storage root, not the witness slots (#53) (Somnath Banerjee @somnergy)
- `a78a662` dev: require the witness of a multi-block bundle to hold the whole state (#63) (Somnath Banerjee @somnergy)
- `d0e1932` dev: walk the reads of absent accounts and slots as claims of absence (#69) (Somnath Banerjee @somnergy)
- `72cfeae` state_zz: require strictly ascending slot keys in witness records (#70) (Somnath Banerjee @somnergy)
- `7a9ee65` state_zz: bind BLOCKHASH to the parent hashes back from the block (#71) (Somnath Banerjee @somnergy)
- `6161d13` state_zz: reject witness blobs whose sections or records overlap (#77) (Somnath Banerjee @somnergy)

#### Merkle Patricia Trie

- `6d74e22` trie_zz: flag failed trie walks in release builds and reject them (#35) (Somnath Banerjee @somnergy)
- `40df7e8` trie_zz: reject a claimed pre-value for a key absent from the trie (#36) (Somnath Banerjee @somnergy)
- `d7fd184` trie_zz: fold a single-child branch's new extension into its parent at once (#59) (Somnath Banerjee @somnergy)
- `55310d0` trie_zz: keep empty leaves out of the grid (#60) (Somnath Banerjee @somnergy)
- `0e9c676` trie_zz: allocate the grid once, at the most lines a depth can name (#61) (Somnath Banerjee @somnergy)
- `238fba1` trie_zz: mask the saved block count before indexing kHeadSlots (#62) (Somnath Banerjee @somnergy)

#### Protocol & Core EVM

- `17e0773` types: reuse the canonical tx RLP for the tx root and hash (#16) (Somnath Banerjee @somnergy)
- `907ef60` types: thread_local RLP scratch for hash and sender pre-images (#17) (Somnath Banerjee @somnergy)
- `b423c68` execution: pass tx.data to evmone as a view (#18) (Somnath Banerjee @somnergy)
- `d002a33` execution: copy at most the 128 bytes that ecrecover reads (#67) (Somnath Banerjee @somnergy)
- `09f25f9` execution: test bn254 multiplication; take evmone's width-5 NAF ECMUL (#87) (Somnath Banerjee @somnergy)
- `622b65b` types: write each receipt's RLP in one pass (#88) (Somnath Banerjee @somnergy)
- `24c59f7` execution: test comparison jump fusions; take evmone's fusions (#89) (Somnath Banerjee @somnergy)

#### ZVM1/EVMone & Third Party

- `0b03bb8` third_party: evmone with the upstream 0.25.0 Amsterdam (#114) (Paweł Bylica @chfast)
- `c732b33` third_party: drop intx submodule, vendor intx inside evmone (#107) (Paweł Bylica @chfast)
- `26f0791` third_party: evmone with the strict-alignment keccak test build linking again (#44) (Somnath Banerjee @somnergy)
- `46f9226` third_party: evmone with word copies between word-layout buffers at any alignment (#58) (Somnath Banerjee @somnergy)
- `3fe6854` third_party: evmone with its own suite running under the word layout (#65) (Somnath Banerjee @somnergy)
- `9b53b67` third_party: evmone with the MODEXP lengths added in 64 bits (#66) (Somnath Banerjee @somnergy)
- `7beea77` third_party: evmone and intx with word accesses through may_alias types (#85) (Somnath Banerjee @somnergy)
- `435b7ed` third_party: evmone with shift_words through named word pointers (#90) (Somnath Banerjee @somnergy)

#### Tests, CI/CD & Workflows

- `34cbe75` dev/cli: keep jumpdest_map_test building with sanitizers (#42) (Somnath Banerjee @somnergy)
- `edc7886` ci: build the Airbender guest with the pinned riscv-none-elf-gcc 15.2.0-1.1 (#43) (Somnath Banerjee @somnergy)
- `0ea960f` cmake: build evmone's blst Airbender patch test with zilkworm.tests (#45) (Somnath Banerjee @somnergy)
- `b307a6e` tests: compare logs and cover hashes, copies and precompiles in the word layout (#57) (Somnath Banerjee @somnergy)
- `346afc4` Airbender follow-ups: fix main's unit tests, test the rv32 paths under sanitizers (#108) (Somnath Banerjee @somnergy)
- `d8743c5` Fix main's unit-test and EEST jobs after round 5 (#110) (Somnath Banerjee @somnergy)

#### Release

- `c9b87d5` Bring release/0.1.0-alpha.4 ERE work into main (#115) (@canepat)

## v0.1.0-alpha.4 - ERE stateless input, stateless new-payload checks and Sepolia

### Highlights

This release lets Zilkworm consume the canonical EEST stateless input (tests-zkevm v21.0.1) used by the ERE zkEVM benchmark, so the same guest validates Sepolia blocks inside `zkevm-benchmark-workload`. The guest now applies the new-payload and witness checks a stateless validator owes the claimed block, and rejects blocks whose execution needs data the witness omits. Releases publish the guest verification key and end with an ERE benchmark run against the published guest.

#### ERE stateless input (statelessInputBytes -> MFBD)

The host adapter `prover/stateless_validator` decodes EEST `statelessInputBytes` and translates it into the MFBD envelope consumed by the guest:
- Decoding via ere-guests `stateless-validator-common` v0.18.0, tracking the tests-zkevm v21.0.1 schema
- Witness preimage keys derived from the Block-Level Access Lists (EIP-7928) for post-Amsterdam blocks
- EIP-8282 builder deposit and exit requests folded into `requests_hash`
- Network selected by chain id: `sepolia` (11155111, Amsterdam at 1791294816), `glamsterdam-devnet-7`, `glamsterdam-devnet-8`, and chain id 1 for the generated EEST benchmark corpus (Amsterdam from genesis)
- Claimed block hash and versioned hashes carried per block as an MFBD engine record (`kBlockFlagEngineRecord`)
- Expected public values (gas used, pre/post-state root, block hash, chain id) derived on the host for comparison with the guest commitment; a block expected to be invalid commits zeros and the chain id

Rust toolchain bumped to 1.95.0.

#### Stateless validation

- Engine checks per execution-specs `execute_new_payload_request`: claimed block hash and blob versioned hashes (EIP-4844) against the block
- Witness headers must each decode as exactly one header, link by parent hash and end at the parent block; host-provided BLOCKHASH entries are checked against them
- Code or block hashes missing from the witness mark the block invalid instead of aborting the guest
- Accounts created and destroyed within the block are proven absent from the parent state trie
- A block rejected at the state-root check no longer leaks its pre-state root into the public values

Validated under SP1 on tests-zkevm v21.0.1: 33,635 / 33,637 `output_matched`; the 2 failures are BAL fixtures also expected to fail for Reth.

#### ERE benchmark integration

- `make ere-bin` builds the guest ELF and derives its SP1 VK (32-byte digest) in the layout expected by `ere-hosts`; `ere-bin-link` links it under the SP1 SDK version of the ere the workload resolves
- `make ere-validate` runs the guest through `ere-hosts --action execute` and gates on `output_matched`
- `make ere-compare` runs `--action estimate-cost` for Zilkworm and Reth and compares SP1 estimated prover cost (`opcode`, `syscall`, `system` components)
- `tools/ere-fetch-fixtures.sh` downloads and sha256-verifies R2 catalog batches (`first`, `all`, `latest N`), Sepolia by default
- `tools/ere_compare.py` and `tools/compare_ere_benchmarks.py` read the ere >= v0.17 metrics schema and report legacy cycles and estimated cost separately
- `tools/scripts/eest_runner.py` reports SP1 cycle and prover-gas distributions
- See `docs/ere_integration.md` for the details about environment and workflow

Validated on the latest Sepolia batch (blocks 11899400..11899499): 100 / 100 `output_matched`. Estimated prover cost on blocks 11871300..11871399 is 0.500x Reth 0.1.0-rc.4's (Zilkworm cheaper on 98 / 100).

#### Prover

- SP1 v6.6.0, up from v6.0.2; the prover builds on `erigontech/sp1` `erigon/patches-v6.6.0` (v6.6.0 plus `prove_with_cycles`) with the `cuda` feature
- C++ witness converter embedded via FFI instead of spawning a binary
- SP1 guest built with wider GCC inlining and loop unrolling (-2.30% cycles); byte swaps expanded inline on rv64im

#### Performance and Fixes

- Keccak calls memoized; `zeroless_view` uses an aligned u64 stride and branchless compare
- Calldata bytes counted once per transaction; no per-transaction copies of calldata and RLP envelopes
- GridMPT copies and patches the branch RLP on fold instead of re-encoding
- `MphfCollisionEntry::offset` widened to u64
- `USE_HASH_KEY` node-store account recovery restored (default off)
- evmone built without its built-in tracers
- MFBD design and specification document (`docs/mfbd_design_specs.md`)

#### CI

- New `ERE Benchmark` workflow: builds the guest at the run's ref or downloads a published release guest (sha256-checked against `SHA256SUMS.txt`), fetches the latest N R2 batches (default: Sepolia, 1 batch, matching upstream `eest-r2-stateless-inputs`), and validates; optional cost comparison against Reth
- Runs on push to `release/*` branches, on `workflow_dispatch`, and from the release workflow
- Release workflow builds and publishes the guest VK and finishes with an ERE benchmark of the published guest, cost comparison enabled
- EEST jobs reuse the build directory, extract only `blockchain_tests` and cache fixtures; unit tests run in the `zilkworm-ci` image

#### ZVM1/EVMone changes

ZVM1 (now corresponds to evmone v0.24.0 plus the Amsterdam picks, up from v0.23.0)
- Code written earlier in the same transaction is served from the transaction's code writes when the witness omits it
- EIP-7702: the delegate's code is read during call target resolution, before a value-transfer failure, as in execution-specs
- `Transaction::data` is a non-owning `bytes_view`
- Keccak calls the zkVM permutation directly and absorbs input with aligned 64-bit loads
- Faster jumpdest analysis on RISC-V
- EVMC hash types word-aligned and passed to the C++ host by reference
- safegcd for 256-bit modular inversion
- Built-in tracers optional (`EVMONE_TRACING`)
- Upstream fixes: account nonexistence restored when a cold access is reverted, widened blob fee in the affordability check, state-independent CALL costs charged first
- Please check the upstream evmone changelog for the full list of changes

### Contributors

| Author | Commits |
|---|---|
| Somnath Banerjee @somnergy | 11 |
| Paweł Bylica @chfast | 3 |
| @canepat | 2 |

### Commit Log by Category (16 non-merge commits since v0.1.0-alpha.3)

#### Witness Format, State & Pre-Trie Validation

- `7191202` mphf: widen MphfCollisionEntry::offset to u64 (#176) (Somnath Banerjee @somnergy)
- `e4bdce4` state_zz: re-add USE_HASH_KEY node-store account recovery (default off) (#130) (Somnath Banerjee @somnergy)
- `66f8500` Add MFBD design and specifications document (#174) (Somnath Banerjee @somnergy)

#### Merkle Patricia Trie

- `e89f3bc` grid_mpt: copy-and-patch the branch RLP on fold instead of re-encoding (#169) (@canepat)

#### Protocol & Core EVM

- `af9274b` protocol: count calldata bytes once per tx (#179) (Somnath Banerjee @somnergy)
- `26dc926` types/trie: avoid per-tx copies of calldata and RLP envelopes (#178) (Somnath Banerjee @somnergy)
- `3a88e8c` core: memoize keccak calls (#139) (Somnath Banerjee @somnergy)
- `da094a9` common: use aligned u64 stride and branchless compare for `zeroless_view` (#121) (Somnath Banerjee @somnergy)
- `416d457` Build evmone without its built-in tracers (#168) (Paweł Bylica @chfast)
- `bf1d76b` evmone: point the submodule at the zvm1 oss branch (Somnath Banerjee @somnergy)

#### Prover & Guest

- `14e1df3` Add ERE stateless-input path and release ERE benchmark (#15) (@canepat)
- `7d73e94` prover: embed C++ witness converter via FFI instead of spawning a binary (#137) (Somnath Banerjee @somnergy)
- `52dafac` guest: Widen GCC inlining and unroll loops on the SP1 guest (-2.30% cycles) (#164) (Paweł Bylica @chfast)
- `a4a46de` guest: Expand byte swaps inline on rv64im (#157) (Paweł Bylica @chfast)

#### CI/CD & Workflows

- `0066de2` ci: use zilkworm-ci image in unit tests workflow (#33) (Somnath Banerjee @somnergy)
- `dcea126` ci: reuse build dir, extract only blockchain_tests, cache fixtures (#135) (Somnath Banerjee @somnergy)

## v0.1.0-alpha.3 - MFBD witness format, pre-trie validation and Amsterdam

### Highlights

This release introduces a new witness flat format - the MFBD (MPHF-based Flat Bundle). It dramatically increases the performance of the guest while reducing the memory footprint of witness- and state-related operations. It also introduces several performance enhancements, upgrades to EVMOne, bug fixes and CI changes.

#### MFBD

Rather than passing in a giant blob of SSZ or RLP-encoded byte-string, we create a quasi-Minimal Perfect Hash function on the host for the plain-state and nodes list. This is `reinterpret_cast`ed by the guest as a memory-mapped region directly.
With some added validations, this provides the guest with a cheap and performant map to access all of the plain and trie-state.
Several CI enhancements go along with it to transpose EESTs into MFBD and running them through the guest program on all supported architectures. See `docs/flat_witness_bundle.md` for the layout and the CHD construction.

#### GridMPT and Pre-Trie Validation

GridMPT algorithm now augments the pre-trie validation along with the post-trie calculation, playing with the MFBD directly. Instead of creating a separate pass, we execute transactions optimistically while recording empty reads, read-only touches and the modified state. All state touches are lined up and sorted by the hash of the addresses and unfolded for verification, not just the modified state. This ensures a wrong post-state cannot be proven or a pre-state cannot be spoofed that's different from the parent header even with a corrupt witness.

Along with it, a set of GridMPT fixes found while hardening the new path:
- Out-of-bounds read in the extension-child copy
- Extension split on fold orphaning the newly created branch
- Crash in the deletion-enabled trie when deletes empty the trie mid-batch
- Failures that were previously swallowed inside GridMPT now surface through a `failed` flag and abort the run
- Single-child branch folding into an extension now installs the child reference
- Redundant branch copy on fresh decode removed

#### Amsterdam (Glamsterdam devnet-8)

The Amsterdam fork is wired through the chain config, the header rules and block execution, with ZVM1 pointed at the matching upstream picks:
- EIP-8037: State creation gas cost increase (two-dimensional block gas, EIP-7778 header commitment)
- EIP-8038: State-access gas cost update
- EIP-2780: Resource-based intrinsic transaction gas
- EIP-7928: Block-Level Access Lists (`blockAccessListHash` header field, BAL construction)
- EIP-7843: `slotNumber` header field
- EIP-8282: Builder execution requests

Verified against the EEST `tests-glamsterdam-devnet@v8.1.1` corpus: 11908 pass / 1 skip / 0 fail. The HyperCube EEST workflow now runs against this corpus on the release branch.

#### Proof binding

The Hypercube guest now commits the chain id, pre-state root, post-state root and block hash as SP1 public values, so a proof is bound to a specific block and parent state rather than only to the guest program.

#### Tests and Benchmarks

- Catch2 unit tests (`zilkworm.tests`) introduced and run in CI on PRs and pushes
- EEST fixtures are no longer a git submodule: pinned, sha256-verified release tarballs (`test-fixtures.json`, `make test-fixtures`), currently `tests@v20.0.1`
- EEST runner requires strict `expectException` matching and the CI job now fails on any fixture failure instead of a threshold
- Integrated into the ERE zkEVM benchmark workload (previously shipped as `v0.1.0-alpha.2-ere`)
- `z6m_prover --download-only` to pre-fetch a block range for later execution or proving

#### Cleanup and Fixes

- Clearing an EIP-7702 delegation no longer wipes the authority's storage
- MFBD collision sidecar entries take their length from the data-section header
- Restored the SP1 syscall-accelerated ZVM1 lineage (keccak, secp256k1, mulmod, patched blst) after the branch was briefly pointed at a non-SP1 evmone
- Dropped the v1 EVM host legacy path and the remaining bor code
- Build on macOS with the xPack RISC-V toolchain auto-detected by the Makefile (first external contribution, thanks @developeruche)
- Fixed the cargo cache sources for the prover build

#### ZVM1/EVMone changes

ZVM1 (now corresponds to evmone v0.23.0 plus the Amsterdam picks listed above, up from v0.21.0)
- SP1 ecrecover MSM handles P+Q == infinity instead of panicking on adversarial input
- EIP-7954: Increase maximum contract size
- Transaction and RLP decoding moved into the state library, sender recovery from the signature, chain id validation
- Non-malleable secp256k1 ecrecover mode; sliding-window and fixed-window modexp
- Journal and account layout slimmed down, EVMC capabilities feature removed
- Please check the upstream evmone changelog for the full list of changes

### Contributors

| Author | Commits |
|---|---|
| Paweł Bylica @chfast | 14 |
| @canepat | 12 |
| Somnath Banerjee @somnergy | 11 |
| Developer Uche @developeruche | 1 |

### Commit Log by Category (38 non-merge commits since v0.1.0-alpha.2)

#### Witness Format, State & Pre-Trie Validation

- `8faa1712` mphf: Take a sidecar entry's length from the data-section header (#173) (Paweł Bylica @chfast)
- `b71b8523` state: Keep account storage when an EIP-7702 delegation is cleared (#159) (Paweł Bylica @chfast)
- `7d0a7414` feat: Witness pre-validation and flat-minimally-perfect-hash-function based state management (#90) (Somnath Banerjee @somnergy)
- `66b9f8dd` direct_state: always create object for empty read and check duplicate addr_hash in check_root (#138) (Somnath Banerjee @somnergy)
- `eb429442` direct_state: add slot-orphan-collision-swap/read-spoofing and honest-path tests suites (#101) (@canepat)
- `9d44bace` tools: add debug_executionWitness validation scripts (#102) (@canepat)

#### Merkle Patricia Trie

- `57df9c44` grid_mpt: install the child reference when a single-child branch folds into an extension (#147) (@canepat)
- `736429b7` trie_zz: Optimize redundant branch copy on new decode in GridMPT (#104) (Somnath Banerjee @somnergy)
- `6198bb65` trie_zz: propagate swallowed GridMPT failures via failed flag (#134) (@canepat)
- `98dcb152` GridMPT: fix OOB in extension-child copy (#113) ( )
- `e258b12d` GridMPT: fix ext-split fold orphaning new branch (#117) (@canepat)
- `3017c89a` trie: fix GridMPT<true> crash when deletes empty the trie mid-batch (#109) (Paweł Bylica @chfast)

#### Protocol & Core EVM

- `5ecf7eba` evmone: point the submodule at zevmone glamsterdam-devnet-8 (Somnath Banerjee @somnergy)
- `109b5cba` core, protocol, dev: Amsterdam support (glamsterdam-devnet-8) (Paweł Bylica @chfast)
- `750576be` core, protocol, dev: Amsterdam support (glamsterdam-devnet-8) (Paweł Bylica @chfast)
- `fc5cf1a6` dev: enforce the EIP-7934 block RLP size cap on fork-transition networks (#112) (Paweł Bylica @chfast)
- `2108ccb8` Bump evmone: merge evmone 0.23.0 (#142) (Paweł Bylica @chfast)
- `cb8d8ae5` core, protocol: drop v1 EVM host legacy path, remove bor (#100) (Somnath Banerjee @somnergy)
- `3305207b` Adjust merge (Somnath Banerjee @somnergy)

#### Prover & Guest

- `f4c49c20` guest_hypercube: commit pre/post roots, block hash, chain id in PV (#133) (@canepat)
- `48b3dd54` prover: add --download-only option (#118) (Somnath Banerjee @somnergy)
- `e40bf2a6` Integrate Zilkworm into the ERE zkEVM benchmark workload (#93) (@canepat)
- `643efb5c` Fix broken cargo caches sources (#97) (Somnath Banerjee @somnergy)

#### Tests, Benchmarks & EESTs

- `52ccc1a9` test: introduce Catch2 and the zilkworm.tests unit-test target (#107) (Paweł Bylica @chfast)
- `0a041f7f` eest: replace the archived eest-fixtures submodule with pinned tarballs (#105) (Paweł Bylica @chfast)
- `419277e4` eest: bump fixtures to tests@v20.0.1 (#106) (Paweł Bylica @chfast)
- `49647310` state_transition: require strict EEST expectException matching (#94) (Paweł Bylica @chfast)
- `bf85f2fe` Fix qemu (Somnath Banerjee @somnergy)

#### CI/CD & Workflows

- `e5ae16b2` ci: run the HyperCube EEST job against the Glamsterdam corpus (Paweł Bylica @chfast)
- `96d5a1a1` ci: trigger HyperCube EEST on evmone submodule bump (#165) (@canepat)
- `f6a99a27` ci: fail EEST Blockchain Tests on any failure (#120) (Paweł Bylica @chfast)
- `b91cd3aa` ci: run unit tests (zilkworm.tests) on PRs and main pushes (#116) (Somnath Banerjee @somnergy)
- `93455153` ci: fix HyperCube EEST Blockchain Tests workflow (#111) (@canepat)
- `e4544552` ci: fix version discrepancies and credit author in release (#10) (@canepat)
- `e6c8a57e` ci: add tag-driven release workflow (#9) (@canepat)
- `c52d6fc9` Fix CI and use ci image for rv* runs (Somnath Banerjee @somnergy)

#### Build System & Tooling

- `4be739ee` Fix failed attempt to `make z6m_guest` and `make z6m_prover` on MacOS (#6) (Developer Uche @developeruche)
- `1566acef` vscode: add Mac IntelliSense config, fix hardcoded cmake.sourceDirectory (#119) (@canepat)


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

