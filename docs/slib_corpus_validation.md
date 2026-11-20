# HashState corpus validation

**Backend: HashState.** How the HashState backend is run against the EEST stateless corpus and how
to read a run. The scoring rules are part of the runner and are specified in
[hashstate.md](hashstate.md#blockchain-test-runner); per-release pass counts are in
[`../CHANGELOG.md`](../CHANGELOG.md). The DirectState corpora are in
[mfbd_fixture_generation.md](mfbd_fixture_generation.md).

## Corpus

The `tests-zkevm` release of `ethereum/execution-specs` that the Makefile pins as
`ZKEVM_RELEASE_VERSION` (asset `fixtures_zkevm.tar.gz`), the release ere-guests tests against. The
fixtures are ordinary `blockchain_test` JSON cases in which each block carries a
`statelessInputBytes` hex field. `make zkevm-fixtures` downloads them with `gh release download`
into `test-fixtures-cache/zkevm_stateless-$(ZKEVM_RELEASE_VERSION)/`; the directory carries the
version, so a bump never runs on a stale corpus.

## Runs

| Run | Command | What it checks |
| --- | --- | --- |
| Native, JSON corpus | `make eest-zkevm-tests` | Builds with `-DZ6M_HASH_STATE=ON` in `build/zkevm` and runs `state_transition` on every fixture file, one ctest case each, through the EJSN slib arm ([hashstate.md](hashstate.md#build-flag-and-test-targets)). |
| Unit tests, flag on | `cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -DZ6M_HASH_STATE=ON`, then `zilkworm.tests` | The `unit-tests-hashstate` job of `unit-tests.yml`; see [hashstate.md](hashstate.md#tests). |
| Guest, raw input | `make ere-validate` | The SP1 guest on each fixture's `statelessInputBytes`, its 43 public bytes compared with `statelessOutputBytes` ([ere_integration.md](ere_integration.md)). |
| Guest, ere-guests test crate | `executes_registered_guest` in ere-guests `stateless-validator-test` | The same comparison over the whole `tests-zkevm` corpus ([ere_integration.md](ere_integration.md#the-ere-guests-corpus-test)). |

`make eest-zkevm-tests` is not wired into a CI workflow; the unit tests and the ERE benchmark are.

## Reading a native run

At tests-zkevm v21.0.7 a run scores the 3340 fixture files 3271 pass, 63 skipped and 6 failed, the
6 being the runner gap below. The same ctest run also holds the unit tests.

- **Pass.** Every witnessed block of the file was decided as the fixture expects.
- **Skip.** A file whose blocks carry no `statelessInputBytes`, such as the pre-fork blocks of a
  fork-transition test. ctest prints each skipped test twice, so count the files, not the
  `Skipped` lines.
- **Known failures.** `zilk_core/dev/eest-known-failures.txt` is not applied under the flag
  (`zilk_core/dev/cli/CMakeLists.txt`): it describes the DirectState runner, which runs a test's
  blocks on one witness in place, while the slib arm rebuilds the state from each block's own
  witness.
- **Witness-validation negatives.** A valid block with a deliberately broken witness carries no
  `expectException`; the runner identifies these fixtures by name and passes them only if the slib
  path rejects ([Scoring witness-validation negatives](hashstate.md#scoring-witness-validation-negatives)).
- **Waived labels.** An expected-invalid block rejected with another label than the fixture's is
  accepted only when the witness pruned an account a validation gate reads; each waiver is logged
  as `STRICT: label waived ...`
  ([Expected-invalid label relaxation](hashstate.md#expected-invalid-label-relaxation)).
- **Witness headers.** They must form one parent-hash chain ending at the block's parent
  ([Witness ancestor headers](hashstate.md#witness-ancestor-headers)).
- **Runner gap: `witness_state_malformed_nodes`.** Six files of this family, new in tests-zkevm
  v21.0.7, fail here with `parent header is not the last witness header`, most likely because their
  `statelessInputBytes` re-seal the parent while the runner takes the block from `rlp`. The runner
  cannot score them; `executes_registered_guest` checks the guest on them
  ([ere_integration.md](ere_integration.md#the-ere-guests-corpus-test)).
