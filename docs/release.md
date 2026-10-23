<!--
Copyright 2026 The Zilkworm Authors
SPDX-License-Identifier: Apache-2.0
-->

# Release process

Version is single-sourced from `PROJECT_VERSION` in [`CMakeLists.txt`](../CMakeLists.txt).
Tagging `vX.Y.Z` triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which builds the artifacts and publishes the GitHub release.
An optional suffix after `vX.Y.Z` is free-form (e.g. `-alpha.2`, `-rc.1`) but the whole tag must
equal `PROJECT_VERSION`; any `-` suffix marks the release as a pre-release.

## Steps

1. Branch: typically `release/X.Y.Z` but any other branch works.
2. Bump `PROJECT_VERSION` in `CMakeLists.txt` to `X.Y.Z` on such branch.
3. Add the `## vX.Y.Z - <title>` section to [`CHANGELOG.md`](../CHANGELOG.md) (release notes
   are extracted from it).
4. Commit and push the branch.
5. Tag the release commit and push the tag:
   ```sh
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```
   The tag must match `PROJECT_VERSION` or the release workflow fails.

The workflow then builds the release binaries, generates `SHA256SUMS.txt`, and publishes them
to the `vX.Y.Z` GitHub release with the CHANGELOG section as the body.

## Hypercube guests

The release builds the SP1 Hypercube guest twice and publishes both:
- `z6m_guest_hypercube_mfbd.{elf,vk}`: the DirectState guest (`make z6m_guest`), which takes
  MFBD bundles; the `z6m_prover_hypercube` binary embeds it.
- `stateless-validator-zilkworm-sp1-<SP1 SDK version>.{elf,vk}`: the HashState guest
  (`make z6m_guest_slib`, staged by `make ere-bin`), which takes the fixtures'
  `statelessInputBytes` unchanged, named as the ere-guests guest handbook asks
  (the version is the `sp1-sdk` tag `derive_vk` builds against, read from
  `prover/stateless_validator/Cargo.toml`); the ERE benchmark runs
  it, both the `release/*` runs and the one `release.yml` triggers after publishing.

After the release, point the `zilkworm` entry of `artifact-registry.json` in the ere-guests fork
(`som/ere-v0.19.5`) at the `stateless-validator-zilkworm-sp1-<SP1 SDK version>` assets, with their sha256 from `SHA256SUMS.txt`, and bump
the fork's version strings; the fork's corpus test and the upstream ere-guests PR resolve the
guest through that entry. The zkevm-benchmark-workload fork then pins its `[patch]` to the new
ere-guests fork commit.

## Airbender image and assets

After checking the tag, and before building anything, the workflow calls
[`airbender-image.yml`](../.github/workflows/airbender-image.yml) for the tag:
- It tags the release commit's Airbender prover image `ghcr.io/erigontech/zilkworm-airbender:vX.Y.Z`.
  The push to `main` already built that image (`:<commit sha>`), so it is only tagged again. A
  commit with no image yet, such as one only on a `release/*` branch, gets it built here (about
  40 minutes). Tag a commit on `main` after its **Airbender Prover Image** run has finished:
  otherwise the release builds the image a second time, alongside main's run, and `:<commit sha>`
  and `:vX.Y.Z` can end up naming two different builds.
- It copies the guest out of the image (`z6m_guest_airbender.bin`, `.text`). The image's prover
  then computes the guest's verification key (`z6m_guest_airbender.vk`, EVKEY001) on the runner's
  CPU, with swap added for its ~15 GB peak.

The release attaches those three files, lists them in `SHA256SUMS.txt`, and adds the image digest
and the key's sha256 to the notes. Ethproofs verifies a cluster's proofs against that key.

## Releasing from any branch

The workflow is tag-driven, not branch-driven: the tag is checked out by commit,
so a `vX.Y.Z` tag can sit on any branch, not just `release/*`.
The branch name is irrelevant; the conditions in step 5 still apply.

## Release an existing tag

If a `vX.Y.Z` tag was pushed before this workflow existed (or a run needs to be
redone), trigger it manually via **Actions → Release → Run workflow**, passing
the tag. Re-publishing the same tag updates the release and overwrites its assets.
This works for `v0.1.0-alpha.5` and later only: older tags lack the Airbender
asset script that the Airbender job runs from the tag's tree.
