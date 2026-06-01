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

## Releasing from any branch

The workflow is tag-driven, not branch-driven: the tag is checked out by commit,
so a `vX.Y.Z` tag can sit on any branch, not just `release/*`.
The branch name is irrelevant; the conditions in step 5 still apply.

## Release an existing tag

If a `vX.Y.Z` tag was pushed before this workflow existed (or a run needs to be
redone), trigger it manually via **Actions → Release → Run workflow**, passing
the tag. Re-publishing the same tag updates the release and overwrites its assets.
