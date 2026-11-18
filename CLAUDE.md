# Zilkworm

Start from [docs/README.md](docs/README.md). It indexes the two state backends (DirectState on MFBD
bundles, HashState on `statelessInputBytes`), their code paths, guests, make targets, tests, corpora
and benchmarks, and the shared parts, build, provers, ERE integration and release.

- Answer from the index and the doc it links before opening sources; do not read test files or
  fixture JSON to learn behaviour.
- Versions (corpora, SP1, ere) are set in one place each; see "Version pins" in the index.
- When a change alters behaviour that a doc describes, update that doc in the same change, and keep
  each fact in one doc.
