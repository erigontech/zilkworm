# Airbender prover service — Docker image & run report

Status report for the dockerized airbender proving service and documentation
for building and running the image. Covers the 2026-07-18/19 validation runs.

## Image

| | |
|---|---|
| Tags | `somnergy/z6m_prover:airbender-next` = `z6m-airbender:uhk` (`162302070d90`, 2.43 GB) |
| Lineage | `release/airbender` with USE_HASH_KEY node-store recovery enabled at build time |
| Base | `nvidia/cuda:13.1.0-devel` (builder) / `nvidia/cuda:13.1.0-runtime` (runtime), Ubuntu 24.04 |
| Runs as | uid 1000, workdir `/home/ubuntu` |

Contents:
- `/usr/local/bin/z6m_prover_airbender` — Rust GPU prover (gpu feature, unified recursion)
- `/opt/z6m/z6m_guest.bin` + `.text` — rv32 guest
- `/usr/local/bin/json_witness_to_flat_bundle` — native witness→MFBD converter the
  fetcher shells out to; wired via `ENV Z6M_FLAT_BUNDLE_BUILDER`

Entrypoint is `z6m_prover_airbender --guest-bin /opt/z6m/z6m_guest`; all CLI args
append to it.

## Build

From the repo root of a `release/airbender` checkout (submodules
initialized):

```bash
docker build --target airbender -f prover/Dockerfile -t somnergy/z6m_prover:airbender-next .
```

Build fixes baked into the branch (earlier lineages do NOT build the image
without them):
- builder installs `python3` + `patch` (blst / secp256k1 patch steps need them)
- guest CMakeLists includes evmc headers from the submodule and drops the
  stale `libevmc-loader.a` / `libevmc-instructions.a` link references (EVMC was
  folded into evmone upstream; the subbuild no longer produces them)
- `Z6M_FLAT_BUNDLE_BUILDER` env override in `prover/common/src/fetcher.rs`
  (the compile-time `BUILDER_PATH` points into the build tree, which does not
  exist inside the container)

## Run

Single line (what the validation run used — prove every 10th block, execute
every block, post to ethproofs staging):

```bash
docker run -d --name z6m-prover --gpus all --restart unless-stopped \
  -v "$PWD/prover/prover_airbender/temp:/home/ubuntu/temp" \
  somnergy/z6m_prover:airbender-next \
  --gpu --until unified --service \
  --rpc-url http://<your-rpc-endpoint>:8545 \
  --data-dir /home/ubuntu/temp \
  --prove-every 10 --execute-every 1 \
  --ethproofs-endpoint https://staging--ethproofs.netlify.app/api/v0 \
  --ethproofs-token "$ETHPROOFS_TOKEN" --ethproofs-cluster-id 4
```

Equivalent docker-compose:

```yaml
services:
  z6m-prover:
    image: somnergy/z6m_prover:airbender-next
    restart: unless-stopped
    command: >
      --gpu --until unified --service
      --rpc-url http://<your-rpc-endpoint>:8545
      --data-dir /home/ubuntu/temp
      --prove-every 10 --execute-every 1
      --ethproofs-endpoint https://staging--ethproofs.netlify.app/api/v0
      --ethproofs-token ${ETHPROOFS_TOKEN} --ethproofs-cluster-id 4
    volumes:
      - ./prover-data:/home/ubuntu/temp
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

Notes:
- **GPU**: needs the nvidia container runtime and host driver ≥ 580 (CUDA 13.x).
- **Volume**: `--data-dir /home/ubuntu/temp` matches the mount (the default is
  the relative path `temp`, which only resolves to the same place because the
  workdir is `/home/ubuntu` — pass it explicitly) — fetched blocks, MFBD bundles,
  and `provingLogs.log` (one line per proof) land there. Mount it or lose the
  recording on container removal. The container user is uid 1000; make the host
  dir owned by uid 1000.
- **Service output** goes to stdout: `docker logs -f z6m-prover`.
- The one-time GPU setup (base+unrolled+unified layers) recomputes at startup,
  ~2 min, before the first block flows.
- Drop the `--ethproofs-*` flags to run without posting.
- One-off execution of a bundle (no service):
  `docker run --rm --gpus all -v /path/to/block:/data:ro somnergy/z6m_prover:airbender-next execute --file-name /data/flatWitnessBundle<N>.mfbd`

## Validation run results

Dockerized run (2026-07-18 12:20 UTC → 2026-07-19 07:02 UTC, ~18.7 h,
blocks 25559560–25565128):

| Metric | Value |
|---|---|
| Blocks processed | 5,569 — every block in range, no gaps |
| Executed (preflight) ok | 5,012 / 5,012 — **zero failures** |
| Proofs (every 10th, 3 layers to unified) | 557 / 557, avg 25.0 s, max 58.9 s |
| USE_HASH_KEY recoveries | 244 events (144 distinct accounts), **all recovered blocks passed** |
| ethproofs `proved` posts | 551 OK / 6 failed (staging-side 500s & network errors, ~1%) |
| Service restarts | 0 |

Host runs earlier the same day (same guest lineage) additionally validated:
release state-root check 200/200 on the benchmark corpus, and preimage-gap
blocks 25538620 / 25540940 / 25540990 pass with recovery.

## Known limitations

1. **Restart resumes at chain head.** With fixed args, a crash-restart loses the
   blocks between crash and recovery (and a hardcoded `--start-block` would
   rewind to a stale block). Designed fix (not yet implemented): checkpoint the
   last processed block into the data dir, resume from checkpoint+1 at startup,
   with a `--max-backfill` cap — see `service.rs` `fetcher_loop`.
2. **Pruned-witness-path blocks are skipped by design.** USE_HASH_KEY recovers
   accounts whose *preimage* is missing from the witness `keys`; if the witness
   also omits the account's *trie path* (observed with existing precompile
   accounts, e.g. `0x…03`), recovery returns null and the preflight fails
   (`kWrongBlockGas`/root mismatch). Fix belongs upstream in the witness
   provider. Zero such blocks occurred in the 18.7 h dockerized run.
3. **ethproofs staging flakes** (~1% of `proved` uploads, 500s or connection
   errors, sometimes clustered). Proofs are always kept locally; the service
   does not retry a failed `proved` upload.
4. The validated image guest was built with **USE_HASH_KEY=1** (the flag is
   default-off in the source tree and must be enabled at build time); proofs
   cover executions that may include node-store-recovered accounts.
