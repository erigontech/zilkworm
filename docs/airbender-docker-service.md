# Airbender prover service — Docker image

How to build, get and run the dockerized Airbender proving service (zksync-airbender v3,
100-bit security, proofs in the Ethproofs EPROOF01 v2 format).

## Image

| | |
|---|---|
| Image | `ghcr.io/erigontech/zilkworm-airbender:<commit sha>` (full or short sha), `:main` for the latest; built from `prover/Dockerfile` target `airbender` |
| Published by | `.github/workflows/airbender-image.yml`, for every commit pushed to `main` (and on manual dispatch) |
| Base | `nvidia/cuda:13.1.0-devel` (builder) / `nvidia/cuda:13.1.0-runtime` (runtime), Ubuntu 24.04 |
| GPU code | CUDA kernels for compute capabilities 8.0, 8.9, 9.0 and 12.0 (A100, RTX 40xx/L40/L4, H100/H200, RTX 50xx/RTX PRO Blackwell; not B200, which is 10.0); build arg `CUDA_ARCHS` changes the list |
| Runs as | root, workdir `/data` |

Contents:
- `/usr/local/bin/z6m_prover_airbender` — the prover (gpu feature); the witness→MFBD converter
  (`prover/witness_ffi`) is linked into it
- `/opt/z6m/z6m_guest.bin` + `.text` — the rv32 guest
- `/opt/z6m/fsv/` — the six recursion verifier program files (`fsv_*_sec_100_blake2_with_compression.{bin,text}`),
  checked at build time against `prover/docker/fsv.sha256`
- `/usr/local/bin/airbender-entrypoint` — the entrypoint (`prover/docker/airbender-entrypoint.sh`)

Environment baked into the image, which the verification key depends on or the prover needs:
`FSV_DIR=/opt/z6m/fsv`, `RISCV_MERGE_WINDOW=0`, `RUST_MIN_STACK=1073741824`, and
`RECURSION_UNROLLED_BLAKE`, `RECURSION_BRIDGE_BLAKE`, `RECURSION_FINAL_BLAKE` set to their default
`blake2_with_compression` (the prover refuses other values). Don't override them.

The package is private until it is made public once, by an org admin: GitHub → erigontech →
Packages → `zilkworm-airbender` → Package settings → Change visibility → Public. Until then,
`docker login ghcr.io` with a token that can read the org's packages before pulling.

## Host requirements

- NVIDIA GPU(s) with at least 32 GB of VRAM each. All GPUs visible to the container prove the
  same block together: one service per host, and `NVIDIA_VISIBLE_DEVICES` (or `--gpus`) picks the
  GPUs.
- About 24 GB of pinned host RAM per GPU (the prover's host buffers: 16 GB per proving job and
  8 GB per device), plus a few GB for the service, the simulator and the block data.
- An NVIDIA driver that supports CUDA 13.1 or newer (the runtime image's `NVIDIA_REQUIRE_CUDA`
  checks it), and the NVIDIA container toolkit.
- An execution client JSON-RPC endpoint that serves `debug_executionWitness` (and optionally a
  WebSocket endpoint for `newHeads`).
- Disk for `/data`: fetched blocks and MFBD bundles (a few MB per block) and proofs (about 1 MB
  each).

## Build

From the repo root (submodules initialized):

```bash
docker build --target airbender -f prover/Dockerfile \
  --build-arg ZILKWORM_REVISION=$(git rev-parse HEAD) \
  -t zilkworm-airbender:local .
```

`--build-arg CUDA_ARCHS="90"` builds the kernels for fewer architectures (faster). The build needs
no GPU. `USE_HASH_KEY=ON` enables node-store account recovery in the guest.

## Run

### The service, configured from the environment

Without arguments the entrypoint runs the proving service, configured from these variables, and
starts it again whenever it exits:

| Variable | |
|---|---|
| `RPC_URL` | execution client JSON-RPC serving `debug_executionWitness` (required) |
| `WS_URL` | its WebSocket endpoint, for newHeads (optional; polls without it) |
| `PROVE_EVERY` | prove the blocks whose number is a multiple of this (default 100) |
| `EXECUTE_EVERY` | execute without proving every N-th block (default: none) |
| `START_BLOCK` | first block (default: the chain's tip) |
| `DATA_DIR` | verification key, blocks, logs and proofs (default `/data`; mount a volume) |
| `ETHPROOFS_ENDPOINT`, `ETHPROOFS_TOKEN`, `ETHPROOFS_CLUSTER_ID` | post to Ethproofs; with any of them unset nothing is posted (a dry run) |
| `RESTART_DELAY` | seconds before the service is started again (default 30) |
| `PROVER_EXTRA_ARGS` | further prover options, word-split |

On first start for an image the entrypoint computes the guest's verification key into
`$DATA_DIR/vk-<revision>-<inputs>/vk.bin`, where `<inputs>` is a hash of the guest and the
recursion programs (on the CPU, about two minutes), and logs its sha256; later starts reuse it. Publish it with the proofs: `verify --vk` and the Ethproofs verifier check proofs
against it. The service then builds the GPU prover once (the setups of the guest and the
recursion programs) and starts at the chain's tip.

```bash
docker run -d --name zilkworm-airbender --gpus all --restart unless-stopped \
  -v /srv/zilkworm-airbender:/data \
  -e RPC_URL=http://<execution-client>:8545 \
  -e WS_URL=ws://<execution-client>:8546 \
  -e PROVE_EVERY=100 \
  -e ETHPROOFS_ENDPOINT=https://staging--ethproofs.netlify.app/api/v0 \
  -e ETHPROOFS_TOKEN="$ETHPROOFS_TOKEN" -e ETHPROOFS_CLUSTER_ID=<cluster id> \
  ghcr.io/erigontech/zilkworm-airbender:<commit sha>
```

On hosts whose NVIDIA container runtime is set up for CDI, `--gpus all` does not reach the GPUs;
use `--runtime=nvidia -e NVIDIA_VISIBLE_DEVICES=all` instead (or a device list such as
`NVIDIA_VISIBLE_DEVICES=0,1`).

Equivalent docker-compose:

```yaml
services:
  zilkworm-airbender:
    image: ghcr.io/erigontech/zilkworm-airbender:<commit sha>
    restart: unless-stopped
    environment:
      RPC_URL: http://<execution-client>:8545
      PROVE_EVERY: "100"
      ETHPROOFS_ENDPOINT: https://staging--ethproofs.netlify.app/api/v0
      ETHPROOFS_TOKEN: ${ETHPROOFS_TOKEN}
      ETHPROOFS_CLUSTER_ID: "<cluster id>"
    volumes:
      - ./prover-data:/data
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]
```

Service output goes to stdout (`docker logs -f zilkworm-airbender`); `/data/provingLogs.log`
has one line per proved (or skipped, or failed) block, and proofs land in
`/data/proofs/<block>/proof.bin`.

### One-off commands

With arguments the entrypoint runs the prover with them (the guest is passed for you):

```bash
# Execute a bundle on the simulator
docker run --rm -v /path/to/block:/in:ro ghcr.io/erigontech/zilkworm-airbender:<sha> \
  execute --file-name /in/flatWitnessBundle<N>.mfbd

# Prove it (writes /out/proof.bin)
docker run --rm --gpus all -v /path/to/block:/in:ro -v "$PWD/out:/out" \
  ghcr.io/erigontech/zilkworm-airbender:<sha> \
  prove --file-name /in/flatWitnessBundle<N>.mfbd --output-dir /out

# Write the verification key, and verify a proof against it (CPU only)
docker run --rm -v "$PWD/out:/out" ghcr.io/erigontech/zilkworm-airbender:<sha> vk --output /out/vk.bin
docker run --rm -v "$PWD/out:/out" -v /path/to/block:/in:ro ghcr.io/erigontech/zilkworm-airbender:<sha> \
  verify --proof /out/proof.bin --vk /out/vk.bin --file-name /in/flatWitnessBundle<N>.mfbd
```

### vast.ai

Pick an instance with ≥ 32 GB VRAM per GPU and ≥ 24 GB of RAM per GPU (more is better), and a
disk of a few tens of GB. Use `ghcr.io/erigontech/zilkworm-airbender:<commit sha>` as the image
(with registry credentials while the package is private).

- **Entrypoint launch mode** ("Docker ENTRYPOINT"): the image's entrypoint runs the service. Pass
  the configuration as `-e` options in the docker options field, e.g.
  `-e RPC_URL=http://... -e PROVE_EVERY=100 -e ETHPROOFS_ENDPOINT=... -e ETHPROOFS_TOKEN=... -e ETHPROOFS_CLUSTER_ID=...`.
  vast.ai has no restart policy; the entrypoint restarts the service itself.
- **SSH (or Jupyter) launch mode**: vast.ai replaces the entrypoint with its own, so start the
  service from the on-start script, with the variables exported there or set as `-e` options:

  ```bash
  export RPC_URL=http://... PROVE_EVERY=100
  export ETHPROOFS_ENDPOINT=... ETHPROOFS_TOKEN=... ETHPROOFS_CLUSTER_ID=...
  nohup airbender-entrypoint > /data/service.log 2>&1 &
  ```

  The image's environment (`FSV_DIR` and the rest) is in the container's environment in this
  mode too; if a shell does not see it, `env | grep -E 'FSV_DIR|RECURSION|RISCV'` shows what to
  export.

## Behavior

- A block is proved only if the simulator runs it to the guest's exit point within the prover's
  cycle limit (1,073,741,822 cycles) and both that run and the proof commit the block's hash; a
  proof is written and posted to Ethproofs only then. A block over the limit, or one the guest
  rejects, is logged as `SKIPPED` in `provingLogs.log`. The simulator runs before proving: the
  prover would abort the service on a block the guest rejects (its recursion layer panics in
  code that cannot unwind). `Z6M_CONCURRENT_PREFLIGHT=1` runs it alongside proving instead,
  saving about 0.5 s a block at the cost of that abort.
- A prover panic fails that block (`FAILED` in the log); the prover is rebuilt and the service
  carries on with the next block.
- Ethproofs receives `queued` when a block is picked, `proving` when its proving starts, and
  `proved` (`proving_time` in ms is the prover's time on the block, from handing it the input
  to the proof: the pipeline's simulation feeding the GPUs and their proving; fetching,
  witness conversion and the preflight are not in it; `proving_cycles` the guest's cycles,
  `proof` the base64 of `proof.bin`).
- `Z6M_REPLAY_THREADS` sets the prover's CPU threads that replay the guest into circuit traces
  (Airbender's default is 8). More threads only help where they, and not host memory or PCIe
  bandwidth, limit the commitment of the base layer's memory.

## Known limitations

1. **Restart resumes at chain head.** A restarted service starts at the tip: blocks between a
   crash and the restart are not proved (the cadence of `PROVE_EVERY` holds, as blocks are chosen
   by number). A checkpoint of the last processed block is not implemented.
2. **Pruned-witness-path blocks are skipped by design.** USE_HASH_KEY recovers accounts whose
   *preimage* is missing from the witness `keys`; if the witness also omits the account's *trie
   path*, recovery fails and so does the preflight. The fix belongs in the witness provider.
3. **Ethproofs flakes.** A failed `proved` upload is logged and not retried; the proof stays in
   `/data/proofs`.
4. The prover's pinned host memory is not configurable (zksync-airbender's `prover_pipeline` uses
   its defaults: 256 × 64 MB per job and 128 × 64 MB per GPU).
