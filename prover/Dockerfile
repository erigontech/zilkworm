# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Multi-prover Docker image for z6m
#
# Usage:
#   Airbender GPU prover (Airbender v3; see docs/airbender-docker-service.md):
#     docker build --target airbender -f prover/Dockerfile .
#   CUDA_ARCHS picks the GPU architectures the kernels are built for (default "80;89;90;120").
#
#   SP1 hypercube GPU prover (pre-built sp1-gpu-server binary):
#     docker build --target hypercube -f prover/Dockerfile prover/
#
# Note: airbender target must be built from repo root (needs top-level CMakeLists).

# ═══════════════════════════════════════════════════════════════════════
# Stage: airbender-builder — cross-compile guest + build Rust GPU prover
# ═══════════════════════════════════════════════════════════════════════
# CUDA 13.1 (upstream builds with 13.3): a newer runtime image's NVIDIA_REQUIRE_CUDA would refuse
# hosts whose driver only supports 13.1.
FROM nvidia/cuda:13.1.0-devel-ubuntu24.04 AS airbender-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates pkg-config \
    libssl-dev xz-utils python3 patch \
    && rm -rf /var/lib/apt/lists/*

# CMake from Kitware: noble's 3.28 cannot parse the download step of the patched blst (its URL
# carries a '#airbender-<hash>' tag).
ARG CMAKE_VERSION=3.31.6
ARG CMAKE_SHA256=518c76bd18cc4ca5faab891db69b1289dc1bf134f394f0983a19576711b95210
RUN curl -fsSL -o /tmp/cmake.sh "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.sh" \
    && echo "${CMAKE_SHA256}  /tmp/cmake.sh" | sha256sum -c - \
    && sh /tmp/cmake.sh --skip-license --prefix=/usr/local && rm /tmp/cmake.sh

# RISC-V bare-metal GCC for guest cross-compilation
ARG RISCV_GCC_VERSION=15.2.0-1
RUN mkdir -p /opt/riscv-gcc && \
    curl -fsSL "https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v${RISCV_GCC_VERSION}/xpack-riscv-none-elf-gcc-${RISCV_GCC_VERSION}-linux-x64.tar.gz" \
    | tar xz -C /opt/riscv-gcc --strip-components=1
ENV PATH="/opt/riscv-gcc/bin:${PATH}"

# Native GCC 15 (xpack) for the C++ witness converter that
# prover/witness_ffi/build.rs compiles into the prover. Noble's stock gcc is 13
# and witness_ffi needs >= 14; its compiler probe picks up g++-15 from PATH,
# leaving CC/CXX (and the CUDA host compiler) at the system default.
ARG GCC_XPACK_VERSION=15.2.0-1
RUN mkdir -p /opt/xpack-gcc && \
    curl -fsSL "https://github.com/xpack-dev-tools/gcc-xpack/releases/download/v${GCC_XPACK_VERSION}/xpack-gcc-${GCC_XPACK_VERSION}-linux-x64.tar.gz" \
    | tar xz -C /opt/xpack-gcc --strip-components=1 && \
    ln -s /opt/xpack-gcc/bin/gcc /usr/local/bin/gcc-15 && \
    ln -s /opt/xpack-gcc/bin/g++ /usr/local/bin/g++-15

# Rust nightly (must match prover/prover_airbender/rust-toolchain.toml and zksync-airbender's)
ARG RUST_TOOLCHAIN=nightly-2026-08-09
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain ${RUST_TOOLCHAIN}
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# Build guest binary (C++ → RISC-V), produces .bin and .text
# USE_HASH_KEY=ON enables node-store account recovery in the guest.
ARG USE_HASH_KEY=OFF
# Z6M_HASH_STATE=ON builds the HashState guest, which takes SLIB input instead of MFBD.
ARG Z6M_HASH_STATE=OFF
WORKDIR /build/prover/guest_airbender
RUN make z6m_guest USE_HASH_KEY=${USE_HASH_KEY} Z6M_HASH_STATE=${Z6M_HASH_STATE}

# Build Rust GPU prover (gpu is default feature, deps fetched from git).
# witness_ffi's libstdc++ (gcc-15) is newer than the runtime image's, so link
# it statically.
#
# The CUDA kernels are built for CUDAARCHS, the only architecture control of zksync-airbender's
# gpu_native_build; its default, "native", needs a GPU at build time. RUST_MIN_STACK as upstream's
# image (matter-labs/ethereum-prover) builds with it.
WORKDIR /build/prover/prover_airbender
ARG CUDA_ARCHS="80;89;90;120"
ENV CUDAARCHS=${CUDA_ARCHS} \
    RUST_MIN_STACK=1073741824
RUN Z6M_STATIC_LIBSTDCXX=1 cargo build --release

# The recursion verifier programs (fsv) the prover loads at run time, from the zksync-airbender
# checkout the build used. Together with the guest they define the verification key, so they are
# checked against the hashes recorded in prover/docker/fsv.sha256 (the files of zksync-airbender
# bd0d5153's tools/gkr_verifier: three programs, .bin and .text each, all for the default
# Blake2s-with-compression recursion).
RUN set -eu; \
    src=$(ls -d "${CARGO_HOME:-/root/.cargo}"/git/checkouts/zksync-airbender-*/bd0d515*/tools/gkr_verifier); \
    [ "$(echo "$src" | wc -l)" = 1 ] || { echo "expected one zksync-airbender bd0d515 checkout, found: $src" >&2; exit 1; }; \
    mkdir -p /opt/z6m/fsv; \
    for f in $(awk '{print $2}' /build/prover/docker/fsv.sha256); do cp "$src/$f" /opt/z6m/fsv/; done; \
    cd /opt/z6m/fsv && sha256sum --strict -c /build/prover/docker/fsv.sha256

# ═══════════════════════════════════════════════════════════════════════
# Target: airbender — runtime image with airbender GPU prover
# ═══════════════════════════════════════════════════════════════════════
FROM nvidia/cuda:13.1.0-runtime-ubuntu24.04 AS airbender

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=airbender-builder /build/prover/prover_airbender/target/release/z6m_prover_airbender /usr/local/bin/
COPY --from=airbender-builder /build/prover/guest_airbender/build/z6m_guest.bin /opt/z6m/z6m_guest.bin
COPY --from=airbender-builder /build/prover/guest_airbender/build/z6m_guest.text /opt/z6m/z6m_guest.text
COPY --from=airbender-builder /opt/z6m/fsv /opt/z6m/fsv
COPY prover/docker/airbender-entrypoint.sh /usr/local/bin/airbender-entrypoint

# What the prover needs at run time, and what must not change under it:
# - FSV_DIR: the recursion verifier programs (without it the prover looks for them in the
#   builder's cargo checkout).
# - RISCV_MERGE_WINDOW=0: the guest jumps into runs of word stores, which the prover's JIT would
#   otherwise fuse (the prover sets it too when it is unset).
# - RUST_MIN_STACK: 1 GiB for every thread; the prover runs the recursion verifiers natively.
# - RECURSION_*_BLAKE: the recursion verifiers' Blake2s mode, which the verification key depends
#   on; these are the defaults, and the prover refuses any other.
ENV FSV_DIR=/opt/z6m/fsv \
    RISCV_MERGE_WINDOW=0 \
    RUST_MIN_STACK=1073741824 \
    RECURSION_UNROLLED_BLAKE=blake2_with_compression \
    RECURSION_BRIDGE_BLAKE=blake2_with_compression \
    RECURSION_FINAL_BLAKE=blake2_with_compression

# The commit the image was built from (the publishing workflow passes it): it names the
# verification key the entrypoint computes, which is only valid for this guest and prover.
ARG ZILKWORM_REVISION=local
ENV ZILKWORM_REVISION=${ZILKWORM_REVISION}
LABEL org.opencontainers.image.revision=${ZILKWORM_REVISION}

# Runs as root, as vast.ai's SSH and Jupyter launch modes expect; state lives under /data, where
# a volume belongs.
WORKDIR /data

# With arguments, runs the prover with them (`docker run IMAGE prove --file-name ...`); without,
# runs the proving service configured from the environment (see the entrypoint script).
ENTRYPOINT ["airbender-entrypoint"]

# ═══════════════════════════════════════════════════════════════════════
# Target: hypercube — runtime image with SP1 GPU prover (pre-built binary)
# ═══════════════════════════════════════════════════════════════════════
FROM ubuntu:24.04 AS hypercube-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl gpg && \
    curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb && \
    dpkg -i /tmp/cuda-keyring.deb && \
    apt-get update && \
    apt-get install -y cuda-toolkit-13-0 cuda-toolkit-13-0-config-common && \
    rm -rf /var/lib/apt/lists/*

COPY sp1-gpu-server /root/.sp1/bin/sp1-gpu-server

FROM scratch AS hypercube
COPY --from=hypercube-builder / /
