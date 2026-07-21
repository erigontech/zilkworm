# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Multi-prover Docker image for z6m
#
# Usage:
#   Airbender GPU prover:
#     docker build --target airbender -f prover/Dockerfile .
#
#   SP1 hypercube GPU prover (pre-built sp1-gpu-server binary):
#     docker build --target hypercube -f prover/Dockerfile prover/
#
# Note: airbender target must be built from repo root (needs top-level CMakeLists).

# ═══════════════════════════════════════════════════════════════════════
# Stage: airbender-builder — cross-compile guest + build Rust GPU prover
# ═══════════════════════════════════════════════════════════════════════
FROM nvidia/cuda:13.1.0-devel-ubuntu24.04 AS airbender-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl ca-certificates pkg-config \
    libssl-dev xz-utils python3 patch \
    && rm -rf /var/lib/apt/lists/*

# RISC-V bare-metal GCC for guest cross-compilation
ARG RISCV_GCC_VERSION=15.2.0-1
RUN mkdir -p /opt/riscv-gcc && \
    curl -fsSL "https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v${RISCV_GCC_VERSION}/xpack-riscv-none-elf-gcc-${RISCV_GCC_VERSION}-linux-x64.tar.gz" \
    | tar xz -C /opt/riscv-gcc --strip-components=1
ENV PATH="/opt/riscv-gcc/bin:${PATH}"

# Rust nightly (must match zksync-airbender's rust-toolchain.toml)
ARG RUST_TOOLCHAIN=nightly-2026-02-10
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain ${RUST_TOOLCHAIN}
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# Build guest binary (C++ → RISC-V), produces .bin and .text
# USE_HASH_KEY=ON enables node-store account recovery in the guest.
ARG USE_HASH_KEY=OFF
WORKDIR /build/prover/guest_airbender
RUN make z6m_guest USE_HASH_KEY=${USE_HASH_KEY}

# Build Rust GPU prover (gpu is default feature, deps fetched from git)
WORKDIR /build/prover/prover_airbender
RUN cargo build --release

# Native build of the witness->flat-bundle converter the fetcher shells out to
WORKDIR /build
RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --target json_witness_to_flat_bundle -j$(nproc)

# ═══════════════════════════════════════════════════════════════════════
# Target: airbender — runtime image with airbender GPU prover
# ═══════════════════════════════════════════════════════════════════════
FROM nvidia/cuda:13.1.0-runtime-ubuntu24.04 AS airbender

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Run as non-root user (uid 1000 = ubuntu in base image, matches typical host user)
RUN mkdir -p /home/ubuntu && chown 1000:1000 /home/ubuntu

COPY --from=airbender-builder /build/prover/prover_airbender/target/release/z6m_prover_airbender /usr/local/bin/
COPY --from=airbender-builder /build/build/zilk_core/dev/cli/json_witness_to_flat_bundle /usr/local/bin/
COPY --from=airbender-builder --chown=1000:1000 /build/prover/guest_airbender/build/z6m_guest.bin /opt/z6m/z6m_guest.bin
COPY --from=airbender-builder --chown=1000:1000 /build/prover/guest_airbender/build/z6m_guest.text /opt/z6m/z6m_guest.text

ENV Z6M_FLAT_BUNDLE_BUILDER=/usr/local/bin/json_witness_to_flat_bundle

USER 1000
WORKDIR /home/ubuntu

# --guest-bin takes path without extension; the prover expects both .bin and .text
ENTRYPOINT ["z6m_prover_airbender", "--guest-bin", "/opt/z6m/z6m_guest"]

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
