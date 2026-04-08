# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Multi-prover Docker image for z6m
# Supports both SP1 hypercube (pre-built binary) and airbender (built from source).
#
# Usage:
#   Airbender GPU prover (build from source):
#     docker build --target airbender -t somnergy/z6m_prover:airbender -f prover/Dockerfile .
#
#   SP1 hypercube GPU prover (pre-built sp1-gpu-server binary):
#     docker build --target hypercube -t somnergy/z6m_prover:hypercube -f prover/Dockerfile prover/
#
# Note: airbender target must be built from repo root (needs top-level CMakeLists).
#       hypercube target can be built from prover/ directory.

# ═══════════════════════════════════════════════════════════════════════
# Stage: airbender-builder — cross-compile guest + build Rust GPU prover
# ═══════════════════════════════════════════════════════════════════════
FROM nvidia/cuda:13.1.0-devel-ubuntu24.04 AS airbender-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git curl ca-certificates pkg-config \
    libssl-dev xz-utils \
    && rm -rf /var/lib/apt/lists/*

# RISC-V bare-metal GCC for guest cross-compilation
ARG RISCV_GCC_VERSION=15.2.0-1
RUN mkdir -p /opt/riscv-gcc && \
    curl -fsSL "https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v${RISCV_GCC_VERSION}/xpack-riscv-none-elf-gcc-${RISCV_GCC_VERSION}-linux-x64.tar.gz" \
    | tar xz -C /opt/riscv-gcc --strip-components=1
ENV PATH="/opt/riscv-gcc/bin:${PATH}"

# Rust nightly
ARG RUST_TOOLCHAIN=nightly-2025-09-01
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain ${RUST_TOOLCHAIN}
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# Build guest binary (C++ → RISC-V)
WORKDIR /build/prover/guest_airbender
RUN make z6m_guest

# Build Rust GPU prover
WORKDIR /build/prover/prover_airbender
RUN cargo build --release --features gpu

# ═══════════════════════════════════════════════════════════════════════
# Target: airbender — runtime image with airbender GPU prover
# ═══════════════════════════════════════════════════════════════════════
FROM nvidia/cuda:13.1.0-runtime-ubuntu24.04 AS airbender

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=airbender-builder /build/prover/prover_airbender/target/release/z6m_prover_airbender /usr/local/bin/
COPY --from=airbender-builder /build/prover/guest_airbender/build/z6m_guest.bin /opt/z6m/z6m_guest.bin

ENTRYPOINT ["z6m_prover_airbender", "--guest-bin", "/opt/z6m/z6m_guest.bin"]

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
