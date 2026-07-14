# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Zilkworm unified build + runtime
#
# Builds from source:
#   1. C++ guest ELF (RISC-V 64IM)
#   2. Rust prover host binary
#   3. sp1-gpu-server (CUDA proving server, from erigontech/sp1)
#
# Prerequisites:
#   git submodule update --init --recursive
#
# Build:
#   docker build --build-arg ZILKWORM_VERSION=0.1.0-alpha.1 -t somnergy/z6m_prover:0.1.0-alpha.1 .
#
# Build for specific GPU architecture (default: 89 = RTX 4090):
#   docker build --build-arg CUDA_ARCHS="90" --build-arg ZILKWORM_VERSION=0.1.0-alpha.1 -t somnergy/z6m_prover:0.1.0-alpha.1 .
#
# Run (CPU):
#   docker run --rm somnergy/z6m_prover:0.1.0-alpha.1 --help
#
# Run (GPU + DinD):
#   docker run --gpus all --rm --network host \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     -e SP1_PROVER=cuda \
#     somnergy/z6m_prover:0.1.0-alpha.1 execute --file-name /work/block.bin

ARG CUDA_ARCHS="89"
ARG ZILKWORM_VERSION="dev"

# Stage 1: Build sp1-gpu-server from the SP1 repository
FROM nvidia/cuda:13.0.0-devel-ubuntu24.04 AS gpu-builder

ARG CUDA_ARCHS

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config \
    git ca-certificates curl wget \
    golang protobuf-compiler libprotobuf-dev \
    libssl-dev libclang-dev \
    && wget -qO /tmp/cmake.sh "https://github.com/Kitware/CMake/releases/download/v3.31.6/cmake-3.31.6-linux-x86_64.sh" \
    && sh /tmp/cmake.sh --skip-license --prefix=/usr/local \
    && rm /tmp/cmake.sh

ENV CARGO_HOME=/root/.cargo \
    RUSTUP_HOME=/root/.rustup \
    PATH="/root/.cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain 1.91.0 --profile default

RUN git clone --depth 1 --branch erigon/patches-v6.0.2 \
        https://github.com/erigontech/sp1.git /tmp/sp1

WORKDIR /tmp/sp1

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    CUDA_ARCHS="${CUDA_ARCHS}" \
    cargo install --locked --root /root/.sp1 --path sp1-gpu/crates/server/

# Stage 2: Build guest ELF + prover binary
FROM ubuntu:24.04 AS builder

LABEL stage=builder

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

# System packages
RUN --mount=type=cache,target=/var/lib/apt/lists \
    --mount=type=cache,target=/var/cache/apt \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build pkg-config \
    git ca-certificates curl wget \
    python3 \
    protobuf-compiler libprotobuf-dev \
    nodejs npm \
    xz-utils file

# CUDA toolkit (needed to compile sp1-cuda crate)
RUN curl -fsSL -o /tmp/cuda-keyring.deb \
        https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb \
    && dpkg -i /tmp/cuda-keyring.deb && rm /tmp/cuda-keyring.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        cuda-toolkit-13-0 \
        cuda-toolkit-13-0-config-common

# RISC-V bare-metal toolchain (xpack riscv-none-elf-gcc)
RUN --mount=type=cache,target=/root/.npm \
    npm install --location=global xpm@latest \
    && xpm install @xpack-dev-tools/riscv-none-elf-gcc@latest --global --verbose

RUN set -e; \
    version_dir="$(ls -1d /root/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/*/ | head -1)"; \
    ln -s "${version_dir}.content/bin" /opt/riscv-none-elf-gcc-bin
ENV PATH="/opt/riscv-none-elf-gcc-bin:${PATH}"

# Rust 1.88.0
ENV CARGO_HOME=/root/.cargo \
    RUSTUP_HOME=/root/.rustup \
    PATH="/root/.cargo/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain 1.91.0 --profile default \
    && rustup component add rustfmt rust-src

WORKDIR /src
COPY . .

# Build guest ELF (C++23 cross-compiled to rv64im)
RUN cmake -S prover/guest_hypercube -B prover/guest_hypercube/build \
        -DCMAKE_TOOLCHAIN_FILE=/src/prover/guest_hypercube/cmake/riscv64im-sp1.cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DSP1=ON \
    && cmake --build prover/guest_hypercube/build -j"$(nproc)"

# Build prover binary (Rust, embeds guest ELF via build.rs)
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/src/prover/target \
    cargo build --release --manifest-path prover/prover_hypercube/Cargo.toml \
    && cp prover/target/release/z6m_prover /tmp/z6m_prover

# Stage 3: Runtime
FROM ubuntu:24.04 AS runtime

ARG ZILKWORM_VERSION
LABEL maintainer="erigontech/zilkworm" \
      description="Zilkworm ZKEVM prover" \
      version="${ZILKWORM_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gpg

# CUDA toolkit
RUN curl -fsSL -o /tmp/cuda-keyring.deb \
        https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb \
    && dpkg -i /tmp/cuda-keyring.deb && rm /tmp/cuda-keyring.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        cuda-toolkit-13-0 \
        cuda-toolkit-13-0-config-common

# NVIDIA Container Toolkit
RUN curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg \
    && curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        nvidia-container-toolkit \
        nvidia-container-toolkit-base \
        libnvidia-container-tools \
        libnvidia-container1

# Docker Engine (DinD)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
        https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin

RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Binaries
COPY --from=builder /tmp/z6m_prover /usr/bin/z6m_prover
COPY --from=builder /src/prover/guest_hypercube/build/z6m_guest.elf /usr/local/bin/z6m_guest
COPY --from=gpu-builder /root/.sp1/bin/sp1-gpu-server /root/.sp1/bin/sp1-gpu-server

ENV SP1_PROVER=cpu

ENTRYPOINT ["/usr/bin/z6m_prover"]
CMD ["--help"]
