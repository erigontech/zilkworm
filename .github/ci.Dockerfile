# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:25.10

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# System dependencies
RUN apt update && apt install -y \
    build-essential cmake ninja-build \
    git git-lfs \
    python3 \
    nodejs npm \
    curl \
    pkg-config libssl-dev \
    protobuf-compiler \
  && rm -rf /var/lib/apt/lists/*

# RISC-V bare-metal toolchain
RUN npm i -g xpm \
  && xpm install @xpack-dev-tools/riscv-none-elf-gcc@15.2.0-1.1 --global --verbose
ENV PATH="/root/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/15.2.0-1.1/.content/bin:${PATH}"

# Rust nightly
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV PATH="/root/.cargo/bin:${PATH}"

# Verify
RUN riscv-none-elf-gcc --version && cmake --version && rustc --version
