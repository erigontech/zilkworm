# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# zilkworm-ci plus zisk-sdk/ziskemu build deps.
FROM ghcr.io/erigontech/zilkworm-ci:latest

LABEL org.opencontainers.image.source=https://github.com/erigontech/z6m

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# clang/libclang: bindgen in mpi-sys.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libgmp-dev \
        nlohmann-json3-dev \
        nasm \
        libsodium-dev \
        libomp-dev \
        libopenmpi-dev \
        clang \
        libclang-dev && \
    rm -rf /var/lib/apt/lists/*

# prover/prover_zisk/rust-toolchain.toml
RUN rustup toolchain install 1.93.1 --profile minimal --component rustfmt,rust-src

# MKDIR_P: uutils mkdir breaks libffi's configure.
RUN MKDIR_P="mkdir -p" cargo install --locked \
        --git https://github.com/0xPolygonHermez/zisk --tag v1.3.1-alpha ziskemu && \
    rm -rf /root/.cargo/registry /root/.cargo/git

RUN ziskemu --help > /dev/null && clang --version && mpicc --version

WORKDIR /workspace

CMD ["bash"]
