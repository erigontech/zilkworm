# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Multi-prover image: `docker build --target airbender -f prover/Dockerfile .` from the repo root (CUDA_ARCHS sets the GPU architectures, default "80;89;90;120"), or `--target hypercube -f prover/Dockerfile prover/`.

# CUDA 13.1 (upstream builds with 13.3): a newer runtime image's NVIDIA_REQUIRE_CUDA would refuse hosts whose driver supports only 13.1.
FROM nvidia/cuda:13.1.0-devel-ubuntu24.04 AS airbender-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl ca-certificates pkg-config \
    libssl-dev xz-utils python3 patch \
    && rm -rf /var/lib/apt/lists/*

# CMake from Kitware: noble's 3.28 cannot parse the download step of the patched blst (its URL carries a '#airbender-<hash>' tag).
ARG CMAKE_VERSION=3.31.6
ARG CMAKE_SHA256=518c76bd18cc4ca5faab891db69b1289dc1bf134f394f0983a19576711b95210
RUN curl -fsSL -o /tmp/cmake.sh "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.sh" \
    && echo "${CMAKE_SHA256}  /tmp/cmake.sh" | sha256sum -c - \
    && sh /tmp/cmake.sh --skip-license --prefix=/usr/local && rm /tmp/cmake.sh

ARG RISCV_GCC_VERSION=15.2.0-1
RUN mkdir -p /opt/riscv-gcc && \
    curl -fsSL "https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases/download/v${RISCV_GCC_VERSION}/xpack-riscv-none-elf-gcc-${RISCV_GCC_VERSION}-linux-x64.tar.gz" \
    | tar xz -C /opt/riscv-gcc --strip-components=1
ENV PATH="/opt/riscv-gcc/bin:${PATH}"

# Native GCC 15 (xpack) for witness_ffi's C++ converter (needs >= 14; noble's stock gcc is 13); its probe finds g++-15 on PATH, leaving CC/CXX at the system default.
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

# Guest build with USE_HASH_KEY (node-store account recovery), which mainnet blocks need and the verification key depends on.
ARG USE_HASH_KEY=ON
WORKDIR /build/prover/guest_airbender
RUN make z6m_guest USE_HASH_KEY=${USE_HASH_KEY}

# The gpu feature is default; witness_ffi's gcc-15 libstdc++ is newer than the runtime image's, so link it statically.
# CUDAARCHS is the only architecture control of zksync-airbender's gpu_native_build (its default "native" needs a GPU at build time); RUST_MIN_STACK as in upstream's image.
WORKDIR /build/prover/prover_airbender
ARG CUDA_ARCHS="80;89;90;120"
ENV CUDAARCHS=${CUDA_ARCHS} \
    RUST_MIN_STACK=1073741824
RUN Z6M_STATIC_LIBSTDCXX=1 cargo build --release

# The recursion verifier programs (fsv) the prover loads at run time, checked against prover/docker/fsv.sha256: with the guest they define the verification key.
RUN set -eu; \
    src=$(ls -d "${CARGO_HOME:-/root/.cargo}"/git/checkouts/zksync-airbender-*/bd0d515*/tools/gkr_verifier); \
    [ "$(echo "$src" | wc -l)" = 1 ] || { echo "expected one zksync-airbender bd0d515 checkout, found: $src" >&2; exit 1; }; \
    mkdir -p /opt/z6m/fsv; \
    for f in $(awk '{print $2}' /build/prover/docker/fsv.sha256); do cp "$src/$f" /opt/z6m/fsv/; done; \
    cd /opt/z6m/fsv && sha256sum --strict -c /build/prover/docker/fsv.sha256

FROM nvidia/cuda:13.1.0-runtime-ubuntu24.04 AS airbender

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=airbender-builder /build/prover/prover_airbender/target/release/z6m_prover_airbender /usr/local/bin/
COPY --from=airbender-builder /build/prover/guest_airbender/build/z6m_guest.bin /opt/z6m/z6m_guest.bin
COPY --from=airbender-builder /build/prover/guest_airbender/build/z6m_guest.text /opt/z6m/z6m_guest.text
COPY --from=airbender-builder /opt/z6m/fsv /opt/z6m/fsv
COPY prover/docker/airbender-entrypoint.sh /usr/local/bin/airbender-entrypoint

# Run-time needs: FSV_DIR (recursion programs), RISCV_MERGE_WINDOW=0 (the JIT must not fuse the guest's store runs), RUST_MIN_STACK (1 GiB per thread), RECURSION_*_BLAKE (defaults; the prover refuses others).
ENV FSV_DIR=/opt/z6m/fsv \
    RISCV_MERGE_WINDOW=0 \
    RUST_MIN_STACK=1073741824 \
    RECURSION_UNROLLED_BLAKE=blake2_with_compression \
    RECURSION_BRIDGE_BLAKE=blake2_with_compression \
    RECURSION_FINAL_BLAKE=blake2_with_compression

# The commit the image was built from (passed by the publishing workflow); it names the verification key the entrypoint computes.
ARG ZILKWORM_REVISION=local
ENV ZILKWORM_REVISION=${ZILKWORM_REVISION}
LABEL org.opencontainers.image.revision=${ZILKWORM_REVISION}

# Runs as root, as vast.ai's SSH and Jupyter modes expect; state lives under /data (mount a volume).
WORKDIR /data

# With arguments runs the prover with them; without, runs the proving service configured from the environment.
ENTRYPOINT ["airbender-entrypoint"]

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
