FROM ubuntu:25.10

LABEL org.opencontainers.image.source=https://github.com/erigontech/z6m

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        g++-15 \
        cmake \
        ninja-build \
        git \
        git-lfs \
        python3 \
        python3-pip \
        pipx \
        ca-certificates \
        curl \
        nodejs \
        npm \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        libprotobuf-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install conan

ENV PATH=/root/.local/bin:$PATH

# RISC-V bare-metal toolchain
RUN npm i -g xpm \
  && xpm install @xpack-dev-tools/riscv-none-elf-gcc@15.2.0-1.1 --global --verbose
ENV PATH="/root/.local/xPacks/@xpack-dev-tools/riscv-none-elf-gcc/15.2.0-1.1/.content/bin:${PATH}"

# Rust nightly
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    PATH="/root/.cargo/bin:${PATH}"

# Verify
RUN riscv-none-elf-gcc --version && cmake --version && rustc --version && protoc --version

WORKDIR /workspace

CMD ["bash"]
