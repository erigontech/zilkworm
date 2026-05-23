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
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install conan

ENV PATH=/root/.local/bin:$PATH

WORKDIR /workspace

CMD ["bash"]
