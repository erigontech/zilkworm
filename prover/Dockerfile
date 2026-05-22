# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

FROM ubuntu:24.04 AS builder
RUN apt update 
RUN apt install -y --no-install-recommends ca-certificates curl gpg

# Install Docker for Docker-in-Docker call
# Add Docker's official GPG key:
RUN apt update
RUN apt install ca-certificates curl

RUN curl -fsSL -o /tmp/cuda-keyring.deb https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
RUN dpkg -i /tmp/cuda-keyring.deb
RUN apt-get update
RUN apt install -y \
  cuda-toolkit-13-0 \
  cuda-toolkit-13-0-config-common
COPY sp1-gpu-server /root/.sp1/bin/sp1-gpu-server

FROM scratch
COPY --from=builder / /