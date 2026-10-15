#!/bin/bash

# Copyright 2026 The Zilkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Stages a release's Airbender assets from the prover image built for the release commit:
#   z6m_guest_airbender.bin, .text   the rv32 guest the image proves with
#   z6m_guest_airbender.vk           its verification key (EVKEY001 v2), which `verify` and the
#                                    Ethproofs verifier check proofs against
# The key is computed by the image's own prover, on the CPU (no GPU needed; about a minute on
# 16 cores), from the guest and the image's recursion verifier programs.
#
#   tools/scripts/airbender_release_assets.sh IMAGE OUT_DIR
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 IMAGE OUT_DIR" >&2
    exit 2
fi
image=$1
mkdir -p "$2"
out=$(cd "$2" && pwd)

docker pull -q "$image" >/dev/null
cid=$(docker create "$image")
trap 'docker rm -f "$cid" >/dev/null' EXIT
docker cp "$cid:/opt/z6m/z6m_guest.bin" "$out/z6m_guest_airbender.bin"
docker cp "$cid:/opt/z6m/z6m_guest.text" "$out/z6m_guest_airbender.text"

# The entrypoint runs the prover with --guest-bin /opt/z6m/z6m_guest and the image's FSV_DIR.
docker run --rm --user "$(id -u):$(id -g)" -v "$out:/out" "$image" \
    vk --output /out/z6m_guest_airbender.vk

if [ "$(head -c 8 "$out/z6m_guest_airbender.vk")" != EVKEY001 ]; then
    echo "$out/z6m_guest_airbender.vk is not an EVKEY001 verification key" >&2
    exit 1
fi
(cd "$out" && sha256sum z6m_guest_airbender.bin z6m_guest_airbender.text z6m_guest_airbender.vk)
