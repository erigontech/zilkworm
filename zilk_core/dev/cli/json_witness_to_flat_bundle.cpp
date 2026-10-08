// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Reads a witness JSON document on stdin, emits a FlatBundle on stdout.
// Thin wrapper over the library converter in zilk_core/dev/witness_converter.

#include <cstdint>
#include <cstdio>
#include <vector>

#include <zilk_core/dev/witness_converter.hpp>

namespace {

std::vector<uint8_t> read_all_stdin() {
    std::vector<uint8_t> buf;
    constexpr size_t kChunk = 64 * 1024;
    uint8_t tmp[kChunk];
    while (true) {
        size_t n = std::fread(tmp, 1, kChunk, stdin);
        if (n == 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        if (n < kChunk) break;
    }
    return buf;
}

}  // namespace

int main() {
    const std::vector<uint8_t> input = read_all_stdin();

    uint8_t* data = nullptr;
    size_t len = 0;
    char* err = nullptr;
    const int rc = z6m_json_witness_to_mfbd(input.data(), input.size(), &data, &len, &err);
    if (rc != 0) {
        std::fprintf(stderr, "%s\n", err != nullptr ? err : "flat_bundle_builder: unknown error");
        z6m_mfbd_free(err);
        return 1;
    }

    const size_t written = std::fwrite(data, 1, len, stdout);
    z6m_mfbd_free(data);
    if (written != len) {
        std::fprintf(stderr, "flat_bundle_builder: short write to stdout\n");
        return 2;
    }
    return 0;
}
