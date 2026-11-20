// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
// C ABI for the witness JSON -> MFBD FlatBundle converter, for non-C++ hosts.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Returns 0 with a malloc'd MFBD buffer in *out_data/*out_len, else nonzero with a malloc'd message in *out_err (may be null); free both with z6m_mfbd_free.
int z6m_json_witness_to_mfbd(const uint8_t* json, size_t json_len,
                             uint8_t** out_data, size_t* out_len,
                             char** out_err);

// Frees *out_data or *out_err; null is a no-op.
void z6m_mfbd_free(void* p);

}  // extern "C"
