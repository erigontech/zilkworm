// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// C ABI for the witness JSON → MFBD FlatBundle converter, so non-C++ hosts
// (e.g. the Rust prover) can link the converter statically instead of
// spawning a CLI subprocess. The json_witness_to_flat_bundle CLI
// (zilk_core/dev/cli) is a thin wrapper over the same entry point.

#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Convert a witness JSON document (single object with "block", "headers" and
// optional "state"/"codes"/"keys"/"fork"/"expect_invalid" members) into an
// MFBD envelope (16-byte header + FBND FlatBundle).
//
// Returns 0 on success: *out_data/*out_len describe a malloc'd buffer with
// the MFBD bytes; release it with z6m_mfbd_free.
// Returns nonzero on failure: *out_err points to a malloc'd NUL-terminated
// error message (may be null if allocation failed); release it with
// z6m_mfbd_free. No exception ever crosses this boundary.
int z6m_json_witness_to_mfbd(const uint8_t* json, size_t json_len,
                             uint8_t** out_data, size_t* out_len,
                             char** out_err);

// Free a buffer returned by z6m_json_witness_to_mfbd (either *out_data or
// *out_err). Null is a no-op.
void z6m_mfbd_free(void* p);

}  // extern "C"
