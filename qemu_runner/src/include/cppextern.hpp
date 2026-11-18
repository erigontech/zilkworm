// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// Runs one fixture envelope (EEST JSON or MFBD, by leading magic); returns a ctest exit code: 0 success, 1 kRunFailure, 2 kRunSkipped.
uint64_t sample_run_wrapped(std::string envelope_str);

#ifdef __cplusplus
}
#endif
