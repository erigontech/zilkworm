// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <cstdint>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// Run one subtest. Returns a ctest-compatible exit code:
// 0 = success (block's gas_used is logged via sys_println)
// 1 = StateTransition::kRunFailure
// 2 = StateTransition::kRunSkipped
// `is_json == true`  → input is an EEST JSON fixture.
// `is_json == false` → input is a single unified-RLP blob.
uint64_t sample_run_wrapped(bool is_json, std::string input_str);

#ifdef __cplusplus
}
#endif
