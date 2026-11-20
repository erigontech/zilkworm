// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdbool.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

bool silkworm_recover_address(uint8_t out[20], const uint8_t message[32], const uint8_t signature[64],
                              uint8_t recovery_id);

#if defined(__cplusplus)
}
#endif
