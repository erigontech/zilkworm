// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>

#include <evmone_precompiles/keccak.hpp>

namespace zilkworm {

// Memoized keccak256; keccak is pure, so entries never go stale.
// size must be 1..32 and is NOT checked — larger overflows the 32-byte slot buffer.
ethash::hash256 keccak256_memo(const uint8_t* data, size_t size) noexcept;

}  // namespace zilkworm
