// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Number of non-zero bytes; the zero count is data.size() minus this.
[[nodiscard]] inline size_t count_nonzero_bytes(silkworm::ByteView data) noexcept {
    return static_cast<size_t>(std::ranges::count_if(data, [](uint8_t b) { return b != 0; }));
}

}  // namespace zilkworm
