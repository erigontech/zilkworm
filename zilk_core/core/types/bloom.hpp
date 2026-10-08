// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <zilk_core/core/types/log.hpp>

namespace silkworm {

inline constexpr size_t kBloomByteLength{256};

using Bloom = std::array<uint8_t, kBloomByteLength>;

//! See Section 4.3.1 "Transaction Receipt" of the Yellow Paper
void m3_2048(Bloom& bloom, ByteView x);

//! Sets bloom to the bloom filter of logs. Filling the caller's bloom in place spares the 256-byte
//! copy that assigning a returned Bloom costs.
void logs_bloom(Bloom& bloom, const std::vector<Log>& logs);

inline Bloom logs_bloom(const std::vector<Log>& logs) {
    Bloom bloom;
    logs_bloom(bloom, logs);
    return bloom;
}

inline void join(Bloom& sum, const Bloom& addend) {
    for (size_t i{0}; i < kBloomByteLength; ++i) {
        sum[i] |= addend[i];
    }
}

inline std::string_view to_string(const Bloom& bloom) {
    return {reinterpret_cast<const char*>(bloom.data()), bloom.size()};
}

}  // namespace silkworm
