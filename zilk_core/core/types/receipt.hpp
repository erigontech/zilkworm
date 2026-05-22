// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <zilk_core/core/types/bloom.hpp>
#include <zilk_core/core/types/log.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

struct Receipt {
    TransactionType type{TransactionType::kLegacy};
    bool success{false};
    uint64_t cumulative_gas_used{0};
    Bloom bloom{};
    std::vector<Log> logs;
};

namespace rlp {
    void encode(Bytes& to, const Receipt&);
}

}  // namespace silkworm
