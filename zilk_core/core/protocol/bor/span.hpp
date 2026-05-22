// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/execution/evm.hpp>

namespace silkworm::protocol::bor {

struct Span {
    uint64_t id{0};
    BlockNum start_block{0};
    BlockNum end_block{0};
};

// See GetCurrentSpan in polygon/bor/spanner.go
std::optional<Span> get_current_span(EVM& evm, const evmc_address& validator_contract);

}  // namespace silkworm::protocol::bor
