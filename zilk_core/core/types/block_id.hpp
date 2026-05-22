// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/types/hash.hpp>

namespace silkworm {

struct BlockId {
    BlockNum block_num{};
    Hash hash;

    friend bool operator==(const BlockId&, const BlockId&) = default;
};

}  // namespace silkworm
