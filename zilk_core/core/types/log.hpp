// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace silkworm {

struct Log {
    evmc::address address;
    std::vector<evmc::bytes32> topics;
    Bytes data;
};

namespace rlp {
    size_t length(const Log&);
    void encode(Bytes& to, const Log&);
}  // namespace rlp

}  // namespace silkworm
