// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/hash_maps.hpp>
#include <zilk_core/core/types/account.hpp>

namespace silkworm::state {

struct Object {
    std::optional<Account> initial;
    std::optional<Account> current;
};

struct CommittedValue {
    evmc::bytes32 initial{};   // value at the beginning of the block
    evmc::bytes32 original{};  // value at the beginning of the transaction; see EIP-2200
};

struct Storage {
    FlatHashMap<evmc::bytes32, CommittedValue> committed;
    FlatHashMap<evmc::bytes32, evmc::bytes32> current;
};

}  // namespace silkworm::state
