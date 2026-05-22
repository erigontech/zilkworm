// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <set>

#include <evmc/evmc.h>

namespace silkworm {

struct CallTraces {
    std::set<evmc::address> senders;
    std::set<evmc::address> recipients;
};

}  // namespace silkworm
