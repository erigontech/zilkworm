// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>
#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/types/block.hpp>

// See https://arvanaghi.com/blog/explaining-the-genesis-block-in-ethereum/

namespace silkworm {

/*
 * \brief Returns genesis data given a known chain_id.
 * If id is not recognized returns an invalid json string
 */
std::string_view read_genesis_data(ChainId chain_id);

BlockHeader read_genesis_header(const nlohmann::json& genesis, const evmc::bytes32& state_root);

std::vector<uint8_t> read_genesis_allocation(const nlohmann::json& alloc);

}  // namespace silkworm
