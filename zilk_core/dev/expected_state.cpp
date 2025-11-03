// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "expected_state.hpp"

#include <iostream>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm::cmd::state_transition {

ChainConfig ExpectedState::get_config() const {
    const auto config_it{test::kNetworkConfig.find(fork_name_)};
    if (config_it == test::kNetworkConfig.end()) {
        // std::cout << "unknown network " << fork_name_ << std::endl;
        // throw std::invalid_argument(fork_name_);
    }
    const ChainConfig& config{config_it->second};
    return config;
}

std::vector<ExpectedSubState> ExpectedState::get_sub_states() {
    std::vector<ExpectedSubState> sub_states;
    unsigned i = 0;
    // std::cout << "\n\n ===== In get_sub_states" << state_data_ << "\n";
    // auto state_itmes =state_data_.items();
    for (auto& tx : state_data_) {
        ExpectedSubState sub_state{tx};
        // std::cout << "\n\n ========= get_sub_states for (auto& tx : state_data_) tx.dump()\n" << tx.dump() << "\n";
        // std::cout << "\n\n ========= get_sub_states get_sub_state_data()\n" << sub_state.get_sub_state_data().dump() << "\n";
        // std::cout << "tx.dump()" << tx.dump() << "\n";
        // sub_state.stateHash = to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
        // sub_state.logsHash = to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
        sub_state.index = i;
        sub_states.push_back(sub_state);
        ++i;
    }

    return sub_states;
}

};  // namespace silkworm::cmd::state_transition