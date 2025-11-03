// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <utility>

#include <nlohmann/json.hpp>

#include <silkworm/core/common/test_util.hpp>

namespace silkworm::cmd::state_transition {

class ExpectedSubState {
  nlohmann::json& sub_state_data_;

  public:
    ExpectedSubState(
      nlohmann::json& sub_state_data
    ) : sub_state_data_(sub_state_data) {}
    // std::move(sub_state_data)
    unsigned index{};
    evmc::bytes32 stateHash;
    evmc::bytes32 logsHash;
    const nlohmann::json& get_sub_state_data() const { return sub_state_data_; };
};

class ExpectedState {
    nlohmann::json state_data_;
    std::string fork_name_;

  public:
    ExpectedState(
        nlohmann::json& state_data,
        std::string fork_name)
        : state_data_(state_data),
          fork_name_{std::move(fork_name)} {}

    ChainConfig get_config() const;

    const nlohmann::json& get_state_data() const { return state_data_; };

    std::vector<ExpectedSubState> get_sub_states();

    std::string fork_name() const { return fork_name_; };
};
};  // namespace silkworm::cmd::state_transition
