// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <span>
#include <utility>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

using ::zilkworm::Account;
using ::zilkworm::DirectState;

namespace silkworm::cmd::state_transition {

class StateTransition {
  private:
    std::span<uint8_t> envelope_;
    bool failed_{false};
    evmc::bytes32 pre_state_root_{};
    evmc::bytes32 post_state_root_{};
    evmc::bytes32 block_hash_{};
    uint64_t chain_id_{0};
    bool pre_root_set_{false};

  public:
    /// Sentinel values returned by the run entry points. Any other value is the gas_used.
    static constexpr uint64_t kRunFailure = UINT64_MAX;
    static constexpr uint64_t kRunSkipped = UINT64_MAX - 1;

    explicit StateTransition(std::span<uint8_t> envelope) noexcept;

    static evmc::address to_evmc_address(const std::string& address);
    std::unique_ptr<evmc::address> sender_to_address(const std::string& sender);

    // Transition summary committed to the guest public values.
    struct Result {
        uint64_t gas_used{0};
        evmc::bytes32 pre_state_root{};   // parent root the proof starts from (MPT validation anchor)
        evmc::bytes32 post_state_root{};  // state root of the last proven block
        evmc::bytes32 block_hash{};       // hash of the last proven block
        uint64_t chain_id{0};
    };

    Result run();

    bool failed() const noexcept { return failed_; }

    bool check_root(DirectState& state, BlockHeader& header, evmc_revision rev);

    bool check_root_new_block(DirectState& state, BlockHeader& header);

  private:
    uint64_t run_ejsn();
    uint64_t run_mfbd();
    std::pair<uint64_t, bool> run_one_bundle(::zilkworm::FlatBundle& bundle);
};

}  // namespace silkworm::cmd::state_transition
