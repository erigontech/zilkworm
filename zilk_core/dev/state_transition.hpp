// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <memory>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/execution/execution.hpp>
#include <zilk_core/core/state/in_memory_state.hpp>
#include <zilk_core/core/trie_zz/flat_store.hpp>

namespace silkworm::cmd::state_transition {

class StateTransition {
  private:
    std::string_view json_str_;
    std::string unified_rlp_data_;   // Owns the RLP data
    ByteView unified_rlp_;           // View into unified_rlp_data_
    bool terminate_on_error_{false};
    bool show_diagnostics_{false};
    silkworm::mpt::FlatNodeStore node_store_;

  public:
    /// Sentinel values returned by `run_rlp`. Any other value is the gas_used.
    static constexpr uint64_t kRunFailure = UINT64_MAX;
    static constexpr uint64_t kRunSkipped = UINT64_MAX - 1;

    explicit StateTransition(std::string_view json_str, bool terminate_on_error, bool show_diagnostics) noexcept;
    explicit StateTransition(const std::string& unified_rlp_str) noexcept;
    explicit StateTransition(std::string&& unified_rlp_str) noexcept;  // Move constructor
    explicit StateTransition(ByteView& unified_rlp) noexcept;
    static evmc::address to_evmc_address(const std::string& address);
    std::unique_ptr<evmc::address> sender_to_address(const std::string& sender);
    uint64_t run();
    uint64_t run_rlp();
    bool check_root(ByteView pre_trie_payload, InMemoryState& state, BlockHeader& header);
};

}  // namespace silkworm::cmd::state_transition
