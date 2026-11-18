// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The NewPayloadRequest of a statelessInputBytes blob: decoded into views, hashed for the validation result, turned into the block to execute.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common_zz/ssz_merkle.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/withdrawal.hpp>

namespace zilkworm {

using ::silkworm::ByteView;

inline constexpr size_t kRequestTypes = 5;

struct SlibPayload {
    // ExecutionPayloadV4. The views point into the input blob.
    evmc::bytes32 parent_hash{};
    evmc::address fee_recipient{};
    evmc::bytes32 state_root{};
    evmc::bytes32 receipts_root{};
    ByteView logs_bloom;
    evmc::bytes32 prev_randao{};
    uint64_t block_number{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};
    ByteView extra_data;
    ByteView base_fee_per_gas;  // uint256, little-endian
    evmc::bytes32 block_hash{};
    std::vector<ByteView> transactions;
    std::vector<silkworm::Withdrawal> withdrawals;
    uint64_t blob_gas_used{0};
    uint64_t excess_blob_gas{0};
    ByteView block_access_list;
    uint64_t slot_number{0};
    ByteView versioned_hashes;  // n * 32 bytes
    evmc::bytes32 parent_beacon_block_root{};
    std::array<ByteView, kRequestTypes> execution_requests;
};

/// nullopt on any offset or size out of place; never reads out of bounds.
std::optional<SlibPayload> decode_slib_payload(ByteView request);

/// hash_tree_root(NewPayloadRequest): what StatelessValidationResult commits to.
ssz::Node slib_payload_root(const SlibPayload& p);

/// Derives the header fields the payload lacks; nullopt on an undecodable transaction or base_fee_per_gas over 64 bits. The caller checks block_hash.
std::optional<silkworm::Block> slib_payload_block(const SlibPayload& p);

}  // namespace zilkworm
