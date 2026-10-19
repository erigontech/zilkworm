// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The NewPayloadRequest of a statelessInputBytes blob (execution-specs amsterdam/stateless.py,
// tests-zkevm v21.0.1, the Gloas shape): decoded into views, hashed for the validation result, and
// turned into the block the guest executes.

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

// EIP-7685 request types, in the order ExecutionRequests lists them.
inline constexpr size_t kRequestTypes = 5;

struct SlibPayload {
    // ExecutionPayloadV4. The views point into the input blob.
    evmc::bytes32 parent_hash{};
    evmc::address fee_recipient{};
    evmc::bytes32 state_root{};
    evmc::bytes32 receipts_root{};
    ByteView logs_bloom;  // 256 bytes
    evmc::bytes32 prev_randao{};
    uint64_t block_number{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};
    ByteView extra_data;
    ByteView base_fee_per_gas;  // uint256, little-endian
    evmc::bytes32 block_hash{};
    std::vector<ByteView> transactions;  // typed envelopes, as the block body carries them
    std::vector<silkworm::Withdrawal> withdrawals;
    uint64_t blob_gas_used{0};
    uint64_t excess_blob_gas{0};
    ByteView block_access_list;  // RLP, EIP-7928
    uint64_t slot_number{0};
    // The rest of the request.
    ByteView versioned_hashes;  // n * 32 bytes
    evmc::bytes32 parent_beacon_block_root{};
    std::array<ByteView, kRequestTypes> execution_requests;  // SSZ request lists by type
};

/// nullopt on any offset or size out of place; never reads out of bounds.
std::optional<SlibPayload> decode_slib_payload(ByteView request);

/// hash_tree_root(NewPayloadRequest): what StatelessValidationResult commits to.
ssz::Node slib_payload_root(const SlibPayload& p);

/// The block the request describes: its header fields the payload does not carry are derived
/// (ommers hash, difficulty, nonce, transactions root, withdrawals root, requests hash, block
/// access list hash). nullopt when a transaction does not decode or base_fee_per_gas exceeds 64
/// bits. The block hash is left for the caller to check against `p.block_hash`.
std::optional<silkworm::Block> slib_payload_block(const SlibPayload& p);

}  // namespace zilkworm
