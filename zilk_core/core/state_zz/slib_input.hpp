// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// SSZ front end decoding a statelessInputBytes blob (EIP-8025) into a HashState.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/state_zz/hash_state.hpp>

namespace zilkworm {

// 2-byte big-endian schema prefix: 0x15 = ProtocolFork.Amsterdam, 0x01 = revision.
inline constexpr std::uint16_t kSlibSchemaId = 0x1501u;

// The first variable offset must equal the fixed size.
inline constexpr std::uint32_t kStatelessInputFixed = 16u;
inline constexpr std::uint32_t kWitnessFixed = 12u;

inline constexpr std::uint32_t kMaxBytesPerWitnessNode = 1u << 10;
inline constexpr std::uint32_t kMaxBytesPerCode = 1u << 16;
inline constexpr std::uint32_t kMaxBytesPerHeader = 1u << 10;
inline constexpr std::uint32_t kMaxWitnessHeaders = 256u;

// The state and code lists are progressive (uncapped); these bound the heap on a hostile input.
inline constexpr std::uint32_t kMaxWitnessStateNodes = 1u << 20;
inline constexpr std::uint32_t kMaxWitnessCodes = 1u << 20;

// The blob cut into views; the caller keeps `blob` alive while they are used.
struct DecodedStatelessInput {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    std::vector<ByteView> state;
    std::vector<ByteView> codes;
    std::vector<ByteView> headers;
};

// Structural decode: nullopt on a bad marker, offset or length; never reads out of bounds.
std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob);

struct StatelessInputView {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    std::vector<ByteView> headers;
    std::uint32_t node_count = 0;
    std::uint32_t code_count = 0;
};

// hs borrows blob; on nullopt discard hs.
std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs);

struct SlibRunResult {
    StatelessInputView input;
    HashState::BuildStatus status = HashState::BuildStatus::kOk;
};
std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs, const evmc::bytes32& prev_root);

}  // namespace zilkworm
