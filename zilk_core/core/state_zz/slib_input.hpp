// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// slib_input: the SSZ front end that decodes a statelessInputBytes blob (EIP-8025, tests-zkevm
// v21.0.1) into a HashState. See docs/hashstate.md, "StatelessInputBytes parsing".

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/state_zz/hash_state.hpp>  // HashState, ByteView

namespace zilkworm {

// 2-byte big-endian schema prefix: 0x15 = ProtocolFork.Amsterdam, 0x01 = revision.
inline constexpr std::uint16_t kSlibSchemaId = 0x1501u;

// Fixed regions: StatelessInput {new_payload_request, witness, chain_id}, ExecutionWitness
// {state, codes, headers}. The first variable offset must equal the fixed size.
inline constexpr std::uint32_t kStatelessInputFixed = 16u;  // 4 + 4 + 8
inline constexpr std::uint32_t kWitnessFixed = 12u;         // 4 + 4 + 4

// The schema's element caps.
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
    ByteView new_payload_request;  // SSZ NewPayloadRequest, see slib_payload.hpp
    std::vector<ByteView> state;   // RLP trie nodes  -> HashState::add_node_borrowed
    std::vector<ByteView> codes;   // contract codes  -> HashState::add_code_borrowed
    std::vector<ByteView> headers;  // RLP block headers
};

// Structural decode: nullopt on a bad marker, offset or length; never reads out of bounds.
std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob);

// What parse_stateless_input keeps for block execution; the nodes and codes are in the stores.
struct StatelessInputView {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    std::vector<ByteView> headers;
    std::uint32_t node_count = 0;
    std::uint32_t code_count = 0;
};

// hs borrows blob; on nullopt discard hs.
std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs);

// parse_stateless_input, then hs.build_state_from_trie(prev_root).
struct SlibRunResult {
    StatelessInputView input;
    HashState::BuildStatus status = HashState::BuildStatus::kOk;
};
std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs, const evmc::bytes32& prev_root);

}  // namespace zilkworm
