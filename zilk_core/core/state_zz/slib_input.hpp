// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// slib_input: the "default path" SSZ front-end that turns a StatelessInputBytes
// blob (schema_id 0x1501, ProtocolFork.Amsterdam) into a populated HashState.
//
// This is a TARGETED, hand-written reader for THIS one container — deliberately not
// a general SSZ library. The exact wire layout it follows (confirmed against
// the tests-zkevm@v0.8.0 release source + a real sample):
//
//   raw = schema_id(2B BIG-endian = 15 01) || SSZ encode(SszStatelessInput)
//
//   SszStatelessInput   fixed region 20B: off(new_payload_request)@0 (== 20),
//                       off(witness)@4, chain_id:uint64 inline @8, off(public_keys)@16
//   SszExecutionWitness fixed region 12B: off(state)@0 (== 12), off(codes)@4,
//                       off(headers)@8
//     state   : ProgressiveList[ByteList[1024]]   RLP MPT nodes   (no spec count cap)
//     codes   : ProgressiveList[ByteList[65536]]  contract code   (no spec count cap)
//     headers : List[ByteList[1024], 256]         RLP block headers (count cap 256)
//   public_keys : ProgressiveList[ByteVector[65]] fixed 65B stride, NO offset table
//
// All SSZ variable-field offsets are u32 little-endian, relative to the start of the
// container they live in. A list-of-variable-bytes serializes as an offset table of
// N u32 LE followed by the concatenated elements, N = first_offset / 4 (ProgressiveList
// and List are byte-identical here, so one routine decodes state/codes/headers).
//
// Every marker / offset / length is validated before use (see decode_stateless_input):
// the decoder never reads out of bounds and fails cleanly (std::nullopt) on any
// malformed input. rv64im-safe: no exceptions/RTTI, multi-byte reads via memcpy
// (8-byte-alignment agnostic), native copies only. It is ADDITIVE and host-testable,
// kept out of the DirectState rv64im guest (parallel to HashState itself).

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/state_zz/hash_state.hpp>  // HashState, ByteView

namespace zilkworm {

// 2-byte BIG-endian schema prefix: 0x15 = ProtocolFork.Amsterdam, 0x01 = revision.
inline constexpr std::uint16_t kSlibSchemaId = 0x1501u;

// Fixed-region sizes (also the value the FIRST variable offset must equal).
inline constexpr std::uint32_t kStatelessInputFixed = 20u;  // 4 + 4 + 8 + 4
inline constexpr std::uint32_t kWitnessFixed = 12u;         // 4 + 4 + 4

// Spec element-size caps (tests-zkevm v0.8.0, tight — NOT zilkworm's loose caps).
inline constexpr std::uint32_t kMaxBytesPerWitnessNode = 1u << 10;   // 1024
inline constexpr std::uint32_t kMaxBytesPerCode = 1u << 16;          // 65536
inline constexpr std::uint32_t kMaxBytesPerHeader = 1u << 10;        // 1024
inline constexpr std::uint32_t kMaxWitnessHeaders = 256u;            // headers count cap
inline constexpr std::uint32_t kPublicKeyBytes = 65u;               // ByteVector[65] stride

// Self-chosen count ceilings for the spec-uncapped ProgressiveLists, to bound heap
// growth on a hostile witness (the confirmed note flags there is genuinely no source
// cap on state/codes/public_keys counts). Generous but finite.
inline constexpr std::uint32_t kMaxWitnessStateNodes = 1u << 20;
inline constexpr std::uint32_t kMaxWitnessCodes = 1u << 20;
inline constexpr std::uint32_t kMaxPublicKeys = 1u << 20;

// Structural decode of the blob: every field is a view INTO `blob` (zero-copy, the
// INPUT_REGION pattern) — the caller must keep `blob` alive while these are used.
struct DecodedStatelessInput {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;        // raw SSZ sub-blob (for later block execution)
    std::vector<ByteView> state;         // RLP MPT nodes  -> HashState::add_node
    std::vector<ByteView> codes;         // contract code  -> HashState::add_code
    std::vector<ByteView> headers;       // RLP block headers (retained for execution)
    std::vector<ByteView> public_keys;   // 65-byte uncompressed secp256k1 keys
};

// Pure decode + full validation. Returns std::nullopt on ANY malformed marker /
// offset / length / overflow, never reading out of bounds. Does not touch HashState.
std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob);

// What parse_stateless_input retains for the later block-execution step. Views point
// into the input blob (see DecodedStatelessInput); state/codes have already been fed
// into the HashState stores by the time this returns.
struct StatelessInputView {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    std::vector<ByteView> headers;
    std::vector<ByteView> public_keys;
    std::uint32_t node_count = 0;        // # state nodes fed to add_node
    std::uint32_t code_count = 0;        // # codes fed to add_code
};

// Parser entry point: decode `blob`, feed each state node to hs.add_node and each code
// to hs.add_code (both keccak-verify on insert), and return the retained fields. Does
// NOT call build_state_from_trie (the caller supplies the anchoring prev_root). Returns
// std::nullopt on malformed input.
std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs);

// Convenience: parse_stateless_input followed by hs.build_state_from_trie(prev_root),
// where prev_root is the pre-state root the witness is anchored to. Returns the retained
// input view together with the build outcome; std::nullopt if the blob is malformed.
struct SlibRunResult {
    StatelessInputView input;
    HashState::BuildStatus status = HashState::BuildStatus::kOk;
};
std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs,
                                      const evmc::bytes32& prev_root);

}  // namespace zilkworm
