// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// slib_input: SSZ front-end that decodes a StatelessInputBytes blob into a HashState.
// See docs/hashstate.md, "StatelessInputBytes parsing".

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
    std::vector<ByteView> state;         // RLP MPT nodes  -> HashState::add_node_borrowed
    std::vector<ByteView> codes;         // contract code  -> HashState::add_code_borrowed
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
    std::uint32_t node_count = 0;        // # state nodes fed to add_node_borrowed
    std::uint32_t code_count = 0;        // # codes fed to add_code_borrowed
};

// Parser entry point: decode `blob`, feed each state node to hs.add_node_borrowed and each
// code to hs.add_code_borrowed (both keccak-verify on insert), and return the retained
// fields. `hs` keeps views into `blob`, so `blob` must outlive every use of `hs`, as it must
// already outlive the returned view. Does NOT call build_state_from_trie (the caller
// supplies the anchoring prev_root). Returns std::nullopt on malformed input.
//
// The state and code lists are streamed straight into the stores as they are validated,
// after hs.reserve_stores has sized the stores from the element counts the lists announce
// (so the one-pass feed grows no table). On std::nullopt `hs` may therefore already hold
// the elements that preceded the malformed one: a failed parse leaves `hs` unusable, and
// the caller must discard it (both production callers run on a fresh HashState per block).
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
