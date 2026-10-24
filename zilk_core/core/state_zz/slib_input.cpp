// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "slib_input.hpp"

#include <algorithm>
#include <array>
#include <utility>

#include <zilk_core/core/common_zz/ssz_read.hpp>

namespace zilkworm {

namespace {

// Framing validated; the lists are still raw.
struct Sections {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    ByteView state;
    ByteView codes;
    ByteView headers;
};

std::optional<Sections> split_stateless_input(ByteView blob) {
    if (blob.size() < 2 || blob[0] != (kSlibSchemaId >> 8) || blob[1] != (kSlibSchemaId & 0xff)) {
        return std::nullopt;
    }
    const ByteView body = ssz::subv(blob, 2, blob.size() - 2);

    // StatelessInput: the offsets of new_payload_request and witness, then chain_id.
    std::vector<ByteView> fields;
    static constexpr std::array<size_t, 2> kInputOffsets{0, 4};
    if (!ssz::split_variable(body, kStatelessInputFixed, kInputOffsets, fields)) return std::nullopt;
    Sections out;
    out.chain_id = ssz::rd_u64(body, 8);
    out.new_payload_request = fields[0];
    const ByteView wit = fields[1];

    // ExecutionWitness: state, codes, headers.
    static constexpr std::array<size_t, 3> kWitnessOffsets{0, 4, 8};
    if (!ssz::split_variable(wit, kWitnessFixed, kWitnessOffsets, fields)) return std::nullopt;
    out.state = fields[0];
    out.codes = fields[1];
    out.headers = fields[2];
    return out;
}

}  // namespace

std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob) {
    const auto sec = split_stateless_input(blob);
    if (!sec) return std::nullopt;
    DecodedStatelessInput out;
    out.chain_id = sec->chain_id;
    out.new_payload_request = sec->new_payload_request;
    if (!ssz::decode_byte_lists(sec->state, kMaxBytesPerWitnessNode, kMaxWitnessStateNodes, out.state) ||
        !ssz::decode_byte_lists(sec->codes, kMaxBytesPerCode, kMaxWitnessCodes, out.codes) ||
        !ssz::decode_byte_lists(sec->headers, kMaxBytesPerHeader, kMaxWitnessHeaders, out.headers)) {
        return std::nullopt;
    }
    return out;
}

std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs) {
    const auto sec = split_stateless_input(blob);
    if (!sec) return std::nullopt;

    const auto n_state = ssz::byte_list_count(sec->state, kMaxWitnessStateNodes);
    const auto n_codes = ssz::byte_list_count(sec->codes, kMaxWitnessCodes);
    if (!n_state || !n_codes) return std::nullopt;
    // Accounts derive from the clamped node hint.
    const std::uint32_t nodes_hint = std::min(*n_state, HashState::kMaxReserve);
    hs.reserve_stores(nodes_hint, *n_codes, std::max<std::uint32_t>(1024u, nodes_hint / 8u), 4096u);

    StatelessInputView v;
    v.chain_id = sec->chain_id;
    v.new_payload_request = sec->new_payload_request;
    // A bad element leaves hs partly fed.
    if (!ssz::for_each_byte_list(sec->state, kMaxBytesPerWitnessNode, kMaxWitnessStateNodes,
                                 [&](ByteView node) {
                                     hs.add_node_borrowed(node);
                                     ++v.node_count;
                                     return true;
                                 }) ||
        !ssz::for_each_byte_list(sec->codes, kMaxBytesPerCode, kMaxWitnessCodes, [&](ByteView code) {
            hs.add_code_borrowed(code);
            ++v.code_count;
            return true;
        }) ||
        !ssz::decode_byte_lists(sec->headers, kMaxBytesPerHeader, kMaxWitnessHeaders, v.headers)) {
        return std::nullopt;
    }
    return v;
}

std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs, const evmc::bytes32& prev_root) {
    auto v = parse_stateless_input(blob, hs);
    if (!v) return std::nullopt;
    const auto status = hs.build_state_from_trie(prev_root);
    return SlibRunResult{std::move(*v), status};
}

}  // namespace zilkworm
