// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "slib_input.hpp"

#include <array>
#include <utility>

#include <zilk_core/core/common_zz/ssz_read.hpp>

namespace zilkworm {

std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob) {
    if (blob.size() < 2 || blob[0] != (kSlibSchemaId >> 8) || blob[1] != (kSlibSchemaId & 0xff)) {
        return std::nullopt;
    }
    const ByteView body = ssz::subv(blob, 2, blob.size() - 2);

    // StatelessInput: the offsets of new_payload_request and witness, then chain_id.
    std::vector<ByteView> fields;
    static constexpr std::array<size_t, 2> kInputOffsets{0, 4};
    if (!ssz::split_variable(body, kStatelessInputFixed, kInputOffsets, fields)) return std::nullopt;
    DecodedStatelessInput out;
    out.chain_id = ssz::rd_u64(body, 8);
    out.new_payload_request = fields[0];
    const ByteView wit = fields[1];

    // ExecutionWitness: state, codes, headers.
    static constexpr std::array<size_t, 3> kWitnessOffsets{0, 4, 8};
    if (!ssz::split_variable(wit, kWitnessFixed, kWitnessOffsets, fields)) return std::nullopt;
    if (!ssz::decode_byte_lists(fields[0], kMaxBytesPerWitnessNode, kMaxWitnessStateNodes, out.state) ||
        !ssz::decode_byte_lists(fields[1], kMaxBytesPerCode, kMaxWitnessCodes, out.codes) ||
        !ssz::decode_byte_lists(fields[2], kMaxBytesPerHeader, kMaxWitnessHeaders, out.headers)) {
        return std::nullopt;
    }
    return out;
}

std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs) {
    auto dec = decode_stateless_input(blob);
    if (!dec) return std::nullopt;

    for (const ByteView node : dec->state) hs.add_node_borrowed(node);
    for (const ByteView code : dec->codes) hs.add_code_borrowed(code);

    StatelessInputView v;
    v.chain_id = dec->chain_id;
    v.new_payload_request = dec->new_payload_request;
    v.headers = std::move(dec->headers);
    v.node_count = static_cast<std::uint32_t>(dec->state.size());
    v.code_count = static_cast<std::uint32_t>(dec->codes.size());
    return v;
}

std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs, const evmc::bytes32& prev_root) {
    auto v = parse_stateless_input(blob, hs);
    if (!v) return std::nullopt;
    const auto status = hs.build_state_from_trie(prev_root);
    return SlibRunResult{std::move(*v), status};
}

}  // namespace zilkworm
