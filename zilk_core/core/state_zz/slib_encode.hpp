// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Host-side encoder for StatelessInputBytes, the inverse of decode_stateless_input
// (slib_input.hpp). Used by legacy_to_slib_fixture and the HashState tests.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/state_zz/slib_input.hpp>

namespace zilkworm {

namespace slib_encode_detail {

    inline void put_u32(Bytes& b, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    inline void put_u64(Bytes& b, std::uint64_t v) {
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }

    // An SSZ list of byte strings: N u32 LE offsets, relative to the list start, then the
    // elements back to back. An empty list is zero bytes.
    inline Bytes encode_bytelist_list(std::span<const ByteView> els) {
        Bytes out;
        std::uint32_t off = static_cast<std::uint32_t>(els.size()) * 4u;
        for (const auto& e : els) {
            put_u32(out, off);
            off += static_cast<std::uint32_t>(e.size());
        }
        for (const auto& e : els) out.append(e.data(), e.size());
        return out;
    }

    inline bool within(std::span<const ByteView> els, std::size_t max_count, std::size_t max_bytes) {
        if (els.size() > max_count) return false;
        for (const auto& e : els)
            if (e.size() > max_bytes) return false;
        return true;
    }

}  // namespace slib_encode_detail

// schema_id || SSZ(StatelessInput) carrying the given witness lists, with an empty
// new_payload_request and no public keys: the fields the HashState runner reads. Returns
// std::nullopt when a list breaks a limit decode_stateless_input enforces, or when the
// encoding would not fit the decoder's u32 offsets.
inline std::optional<Bytes> encode_stateless_input(std::span<const ByteView> state,
                                                   std::span<const ByteView> codes,
                                                   std::span<const ByteView> headers,
                                                   std::uint64_t chain_id) {
    using namespace slib_encode_detail;
    if (!within(state, kMaxWitnessStateNodes, kMaxBytesPerWitnessNode) ||
        !within(codes, kMaxWitnessCodes, kMaxBytesPerCode) ||
        !within(headers, kMaxWitnessHeaders, kMaxBytesPerHeader))
        return std::nullopt;

    const Bytes state_blob = encode_bytelist_list(state);
    const Bytes codes_blob = encode_bytelist_list(codes);
    const Bytes headers_blob = encode_bytelist_list(headers);
    const std::size_t witness_size =
        kWitnessFixed + state_blob.size() + codes_blob.size() + headers_blob.size();
    if (kStatelessInputFixed + witness_size > UINT32_MAX) return std::nullopt;

    // SszExecutionWitness: [off(state)=12][off(codes)][off(headers)], then the three lists.
    const auto off_codes = static_cast<std::uint32_t>(kWitnessFixed + state_blob.size());
    const auto off_headers = static_cast<std::uint32_t>(off_codes + codes_blob.size());
    // SszStatelessInput: [off(npr)=20][off(witness)=20][chain_id][off(public_keys)], with an
    // empty new_payload_request before the witness and no public keys after it.
    const auto off_public_keys = static_cast<std::uint32_t>(kStatelessInputFixed + witness_size);

    Bytes blob;
    blob.reserve(2 + kStatelessInputFixed + witness_size);
    blob.push_back(static_cast<std::uint8_t>(kSlibSchemaId >> 8));
    blob.push_back(static_cast<std::uint8_t>(kSlibSchemaId & 0xFF));
    put_u32(blob, kStatelessInputFixed);
    put_u32(blob, kStatelessInputFixed);
    put_u64(blob, chain_id);
    put_u32(blob, off_public_keys);
    put_u32(blob, kWitnessFixed);
    put_u32(blob, off_codes);
    put_u32(blob, off_headers);
    blob += state_blob;
    blob += codes_blob;
    blob += headers_blob;
    return blob;
}

}  // namespace zilkworm
