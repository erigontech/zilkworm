// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {
using ::silkworm::ByteView;

// Wire layout: [hash:32][payload]. hash == keccak256(payload).
struct FlatKv {
    static constexpr std::size_t kKeyOffset     = 0;
    static constexpr std::size_t kKeySize       = 32;
    static constexpr std::size_t kPayloadOffset = kKeyOffset + kKeySize;

    static void encode(std::vector<uint8_t>& out,
                       const evmc::bytes32& hash,
                       ByteView payload) {
        out.reserve(out.size() + kKeySize + payload.size());
        out.insert(out.end(), hash.bytes, hash.bytes + kKeySize);
        out.insert(out.end(), payload.data(), payload.data() + payload.size());
    }

    static inline ByteView payload(ByteView body) noexcept {
        return body.substr(kPayloadOffset);
    }
    static inline const uint8_t* hash(ByteView body) noexcept {
        return body.data() + kKeyOffset;
    }
};

}  // namespace zilkworm
