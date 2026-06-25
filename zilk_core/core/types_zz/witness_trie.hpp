// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <unordered_map>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm::witness {

// keccak256(node_rlp) -> raw node RLP bytes.
struct NodeHash {
    size_t operator()(const evmc::bytes32& h) const noexcept {
        size_t v;
        std::memcpy(&v, h.bytes, sizeof(v));
        return v;
    }
};
using NodeMap = std::unordered_map<evmc::bytes32, silkworm::ByteView, NodeHash>;

using LeafCb = std::function<void(std::span<const uint8_t> nibbles, silkworm::ByteView value)>;

// Partial tries are normal; missing subtrees are silently skipped.
void for_each_leaf(const NodeMap& nodes, const evmc::bytes32& root, LeafCb cb);

}  // namespace zilkworm::witness
