// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// SSZ merkleization (consensus-specs simple-serialize.md, EIP-7916 progressive lists, EIP-7495
// progressive containers), enough to take the hash tree root of a stateless-input
// NewPayloadRequest. The reference is libssz-merkle, which ere-guests uses.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm::ssz {

using ::silkworm::ByteView;
using Node = std::array<uint8_t, 32>;

/// SHA-256 of `a || b`.
Node hash_nodes(const Node& a, const Node& b);

/// `bytes` cut into 32-byte chunks, the last one zero-padded; no chunk for no bytes.
std::vector<Node> pack(ByteView bytes);

/// Binary Merkle root of `chunks` as the leaves of a tree with `limit` leaves (chunks.size() rounded up
/// to a power of two when none); the leaves past the chunks are zero.
Node merkleize(std::span<const Node> chunks, std::optional<size_t> limit = std::nullopt);

/// EIP-7916: hash(merkleize(chunks[0:1], 1), hash(merkleize(chunks[1:5], 4), hash(..., 16), ...)), zero
/// where the chunks end.
Node merkleize_progressive(std::span<const Node> chunks);

/// hash(root, length as a little-endian uint256).
Node mix_in_length(const Node& root, uint64_t length);

/// EIP-7495: hash(root, active_fields as a bitvector), every one of `num_fields` (at most 256) active.
Node mix_in_active_fields(const Node& root, size_t num_fields);

// Hash tree roots of the schema's types.
Node root_u64(uint64_t v);
Node root_bool(bool v);
/// Vector[byte, N]: the bytes as one chunk up to 32, the root of their chunks beyond.
Node root_bytes_fixed(ByteView bytes);
/// List[byte, limit].
Node root_byte_list(ByteView bytes, size_t limit);
/// ProgressiveList[byte].
Node root_progressive_bytes(ByteView bytes);
/// ProgressiveList[T] of composite T, or of Vector[byte, 32]: the item roots are the chunks either way.
Node root_progressive_list(std::span<const Node> item_roots);
/// Container, from the field roots in declaration order.
Node root_container(std::span<const Node> field_roots);
/// ProgressiveContainer with every field active.
Node root_progressive_container(std::span<const Node> field_roots);

}  // namespace zilkworm::ssz
