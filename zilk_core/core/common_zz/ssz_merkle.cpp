// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "ssz_merkle.hpp"

#include <algorithm>
#include <bit>
#include <cstring>

#include <evmone_precompiles/sha256.hpp>

namespace zilkworm::ssz {

namespace {

    // zero_hashes[d] roots an all-zero subtree of depth d.
    const std::array<Node, 64>& zero_hashes() {
        static const std::array<Node, 64> table = [] {
            std::array<Node, 64> t{};
            for (size_t d = 1; d < t.size(); ++d) t[d] = hash_nodes(t[d - 1], t[d - 1]);
            return t;
        }();
        return table;
    }

    size_t depth_for(size_t leaves) noexcept {
        return leaves <= 1 ? 0 : static_cast<size_t>(std::countr_zero(std::bit_ceil(leaves)));
    }

    Node progressive(std::span<const Node> chunks, size_t num_leaves) {
        if (chunks.empty()) return Node{};
        const size_t take = std::min(num_leaves, chunks.size());
        const Node subtree = merkleize(chunks.first(take), num_leaves);
        const Node rest = progressive(chunks.subspan(take), num_leaves * 4);
        return hash_nodes(subtree, rest);
    }

}  // namespace

Node hash_nodes(const Node& a, const Node& b) {
    std::byte buf[64];
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
    Node out;
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(out.data()), buf, sizeof(buf));
    return out;
}

std::vector<Node> pack(ByteView bytes) {
    std::vector<Node> chunks((bytes.size() + 31) / 32);
    for (size_t i = 0; i < chunks.size(); ++i) {
        chunks[i] = Node{};
        std::memcpy(chunks[i].data(), bytes.data() + i * 32, std::min<size_t>(32, bytes.size() - i * 32));
    }
    return chunks;
}

Node merkleize(std::span<const Node> chunks, std::optional<size_t> limit) {
    const size_t count = limit.value_or(chunks.size());
    const auto& zero = zero_hashes();
    if (count == 0) return zero[0];
    const size_t depth = depth_for(count);
    if (chunks.empty()) return zero[depth];

    // Fold the chunks a level at a time; an odd node pairs with the zero subtree of its level.
    const size_t real_depth = depth_for(chunks.size());
    std::vector<Node> layer(chunks.begin(), chunks.end());
    std::vector<Node> next;
    for (size_t level = 0; level < real_depth; ++level) {
        next.clear();
        size_t i = 0;
        for (; i + 1 < layer.size(); i += 2) next.push_back(hash_nodes(layer[i], layer[i + 1]));
        if (i < layer.size()) next.push_back(hash_nodes(layer[i], zero[level]));
        layer.swap(next);
    }
    // The levels above the chunks pair the running root with zero subtrees.
    Node root = layer[0];
    for (size_t level = real_depth; level < depth; ++level) root = hash_nodes(root, zero[level]);
    return root;
}

Node merkleize_progressive(std::span<const Node> chunks) {
    return progressive(chunks, 1);
}

Node mix_in_length(const Node& root, uint64_t length) {
    Node len{};
    for (unsigned i = 0; i < 8; ++i) len[i] = static_cast<uint8_t>(length >> (8 * i));
    return hash_nodes(root, len);
}

Node mix_in_active_fields(const Node& root, size_t num_fields) {
    Node bits{};
    for (size_t i = 0; i < num_fields; ++i) bits[i / 8] |= static_cast<uint8_t>(1u << (i % 8));
    return hash_nodes(root, bits);
}

Node root_u64(uint64_t v) {
    Node n{};
    for (unsigned i = 0; i < 8; ++i) n[i] = static_cast<uint8_t>(v >> (8 * i));
    return n;
}

Node root_bool(bool v) {
    Node n{};
    n[0] = v ? 1 : 0;
    return n;
}

Node root_bytes_fixed(ByteView bytes) {
    if (bytes.size() <= 32) {
        Node n{};
        std::memcpy(n.data(), bytes.data(), bytes.size());
        return n;
    }
    return merkleize(pack(bytes));
}

Node root_byte_list(ByteView bytes, size_t limit) {
    return mix_in_length(merkleize(pack(bytes), (limit + 31) / 32), bytes.size());
}

Node root_progressive_bytes(ByteView bytes) {
    return mix_in_length(merkleize_progressive(pack(bytes)), bytes.size());
}

Node root_progressive_list(std::span<const Node> item_roots) {
    return mix_in_length(merkleize_progressive(item_roots), item_roots.size());
}

Node root_container(std::span<const Node> field_roots) {
    return merkleize(field_roots);
}

Node root_progressive_container(std::span<const Node> field_roots) {
    return mix_in_active_fields(merkleize_progressive(field_roots), field_roots.size());
}

}  // namespace zilkworm::ssz
