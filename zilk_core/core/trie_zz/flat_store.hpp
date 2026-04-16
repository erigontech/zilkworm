// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstring>
#include <unordered_map>  // must come after evmc.hpp so operator== is visible
#include <vector>

#include "node_store_i.hpp"  // includes evmc.hpp which defines operator== for bytes32
#include <zilk_core/core/rlp/encode.hpp>

namespace silkworm::mpt {

inline uint64_t key8(const bytes32& key) {
    uint64_t v;
    std::memcpy(&v, key.bytes, 8);
    return v;
}

// Single-ld RLP header decode, assumes valid input
[[gnu::always_inline]] inline rlp::Header fast_decode_header(ByteView& from) noexcept {
    if (from.size() < 8) [[unlikely]] {
        return {false, from.size()};
    }
    uint64_t word;
    std::memcpy(&word, from.data(), 8);
    uint8_t first = word & 0xFF;

    if (first < 0x80) return {false, 1};

    bool is_list = first >= 0xC0;
    uint8_t offset = first & 0x3Fu;

    from.remove_prefix(1);
    if (offset <= 55) return {is_list, offset};

    size_t len_bytes = offset - 55;
    size_t length = ((word >> 8) & 0xFF) << 16 | ((word >> 16) & 0xFF) << 8 | ((word >> 24) & 0xFF);
    length >>= (8 * (3 - len_bytes));
    from.remove_prefix(len_bytes);
    return {is_list, length};
}

// For referenced nodes payload >= 32 bytes
[[gnu::always_inline]] inline ByteView fast_rlp_view(const uint8_t* p_start) {
    if (p_start[0] <= 0xB7)
        return {p_start + 1, static_cast<size_t>(p_start[0] - 0x80u)};
    if (p_start[0] == 0xB8)
        return {p_start + 2, static_cast<size_t>(p_start[1])};
    // 0xB9: 2-byte length (branch nodes 256+ bytes)
    return {p_start + 3, (static_cast<size_t>(p_start[1]) << 8) | static_cast<size_t>(p_start[2])};
}

struct NodeRef {
    const uint8_t* hash_ptr;  // points to 32-byte hash in buffer (nullptr = sentinel)
    uint64_t off_len;         // [63:32] payload offset from hash_ptr, [31:0] payload length
};

// Class to store map of MPT nodes
class FlatNodeStore final : public NodeStore {
  public:

    FlatNodeStore() = default;

    void clear() { storage_.clear(); collisions_.clear(); }
    size_t size() const { return storage_.size(); }
    // Populate the store from RLP-encoded trie node byteviews
    // Layout: [rlp{32-byte hash, bytes}, rlp{32-byte hash, bytes}, ...]
    void populate_from_rlp(ByteView trie_rlp);

    std::optional<ByteView> get_rlp(const bytes32& hash) const override {
        auto it = storage_.find(key8(hash));
        if (it != storage_.end()) [[likely]] {
            auto [ptr, ol] = it->second;
            if (ptr != nullptr) [[likely]]
                return ByteView{ptr + (ol >> 32), ol & 0xFFFFFFFF};
            for (const uint8_t* p : collisions_) {
                if (std::memcmp(p, hash.bytes, 32) == 0)
                    return fast_rlp_view(p + 32);
            }
        }
        return {};
    }
private:
    std::unordered_map<uint64_t, NodeRef> storage_;
    std::vector<const uint8_t*> collisions_;
};

}  // namespace silkworm::mpt
