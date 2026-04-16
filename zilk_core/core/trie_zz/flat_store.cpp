// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#include "flat_store.hpp"

#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/print.hpp>

namespace silkworm::mpt {

[[gnu::always_inline]] inline DecodingResult decode8(ByteView& from, uint64_t& to) noexcept {
    if (from.size() < 33) [[unlikely]] {
        return std::unexpected{DecodingError::kInputTooShort};
    }
    if (from[0] != 0xA0) [[unlikely]] {
        return std::unexpected{DecodingError::kUnexpectedLength};
    }
    from.remove_prefix(1);

    std::memcpy(&to, from.data(), 8);
    from.remove_prefix(32);
    return {};
}

// Function to populate a FlatNodeStore from the given trie_rlp structure
// Layout is [rlp{32-byte hash, bytes}, rlp{32-byte hash, bytes}, ...]
void FlatNodeStore::populate_from_rlp(ByteView trie_rlp) {
    auto trie_header{fast_decode_header(trie_rlp)};
    if (!trie_header.list) {
        sys_println("Invalid trie_header in populate_from_rlp");
        return;
    }

    ByteView trie_view = trie_rlp.substr(0, trie_header.payload_length);

    // Clear old entries (keeps bucket capacity), higher load factor = fewer buckets = fewer allocs
    storage_.clear();
    collisions_.clear();
    storage_.max_load_factor(4.0f);
    storage_.reserve(trie_header.payload_length / 70);

    while (!trie_view.empty()) {
        uint64_t node_hash;
        const uint8_t* hash_start = trie_view.data() + 1;  // skip 0xA0, points to 32-byte hash

        if (DecodingResult res = decode8(trie_view, node_hash); !res) [[unlikely]] {
            sys_println("Failed to decode node_hash from trie_view");
            break;
        }

        auto hdr = fast_decode_header(trie_view);
        uint32_t payload_off = static_cast<uint32_t>(trie_view.data() - hash_start);
        uint32_t payload_len = static_cast<uint32_t>(hdr.payload_length);
        uint64_t off_len = (static_cast<uint64_t>(payload_off) << 32) | payload_len;
        trie_view.remove_prefix(payload_len);

        auto [it, inserted] = storage_.emplace(node_hash, NodeRef{hash_start, off_len});
        if (!inserted) [[unlikely]] {
            if (it->second.hash_ptr != nullptr) {
                collisions_.push_back(it->second.hash_ptr);
                it->second = {nullptr, 0};
            }
            collisions_.push_back(hash_start);
        }
    }
}

}  // namespace silkworm::mpt
