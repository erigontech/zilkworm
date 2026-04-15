// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstring>
#include <unordered_map>  // must come after evmc.hpp so operator== is visible

#include "node_store_i.hpp"  // includes evmc.hpp which defines operator== for bytes32

namespace silkworm::mpt {

// Custom hasher: direct word extraction (bytes32 values are keccak outputs
// with full entropy, so any 32-bit slice is a high-quality hash).
struct FastHash {
    size_t operator()(const bytes32& key) const noexcept {
        return *reinterpret_cast<const uint32_t*>(key.bytes);
    }
};

// Class to store map of MPT nodes
class FlatNodeStore final : public NodeStore {
  public:

    FlatNodeStore() = default;

    void clear() { storage_.clear(); }
    size_t size() const { return storage_.size(); }
    // Populate the store from RLP-encoded trie nodes
    // Layout: [rlp{32-byte hash, bytes}, rlp{32-byte hash, bytes}, ...]
    void populate_from_rlp(ByteView trie_rlp);

    inline void insert(const bytes32& hash, Bytes rlp) {
        storage_.emplace(hash, std::move(rlp));
    }

    std::optional<ByteView> get_rlp(const bytes32& hash) const override {
        auto it = storage_.find(hash);
        if (it == storage_.end()) {
            return {};
        }
        return ByteView{it->second};
    }

    void put_rlp(const bytes32& hash, const Bytes& rlp) override {
        storage_[hash] = rlp;
    }
private:
    std::unordered_map<bytes32, Bytes, FastHash> storage_;

};

}  // namespace silkworm::mpt