// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>
#include <variant>
#include <vector>

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/trie/node.hpp>

namespace silkworm::trie {

using NodeCollector = std::function<void(ByteView nibbled_key, const Node&)>;

class HashBuilder {
  public:
    HashBuilder() = default;

    HashBuilder(const HashBuilder&) = delete;
    HashBuilder& operator=(const HashBuilder&) = delete;

    // Keys strictly increasing and unpacked; a leaf key may not be a prefix of another leaf key.
    void add_leaf(Bytes nibbled_key, ByteView value);

    // Same key order as add_leaf; nodes whose RLP is shorter than 32 bytes may not be added.
    void add_branch_node(Bytes nibbled_key, const evmc::bytes32& hash, bool is_in_db_trie = false);

    // Returns kEmptyRoot when nothing was added.
    evmc::bytes32 root_hash();

    NodeCollector node_collector{nullptr};

    // Called with each node RLP of 32 bytes or more (those referenced by hash); the caller hashes.
    using RlpCollector = std::function<void(ByteView node_rlp)>;
    RlpCollector rlp_collector{nullptr};

    void reset();

  private:
    evmc::bytes32 root_hash(bool auto_finalize);

    void finalize();

    void gen_struct_step(ByteView current, ByteView succeeding);

    std::vector<Bytes> branch_ref(uint16_t state_mask, uint16_t hash_mask);

    ByteView leaf_node_rlp(ByteView path, ByteView value);

    ByteView extension_node_rlp(ByteView path, ByteView child_ref);

    Bytes key_;                                 // unpacked – one nibble per byte
    std::variant<ByteView, evmc::bytes32> value_;  // leaf value (borrowed) or node hash
    bool is_in_db_trie_{false};

    std::vector<uint16_t> groups_;
    std::vector<uint16_t> tree_masks_;
    std::vector<uint16_t> hash_masks_;
    std::vector<Bytes> stack_;  // node references: hashes or embedded RLPs

    Bytes rlp_buffer_;
};

}  // namespace silkworm::trie
