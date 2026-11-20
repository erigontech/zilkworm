// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace silkworm::trie {

// If x is in the set and x starts with y, then y is in the set.
class PrefixSet {
  public:
    PrefixSet() = default;

    PrefixSet(const PrefixSet& other) = default;
    PrefixSet& operator=(const PrefixSet& other) = default;

    void insert(ByteView key, bool marker = false);
    void insert(Bytes&& key, bool marker = false);

    // Not const: unsafe to call concurrently.
    bool contains(ByteView prefix);

    // Scanned items must share the first invariant_prefix_len bytes with prefix.
    std::pair<bool, ByteView> contains_and_next_marked(ByteView prefix, size_t invariant_prefix_len = 0);

    size_t size() const { return keys_.size(); }
    bool empty() const { return keys_.empty(); }

    void clear() noexcept {
        keys_.clear();
        index_ = 0;
        sorted_ = false;
    }

  private:
    void ensure_sorted();

    std::vector<std::pair<Bytes, bool>> keys_;  // Collection of nibbled keys with marker of newly created
    size_t index_{0};                           // Index of last compared key
    bool sorted_{false};                        // Whether nibbled_keys_ has been unique-ed and sorted
};

}  // namespace silkworm::trie
