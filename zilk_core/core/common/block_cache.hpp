// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <memory>

#include <evmc/evmc.hpp>
#include <evmone/lru_cache.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/types/block.hpp>

namespace silkworm {

class BlockCache {
  public:
    // The second argument (formerly a thread-safety flag) is retained for
    // source compatibility but is now inert: evmone::LRUCache is not internally
    // synchronized, matching the previous behavior where locking was disabled.
    explicit BlockCache(size_t capacity = 1024, bool = true)
        : block_cache_(capacity) {}

    std::shared_ptr<BlockWithHash> get(const evmc::bytes32& key) {
        auto result = block_cache_.get(key);
        if (result) {
            return *result;
        }
        return nullptr;
    }

    void insert(const evmc::bytes32& key, const std::shared_ptr<BlockWithHash>& block) {
        block_cache_.put(key, block);
    }

  private:
    evmone::LRUCache<evmc::bytes32, std::shared_ptr<BlockWithHash>> block_cache_;
};

}  // namespace silkworm
