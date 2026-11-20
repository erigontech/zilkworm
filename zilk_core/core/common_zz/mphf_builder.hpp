// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>

namespace zilkworm {
using ::silkworm::ByteView;

template <size_t KeySize>
class MphfBuilder {
  public:
    MphfBuilder(uint32_t magic, uint32_t version) noexcept
        : magic_{magic}, version_{version} {}

    // Copies body; a duplicate key's existing value moves to collision_bodies_.
    void add(uint64_t key, ByteView body);

    std::vector<uint8_t> finalize() &&;

    // Test-only overrides; 0 = production default.
    void set_max_retries_for_test(uint32_t v) noexcept { max_retries_override_ = v; }
    uint32_t max_retries_for_test() const noexcept { return max_retries_override_; }
    void set_max_displacement_for_test(uint32_t v) noexcept { max_displacement_override_ = v; }
    uint32_t max_displacement_for_test() const noexcept { return max_displacement_override_; }

  private:
    uint32_t magic_;
    uint32_t version_;
    // std::map keeps iteration order deterministic (ascending order).
    std::map<uint64_t, std::vector<uint8_t>> unique_kv_entries_;
    std::vector<MphfCollisionEntry> collision_keys_;
    std::vector<std::vector<uint8_t>> collision_bodies_;
    uint32_t max_retries_override_{0u};
    uint32_t max_displacement_override_{0u};
};

}  // namespace zilkworm
