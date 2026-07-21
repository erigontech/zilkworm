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

// MphfBuilder<KeySize> — host-only construction. add() copies the body bytes
// into the builder; finalize() consumes the builder and returns the ready-to-embed blob.
template <size_t KeySize>
class MphfBuilder {
  public:
    MphfBuilder(uint32_t magic, uint32_t version) noexcept
        : magic_{magic}, version_{version} {}

    // Add a (key, body) pair. Body bytes are copied. Duplicate keys are marked with 0 body
    // Existing value for a collision key is thrown to collision_bodies_
    void add(uint64_t key, ByteView body);

    // Consume the builder, produce the final blob.
    std::vector<uint8_t> finalize() &&;

    // Test-only overrides. 0 = use production defaults (kMaxSeedRetries /
    // kMaxDisplacement). Per-instance — no process-wide state.
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
