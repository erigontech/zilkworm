// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "mphf_builder.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <vector>

#include <zilk_core/print.hpp>

namespace zilkworm {

namespace {

inline constexpr uint32_t kLambda = 4u;
inline constexpr uint32_t kMaxDisplacement = 1u << 20;
inline constexpr uint32_t kMaxSeedRetries = 32u;
inline constexpr uint32_t kNoKey = UINT32_MAX;  // slot_owner: slot holds no key

// Returns true even with non-empty spill; spilled keys resolve via sidecar.
bool chd_solve(std::span<const uint64_t> distinct_keys,
               uint32_t& n_buckets_out,
               std::vector<uint64_t>& displacement_factors_out,
               uint64_t& seed_out,
               uint64_t& seed_factor_out,
               std::vector<uint32_t>& idx_for_key_out,
               std::vector<uint32_t>& spilled_keys_out,
               uint32_t max_retries_override,
               uint32_t max_displacement_override) {
    spilled_keys_out.clear();
    const uint32_t n_keys = static_cast<uint32_t>(distinct_keys.size());
    if (n_keys == 0) {
        n_buckets_out = 1;
        displacement_factors_out.assign(1, 0);
        seed_out = 0;
        seed_factor_out = 0;
        idx_for_key_out.clear();
        return true;
    }

    const uint32_t n_buckets = std::max(uint32_t{1}, (n_keys + kLambda - 1) / kLambda);
    n_buckets_out = n_buckets;

    std::vector<std::vector<uint32_t>> buckets;
    // slot_owner[pos] = key placed at pos, kNoKey when pos is free. Doubles as
    // the occupancy map the displacement search probes.
    std::vector<uint32_t> slot_owner;
    std::vector<uint32_t> trial_positions;

    std::vector<uint64_t> z1_cache(n_keys);

    struct Attempt {
        bool set = false;
        uint64_t seed_try = 0;
        uint64_t seed_factor = 0;
        std::vector<uint64_t> displacement_factors;
        std::vector<uint32_t> idx_for_key;
        std::vector<uint32_t> spilled_keys;
    };
    Attempt best;

    const uint32_t max_retries = max_retries_override ? max_retries_override : kMaxSeedRetries;
    for (uint64_t seed_try = 0; seed_try < max_retries; ++seed_try) {
        const uint64_t seed_factor = seed_try * kMphfGoldenRatio;

        buckets.assign(n_buckets, {});
        for (uint32_t key_idx = 0; key_idx < n_keys; ++key_idx) {
            const uint64_t z1 = distinct_keys[key_idx] + seed_factor;
            z1_cache[key_idx] = z1;
            const uint64_t h1 = mix64_body(z1);
            const uint32_t b  = fast_mod_u32(static_cast<uint32_t>(h1), n_buckets);
            buckets[b].push_back(key_idx);
        }

        std::vector<uint32_t> order(n_buckets);
        for (uint32_t i = 0; i < n_buckets; ++i) order[i] = i;
        // stable_sort: equal-sized buckets retain ascending-index order so the CHD seed search is deterministic.
        std::stable_sort(order.begin(), order.end(),
                         [&](uint32_t a, uint32_t b) { return buckets[a].size() > buckets[b].size(); });

        slot_owner.assign(n_keys, kNoKey);
        std::vector<uint64_t> displacement_factors(n_buckets, 0);
        std::vector<uint32_t> idx_for_key(n_keys, UINT32_MAX);
        std::vector<uint32_t> spilled_this_try;

        for (uint32_t bi : order) {
            const auto& bucket = buckets[bi];
            if (bucket.empty()) {
                displacement_factors[bi] = 0;
                continue;
            }

            bool placed = false;
            const uint32_t max_d = max_displacement_override ? max_displacement_override : kMaxDisplacement;
            for (uint32_t d = 0; d <= max_d; ++d) {
                const uint64_t d_factor =
                    ((seed_try ^ uint64_t(d) ^ kMphfGoldenRatio) - seed_try) * kMphfGoldenRatio;

                trial_positions.clear();
                bool collision = false;
                for (uint32_t key_idx : bucket) {
                    const uint64_t h2  = mix64_body(z1_cache[key_idx] + d_factor);
                    const uint32_t pos = fast_mod_u32(static_cast<uint32_t>(h2), n_keys);
                    if (slot_owner[pos] != kNoKey) { collision = true; break; }
                    bool dup = false;
                    for (uint32_t p : trial_positions) {
                        if (p == pos) { dup = true; break; }
                    }
                    if (dup) { collision = true; break; }
                    trial_positions.push_back(pos);
                }
                if (!collision) {
                    for (size_t pi = 0; pi < trial_positions.size(); ++pi) {
                        slot_owner[trial_positions[pi]] = bucket[pi];   // key_idx assigned to the new absolute pos after mix
                        idx_for_key[bucket[pi]] = trial_positions[pi];
                    }
                    displacement_factors[bi] = d_factor;
                    placed = true;
                    break;
                }
            }
            if (!placed) {
                // Bucket overflow: spill its keys; runtime resolves via sidecar memcmp fallback.
                displacement_factors[bi] = 0;
                for (uint32_t key_idx : bucket) {
                    const uint64_t h2 = mix64_body(z1_cache[key_idx]);  // d_factor=0
                    const uint32_t pos = fast_mod_u32(static_cast<uint32_t>(h2), n_keys);
                    idx_for_key[key_idx] = pos;
                    spilled_this_try.push_back(key_idx);
                }
            }
        }

        // Sidecar invariant: slot_offsets[index_lookup(key)] == 0 for every key
        // whose body lives in the sidecar.
        //
        // A spilled bucket keeps displacement factor 0, so its keys probe the
        // very index index_lookup() reproduces at runtime — an index a placed
        // key may already own. MphfMap::find() treats an occupied slot whose
        // embedded key fails memcmp as a definitive miss and consults the
        // sidecar only from an empty slot, so such a spilled key would be
        // unreachable. Spill the slot's owner as well: finalize() writes no
        // slot for a sidecar body, so the slot stays 0 and both keys resolve
        // through the sidecar. Placement is injective (slot_owner rejects
        // taken positions), so clearing the owner frees the index for good.
        for (size_t si = 0; si < spilled_this_try.size(); ++si) {
            const uint32_t pos = idx_for_key[spilled_this_try[si]];
            const uint32_t owner = slot_owner[pos];
            if (owner == kNoKey) continue;  // free slot, or its owner already co-spilled
            slot_owner[pos] = kNoKey;
            spilled_this_try.push_back(owner);
        }

        if (spilled_this_try.empty()) {
            displacement_factors_out = std::move(displacement_factors);
            idx_for_key_out = std::move(idx_for_key);
            seed_out = seed_try;
            seed_factor_out = seed_factor;
            spilled_keys_out.clear();
            return true;
        }

        if (!best.set || spilled_this_try.size() < best.spilled_keys.size()) {
            best.set = true;
            best.seed_try = seed_try;
            best.seed_factor = seed_factor;
            best.displacement_factors = std::move(displacement_factors);
            best.idx_for_key = std::move(idx_for_key);
            best.spilled_keys = std::move(spilled_this_try);
        }
    }

    if (best.set) {
        sys_println(
            "MphfBuilder: CHD exhausted retry budget, spilling keys into "
            "collision sidecar (best seed attempt)");
        displacement_factors_out = std::move(best.displacement_factors);
        idx_for_key_out = std::move(best.idx_for_key);
        seed_out = best.seed_try;
        seed_factor_out = best.seed_factor;
        spilled_keys_out = std::move(best.spilled_keys);
        return true;
    }

    sys_println("MphfBuilder: CHD solve failed within retry budget");
    return false;
}

}  // namespace

template <size_t KeySize>
void MphfBuilder<KeySize>::add(uint64_t key, ByteView body) {
    auto it = unique_kv_entries_.find(key);
    if (it != unique_kv_entries_.end()) {
        if (!it->second.empty()) {
            collision_keys_.emplace_back(key, 0u, 0u);
            collision_bodies_.emplace_back(std::move(it->second));
            it->second.clear();
        }
        collision_keys_.emplace_back(key, 0u, 0u);
        collision_bodies_.emplace_back(body.begin(), body.end());
        return;
    }
    unique_kv_entries_.emplace(key, std::vector<uint8_t>(body.begin(), body.end()));
}

template <size_t KeySize>
std::vector<uint8_t> MphfBuilder<KeySize>::finalize() && {
    const uint32_t n_keys = static_cast<uint32_t>(unique_kv_entries_.size());
    std::vector<uint64_t> distinct_keys;
    distinct_keys.reserve(n_keys);
    for (const auto& [k, _] : unique_kv_entries_) distinct_keys.push_back(k);

    uint32_t n_buckets = 1;
    std::vector<uint64_t> dfacs;
    uint64_t seed = 0, seed_factor = 0;
    std::vector<uint32_t> idx_for_key;
    std::vector<uint32_t> spilled;
    if (!chd_solve(distinct_keys, n_buckets, dfacs, seed, seed_factor,
                   idx_for_key, spilled,
                   max_retries_override_, max_displacement_override_)) {
        return {};
    }

    // CHD-spilled distinct keys route through the sidecar.
    for (uint32_t i : spilled) {
        auto& body = unique_kv_entries_.at(distinct_keys[i]);
        if (!body.empty()) {
            collision_keys_.emplace_back(distinct_keys[i], 0u, 0u);
            collision_bodies_.emplace_back(std::move(body));
            body.clear();
        }
    }

    auto entry_size = [](size_t body_len) noexcept -> uint32_t {
        return mphf_align8(static_cast<uint32_t>(8u + body_len));
    };

    uint32_t data_size = 8;  // reserved [0..8) so slot_offsets[idx]==0 means sidecar
    for (const auto& [_, body] : unique_kv_entries_) {
        if (!body.empty()) data_size += entry_size(body.size());
    }
    for (const auto& body : collision_bodies_) {
        data_size += entry_size(body.size());
    }

    const uint32_t n_collisions = static_cast<uint32_t>(collision_keys_.size());
    const uint32_t collisions_size = n_collisions * static_cast<uint32_t>(sizeof(MphfCollisionEntry));

    uint32_t off = mphf_align8(static_cast<uint32_t>(sizeof(MphfMapHeader)));
    const uint32_t displacement_offset = off;
    off += mphf_align8(n_buckets * static_cast<uint32_t>(sizeof(uint64_t)));
    const uint32_t slot_offsets_offset = off;
    off += mphf_align8(n_keys * static_cast<uint32_t>(sizeof(uint32_t)));
    const uint32_t collisions_offset = off;
    off += mphf_align8(collisions_size);
    const uint32_t data_offset = off;
    off += mphf_align8(data_size);
    const uint32_t total_size = off;

    std::vector<uint8_t> blob(total_size, 0);

    {
        auto* hdr = reinterpret_cast<MphfMapHeader*>(blob.data());
        hdr->magic               = magic_;
        hdr->version             = version_;
        hdr->n_keys              = n_keys;
        hdr->n_buckets           = n_buckets;
        hdr->seed                = seed;
        hdr->seed_factor         = seed_factor;
        hdr->collisions_offset   = collisions_offset;
        hdr->collisions_size     = collisions_size;
        hdr->displacement_offset = displacement_offset;
        hdr->slot_offsets_offset = slot_offsets_offset;
        hdr->data_offset         = data_offset;
        hdr->data_size           = data_size;
    }

    if (n_buckets > 0) {
        std::memcpy(blob.data() + displacement_offset, dfacs.data(),
                    n_buckets * sizeof(uint64_t));
    }

    uint32_t* slot_offsets = n_keys
        ? reinterpret_cast<uint32_t*>(blob.data() + slot_offsets_offset)
        : nullptr;
    uint8_t* data = blob.data() + data_offset;
    uint32_t data_cur = 8;

    for (uint32_t i = 0; i < n_keys; ++i) {
        const uint32_t idx = idx_for_key[i];
        const auto& body = unique_kv_entries_.at(distinct_keys[i]);
        if (body.empty()) continue;  // sidecar-resolved; leave slot zero-init
        const uint64_t body_len = body.size();
        slot_offsets[idx] = data_cur;
        std::memcpy(data + data_cur, &body_len, 8);
        std::memcpy(data + data_cur + 8, body.data(), body.size());
        data_cur += entry_size(body.size());
    }

    for (uint32_t i = 0; i < n_collisions; ++i) {
        const auto& body = collision_bodies_[i];
        const uint64_t body_len = body.size();
        collision_keys_[i].offset = data_cur;
        collision_keys_[i].len    = static_cast<uint32_t>(body.size());
        std::memcpy(data + data_cur, &body_len, 8);
        std::memcpy(data + data_cur + 8, body.data(), body.size());
        data_cur += entry_size(body.size());
    }

    // stable_sort: same-key collisions keep insertion order so the data-section
    // offsets they were just assigned stay consistent with the sorted index.
    std::ranges::stable_sort(collision_keys_, {}, &MphfCollisionEntry::key);
    if (n_collisions > 0) {
        std::memcpy(blob.data() + collisions_offset, collision_keys_.data(), collisions_size);
    }

    return blob;
}

template void MphfBuilder<20>::add(uint64_t, ByteView);
template void MphfBuilder<32>::add(uint64_t, ByteView);
template std::vector<uint8_t> MphfBuilder<20>::finalize() &&;
template std::vector<uint8_t> MphfBuilder<32>::finalize() &&;

}  // namespace zilkworm
