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
// slot_owner: slot must stay empty forever. A sidecar key probes it, so placing
// anything here would re-occupy the index that key resolves through. Distinct
// from kNoKey so the occupancy test rejects it, and outside the key-index range
// of any table this builder can represent.
inline constexpr uint32_t kBlocked = UINT32_MAX - 1u;

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
    // slot_owner[pos] = <key placed at pos>, or <kNoKey> when pos is free, kBlocked
    // when pos is reserved empty for a sidecar key. Doubles as the occupancy map
    // the displacement search probes: only kNoKey accepts a placement.
    std::vector<uint32_t> slot_owner;
    // Positions the bucket's keys map to, parallel to the bucket's key order:
    // trial_positions for the candidate under test, best_positions for the
    // cheapest candidate seen so far.
    std::vector<uint32_t> trial_positions;
    std::vector<uint32_t> best_positions;

    std::vector<uint64_t> z1_cache(n_keys);

    // Visit each distinct position once, at its first occurrence, as
    // fn(first_index, pos, multiplicity). Walking the bucket in key order groups
    // duplicates deterministically without an order-dependent hash container.
    auto for_each_distinct_pos = [](const std::vector<uint32_t>& positions, auto&& fn) {
        for (size_t pi = 0; pi < positions.size(); ++pi) {
            const uint32_t pos = positions[pi];
            bool first = true;
            for (size_t pj = 0; pj < pi; ++pj) {
                if (positions[pj] == pos) { first = false; break; }
            }
            if (!first) continue;
            uint32_t multiplicity = 1;
            for (size_t pj = pi + 1; pj < positions.size(); ++pj) {
                if (positions[pj] == pos) ++multiplicity;
            }
            fn(pi, pos, multiplicity);
        }
    };

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
                displacement_factors[bi] = 0;  // no key maps here
                continue;
            }

            // Score every displacement by the number of keys it forces into the
            // sidecar — the bucket keys that cannot place, plus the placed key a
            // taken slot has to give up — and keep the cheapest. Ties go to the
            // lowest d, and a zero-cost candidate wins outright, so a bucket that
            // places cleanly still takes the first displacement that fits it.
            const uint32_t max_d = max_displacement_override ? max_displacement_override : kMaxDisplacement;
            uint32_t best_cost = UINT32_MAX;
            uint64_t best_d_factor = 0;
            best_positions.clear();
            for (uint32_t d = 0; d <= max_d; ++d) {
                const uint64_t d_factor =
                    ((seed_try ^ uint64_t(d) ^ kMphfGoldenRatio) - seed_try) * kMphfGoldenRatio;

                trial_positions.clear();
                for (uint32_t key_idx : bucket) {
                    const uint64_t h2  = mix64_body(z1_cache[key_idx] + d_factor);
                    const uint32_t pos = fast_mod_u32(static_cast<uint32_t>(h2), n_keys);
                    trial_positions.push_back(pos);
                }

                uint32_t cost = 0;
                for_each_distinct_pos(trial_positions, [&](size_t, uint32_t pos, uint32_t multiplicity) {
                    const uint32_t owner = slot_owner[pos];
                    if (owner == kNoKey && multiplicity == 1) return;   // places, costs nothing
                    cost += multiplicity;                               // the whole group spills
                    if (owner != kNoKey && owner != kBlocked) ++cost;   // and evicts the slot's owner
                });

                if (cost < best_cost) {
                    best_cost = cost;
                    best_d_factor = d_factor;
                    best_positions = trial_positions;
                }
                if (cost == 0) break;
            }

            // Always a factor the search validated against slot_owner.
            displacement_factors[bi] = best_d_factor;
            for_each_distinct_pos(best_positions, [&](size_t pi, uint32_t pos, uint32_t multiplicity) {
                const uint32_t owner = slot_owner[pos];
                if (owner == kNoKey && multiplicity == 1) {
                    slot_owner[pos] = bucket[pi];   // key_idx assigned to the new absolute pos after mix
                    idx_for_key[bucket[pi]] = pos;
                    return;
                }
                // Every bucket key landing here spills, and so does the placed
                // key it displaces, so they reach the sidecar together. Spilled
                // keys keep idx_for_key == UINT32_MAX so a stray use is loud.
                for (size_t pj = pi; pj < best_positions.size(); ++pj) {
                    if (best_positions[pj] == pos) spilled_this_try.push_back(bucket[pj]);
                }
                if (owner != kNoKey && owner != kBlocked) spilled_this_try.push_back(owner);
                // Block rather than free: a later bucket claiming pos would
                // re-occupy the very index these sidecar keys probe.
                slot_owner[pos] = kBlocked;
            });
        }

        // Sidecar invariant: slot_offsets[index_lookup(key)] == 0 for every key
        // whose body lives in the sidecar. A CHD-spilled key probes the index the
        // bucket loop just blocked, which no placed key owns and none can claim
        // later; a duplicate-key8 key probes the index of the distinct key whose
        // body add() emptied, and finalize() writes no slot for an empty body.

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
            collision_keys_.push_back({key, 0u});
            collision_bodies_.emplace_back(std::move(it->second));
            it->second.clear();
        }
        collision_keys_.push_back({key, 0u});
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
            collision_keys_.push_back({distinct_keys[i], 0u});
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
        const auto& body = unique_kv_entries_.at(distinct_keys[i]);
        if (body.empty()) continue;  // sidecar-resolved; leave slot zero-init
        const uint32_t idx = idx_for_key[i];  // read after the guard: spilled keys hold UINT32_MAX
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
