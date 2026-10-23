// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// ethash_keccak256_cap() across its keccak.h contract.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <evmone_precompiles/keccak.hpp>

namespace {

constexpr size_t kBlock = 136;
constexpr uint64_t kPoison = 0xa5a5a5a5a5a5a5a5;

bool same(const ethash::hash256& a, const ethash::hash256& b) {
    return std::memcmp(a.bytes, b.bytes, sizeof(a.bytes)) == 0;
}

}  // namespace

TEST_CASE("keccak256_cap: the hash and the captured state follow the contract", "[keccak][kprefix]") {
    std::mt19937_64 rng{0xca9};
    for (const size_t blocks : {size_t{1}, size_t{2}, size_t{4}}) {
        for (const size_t tail : {size_t{0}, size_t{1}, size_t{37}, size_t{135}}) {
            const size_t size = blocks * kBlock + tail;
            std::vector<uint64_t> words((size + 7) / 8);
            auto* const data = reinterpret_cast<uint8_t*>(words.data());
            for (size_t i = 0; i < size; ++i) data[i] = static_cast<uint8_t>(rng());
            const auto full = ethash::keccak256(data, size);

            for (size_t init = 0; init < blocks; ++init) {
                alignas(256) uint64_t init_state[32]{};
                if (init != 0) REQUIRE(same(ethash_keccak256_snap(data, size, init, init_state), full));
                std::array<uint64_t, 32> init_copy{};
                std::copy_n(init_state, 32, init_copy.begin());

                for (size_t cap = 0; cap <= blocks; ++cap) {
                    if (cap != 0 && cap <= init) continue;
                    alignas(256) uint64_t out[32];
                    std::fill_n(out, 32, kPoison);
                    const auto h = ethash_keccak256_cap(data, size, init != 0 ? init_state : nullptr, init, cap, out);
                    REQUIRE(same(h, full));
                    REQUIRE(std::equal(init_copy.begin(), init_copy.end(), init_state));
                    // Only the 25 state words are written.
                    REQUIRE(std::all_of(out + 25, out + 32, [](uint64_t w) { return w == kPoison; }));
                    if (cap == 0) {
                        REQUIRE(std::all_of(out, out + 25, [](uint64_t w) { return w == kPoison; }));
                        continue;
                    }
                    alignas(256) uint64_t ref[32]{};
                    REQUIRE(same(ethash_keccak256_snap(data, size, cap, ref), full));
                    REQUIRE(std::equal(out, out + 25, ref));
                    alignas(256) uint64_t slot[32]{};
                    std::copy_n(out, 25, slot);
                    REQUIRE(same(ethash_keccak256_resume(slot, cap, data, size), full));
                }
            }

            // init may alias out_state.
            if (blocks >= 2) {
                alignas(256) uint64_t state[32]{};
                REQUIRE(same(ethash_keccak256_snap(data, size, 1, state), full));
                REQUIRE(same(ethash_keccak256_cap(data, size, state, 1, blocks, state), full));
                alignas(256) uint64_t ref[32]{};
                REQUIRE(same(ethash_keccak256_snap(data, size, blocks, ref), full));
                REQUIRE(std::equal(state, state + 25, ref));
            }
        }
    }
}
