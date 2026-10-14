// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// DirectState::get_block_hash() keeps the parent-hash walk of the header it was asked for and
// extends it on demand. Against the walk it replaced, repeated for every request: the same hash
// for every depth, in any order of requests, for headers that alternate, with headers inserted in
// between, and with a header missing from the chain, which sets ancestor_missing() exactly when
// the walk would.

#include <cstdint>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace {

using silkworm::BlockHeader;
using zilkworm::DirectState;

struct Rng {
    uint64_t s;
    uint64_t below(uint64_t n) {
        s = s * 6364136223846793005ull + 1442695040888963407ull;
        return (s >> 33) % n;
    }
};

// The headers a DirectState holds, as the walk before the cache read them.
struct Reference {
    std::map<evmc::bytes32, BlockHeader> headers;
    bool missing = false;

    evmc::bytes32 get(const BlockHeader& header, uint64_t n) {
        if (n >= header.number) return {};
        evmc::bytes32 hash = header.parent_hash;
        for (uint64_t child = header.number - 1; child > n; --child) {
            const auto it = headers.find(hash);
            if (it == headers.end()) {
                missing = true;
                return {};
            }
            hash = it->second.parent_hash;
        }
        return hash;
    }
};

}  // namespace

TEST_CASE("BLOCKHASH's kept ancestor walk answers as the walk from the header does", "[block_hash]") {
    // A chain of 300 headers from block 1000; the one at index `gap` is held back at first.
    constexpr uint64_t kFirst = 1000;
    constexpr size_t kCount = 300;
    std::vector<BlockHeader> chain(kCount);
    for (size_t i = 0; i < kCount; ++i) {
        chain[i].number = kFirst + i;
        chain[i].gas_limit = 30'000'000 + i;
        if (i > 0) chain[i].parent_hash = chain[i - 1].hash();
    }

    for (const size_t gap : {size_t{40}, size_t{150}, size_t{290}}) {
        Rng rng{0x5DEECE66Dull + gap};
        std::vector<uint8_t> blob = DirectState::build_blob_from_accounts({}, {}, {});
        DirectState ds{std::span<uint8_t>{blob}};
        Reference ref;
        const auto insert = [&](const BlockHeader& h) {
            ds.insert_header(h);
            ref.headers[h.hash()] = h;
        };
        for (size_t i = 0; i < kCount; ++i)
            if (i != gap) insert(chain[i]);

        // The headers asked for: one past the chain's end (the block being run), two earlier ones and a
        // fork of the first, none of which the cache may answer for another.
        BlockHeader tip;
        tip.number = kFirst + kCount;
        tip.parent_hash = chain[kCount - 1].hash();
        // A fork of the tip: the same number, another parent, which only the parent hash tells apart.
        BlockHeader fork = tip;
        fork.parent_hash = chain[kCount - 3].hash();
        const BlockHeader* const asked[] = {&tip, &chain[kCount - 1], &chain[kCount / 2 + 7], &fork};

        for (int step = 0; step < 4000; ++step) {
            if (step == 2500) insert(chain[gap]);  // The gap closes: deeper walks succeed from here.
            const BlockHeader& h = *asked[rng.below(4) == 0 ? 1 + rng.below(3) : 0];
            // Depths around the chain's start and the gap, near the header and beyond it.
            uint64_t n;
            switch (rng.below(4)) {
            case 0: n = h.number - 1 - rng.below(8); break;
            case 1: n = kFirst + gap - 3 + rng.below(6); break;
            case 2: n = kFirst - 3 + rng.below(8); break;
            default: n = h.number + 2 - rng.below(h.number - kFirst + 10); break;
            }
            const evmc::bytes32 want = ref.get(h, n);
            REQUIRE(ds.get_block_hash(h, n) == want);
            REQUIRE(ds.ancestor_missing() == ref.missing);
        }
        CHECK(ref.missing);  // The walks below the chain's start always fail.
    }
}
