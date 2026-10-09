// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// UnsignedTransaction::maximum_gas_cost skips the blob-gas term when there are no blob hashes. It must still
// equal gas_limit * max_fee_per_gas + total_blob_gas * max_fee_per_blob_gas (the formula as it was written
// before the skip) for every mix of blob count and fees, including fees at the top of the uint256 range.

#include "transaction.hpp"

#include <cstdint>
#include <random>

#include <catch2/catch_test_macros.hpp>
#include <intx/intx.hpp>

#include <zilk_core/core/protocol/param.hpp>

namespace silkworm {

namespace {

    intx::uint512 formula(const UnsignedTransaction& tx) {
        intx::uint512 cost{intx::umul(intx::uint256{tx.gas_limit}, tx.max_fee_per_gas)};
        cost += intx::umul(intx::uint256{tx.total_blob_gas()}, tx.max_fee_per_blob_gas);
        return cost;
    }

    intx::uint256 random_fee(std::mt19937_64& rng) {
        switch (rng() % 5) {
            case 0:
                return 0;
            case 1:
                return ~intx::uint256{0};
            case 2:
                return intx::uint256{rng() % 1000};
            case 3:
                return intx::uint256{rng()};
            default:
                return intx::uint256{rng(), rng(), rng(), rng()};
        }
    }

}  // namespace

TEST_CASE("maximum_gas_cost: blob term present exactly when there are blob hashes", "[max_gas_cost]") {
    UnsignedTransaction tx;
    tx.gas_limit = 21'000;
    tx.max_fee_per_gas = 10;
    tx.max_fee_per_blob_gas = 7;

    CHECK(tx.maximum_gas_cost() == intx::uint512{210'000});

    tx.blob_versioned_hashes.resize(1);
    CHECK(tx.total_blob_gas() == protocol::kGasPerBlob);
    CHECK(tx.maximum_gas_cost() == intx::uint512{210'000} + intx::uint512{protocol::kGasPerBlob * 7});

    tx.blob_versioned_hashes.resize(6);
    CHECK(tx.maximum_gas_cost() == intx::uint512{210'000} + intx::uint512{6 * protocol::kGasPerBlob * 7});

    // No hashes: the blob fee is irrelevant, even at its maximum.
    tx.blob_versioned_hashes.clear();
    tx.max_fee_per_blob_gas = ~intx::uint256{0};
    CHECK(tx.maximum_gas_cost() == intx::uint512{210'000});

    // One hash at the maximum blob fee: the full 512-bit product (no truncation).
    tx.blob_versioned_hashes.resize(1);
    CHECK(tx.maximum_gas_cost() == intx::uint512{210'000} + intx::umul(intx::uint256{protocol::kGasPerBlob}, ~intx::uint256{0}));
}

TEST_CASE("maximum_gas_cost: equals the unconditional formula on random transactions", "[max_gas_cost]") {
    std::mt19937_64 rng{0xB10B5ULL};
    for (int i = 0; i < 20'000; ++i) {
        UnsignedTransaction tx;
        tx.gas_limit = (rng() % 4 == 0) ? ~uint64_t{0} : rng() % 60'000'000;
        tx.max_fee_per_gas = random_fee(rng);
        tx.max_fee_per_blob_gas = random_fee(rng);
        tx.blob_versioned_hashes.resize(rng() % 3 == 0 ? 0 : 1 + rng() % 9);
        REQUIRE(tx.maximum_gas_cost() == formula(tx));
    }
}

}  // namespace silkworm
