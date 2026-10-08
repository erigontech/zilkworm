// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intrinsic_gas.hpp"

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/common_zz/data_byte_count.hpp>

#include "param.hpp"

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("num_words rounds up to whole 32-byte words", "[intrinsic_gas]") {
    CHECK(num_words(0) == 0);
    CHECK(num_words(1) == 1);
    CHECK(num_words(31) == 1);
    CHECK(num_words(32) == 1);
    CHECK(num_words(33) == 2);
    CHECK(num_words(0xFFFFFFFFFFFFFFDF) == 0x7FFFFFFFFFFFFFF);
    CHECK(num_words(0xFFFFFFFFFFFFFFE0) == 0x7FFFFFFFFFFFFFF);
    CHECK(num_words(0xFFFFFFFFFFFFFFE1) == 0x800000000000000);
    CHECK(num_words(0xFFFFFFFFFFFFFFFE) == 0x800000000000000);
    CHECK(num_words(0xFFFFFFFFFFFFFFFF) == 0x800000000000000);
}

namespace protocol {

    // The count a caller would compute for `txn` before invoking the gas functions.
    size_t nonzero_of(const UnsignedTransaction& txn) noexcept {
        return zilkworm::count_nonzero_bytes(txn.data);
    }

    TEST_CASE("EIP-2930 intrinsic gas", "[intrinsic_gas]") {
        std::vector<AccessListEntry> access_list{
            {0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae_address,
             {
                 0x0000000000000000000000000000000000000000000000000000000000000003_bytes32,
                 0x0000000000000000000000000000000000000000000000000000000000000007_bytes32,
             }},
            {0xbb9bc244d798123fde783fcc1c72d3bb8c189413_address, {}},
        };

        UnsignedTransaction txn{
            .type = TransactionType::kAccessList,
            .chain_id = kSepoliaConfig.chain_id,
            .nonce = 7,
            .max_priority_fee_per_gas = 30000000000,
            .max_fee_per_gas = 30000000000,
            .gas_limit = 5748100,
            .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
            .value = 2 * kEther,
            .access_list = access_list};

        const intx::uint128 g0{intrinsic_gas(txn, EVMC_ISTANBUL, nonzero_of(txn))};
        CHECK(g0 == fee::kGTransaction + 2 * fee::kAccessListAddressCost + 2 * fee::kAccessListStorageKeyCost);
    }

    TEST_CASE("EIP-7623 floor cost dominates for all-ones calldata", "[intrinsic_gas]") {
        const Bytes calldata = Bytes(22 * 1024, 1);
        UnsignedTransaction txn{
            .type = TransactionType::kDynamicFee,
            .chain_id = kSepoliaConfig.chain_id,
            .nonce = 7,
            .max_priority_fee_per_gas = 30000000000,
            .max_fee_per_gas = 30000000000,
            .gas_limit = 25748100,
            .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
            .value = 2 * kEther,
            .data = calldata};

        const size_t non_zero{nonzero_of(txn)};
        CHECK(intrinsic_gas(txn, EVMC_PRAGUE, non_zero) < floor_cost(txn, non_zero));
    }

    // Pins the arithmetic itself, so a wrong zero/non-zero split cannot pass by
    // agreeing with a reference that shares the same counter.
    TEST_CASE("intrinsic gas and floor cost for mixed calldata", "[intrinsic_gas]") {
        constexpr size_t kZeros{70};
        constexpr size_t kNonZeros{53};
        Bytes calldata(kZeros, 0);
        calldata.append(Bytes(kNonZeros, 0xab));

        // Legacy and chain-id-less, so every revision asserted below is a shape that can exist:
        // kDynamicFee is gated at London and a chain id is rejected before Spurious Dragon.
        UnsignedTransaction txn{
            .type = TransactionType::kLegacy,
            .gas_limit = 1'000'000,
            .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address,
            .data = calldata};

        const size_t non_zero{nonzero_of(txn)};
        CHECK(non_zero == kNonZeros);
        CHECK(txn.data.size() - non_zero == kZeros);

        // 21000 + 53*16 + 70*4
        CHECK(intrinsic_gas(txn, EVMC_PRAGUE, non_zero) == 22128);
        // 21000 + 53*68 + 70*4  (pre-EIP-2028 non-zero byte price)
        CHECK(intrinsic_gas(txn, EVMC_FRONTIER, non_zero) == 24884);
        // 21000 + (70 + 53*4) * 10
        CHECK(floor_cost(txn, non_zero) == 23820);

        // Contract creation adds kGTxCreate and, since Shanghai, the EIP-3860 word cost.
        UnsignedTransaction creation{txn};
        creation.to = std::nullopt;
        CHECK(intrinsic_gas(creation, EVMC_PRAGUE, non_zero) == 22128 + 32000 + 4 * 2);
        CHECK(intrinsic_gas(creation, EVMC_BERLIN, non_zero) == 22128 + 32000);
    }

    TEST_CASE("intrinsic gas and floor cost for empty calldata", "[intrinsic_gas]") {
        UnsignedTransaction txn{
            .type = TransactionType::kDynamicFee,
            .chain_id = kSepoliaConfig.chain_id,
            .gas_limit = 1'000'000,
            .to = 0x811a752c8cd697e3cb27279c330ed1ada745a8d7_address};

        const size_t non_zero{nonzero_of(txn)};
        CHECK(non_zero == 0);
        CHECK(txn.data.size() == 0);
        CHECK(intrinsic_gas(txn, EVMC_PRAGUE, non_zero) == fee::kGTransaction);
        CHECK(floor_cost(txn, non_zero) == fee::kGTransaction);
    }

}  // namespace protocol

}  // namespace silkworm
