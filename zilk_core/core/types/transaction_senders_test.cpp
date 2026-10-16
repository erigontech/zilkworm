// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Transaction::recover_senders(), which the guests call before validation and execution read the
// senders so that the recoveries share their inversions (secp256k1::ecrecover_batch()), must leave
// each transaction not recovered yet with exactly the sender that sender() recovers on its own, keep
// a sender set or recovered before, and leave an invalid signature without one. The signatures are
// made up: r is the x of a point (or not, for the invalid ones) and s is random, so the senders are
// arbitrary addresses. The native build runs the generic batch, which recovers each signature with
// ecrecover(); with EVMONE_RV32_DISPATCH_TEST, the Airbender one.

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/secp256k1.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

namespace {

    using intx::operator""_u256;
    using evmone::crypto::secp256k1::Curve;

    intx::uint256 random_uint256(std::mt19937_64& rng) { return intx::uint256{rng(), rng(), rng(), rng()}; }

    /// The x of a point below the group order, as a valid signature's r is.
    intx::uint256 random_point_x(std::mt19937_64& rng) {
        for (;;) {
            const auto x{random_uint256(rng) % Curve::ORDER};
            if (evmone::crypto::secp256k1::calculate_y(Curve::Fp{x}, false).has_value()) return x;
        }
    }

}  // namespace

TEST_CASE("Transaction::recover_senders caches what sender() recovers on its own") {
    using namespace evmc::literals;
    std::mt19937_64 rng{23};
    static const std::array<uint8_t, 70> kData{1, 2, 3, 0, 0, 5};
    const std::array types{TransactionType::kLegacy, TransactionType::kAccessList, TransactionType::kDynamicFee};
    std::vector<Transaction> txns;
    for (size_t i{0}; i < 40; ++i) {
        Transaction& txn{txns.emplace_back()};
        txn.type = types[i % types.size()];
        if (txn.type != TransactionType::kLegacy || i % 2 == 0) txn.chain_id = 1;  // EIP-155, or not
        txn.nonce = i;
        txn.max_fee_per_gas = 7 + i;
        txn.max_priority_fee_per_gas = txn.type == TransactionType::kDynamicFee ? 3 : txn.max_fee_per_gas;
        txn.gas_limit = 21000 + i;
        txn.to = evmc::address{static_cast<uint64_t>(0x1000 + i)};
        txn.value = i;
        txn.data = ByteView{kData.data(), i % kData.size()};
        txn.odd_y_parity = (rng() & 1) != 0;
        txn.r = random_point_x(rng);
        txn.s = random_uint256(rng) % Curve::ORDER;
        switch (i % 10) {
            case 3: txn.r = 0; break;
            case 5: txn.r = 5; break;  // 5^3 + 7 is not a square: no point has x == 5
            case 7: txn.s = 0; break;
            case 8: txn.r = Curve::ORDER; break;
            default: break;
        }
    }

    // Copies recover each sender on their own; two of the originals have one already.
    std::vector<std::optional<evmc::address>> expected;
    for (const auto& txn : txns) expected.push_back(Transaction{txn}.sender());
    const auto preset{0x00000000000000000000000000000000000000ff_address};
    txns[1].set_sender(preset);
    REQUIRE(txns[2].sender() == expected[2]);

    Transaction::recover_senders(txns);
    size_t invalid{0};
    for (size_t i{0}; i < txns.size(); ++i) {
        INFO("transaction " << i);
        CHECK(txns[i].sender() == (i == 1 ? std::optional{preset} : expected[i]));
        invalid += expected[i].has_value() ? size_t{0} : size_t{1};
    }
    CHECK(invalid >= 16);
    CHECK(invalid < txns.size());

    // A second call finds nothing to recover and changes nothing.
    Transaction::recover_senders(txns);
    for (size_t i{0}; i < txns.size(); ++i) CHECK(txns[i].sender() == (i == 1 ? std::optional{preset} : expected[i]));
}

}  // namespace silkworm
