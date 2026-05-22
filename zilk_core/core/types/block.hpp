// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <evmone_precompiles/hash_types.h>
#include <intx/intx.hpp>
#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/types/bloom.hpp>
#include <zilk_core/core/types/hash.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/core/types/withdrawal.hpp>

namespace silkworm {

using TotalDifficulty = intx::uint256;

intx::uint256 calc_blob_gas_price(uint64_t excess_blob_gas, BlobParams blob_params);

struct BlockHeader {
    using NonceType = std::array<uint8_t, 8>;

    evmc::bytes32 parent_hash{};
    evmc::bytes32 ommers_hash{};
    evmc::address beneficiary{};
    evmc::bytes32 state_root{};
    evmc::bytes32 transactions_root{};
    evmc::bytes32 receipts_root{};
    Bloom logs_bloom{};
    intx::uint256 difficulty{};
    uint64_t number{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};

    Bytes extra_data{};

    evmc::bytes32 prev_randao{};  // mix hash (digest) prior to EIP-4399
    NonceType nonce{};

    // Added in London
    std::optional<intx::uint256> base_fee_per_gas{std::nullopt};  // EIP-1559

    // Added in Shanghai
    std::optional<evmc::bytes32> withdrawals_root{std::nullopt};  // EIP-4895

    // Added in Cancun
    std::optional<uint64_t> blob_gas_used{std::nullopt};                  // EIP-4844
    std::optional<uint64_t> excess_blob_gas{std::nullopt};                // EIP-4844
    std::optional<evmc::bytes32> parent_beacon_block_root{std::nullopt};  // EIP-4788

    // Added in Prague
    std::optional<evmc::bytes32> requests_hash{std::nullopt};  // EIP-7685

    evmc::bytes32 hash(bool for_sealing = false, bool exclude_extra_data_sig = false) const;

    //! \brief Calculates header's boundary. This is described by Equation(50) by the Yellow Paper.
    //! \return A hash of 256 bits with big endian byte order
    ethash::hash256 boundary() const;

    //! \see https://eips.ethereum.org/EIPS/eip-4844#gas-accounting
    std::optional<intx::uint256> blob_gas_price(const ChainConfig& config) const;

    friend bool operator==(const BlockHeader&, const BlockHeader&) = default;
};

struct BlockBody {
    std::vector<Transaction> transactions;
    std::vector<BlockHeader> ommers;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};

    friend bool operator==(const BlockBody&, const BlockBody&) = default;
};

struct Block : public BlockBody {
    BlockHeader header;

    BlockBody copy_body() const {
        return *this;  // NOLINT(cppcoreguidelines-slicing)
    }
};

struct BlockWithHash {
    Block block;
    evmc::bytes32 hash;
};

namespace rlp {
    size_t length(const BlockHeader&);
    size_t length(const BlockBody&);
    size_t length(const Block&);

    void encode(Bytes& to, const BlockBody&);
    void encode(Bytes& to, const BlockHeader&, bool for_sealing = false, bool exclude_extra_data_sig = false);
    void encode(Bytes& to, const Block&);

    DecodingResult decode(ByteView& from, BlockBody& to, Leftover mode = Leftover::kProhibit) noexcept;
    DecodingResult decode(ByteView& from, BlockHeader& to, Leftover mode = Leftover::kProhibit) noexcept;
    DecodingResult decode(ByteView& from, Block& to, Leftover mode = Leftover::kProhibit) noexcept;
}  // namespace rlp

}  // namespace silkworm
