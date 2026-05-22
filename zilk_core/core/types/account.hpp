// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

namespace silkworm {
struct Account {
    uint64_t nonce{0};
    intx::uint256 balance;
    evmc::bytes32 code_hash{kEmptyHash};
    evmc::bytes32 storage_root_{kEmptyRoot};

    //! \brief Serialize the account into its Recursive-Length Prefix (RLP) representation
    Bytes rlp(const evmc::bytes32& storage_root) const;

    friend bool operator==(const Account&, const Account&) = default;

    std::string to_string() const;
};

}  // namespace silkworm
