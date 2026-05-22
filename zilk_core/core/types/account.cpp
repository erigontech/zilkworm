// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <format>

#include "account.hpp"
#include <zilk_core/core/rlp/encode.hpp>

namespace silkworm {

Bytes Account::rlp(const evmc::bytes32& storage_root) const {
    rlp::Header h{true, 0};
    h.payload_length += rlp::length(nonce);
    h.payload_length += rlp::length(balance);
    h.payload_length += kHashLength + 1;
    h.payload_length += kHashLength + 1;

    Bytes to;

    rlp::encode_header(to, h);
    rlp::encode(to, nonce);
    rlp::encode(to, balance);
    rlp::encode(to, storage_root);
    rlp::encode(to, code_hash);

    return to;
}

std::string Account::to_string() const {
    return std::format("nonce: {} balance: 0x{} code_hash: 0x{}",
                       nonce,
                       intx::hex(balance),
                       to_hex(code_hash));
}

}  // namespace silkworm
