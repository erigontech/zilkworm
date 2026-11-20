// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>
#include <string>
#include <string_view>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>

#include "zilk_core/core/common/decoding_result.hpp"

namespace silkworm {

evmc::address create_address(const evmc::address& caller, uint64_t nonce) noexcept;

// EIP-1014
evmc::address create2_address(const evmc::address& caller, const evmc::bytes32& salt,
                              uint8_t (&code_hash)[32]) noexcept;

// Crops long input, left-pads short input with zeros.
evmc::address bytes_to_address(ByteView bytes);

// Terminates on invalid hex unless return_zero_on_err is true.
evmc::address hex_to_address(std::string_view hex, bool return_zero_on_err = false);

std::string address_to_hex(const evmc::address& address);

namespace rlp {
    void encode(Bytes& to, const evmc::address& address);
    DecodingResult decode(ByteView& from, evmc::address& address, Leftover mode = Leftover::kProhibit);
    size_t length(const evmc::address& address) noexcept;
}  // namespace rlp

}  // namespace silkworm

namespace evmc {

std::ostream& operator<<(std::ostream& out, const evmc::address& address);

}  // namespace evmc
