// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>

namespace silkworm {

// Crops long input, left-pads short input with zeros.
evmc::bytes32 to_bytes32(ByteView bytes);

std::string to_hex(const evmc::bytes32& value, bool with_prefix = false);

}  // namespace silkworm

namespace silkworm::rlp {

void encode(Bytes& to, const evmc::bytes32& value);
size_t length(const evmc::bytes32& value) noexcept;

DecodingResult decode(ByteView& from, evmc::bytes32& to, Leftover mode = Leftover::kProhibit) noexcept;

}  // namespace silkworm::rlp

namespace evmc {
using silkworm::rlp::encode;
using silkworm::rlp::length;
}  // namespace evmc
