// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <expected>

namespace silkworm {

enum class [[nodiscard]] DecodingError {
    kOverflow,
    kLeadingZero,
    kInputTooShort,
    kInputTooLong,
    kNonCanonicalSize,
    kUnexpectedLength,
    kUnexpectedString,
    kUnexpectedList,
    kUnexpectedListElements,
    kInvalidVInSignature,         // v != 27 && v != 28 && v < 35, see EIP-155
    kUnsupportedTransactionType,
    kInvalidFieldset,
    kUnexpectedEip2718Serialization,
    kInvalidHashesLength,
    kInvalidMasksSubsets,
};

using DecodingResult = std::expected<void, DecodingError>;

}  // namespace silkworm
