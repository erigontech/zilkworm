// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <expected>

namespace silkworm {

// Error codes for RLP and other decoding
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
    kUnsupportedTransactionType,  // EIP-2718
    kInvalidFieldset,
    kUnexpectedEip2718Serialization,
    kInvalidHashesLength,  // trie::Node decoding
    kInvalidMasksSubsets,  // trie::Node decoding
};

using DecodingResult = std::expected<void, DecodingError>;

}  // namespace silkworm
