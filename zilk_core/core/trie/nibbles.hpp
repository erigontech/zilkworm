// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace silkworm::trie {

// Nibble values are in [0..16).
Bytes pack_nibbles(ByteView unpacked);

Bytes unpack_nibbles(ByteView data);

}  // namespace silkworm::trie
