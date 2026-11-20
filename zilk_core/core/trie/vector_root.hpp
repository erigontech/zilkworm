// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <concepts>
#include <functional>

#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>

namespace silkworm::trie {

// RLP integers sort as their values except 0, which sorts between 0x7f and 0x80.
inline size_t adjust_index_for_rlp(size_t i, size_t len) {
    if (i > 0x7f) {
        return i;
    }
    if (i == 0x7f || i + 1 == len) {
        return 0;
    }
    return i + 1;
}

// Keys are the RLP-encoded indices of the values.
template <class Value, std::invocable<Bytes&, const Value&> Encoder>
evmc::bytes32 root_hash(const std::vector<Value>& v, const Encoder& value_encoder) {
    Bytes index_rlp;
    Bytes value_rlp[2];  // hb views the pending leaf's buffer

    HashBuilder hb;

    for (size_t j{0}; j < v.size(); ++j) {
        const size_t index{adjust_index_for_rlp(j, v.size())};
        index_rlp.clear();
        rlp::encode(index_rlp, index);
        Bytes& value{value_rlp[j & 1]};
        value.clear();
        std::invoke(value_encoder, value, v[index]);

        hb.add_leaf(unpack_nibbles(index_rlp), value);
    }

    return hb.root_hash();
}

}  // namespace silkworm::trie
