// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the witness-trie leaf walk: a NodeMap (keccak(rlp) -> node
// rlp) built from the input, walked from an attacker-chosen root. The walk decodes
// every visited node with rlp_sw and must never read out of bounds.

#include <cstdint>
#include <cstring>
#include <vector>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/types_zz/witness_trie.hpp>

using namespace zilkworm;
using namespace zilkworm::witness;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 8 || size > (1u << 16)) {
        return 0;
    }

    // [u16 LE entry length][entry bytes]...; entry = node RLP, keyed by its keccak.
    // The first entry's hash is the root the walk starts from. The entries are counted
    // first so `storage` never reallocates: the map holds views into it.
    NodeMap nodes;
    evmc::bytes32 root{};
    bool root_set{false};
    size_t off{0};
    size_t n_entries{0};
    for (size_t o{0}; o + 2 <= size;) {
        uint16_t len{0};
        std::memcpy(&len, data + o, sizeof(len));
        o += 2;
        if (len == 0 || o + len > size) {
            break;
        }
        ++n_entries;
        o += len;
    }
    std::vector<silkworm::Bytes> storage;
    storage.reserve(n_entries);
    nodes.reserve(n_entries);
    off = 0;
    while (off + 2 <= size) {
        uint16_t len{0};
        std::memcpy(&len, data + off, sizeof(len));
        off += 2;
        if (len == 0 || off + len > size) {
            break;
        }
        storage.emplace_back(data + off, data + off + len);
        const silkworm::Bytes& rlp{storage.back()};
        const auto h = silkworm::keccak256(rlp);
        if (!root_set) {
            std::memcpy(root.bytes, h.bytes, 32);
            root_set = true;
        }
        evmc::bytes32 key{};
        std::memcpy(key.bytes, h.bytes, 32);
        nodes[key] = silkworm::ByteView{rlp};
        off += len;
    }
    if (!root_set) {
        return 0;
    }

    size_t leaf_bytes{0};
    for_each_leaf(nodes, root, [&](std::span<const uint8_t>, silkworm::ByteView value) noexcept {
        leaf_bytes += value.size();
    });
    (void)leaf_bytes;
    return 0;
}
