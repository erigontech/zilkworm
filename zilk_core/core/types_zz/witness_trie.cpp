// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "witness_trie.hpp"

#include <cstring>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm::witness {

using silkworm::ByteView;

namespace {

void walk_tree(
    const NodeMap& nodes,
    ByteView node_rlp,
    std::array<uint8_t, 64>& path,
    size_t depth,
    const LeafCb& cb)
{
    auto outer = silkworm::rlp::decode_header(node_rlp);
    if (!outer || !outer->list) return;
    ByteView body = node_rlp.substr(0, outer->payload_length);

    {
        BranchNode br{};
        ByteView body_copy = body;
        if (decode_branch(body_copy, br)) {
            for (unsigned slot = 0; slot < 16; ++slot) {
                if ((br.mask & (1u << slot)) == 0) continue;
                path[depth] = static_cast<uint8_t>(slot);
                const uint8_t child_len = br.child_len[slot];
                if (child_len == 32) {
                    evmc::bytes32 child_hash;
                    std::memcpy(child_hash.bytes, br.child[slot].bytes, 32);
                    auto it = nodes.find(child_hash);
                    if (it != nodes.end()) {
                        walk_tree(nodes, it->second, path, depth + 1, cb);
                    }
                } else {
                    walk_tree(nodes,
                              ByteView{br.child[slot].bytes, child_len},
                              path, depth + 1, cb);
                }
            }
            return;
        }
    }

    bool is_leaf = false;
    std::array<uint8_t, 64> ext_path{};
    uint8_t plen = 0;
    ByteView second{};
    if (!decode_ext_or_leaf(body, is_leaf, ext_path, plen, second)) {
        return;
    }

    if (depth + plen > 64) return;
    std::memcpy(path.data() + depth, ext_path.data(), plen);
    const size_t new_depth = depth + plen;

    if (is_leaf) {
        cb(std::span<const uint8_t>{path.data(), new_depth}, second);
        return;
    }

    if (second.size() == 32) {
        evmc::bytes32 child_hash;
        std::memcpy(child_hash.bytes, second.data(), 32);
        auto it = nodes.find(child_hash);
        if (it != nodes.end()) {
            walk_tree(nodes, it->second, path, new_depth, cb);
        }
    } else {
        walk_tree(nodes, second, path, new_depth, cb);
    }
}

}  // namespace

void for_each_leaf(const NodeMap& nodes, const evmc::bytes32& root, LeafCb cb) {
    if (root == silkworm::kEmptyRoot || root == evmc::bytes32{}) return;
    auto it = nodes.find(root);
    if (it == nodes.end()) return;
    std::array<uint8_t, 64> path{};
    walk_tree(nodes, it->second, path, /*depth=*/0, cb);
}

}  // namespace zilkworm::witness
