// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the witness MPT node decoders (rlp_sw): hp_decode,
// decode_branch, decode_ext_or_leaf, decode_node, plus the account leaf decoder
// the trie walk feeds decoded leaves into. All take attacker-controlled RLP.

#include <array>
#include <cstdint>
#include <cstdlib>

#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/account.hpp>

using namespace zilkworm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > (1u << 16)) {
        return 0;
    }
    const ByteView payload{data, size};

    // The node-kind dispatcher used on every witness node read.
    {
        BranchNode branch;
        bool is_leaf{false};
        std::array<uint8_t, 64> path{};
        uint8_t plen{0};
        ByteView second;
        const Kind kind = decode_node(payload, branch, is_leaf, path, plen, second);
        // Only the fields the returned kind populates may be read.
        if (kind == Kind::kBranch) {
            (void)branch.mask;
            (void)branch.value.size();
        } else if (kind == Kind::kLeaf || kind == Kind::kExt ||
                   kind == Kind::kExtOrLeaf) {
            if (plen > 64) {
                std::abort();  // hp path length must stay within the 64-nibble bound.
            }
        }
    }

    // The hp (hex-prefix) decoder standalone.
    {
        bool is_leaf{false};
        std::array<uint8_t, 64> out{};
        uint8_t out_len{0};
        if (hp_decode(payload, is_leaf, out, out_len)) {
            if (out_len > 64) {
                std::abort();
            }
        }
    }

    // The account leaf-value decoder.
    {
        Account account;
        if (decode_trie_account(payload, account)) {
            // A decoded account must re-encode losslessly through the trie leaf form
            // only when the input was canonical; just touch the fields here.
            (void)account.nonce;
            (void)account.balance;
            (void)account.code_hash;
            (void)account.storage_root;
        }
    }

    return 0;
}
