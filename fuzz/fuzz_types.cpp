// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the outer Ethereum type decoders: transactions (all EIP-2718
// wrappings), block headers, block bodies, blocks and withdrawals. On a successful
// decode the payload is re-encoded and must round-trip to the input bytes.

#include <cstdio>
#include <cstdlib>

#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/core/types/withdrawal.hpp>

using namespace silkworm;

namespace {

[[gnu::noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "FUZZTYPES: %s\n", what);
    std::abort();
}

void round_trip_tx(const uint8_t* data, size_t size, rlp::Eip2718Wrapping wrapping) {
    ByteView v{data, size};
    Transaction txn;
    if (!rlp::decode_transaction(v, txn, wrapping, rlp::Leftover::kProhibit).has_value()) {
        return;
    }
    // With kBoth the input may arrive in either wrapping; accept either encoding.
    Bytes re_wrapped;
    rlp::encode(re_wrapped, txn, true);
    if (re_wrapped == Bytes{data, size}) {
        return;
    }
    Bytes re_raw;
    rlp::encode(re_raw, txn, false);
    if (re_raw == Bytes{data, size}) {
        return;
    }
    fail("decode/encode(Transaction) round trip mismatch");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Transactions: each accepted wrapping must re-encode to the same bytes.
    round_trip_tx(data, size, rlp::Eip2718Wrapping::kBoth);

    // Block header.
    {
        ByteView v{data, size};
        BlockHeader header;
        if (rlp::decode(v, header, rlp::Leftover::kProhibit).has_value()) {
            Bytes re;
            rlp::encode(re, header);
            if (re != Bytes{data, size}) {
                fail("decode/encode(BlockHeader) round trip mismatch");
            }
        }
    }

    // Block body (transactions + withdrawals + uncles).
    {
        ByteView v{data, size};
        BlockBody body;
        if (rlp::decode(v, body, rlp::Leftover::kProhibit).has_value()) {
            Bytes re;
            rlp::encode(re, body);
            if (re != Bytes{data, size}) {
                fail("decode/encode(BlockBody) round trip mismatch");
            }
        }
    }

    // Full block.
    {
        ByteView v{data, size};
        Block block;
        if (rlp::decode(v, block, rlp::Leftover::kProhibit).has_value()) {
            Bytes re;
            rlp::encode(re, block);
            if (re != Bytes{data, size}) {
                fail("decode/encode(Block) round trip mismatch");
            }
        }
    }

    // Withdrawal.
    {
        ByteView v{data, size};
        Withdrawal w;
        if (rlp::decode(v, w, rlp::Leftover::kProhibit).has_value()) {
            Bytes re;
            rlp::encode(re, w);
            if (re != Bytes{data, size}) {
                fail("decode/encode(Withdrawal) round trip mismatch");
            }
        }
    }

    return 0;
}
