// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the RLP primitives: header decoding, string/integer/bool/list
// decoding, and the decode->re-encode canonicality round trip. All paths take fully
// attacker-controlled bytes.

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <intx/intx.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/endian.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/decode_vector.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>

using namespace silkworm;

namespace {

[[gnu::noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "FUZZRLP: %s\n", what);
    std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const ByteView input{data, size};

    // 1. Header decoding must never read past the buffer, and must consume exactly
    //    the header (payload_length bytes must remain afterwards when they fit).
    {
        ByteView v{input};
        const auto h{rlp::decode_header(v)};
        if (h) {
            // The header is the only thing consumed; the payload must fit in the input.
            if (v.size() + 0 < h->payload_length) {
                fail("decode_header: payload longer than remaining input");
            }
        }
    }

    // 2. String decode + re-encode round trip: any accepted (canonical) input must
    //    re-encode to itself.
    {
        ByteView v{input};
        Bytes to;
        if (rlp::decode(v, to).has_value()) {
            if (!v.empty()) {
                fail("decode(Bytes): leftover with kProhibit");
            }
            Bytes re;
            rlp::encode(re, ByteView{to});
            if (re != Bytes{input}) {
                fail("decode/encode(Bytes) round trip mismatch");
            }
        }
    }

    // 3. uint64 / uint256 / bool round trips.
    {
        ByteView v{input};
        uint64_t to{0};
        if (rlp::decode(v, to).has_value()) {
            if (!v.empty()) {
                fail("decode(uint64): leftover with kProhibit");
            }
            Bytes re;
            rlp::encode(re, to);
            if (re != Bytes{input}) {
                fail("decode/encode(uint64) round trip mismatch");
            }
        }
    }
    {
        ByteView v{input};
        intx::uint256 to{0};
        if (rlp::decode(v, to).has_value()) {
            if (!v.empty()) {
                fail("decode(uint256): leftover with kProhibit");
            }
            Bytes re;
            rlp::encode(re, to);
            if (re != Bytes{input}) {
                fail("decode/encode(uint256) round trip mismatch");
            }
        }
    }
    {
        ByteView v{input};
        bool to{false};
        if (rlp::decode(v, to).has_value()) {
            if (!v.empty()) {
                fail("decode(bool): leftover with kProhibit");
            }
            // encode(bool) writes 0x80 or 0x01; only those two inputs decode to bool.
        }
    }

    // 4. Vector-of-strings decode + re-encode.
    {
        ByteView v{input};
        std::vector<Bytes> to;
        if (rlp::decode(v, to).has_value()) {
            if (!v.empty()) {
                fail("decode(vector<Bytes>): leftover with kProhibit");
            }
            Bytes re;
            rlp::encode(re, std::span<const Bytes>{to});
            if (re != Bytes{input}) {
                fail("decode/encode(vector<Bytes>) round trip mismatch");
            }
        }
    }

    return 0;
}
