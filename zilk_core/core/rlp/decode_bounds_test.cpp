// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Length bounds of the RLP decoder. A long-form length is read as 64 bits and must be checked against
// the input before it is narrowed to size_t: on rv32 a length of 2^32 + n would otherwise pass as n.
// The host has a 64-bit size_t, where these inputs are rejected for being longer than the input; the
// narrowing itself only happens on the 32-bit guest. Also the typed transaction's inner list length,
// which must equal the bytes its items consume.

#include <cstdint>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

namespace {

    // `header` followed by `body_len` bytes of payload.
    Bytes with_body(std::initializer_list<uint8_t> header, size_t body_len) {
        Bytes out{header};
        out.append(body_len, 0x11);
        return out;
    }

    std::expected<rlp::Header, DecodingError> header_of(const Bytes& input) {
        ByteView view{input};
        return rlp::decode_header(view);
    }

    // Long enough for the transaction's list header to use the long form.
constexpr uint8_t kData[64]{1, 2, 3, 4, 5, 6, 7, 8};

    Transaction make_typed(TransactionType type) {
        Transaction txn;
        txn.type = type;
        txn.chain_id = 1;
        txn.nonce = 7;
        txn.max_priority_fee_per_gas = 2;
        txn.max_fee_per_gas = type == TransactionType::kAccessList ? txn.max_priority_fee_per_gas : intx::uint256{30};
        txn.gas_limit = 21'000;
        txn.to = evmc::address{};
        txn.value = 5;
        txn.data = ByteView{kData, sizeof(kData)};
        txn.r = 11;
        txn.s = 13;
        return txn;
    }

    // The list header of a typed transaction's type-prefixed encoding and its items.
    struct Split {
        uint8_t type;
        Bytes items;
    };

    Split split_typed(const Bytes& raw) {
        ByteView view{raw};
        const uint8_t type{view[0]};
        view.remove_prefix(1);
        const auto h{rlp::decode_header(view)};
        REQUIRE(h);
        REQUIRE(h->list);
        REQUIRE(h->payload_length == view.size());
        return {type, Bytes{view}};
    }

    // type || list header for `declared` bytes || items, wrapped into a string as in a block body.
    Bytes assemble(const Split& s, size_t declared, bool wrap) {
        Bytes inner;
        inner.push_back(s.type);
        rlp::encode_header(inner, {.list = true, .payload_length = declared});
        inner.append(s.items);
        if (!wrap) {
            return inner;
        }
        Bytes out;
        rlp::encode_header(out, {.list = false, .payload_length = inner.size()});
        out.append(inner);
        return out;
    }

    DecodingResult decode_wrapped(const Bytes& wrapped) {
        ByteView view{wrapped};
        Transaction out;
        return rlp::decode(view, out);
    }

    DecodingResult decode_raw(const Bytes& raw) {
        ByteView view{raw};
        Transaction out;
        return rlp::decode_transaction(view, out, rlp::Eip2718Wrapping::kNone);
    }

}  // namespace

TEST_CASE("decode_header: valid canonical encodings") {
    const auto s{header_of(with_body({0xb8, 0x40}, 64))};
    REQUIRE(s);
    CHECK(!s->list);
    CHECK(s->payload_length == 64);

    const auto l{header_of(with_body({0xf8, 0x40}, 64))};
    REQUIRE(l);
    CHECK(l->list);
    CHECK(l->payload_length == 64);

    const auto big{header_of(with_body({0xb9, 0x01, 0x00}, 256))};
    REQUIRE(big);
    CHECK(big->payload_length == 256);

    const auto short_form{header_of(with_body({0xb7}, 55))};
    REQUIRE(short_form);
    CHECK(short_form->payload_length == 55);
}

TEST_CASE("decode_header: lengths beyond the input are rejected") {
    // 2^32 + 64, 2^56 + 64 and 2^32 + 64 as a list: a 32-bit size_t would read each of them as 64.
    CHECK(header_of(with_body({0xbc, 0x01, 0x00, 0x00, 0x00, 0x40}, 64)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xbf, 0x01, 0, 0, 0, 0, 0, 0, 0x40}, 64)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xfc, 0x01, 0x00, 0x00, 0x00, 0x40}, 64)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xff, 0x01, 0, 0, 0, 0, 0, 0, 0x40}, 64)).error() == DecodingError::kInputTooShort);

    // Exactly 2^32 and the largest 64-bit length: nothing in the low 32 bits.
    CHECK(header_of(with_body({0xbc, 0x01, 0x00, 0x00, 0x00, 0x00}, 64)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 64)).error() ==
          DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xbb, 0xff, 0xff, 0xff, 0xff}, 64)).error() == DecodingError::kInputTooShort);

    // One byte short of the declared length, as a string and as a list.
    CHECK(header_of(with_body({0xb8, 0x40}, 63)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xf8, 0x40}, 63)).error() == DecodingError::kInputTooShort);
    CHECK(header_of(with_body({0xb9, 0x01, 0x00}, 255)).error() == DecodingError::kInputTooShort);
}

TEST_CASE("decode_header: malformed long forms") {
    // Long form below 56: non-canonical even when the input is too short for it.
    CHECK(header_of(with_body({0xb8, 0x37}, 55)).error() == DecodingError::kNonCanonicalSize);
    CHECK(header_of(with_body({0xb8, 0x37}, 0)).error() == DecodingError::kNonCanonicalSize);
    CHECK(header_of(with_body({0xf8, 0x00}, 0)).error() == DecodingError::kLeadingZero);
    CHECK(header_of(with_body({0xbc, 0x00, 0x00, 0x00, 0x37}, 55)).error() == DecodingError::kLeadingZero);

    // Leading zero in the length.
    CHECK(header_of(with_body({0xb9, 0x00, 0x40}, 64)).error() == DecodingError::kLeadingZero);
    CHECK(header_of(with_body({0xf9, 0x00, 0x40}, 64)).error() == DecodingError::kLeadingZero);

    // The length bytes themselves are missing.
    CHECK(header_of(Bytes{0xbc, 0x01}).error() == DecodingError::kInputTooShort);
    CHECK(header_of(Bytes{0xff}).error() == DecodingError::kInputTooShort);
}

TEST_CASE("typed transaction: the inner list length equals the bytes its items consume") {
    for (const auto type : {TransactionType::kAccessList, TransactionType::kDynamicFee}) {
        const Transaction txn{make_typed(type)};
        Bytes raw;
        rlp::encode(raw, txn, /*wrap_eip2718_into_string=*/false);
        const Split s{split_typed(raw)};
        const size_t n{s.items.size()};

        SECTION("canonical encodings are accepted") {
            CHECK(assemble(s, n, false) == raw);
            CHECK(decode_raw(raw));
            CHECK(decode_wrapped(assemble(s, n, true)));
        }

        SECTION("understated") {
            CHECK(decode_raw(assemble(s, n - 1, false)).error() == DecodingError::kUnexpectedListElements);
            CHECK(decode_wrapped(assemble(s, n - 1, true)).error() == DecodingError::kUnexpectedListElements);
            CHECK(!decode_wrapped(assemble(s, 1, true)));
        }

        SECTION("overstated") {
            Split longer{s};
            longer.items.push_back(0x80);  // the declared length covers one more byte than the items use
            CHECK(decode_raw(assemble(longer, n + 1, false)).error() == DecodingError::kUnexpectedListElements);
            CHECK(decode_wrapped(assemble(longer, n + 1, true)).error() == DecodingError::kUnexpectedListElements);
        }

        SECTION("a trailing item inside the list") {
            Split longer{s};
            longer.items.push_back(0x80);
            CHECK(!decode_wrapped(assemble(longer, n, true)));
            CHECK(!decode_wrapped(assemble(longer, n + 1, true)));
        }

        SECTION("items that end before `to`") {
            // The list stops after gas_limit: peeking `to` must not read past the transaction.
            Bytes head;
            rlp::encode(head, *txn.chain_id);
            rlp::encode(head, txn.nonce);
            rlp::encode(head, txn.max_priority_fee_per_gas);
            if (type != TransactionType::kAccessList) {
                rlp::encode(head, txn.max_fee_per_gas);
            }
            rlp::encode(head, txn.gas_limit);
            const Split cut{static_cast<uint8_t>(type), head};
            CHECK(decode_wrapped(assemble(cut, head.size(), true)).error() == DecodingError::kInputTooShort);
            CHECK(decode_raw(assemble(cut, head.size(), false)).error() == DecodingError::kInputTooShort);
        }
    }
}

TEST_CASE("typed transaction: long-form list lengths that do not fit are rejected") {
    const Transaction txn{make_typed(TransactionType::kDynamicFee)};
    Bytes raw;
    rlp::encode(raw, txn, /*wrap_eip2718_into_string=*/false);
    const Split s{split_typed(raw)};

    // Replace the inner list header by a 5-byte length 2^32 + n, which a 32-bit size_t reads as n.
    const size_t n{s.items.size()};
    REQUIRE(n >= 56);
    Bytes forged{raw[0]};
    forged.append({0xfc, 0x01, 0x00, 0x00, 0x00, static_cast<uint8_t>(n)});
    forged.append(s.items);
    CHECK(decode_raw(forged).error() == DecodingError::kInputTooShort);

    Bytes wrapped;
    rlp::encode_header(wrapped, {.list = false, .payload_length = forged.size()});
    wrapped.append(forged);
    CHECK(decode_wrapped(wrapped).error() == DecodingError::kInputTooShort);
}

TEST_CASE("legacy transaction: long-form list length that does not fit is rejected") {
    Transaction txn{make_typed(TransactionType::kLegacy)};
    txn.chain_id = std::nullopt;
    REQUIRE(txn.set_v(27));
    Bytes raw;
    rlp::encode(raw, txn);
    REQUIRE(raw[0] == 0xf8);
    CHECK(decode_wrapped(raw));

    Bytes forged{0xfc, 0x01, 0x00, 0x00, 0x00, raw[1]};
    forged.append(ByteView{raw}.substr(2));
    CHECK(decode_wrapped(forged).error() == DecodingError::kInputTooShort);
}

}  // namespace silkworm
