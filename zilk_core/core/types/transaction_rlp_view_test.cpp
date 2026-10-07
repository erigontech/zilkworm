// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// A decoded transaction keeps views of its own bytes: the transaction-trie value and the unsigned items
// before the signature. The transactions root and the signing hashes are taken from them instead of
// from a re-encoding, which is only exact if the decoder accepts nothing but canonical encodings. These
// tests check the views against the encoders for every transaction type and header size, that every
// non-canonical encoding is still rejected, and that a transaction built in code still uses the encoders.

#include <cstdint>
#include <memory>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace silkworm {

namespace {

    using intx::operator""_u256;

    // Owns the calldata that the transactions of a test view.
    class Fixture {
      public:
        ByteView data(size_t n, uint8_t seed = 0) {
            Bytes& d{*owned_.emplace_back(std::make_unique<Bytes>())};
            d.resize(n);
            for (size_t i{0}; i < n; ++i) {
                d[i] = static_cast<uint8_t>(seed + i * 7);
            }
            return d;
        }

        Transaction make(TransactionType type, ByteView data, bool creation = false) {
            Transaction txn;
            txn.type = type;
            txn.nonce = 7;
            txn.max_priority_fee_per_gas = 2;
            txn.max_fee_per_gas = type == TransactionType::kLegacy || type == TransactionType::kAccessList
                                      ? txn.max_priority_fee_per_gas
                                      : intx::uint256{30};
            txn.gas_limit = 1'000'000;
            if (!creation) {
                txn.to = evmc::address{};
                txn.to->bytes[19] = 0x42;
            }
            txn.value = 5;
            txn.data = data;
            txn.r = 11;
            txn.s = 13;
            if (type == TransactionType::kLegacy) {
                REQUIRE(txn.set_v(27));
                return txn;
            }
            txn.chain_id = 1;
            txn.odd_y_parity = true;
            txn.access_list.push_back({.account = evmc::address{}, .storage_keys = {evmc::bytes32{}, evmc::bytes32{}}});
            txn.access_list.push_back({.account = evmc::address{}, .storage_keys = {}});
            if (type == TransactionType::kBlob) {
                txn.max_fee_per_blob_gas = 3;
                txn.blob_versioned_hashes.push_back(Hash{});
                txn.blob_versioned_hashes.back().bytes[0] = 1;
            }
            if (type == TransactionType::kSetCode) {
                Authorization a{.chain_id = 1, .address = evmc::address{}, .nonce = 9, .y_parity = 1, .r = 17, .s = 19};
                txn.authorizations.push_back(a);
                a.nonce = 0;
                a.y_parity = 0;
                txn.authorizations.push_back(a);
            }
            return txn;
        }

      private:
        std::vector<std::unique_ptr<Bytes>> owned_;
    };

    Bytes encoded(const Transaction& txn, bool wrap) {
        Bytes out;
        rlp::encode(out, txn, wrap);
        return out;
    }

    Bytes signing(const Transaction& txn) {
        Bytes out;
        txn.encode_for_signing(out);
        return out;
    }

    Bytes payload(const Transaction& txn) {
        Bytes out;
        txn.signing_payload(out);
        return out;
    }

    DecodingResult decode_block_tx(const Bytes& wrapped, Transaction& out) {
        ByteView view{wrapped};
        return rlp::decode(view, out);
    }

    bool views_empty(const Transaction& txn) {
        return txn.rlp_encoded().empty() && txn.rlp_unsigned().empty();
    }

    bool within(ByteView inner, const Bytes& outer) {
        return inner.data() >= outer.data() && inner.data() + inner.size() <= outer.data() + outer.size();
    }

    // The decoded transaction's views and payload equal what the encoders write for `txn`.
    void check_views(const Transaction& txn) {
        const Bytes wrapped{encoded(txn, true)};
        Transaction decoded;
        REQUIRE(decode_block_tx(wrapped, decoded));

        CHECK(Bytes{decoded.rlp_encoded()} == encoded(txn, false));
        CHECK(within(decoded.rlp_encoded(), wrapped));
        CHECK(within(decoded.rlp_unsigned(), wrapped));
        CHECK(!decoded.rlp_unsigned().empty());
        CHECK(payload(decoded) == signing(txn));
        CHECK(payload(decoded) == signing(decoded));

        // Built in code: no views, the encoders are used.
        CHECK(views_empty(txn));
        CHECK(payload(txn) == signing(txn));
    }

    std::vector<Transaction> every_type(Fixture& f, ByteView data, bool creation) {
        std::vector<Transaction> txns;
        txns.push_back(f.make(TransactionType::kLegacy, data, creation));  // v 27
        txns.push_back(f.make(TransactionType::kLegacy, data, creation));
        REQUIRE(txns.back().set_v(28));
        txns.push_back(f.make(TransactionType::kLegacy, data, creation));
        REQUIRE(txns.back().set_v(37));  // chain id 1
        txns.push_back(f.make(TransactionType::kLegacy, data, creation));
        REQUIRE(txns.back().set_v((intx::uint256{1} << 70) * 2 + 36));  // a chain id of 2^70, odd parity
        txns.push_back(f.make(TransactionType::kAccessList, data, creation));
        txns.push_back(f.make(TransactionType::kDynamicFee, data, creation));
        if (!creation) {
            txns.push_back(f.make(TransactionType::kBlob, data));
            txns.push_back(f.make(TransactionType::kSetCode, data));
        }
        return txns;
    }

    // Encoded items of a transaction, to build the malformed lists below one item at a time.
    using Items = std::vector<Bytes>;

    Bytes item(uint64_t v) {
        Bytes out;
        rlp::encode(out, v);
        return out;
    }

    Bytes str(ByteView v) {
        Bytes out;
        rlp::encode(out, v);
        return out;
    }

    Bytes list_of(const Items& items) {
        size_t n{0};
        for (const Bytes& i : items) {
            n += i.size();
        }
        Bytes out;
        rlp::encode_header(out, {.list = true, .payload_length = n});
        for (const Bytes& i : items) {
            out.append(i);
        }
        return out;
    }

    Bytes in_block(Bytes inner) {
        Bytes out;
        rlp::encode_header(out, {.list = false, .payload_length = inner.size()});
        out.append(inner);
        return out;
    }

    Bytes address_item() {
        Bytes a(20, 0x42);
        return str(a);
    }

    // 1559 items: chain_id nonce tip fee gas to value data access_list y r s
    Items dynamic_fee_items() {
        return {item(1), item(7), item(2), item(30), item(21000), address_item(), item(5), str(Bytes{1, 2, 3}), list_of({}), item(1), item(11), item(13)};
    }

    // legacy items: nonce price gas to value data v r s
    Items legacy_items() {
        return {item(7), item(2), item(21000), address_item(), item(5), str(Bytes{1, 2, 3}), item(37), item(11), item(13)};
    }

    Bytes typed_tx(const Items& items) {
        Bytes inner{static_cast<uint8_t>(TransactionType::kDynamicFee)};
        inner.append(list_of(items));
        return in_block(inner);
    }

}  // namespace

TEST_CASE("decoded transaction views: every type and header size") {
    Fixture f;
    // Calldata of 0 and 1 bytes (0x05, 0x85), the short/long form boundary at 55 and 56, one to four
    // length bytes in the list header (255, 256, 65535, 65536 and beyond 2^24).
    for (const size_t n : {size_t{0}, size_t{1}, size_t{55}, size_t{56}, size_t{255}, size_t{256}, size_t{65'535},
                           size_t{65'536}}) {
        DYNAMIC_SECTION("calldata " << n) {
            for (const bool creation : {false, true}) {
                const ByteView data{f.data(n)};
                for (const Transaction& txn : every_type(f, data, creation)) {
                    check_views(txn);
                }
            }
        }
    }
    SECTION("single byte calldata below and above 0x80") {
        for (const uint8_t b : {uint8_t{0x05}, uint8_t{0x85}, uint8_t{0x00}, uint8_t{0x80}, uint8_t{0x7f}}) {
            static Bytes one;
            one.assign(1, b);
            for (const Transaction& txn : every_type(f, one, false)) {
                check_views(txn);
            }
        }
    }
}

TEST_CASE("decoded transaction views: the payload header at its size boundaries") {
    // Calldata sizes that put the unsigned list payload within a few bytes of 56, 2^8, 2^16 and 2^24,
    // where the list header takes one to five bytes.
    for (const size_t boundary : {size_t{56}, size_t{256}, size_t{65'536}, size_t{16'777'216}}) {
        const size_t step{boundary > 100'000 ? size_t{20} : size_t{5}};
        for (size_t d{boundary - 120}; d < boundary - 10; d += step) {
            Fixture f;
            const ByteView data{f.data(d)};
            check_views(f.make(TransactionType::kAccessList, data));
            check_views(f.make(TransactionType::kLegacy, data));
        }
    }
}

TEST_CASE("decoded transaction views: set_v, reset and copies") {
    Fixture f;
    const ByteView data{f.data(20)};
    const Bytes wrapped{encoded(f.make(TransactionType::kLegacy, data), true)};

    Transaction decoded;
    REQUIRE(decode_block_tx(wrapped, decoded));
    REQUIRE(!views_empty(decoded));

    const Transaction copy{decoded};
    CHECK(copy.rlp_encoded().data() == decoded.rlp_encoded().data());
    CHECK(copy.rlp_unsigned().size() == decoded.rlp_unsigned().size());

    // Changing the fields invalidates the views: the payload must follow the fields.
    REQUIRE(decoded.set_v(37));
    CHECK(views_empty(decoded));
    CHECK(payload(decoded) == signing(decoded));
    CHECK(payload(decoded) != payload(copy));

    REQUIRE(!views_empty(copy));
    Transaction again{copy};
    again.reset();
    CHECK(views_empty(again));
    CHECK(!views_empty(copy));
}

TEST_CASE("decoded transaction views: a bare typed transaction has none") {
    Fixture f;
    const Transaction built{f.make(TransactionType::kDynamicFee, f.data(30))};
    const Bytes raw{encoded(built, false)};
    ByteView view{raw};
    Transaction decoded;
    REQUIRE(rlp::decode_transaction(view, decoded, rlp::Eip2718Wrapping::kNone));
    CHECK(views_empty(decoded));
    CHECK(payload(decoded) == signing(built));
}

TEST_CASE("decoded transaction views: a failed decode leaves them empty") {
    Fixture f;
    const Bytes good{encoded(f.make(TransactionType::kDynamicFee, f.data(30)), true)};

    Transaction txn;
    REQUIRE(decode_block_tx(good, txn));
    REQUIRE(!views_empty(txn));

    Bytes bad{good};
    bad.push_back(0x80);  // trailing byte after the string
    CHECK(!decode_block_tx(bad, txn));
    CHECK(views_empty(txn));

    REQUIRE(decode_block_tx(good, txn));
    Bytes truncated{good.begin(), good.end() - 1};
    CHECK(!decode_block_tx(truncated, txn));
    CHECK(views_empty(txn));
}

TEST_CASE("decoded transaction views: the canonical lists the negative cases are built from decode") {
    Transaction txn;
    const Bytes typed{typed_tx(dynamic_fee_items())};  // the views point into it
    CHECK(decode_block_tx(typed, txn));
    CHECK(Bytes{txn.rlp_encoded()} == encoded(txn, false));

    const Bytes raw{list_of(legacy_items())};
    ByteView view{raw};
    Transaction l;
    REQUIRE(rlp::decode(view, l));
    CHECK(Bytes{l.rlp_encoded()} == raw);
}

TEST_CASE("decoded transaction views: non-canonical encodings are rejected") {
    Transaction txn;
    const auto rejected = [&](const Bytes& wrapped) { return !decode_block_tx(wrapped, txn) && views_empty(txn); };
    const auto typed_with = [](size_t index, Bytes replacement) {
        Items items{dynamic_fee_items()};
        items[index] = std::move(replacement);
        return typed_tx(items);
    };
    const auto legacy_with = [](size_t index, Bytes replacement) {
        Items items{legacy_items()};
        items[index] = std::move(replacement);
        return list_of(items);
    };
    const auto legacy_rejected = [&](const Bytes& raw) {
        ByteView view{raw};
        return !rlp::decode(view, txn) && views_empty(txn);
    };

    SECTION("integers with a leading zero") {
        CHECK(rejected(typed_with(1, Bytes{0x82, 0x00, 0x07})));  // nonce
        CHECK(rejected(typed_with(4, Bytes{0x83, 0x00, 0x52, 0x08})));  // gas limit
        CHECK(rejected(typed_with(6, Bytes{0x82, 0x00, 0x05})));  // value
        CHECK(rejected(typed_with(9, Bytes{0x00})));  // y parity
        CHECK(rejected(typed_with(10, Bytes{0x82, 0x00, 0x0b})));  // r
        CHECK(legacy_rejected(legacy_with(0, Bytes{0x82, 0x00, 0x07})));
        CHECK(legacy_rejected(legacy_with(7, Bytes{0x82, 0x00, 0x0b})));
    }
    SECTION("a single byte below 0x80 as a string") {
        CHECK(rejected(typed_with(1, Bytes{0x81, 0x05})));
        CHECK(rejected(typed_with(7, Bytes{0x81, 0x05})));  // calldata
        CHECK(legacy_rejected(legacy_with(5, Bytes{0x81, 0x05})));
        CHECK(legacy_rejected(legacy_with(4, Bytes{0x81, 0x05})));
    }
    SECTION("a long form below 56") {
        CHECK(rejected(typed_with(7, Bytes{0xb8, 0x03, 0x01, 0x02, 0x03})));
        CHECK(legacy_rejected(legacy_with(5, Bytes{0xb8, 0x03, 0x01, 0x02, 0x03})));
        CHECK(rejected(typed_with(8, Bytes{0xf8, 0x00})));  // access list
    }
    SECTION("a long form with a leading zero or a length that does not fit") {
        CHECK(rejected(typed_with(7, Bytes{0xb9, 0x00, 0x03, 0x01, 0x02, 0x03})));
        CHECK(rejected(typed_with(7, Bytes{0xbc, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03})));
        Bytes raw{0xfc, 0x01, 0x00, 0x00, 0x00, 0x40};
        raw.append(64, 0x11);
        CHECK(legacy_rejected(raw));
    }
    SECTION("a wrong to, access list entry or y parity") {
        CHECK(rejected(typed_with(5, Bytes{0x93, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19})));
        CHECK(rejected(typed_with(5, Bytes{0x81, 0x01})));
        CHECK(rejected(typed_with(9, Bytes{0x02})));
        CHECK(rejected(typed_with(9, Bytes{0x81, 0x01})));
        // An access list entry whose storage key is 31 bytes, and one with a key of the wrong item kind.
        const Bytes entry{list_of({address_item(), list_of({str(Bytes(31, 0))})})};
        CHECK(rejected(typed_with(8, list_of({entry}))));
        const Bytes entry2{list_of({address_item(), list_of({item(1)})})};
        CHECK(rejected(typed_with(8, list_of({entry2}))));
        // An entry with a trailing item.
        const Bytes entry3{list_of({address_item(), list_of({}), item(1)})};
        CHECK(rejected(typed_with(8, list_of({entry3}))));
        CHECK(legacy_rejected(legacy_with(6, item(26))));  // v
        CHECK(legacy_rejected(legacy_with(6, item(0))));
    }
    SECTION("an inner list length that does not match its items") {
        const Bytes list{list_of(dynamic_fee_items())};
        const Bytes tx_body{static_cast<uint8_t>(TransactionType::kDynamicFee)};
        const ByteView items{ByteView{list}.substr(1)};  // the list is short enough for a one-byte header
        REQUIRE(list[0] >= 0xc0);
        REQUIRE(list[0] < 0xf8);

        const auto with_length = [&](size_t declared, ByteView body) {
            Bytes inner{tx_body};
            rlp::encode_header(inner, {.list = true, .payload_length = declared});
            inner.append(body);
            return in_block(inner);
        };
        CHECK(!rejected(with_length(items.size(), items)));
        CHECK(rejected(with_length(items.size() - 1, items)));
        CHECK(rejected(with_length(items.size() + 1, items)));
        CHECK(rejected(with_length(items.size() - 40, items)));
        Bytes extra{items};
        extra.push_back(0x80);
        CHECK(rejected(with_length(items.size(), extra)));
        CHECK(rejected(with_length(extra.size(), extra)));
    }
    SECTION("an extra trailing item in the list") {
        Items items{dynamic_fee_items()};
        items.push_back(item(1));
        CHECK(rejected(typed_tx(items)));
        Items legacy{legacy_items()};
        legacy.push_back(item(1));
        CHECK(legacy_rejected(list_of(legacy)));
        Items short_list{dynamic_fee_items()};
        short_list.pop_back();
        CHECK(rejected(typed_tx(short_list)));
        Items legacy_short{legacy_items()};
        legacy_short.pop_back();
        CHECK(legacy_rejected(list_of(legacy_short)));
    }
    SECTION("a typed transaction cut off before its last field") {
        Items items{dynamic_fee_items()};
        items.resize(5);  // up to the gas limit
        CHECK(rejected(typed_tx(items)));
    }
}

TEST_CASE("decoded transaction views: blob and set code transactions without a recipient") {
    Fixture f;
    for (const TransactionType type : {TransactionType::kBlob, TransactionType::kSetCode}) {
        Transaction txn{f.make(type, f.data(10))};
        txn.to = std::nullopt;
        check_views(txn);

        Transaction decoded;
        const Bytes wire{encoded(txn, true)};  // the views point into it
        REQUIRE(decode_block_tx(wire, decoded));
        CHECK(!decoded.to);
        const intx::uint256 base_fee{1};
        CHECK(protocol::pre_validate_transaction(decoded, EVMC_PRAGUE, 1, base_fee, intx::uint256{1}) ==
              ValidationResult::kProhibitedContractCreation);
    }
}

TEST_CASE("compute_transaction_root: decoded, built and mixed bodies agree") {
    Fixture f;
    const std::vector<Transaction> pool{every_type(f, f.data(70), false)};
    const std::vector<Transaction> creations{every_type(f, f.data(3), true)};

    const auto body_of = [&](size_t n) {
        BlockBody body;
        for (size_t i{0}; i < n; ++i) {
            body.transactions.push_back(i % 3 == 2 ? creations[i % creations.size()] : pool[i % pool.size()]);
        }
        return body;
    };
    const auto decode_body = [](const Bytes& wire) {
        BlockBody out;
        ByteView view{wire};
        REQUIRE(rlp::decode(view, out));
        return out;
    };

    SECTION("an empty body") {
        const BlockBody built;
        Bytes wire;
        rlp::encode(wire, built);
        const BlockBody decoded{decode_body(wire)};
        CHECK(protocol::compute_transaction_root(decoded) == kEmptyRoot);
        CHECK(protocol::compute_transaction_root(built) == kEmptyRoot);
    }

    // Sizes around the points where the trie's key order changes (0x7f, 0x80).
    for (const size_t n : {size_t{1}, size_t{2}, size_t{3}, size_t{16}, size_t{126}, size_t{127}, size_t{128}, size_t{129},
                           size_t{300}}) {
        DYNAMIC_SECTION(n << " transactions") {
            const BlockBody built{body_of(n)};
            Bytes wire;
            rlp::encode(wire, built);
            const BlockBody decoded{decode_body(wire)};
            REQUIRE(decoded.transactions.size() == n);
            for (const Transaction& txn : decoded.transactions) {
                REQUIRE(!txn.rlp_encoded().empty());
            }

            const evmc::bytes32 expected{protocol::compute_transaction_root(built)};
            CHECK(protocol::compute_transaction_root(decoded) == expected);

            // Mixed: one built transaction among decoded ones takes the encoding path.
            BlockBody mixed{decoded};
            mixed.transactions[n / 2] = built.transactions[n / 2];
            CHECK(views_empty(mixed.transactions[n / 2]));
            CHECK(protocol::compute_transaction_root(mixed) == expected);

            // The signing payloads of a decoded body are those of the built one.
            for (size_t i{0}; i < n; ++i) {
                CHECK(payload(decoded.transactions[i]) == signing(built.transactions[i]));
            }
        }
    }
}

TEST_CASE("decoded transaction views: random mutations accept only canonical encodings") {
    Fixture f;
    std::vector<Bytes> seeds;
    for (const size_t n : {size_t{0}, size_t{9}, size_t{60}}) {
        for (const bool creation : {false, true}) {
            for (const Transaction& txn : every_type(f, f.data(n), creation)) {
                seeds.push_back(encoded(txn, true));
            }
        }
    }

    std::mt19937_64 rng{0x7a6b2d};
    size_t accepted{0};
    for (size_t iteration{0}; iteration < 40'000; ++iteration) {
        Bytes wire{seeds[rng() % seeds.size()]};
        const size_t mutations{1 + rng() % 3};
        for (size_t m{0}; m < mutations && !wire.empty(); ++m) {
            const size_t pos{rng() % wire.size()};
            switch (rng() % 6) {
                case 0:
                    wire[pos] ^= static_cast<uint8_t>(1u << (rng() % 8));
                    break;
                case 1:
                    wire[pos] = static_cast<uint8_t>(rng());
                    break;
                case 2:
                    wire.insert(wire.begin() + static_cast<std::ptrdiff_t>(pos), static_cast<uint8_t>(rng()));
                    break;
                case 3:
                    wire.erase(wire.begin() + static_cast<std::ptrdiff_t>(pos));
                    break;
                case 4:
                    wire.resize(pos);
                    break;
                default:  // interesting header bytes
                    wire[pos] = static_cast<uint8_t>(std::array<uint8_t, 8>{0x00, 0x80, 0x81, 0xb8, 0xf8, 0xbc, 0xfc, 0xc0}[rng() % 8]);
                    break;
            }
        }

        Transaction txn;
        ByteView view{wire};
        if (!rlp::decode(view, txn)) {
            CHECK(views_empty(txn));
            continue;
        }
        ++accepted;
        // Accepted: it is the canonical encoding of what it decoded to, so the views are the encoders' bytes.
        REQUIRE(encoded(txn, true) == wire);
        REQUIRE(Bytes{txn.rlp_encoded()} == encoded(txn, false));
        REQUIRE(payload(txn) == signing(txn));
    }
    CHECK(accepted > 0);
}

}  // namespace silkworm
