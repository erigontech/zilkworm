// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// rlp::encode(Bytes&, const Receipt&) writes a receipt in one pass. These tests compare it with the
// composition of the generic encoders it replaced (encode_header, then encode of the status, the gas, the
// bloom and the logs) for every receipt type, status, gas width and log shape, and for RLP headers of 1 to
// 5 bytes, on both sides of each size boundary up to payloads of 2^24 bytes. The receipts compared through
// check() are also appended after 1 to 7 bytes already in the buffer, so that the bloom, the addresses and
// the topics are written at every destination alignment; the 16 MiB ones are appended after one byte, and
// the known answers are written into an empty buffer.

#include "receipt.hpp"

#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>

namespace silkworm {

namespace {

    using namespace evmc::literals;

    constexpr TransactionType kTypes[]{TransactionType::kLegacy, TransactionType::kAccessList,
                                       TransactionType::kDynamicFee, TransactionType::kBlob,
                                       TransactionType::kSetCode, TransactionType::kSystem};

    // Gas of every compact width: 0, a single byte below 0x80, and 1 to 8 big-endian bytes at both ends.
    // Past 4 bytes the ends' low 32-bit half is 0 or 0xffffffff, the same in either byte order, so the
    // last two have bytes that all differ.
    constexpr uint64_t kGas[]{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 21'000, (uint64_t{1} << 24) - 1,
                              uint64_t{1} << 24, (uint64_t{1} << 32) - 1, uint64_t{1} << 32, (uint64_t{1} << 40) - 1,
                              uint64_t{1} << 40, (uint64_t{1} << 48) - 1, uint64_t{1} << 48, (uint64_t{1} << 56) - 1,
                              uint64_t{1} << 56, ~uint64_t{0}, 0x0102030405, 0x0102030405060708};

    // The receipt as the generic encoders write it.
    Bytes generic_encoding(const Receipt& r) {
        Bytes out;
        if (r.type != TransactionType::kLegacy) {
            out.push_back(static_cast<uint8_t>(r.type));
        }
        const rlp::Header h{.list = true,
                            .payload_length = rlp::length(r.success) + rlp::length(r.cumulative_gas_used) +
                                              rlp::length(ByteView{r.bloom}) + rlp::length(r.logs)};
        rlp::encode_header(out, h);
        rlp::encode(out, r.success);
        rlp::encode(out, r.cumulative_gas_used);
        rlp::encode(out, ByteView{r.bloom});
        rlp::encode(out, r.logs);
        return out;
    }

    // rlp::encode(Receipt) appends exactly the generic encoding: to an empty buffer, after 1 to 7 bytes,
    // and into a cleared buffer whose capacity is already larger than the receipt. The double parentheses
    // keep Catch2 from printing the buffers, which can be megabytes long.
    void check(const Receipt& r) {
        const Bytes want{generic_encoding(r)};
        for (size_t prefix{0}; prefix < 8; ++prefix) {
            CAPTURE(prefix);
            Bytes out(prefix, 0xab);
            rlp::encode(out, r);
            CHECK((out == Bytes(prefix, 0xab) + want));
        }
        Bytes reused(want.size() + 100, 0xcd);
        reused.clear();
        rlp::encode(reused, r);
        CHECK((reused == want));
    }

    Log make_log(size_t topics, size_t data, uint8_t seed) {
        Log l;
        for (size_t i{0}; i < kAddressLength; ++i) {
            l.address.bytes[i] = static_cast<uint8_t>(seed + 3 * i);
        }
        l.topics.resize(topics);
        for (size_t t{0}; t < topics; ++t) {
            for (size_t i{0}; i < kHashLength; ++i) {
                l.topics[t].bytes[i] = static_cast<uint8_t>(seed + 5 * t + 7 * i + 1);
            }
        }
        l.data.resize(data);
        for (size_t i{0}; i < data; ++i) {
            l.data[i] = static_cast<uint8_t>(seed + 11 * i + 2);
        }
        return l;
    }

    Receipt make_receipt(TransactionType type, bool success, uint64_t gas, std::vector<Log> logs) {
        Receipt r{.type = type, .success = success, .cumulative_gas_used = gas, .bloom = {}, .logs = std::move(logs)};
        for (size_t i{0}; i < kBloomByteLength; ++i) {
            r.bloom[i] = static_cast<uint8_t>(i * 13 + 1);
        }
        return r;
    }

}  // namespace

TEST_CASE("receipt encoding: known answers") {
    // An EIP-1559 receipt of a plain transfer: status 1, 21,000 gas, an empty bloom and no logs.
    Receipt transfer{.type = TransactionType::kDynamicFee, .success = true, .cumulative_gas_used = 21'000};
    Bytes want{*from_hex("02f9010801825208b90100")};
    want += Bytes(kBloomByteLength, 0);
    want += *from_hex("c0");
    Bytes out;
    rlp::encode(out, transfer);
    CHECK(to_hex(out) == to_hex(want));

    // A failed legacy receipt with no gas and one log (the log is silkworm's Log RLP test vector).
    Receipt failed{.type = TransactionType::kLegacy, .success = false, .cumulative_gas_used = 0};
    failed.logs.push_back(Log{
        .address = 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address,
        .topics = {},
        .data = *from_hex("010043"),
    });
    want = *from_hex("f90121" "80" "80" "b90100");
    want += Bytes(kBloomByteLength, 0);
    want += *from_hex("db" "da94ea674fdde714fd979de3edf0f56aa9716b898ec8c083010043");
    out.clear();
    rlp::encode(out, failed);
    CHECK(to_hex(out) == to_hex(want));
}

TEST_CASE("receipt encoding: every type, status and gas width") {
    for (const TransactionType type : kTypes) {
        for (const bool success : {false, true}) {
            for (const uint64_t gas : kGas) {
                CAPTURE(type, success, gas);
                check(make_receipt(type, success, gas, {}));
                check(make_receipt(type, success, gas, {make_log(2, 32, 9)}));
            }
        }
    }
}

TEST_CASE("receipt encoding: log shapes") {
    const size_t data_sizes[]{0, 2, 31, 32, 33, 54, 55, 56, 57, 63, 64, 65, 255, 256, 257, 1000, 65535, 65536, 70000};
    for (size_t topics{0}; topics <= 4; ++topics) {
        for (const size_t data : data_sizes) {
            CAPTURE(topics, data);
            check(make_receipt(TransactionType::kBlob, true, 0x1234, {make_log(topics, data, 1)}));
        }
        // A single data byte below 0x80 is its own encoding; from 0x80 on it takes a header.
        for (const unsigned byte : {0x00u, 0x01u, 0x7fu, 0x80u, 0x81u, 0xffu}) {
            CAPTURE(topics, byte);
            Log l{make_log(topics, 1, 2)};
            l.data[0] = static_cast<uint8_t>(byte);
            check(make_receipt(TransactionType::kLegacy, false, 0x80, {l}));
        }
    }
    // Topic lists past what a LOG opcode writes, across the 1-, 2- and 3-byte length forms.
    for (const size_t topics : {7u, 8u, 1985u, 1986u}) {
        CAPTURE(topics);
        check(make_receipt(TransactionType::kSetCode, true, 1, {make_log(topics, 3, 4)}));
    }
    for (size_t logs{0}; logs <= 80; ++logs) {
        CAPTURE(logs);
        std::vector<Log> v;
        for (size_t i{0}; i < logs; ++i) {
            v.push_back(make_log(i % 5, (i * 37) % 300, static_cast<uint8_t>(i)));
        }
        check(make_receipt(TransactionType::kDynamicFee, logs % 2 == 0, 30'000'000 + logs, std::move(v)));
    }
}

TEST_CASE("receipt encoding: headers at their size boundaries") {
    // One log without topics and n data bytes: the data string, the log list and the logs list cross 56
    // and 256 bytes for some n up to 320 (the receipt list is longer than 256 bytes), and all four cross
    // 65536 bytes in the second range.
    for (size_t n{0}; n <= 320; ++n) {
        CAPTURE(n);
        check(make_receipt(TransactionType::kAccessList, true, 0x7f, {make_log(0, n, 5)}));
    }
    for (size_t n{65536 - 300}; n <= 65536 + 2; ++n) {
        CAPTURE(n);
        check(make_receipt(TransactionType::kLegacy, true, 0x7f, {make_log(0, n, 6)}));
    }
    // Payloads of 2^24 bytes take a 5-byte header. Below 2^24 the data header is 4 bytes, so the log
    // list's payload is 26 + n, the logs list's 30 + n and the receipt list's 295 + n (gas below 0x80):
    // each of them and the data string itself is 2^24 - 1 at the first n and 2^24 at the second.
    constexpr size_t k24{size_t{1} << 24};
    for (const size_t n : {k24 - 296, k24 - 295, k24 - 31, k24 - 30, k24 - 27, k24 - 26, k24 - 1, k24}) {
        CAPTURE(n);
        const Receipt r{make_receipt(TransactionType::kDynamicFee, false, 0x7f, {make_log(0, n, 7)})};
        const Bytes want{generic_encoding(r)};
        CHECK(want[1] == (n < k24 - 295 ? 0xfa : 0xfb));
        Bytes out(1, 0xab);
        rlp::encode(out, r);
        CHECK((out == Bytes(1, 0xab) + want));
    }
}

TEST_CASE("receipt encoding: random receipts") {
    std::mt19937_64 rng{20261007};
    const auto below = [&rng](uint64_t n) { return rng() % n; };
    const size_t data_sizes[]{0, 1, 1, 2, 31, 32, 32, 32, 33, 55, 56, 64, 96, 128, 160, 255, 256, 1000, 4096};
    for (int i{0}; i < 3000; ++i) {
        CAPTURE(i);
        Receipt r;
        r.type = kTypes[below(std::size(kTypes))];
        r.success = below(2) == 0;
        r.cumulative_gas_used = below(3) != 0 ? kGas[below(std::size(kGas))] : rng() >> below(64);
        if (below(2) == 0) {
            for (uint8_t& b : r.bloom) {
                b = static_cast<uint8_t>(rng());
            }
        }
        const size_t logs{below(4) == 0 ? below(81) : below(5)};
        for (size_t j{0}; j < logs; ++j) {
            const size_t topics{below(5)};
            const size_t data{data_sizes[below(std::size(data_sizes))]};
            Log l{make_log(topics, data, static_cast<uint8_t>(rng()))};
            if (l.data.size() == 1) {
                l.data[0] = static_cast<uint8_t>(below(2) == 0 ? below(0x80) : 0x80 + below(0x80));
            }
            r.logs.push_back(std::move(l));
        }
        check(r);
    }
}

}  // namespace silkworm
