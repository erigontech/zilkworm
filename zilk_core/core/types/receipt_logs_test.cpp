// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// ExecutionProcessor reads the logs where the receipts keep them: logs_bloom() writes into the
// receipt's bloom, the block bloom joins only receipts with logs, and EIP-6110 deposits are
// extracted receipt by receipt instead of from a block-wide copy of all logs. These tests check
// that each gives what the code it replaced gave: logs_bloom() into a dirty bloom (the receipts
// vector is reused across blocks) equals a fresh bloom and the known answer, and per-receipt
// deposit extraction equals extraction from the concatenated logs, failures included.

#include <cstdint>
#include <random>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/types/bloom.hpp>
#include <zilk_core/core/types/eip_7685_requests.hpp>
#include <zilk_core/core/types/receipt.hpp>

namespace silkworm {

namespace {

    using namespace evmc::literals;

    constexpr auto kDepositEvent = 0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5_bytes32;

    // The two logs of the bloom known answer (silkworm's "Hardcoded Bloom" test).
    std::vector<Log> known_logs() {
        return {
            {0x22341ae42d6dd7384bc8584e50419ea3ac75b83f_address,
             {0x04491edcd115127caedbd478e2e7895ed80c7847e903431f94f9cfa579cad47f_bytes32},
             {}},
            {0xe7fb22dfef11920312e4989a3a2b81e2ebf05986_address,
             {0x7f1fef85c4b037150d3675218e0cdb7cf38fea354759471e309f3354918a442f_bytes32,
              0xd85629c7eaae9ea4a10234fed31bc0aeda29b2683ebe0c1882499d272621f6b6_bytes32},
             *from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b")},
        };
    }

    // The 576-byte DepositEvent data of EIP-6110: five offsets, then each field's length and its
    // bytes padded to words. Field bytes are drawn from rng; `bad_word` >= 0 corrupts that word.
    Bytes deposit_data(std::mt19937& rng, int bad_word = -1) {
        Bytes data(576, 0);
        const auto put_word = [&](size_t pos, uint32_t v) {
            for (size_t i = 0; i < 4; ++i) data[pos + 31 - i] = static_cast<uint8_t>(v >> (8 * i));
        };
        constexpr uint32_t kOffsets[]{160, 256, 320, 384, 512};
        constexpr uint32_t kSizes[]{48, 32, 8, 96, 8};
        for (size_t i = 0; i < 5; ++i) {
            put_word(32 * i, kOffsets[i]);
            put_word(kOffsets[i], kSizes[i]);
            for (size_t j = 0; j < kSizes[i]; ++j) data[kOffsets[i] + 32 + j] = static_cast<uint8_t>(rng());
        }
        if (bad_word >= 0) data[32 * static_cast<size_t>(bad_word) + 31] ^= 1;
        return data;
    }

    // A log of one of the kinds the deposit scan tells apart: a deposit, a malformed deposit, the
    // deposit event from another contract, another event from the deposit contract, and no topics.
    Log make_log(std::mt19937& rng, unsigned kind) {
        Log log{protocol::kDepositContractAddress, {kDepositEvent}, {}};
        switch (kind) {
            case 0:
                log.data = deposit_data(rng);
                break;
            case 1: {
                // One of the five offset words or the five length words.
                constexpr int kLayoutWords[]{0, 1, 2, 3, 4, 5, 8, 10, 12, 16};
                log.data = deposit_data(rng, kLayoutWords[rng() % std::size(kLayoutWords)]);
                break;
            }
            case 2:
                log.address = 0x00000000219ab540356cbb839cbe05303d7705fb_address;
                log.data = deposit_data(rng);
                break;
            case 3:
                log.topics[0].bytes[31] ^= 1;
                log.data = deposit_data(rng);
                break;
            default:
                log.topics.clear();
                log.data = deposit_data(rng);
                break;
        }
        return log;
    }

    struct Extracted {
        bool ok;
        Bytes deposits;
        Hash requests_hash;
    };

    Extracted extract_from_copy(const std::vector<Receipt>& receipts) {
        std::vector<Log> logs;
        for (const auto& receipt : receipts) std::ranges::copy(receipt.logs, std::back_inserter(logs));
        FlatRequests requests;
        const bool ok = requests.extract_deposits_from_logs(logs);
        return {ok, Bytes{requests.preview_data_by_type(FlatRequestType::kDepositRequest)}, requests.calculate_sha256()};
    }

    // As ExecutionProcessor::execute_block does it.
    Extracted extract_per_receipt(const std::vector<Receipt>& receipts) {
        FlatRequests requests;
        bool ok = true;
        for (const Receipt& receipt : receipts) {
            if (!requests.extract_deposits_from_logs(receipt.logs)) {
                ok = false;
                break;
            }
        }
        return {ok, Bytes{requests.preview_data_by_type(FlatRequestType::kDepositRequest)}, requests.calculate_sha256()};
    }

}  // namespace

TEST_CASE("logs_bloom in place: known answer, dirty destination, no logs") {
    const auto logs = known_logs();
    const std::string expected =
        "000000000000000000810000000000000000000000000000000000020000000000000000000000000000008000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000280000000000400000800000004000000000"
        "000000000000000000000000000000000000000000000000000000000000100000100000000000000000000000"
        "00000000001400000000000000008000000000000000000000000000000000";
    CHECK(to_hex(logs_bloom(logs)) == expected);

    // A receipt reused from an earlier block keeps its old bloom until logs_bloom overwrites it.
    Bloom bloom;
    bloom.fill(0xa5);
    logs_bloom(bloom, logs);
    CHECK(to_hex(bloom) == expected);

    bloom.fill(0xff);
    logs_bloom(bloom, {});
    CHECK(bloom == Bloom{});
}

TEST_CASE("Block bloom: joining only receipts with logs gives the full join") {
    std::mt19937 rng{7};
    std::vector<Receipt> receipts(64);
    for (auto& receipt : receipts) {
        receipt.bloom.fill(0x5a);  // dirty, as in a reused receipts vector
        const unsigned n = rng() % 3 == 0 ? 0 : rng() % 4;
        for (unsigned i = 0; i < n; ++i) {
            Log log{};
            for (auto& b : log.address.bytes) b = static_cast<uint8_t>(rng());
            log.topics.resize(rng() % 5);
            for (auto& topic : log.topics) {
                for (auto& b : topic.bytes) b = static_cast<uint8_t>(rng());
            }
            receipt.logs.push_back(std::move(log));
        }
        logs_bloom(receipt.bloom, receipt.logs);
    }
    Bloom all{};
    Bloom with_logs{};
    for (const auto& receipt : receipts) {
        join(all, receipt.bloom);
        if (!receipt.logs.empty()) join(with_logs, receipt.bloom);
    }
    CHECK(with_logs == all);
    CHECK(all != Bloom{});
}

TEST_CASE("EIP-6110 deposits per receipt equal deposits from all logs") {
    std::mt19937 rng{6110};
    size_t failures = 0;
    size_t with_deposits = 0;
    for (unsigned round = 0; round < 400; ++round) {
        std::vector<Receipt> receipts(rng() % 6);
        // Mostly well-formed deposits; a malformed one in about one block of eight.
        for (auto& receipt : receipts) {
            const unsigned n = rng() % 4;
            for (unsigned i = 0; i < n; ++i) {
                const unsigned kind = rng() % 32 == 0 ? 1 : (rng() % 2 == 0 ? 0 : 2 + rng() % 3);
                receipt.logs.push_back(make_log(rng, kind));
            }
        }
        const auto expected = extract_from_copy(receipts);
        const auto actual = extract_per_receipt(receipts);
        REQUIRE(actual.ok == expected.ok);
        if (expected.ok) {
            REQUIRE(actual.deposits == expected.deposits);
            REQUIRE(actual.requests_hash == expected.requests_hash);
            with_deposits += !expected.deposits.empty();
        }
        failures += !expected.ok;
    }
    CHECK(failures > 0);
    CHECK(with_deposits > 100);
}

}  // namespace silkworm
