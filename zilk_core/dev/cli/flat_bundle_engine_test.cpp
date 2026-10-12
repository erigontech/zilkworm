// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Flat-bundle parsing of the data a stateless new-payload check needs beyond the block RLP:
// the per-block engine record (claimed block hash, versioned hashes) and the witness headers,
// which must decode as exactly one header each.

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

namespace zilkworm {

namespace {

    silkworm::Bytes rlp_of(const silkworm::Block& block) {
        silkworm::Bytes out;
        silkworm::rlp::encode(out, block);
        return out;
    }

    silkworm::Bytes rlp_of(const silkworm::BlockHeader& header) {
        silkworm::Bytes out;
        silkworm::rlp::encode(out, header);
        return out;
    }

    // RLP list whose payload is `payload` verbatim.
    silkworm::Bytes rlp_list(const silkworm::Bytes& payload) {
        silkworm::Bytes out;
        silkworm::rlp::encode_header(out, {.list = true, .payload_length = payload.size()});
        out.append(payload);
        return out;
    }

    std::optional<FlatBundle> load(std::vector<uint8_t>& blob) { return load_flat_bundle(std::span<uint8_t>{blob}); }

    std::vector<uint8_t> bundle(const silkworm::Bytes& ancestors_rlp, std::span<const uint8_t> flags = {},
                                std::span<const std::optional<BlockEngineRecord>> engine = {}) {
        silkworm::Block parent;
        parent.header.number = 9;
        silkworm::Block block;
        block.header.number = 10;
        const auto parent_rlp = rlp_of(parent);
        const auto block_rlp = rlp_of(block);
        const std::array<silkworm::ByteView, 1> blocks{silkworm::ByteView{block_rlp}};
        return build_flat_bundle(parent_rlp, blocks, ancestors_rlp, DirectState::build_blob_from_accounts({}, {}, {}),
                                 {}, "Amsterdam", flags, engine);
    }

}  // namespace

TEST_CASE("engine record round-trips through the blocks section", "[flat_bundle][engine]") {
    std::array<uint8_t, 64> versioned_hashes{};
    versioned_hashes[0] = 0x01;
    versioned_hashes[32] = 0x01;
    versioned_hashes[63] = 0x7f;
    BlockEngineRecord rec{};
    rec.block_hash.bytes[0] = 0xab;
    rec.block_hash.bytes[31] = 0xcd;
    rec.versioned_hashes = versioned_hashes;
    const std::array<std::optional<BlockEngineRecord>, 1> engine{rec};
    const std::array<uint8_t, 1> flags{kBlockFlagExpectInvalid | kBlockFlagEngineRecord};

    auto blob = bundle({}, flags, engine);
    const auto fb = load(blob);
    REQUIRE(fb);
    REQUIRE(fb->engine_records.size() == 1);
    REQUIRE(fb->engine_records[0]);
    CHECK(fb->engine_records[0]->block_hash == rec.block_hash);
    REQUIRE(fb->engine_records[0]->versioned_hashes.size() == versioned_hashes.size());
    CHECK(std::equal(versioned_hashes.begin(), versioned_hashes.end(),
                     fb->engine_records[0]->versioned_hashes.begin()));
    CHECK(fb->block_flags[0] == (kBlockFlagExpectInvalid | kBlockFlagEngineRecord));
}

TEST_CASE("bundle without engine records carries none", "[flat_bundle][engine]") {
    const std::array<uint8_t, 1> flags{kBlockFlagExpectInvalid};
    auto blob = bundle({}, flags);
    const auto fb = load(blob);
    REQUIRE(fb);
    CHECK(fb->engine_records.empty());
}

TEST_CASE("witness headers decode as header lists or wrapped byte strings", "[flat_bundle][ancestors]") {
    silkworm::BlockHeader h8;
    h8.number = 8;
    silkworm::BlockHeader h9;
    h9.number = 9;
    const auto r8 = rlp_of(h8);
    const auto r9 = rlp_of(h9);

    // Rust host: RLP list of header lists.
    auto lists = bundle(rlp_list(r8 + r9));
    // C++ hosts: RLP list of byte strings wrapping each header.
    silkworm::Bytes wrapped;
    silkworm::rlp::encode(wrapped, silkworm::ByteView{r8});
    silkworm::rlp::encode(wrapped, silkworm::ByteView{r9});
    auto strings = bundle(rlp_list(wrapped));

    for (auto* blob : {&lists, &strings}) {
        const auto fb = load(*blob);
        REQUIRE(fb);
        CHECK(fb->ancestors_well_formed);
        REQUIRE(fb->ancestors.size() == 2);
        CHECK(fb->ancestors[1].number == 9);
        REQUIRE(fb->ancestor_rlps.size() == 2);
        CHECK(fb->ancestor_rlps[1] == silkworm::ByteView{r9});
    }
}

TEST_CASE("witness header followed by trailing bytes is malformed", "[flat_bundle][ancestors]") {
    silkworm::BlockHeader h9;
    h9.number = 9;
    auto padded = rlp_of(h9);
    padded.push_back(0x00);  // trailing byte after the header RLP, as in an SSZ-padded witness header

    auto blob = bundle(rlp_list(padded));
    const auto fb = load(blob);
    REQUIRE(fb);
    CHECK_FALSE(fb->ancestors_well_formed);
    CHECK(fb->ancestors.size() == 1);
}

}  // namespace zilkworm
