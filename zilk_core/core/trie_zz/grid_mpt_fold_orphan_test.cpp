// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Regression test: calc_root_from_updates fold bug on an orig-ext split (EEST test_storage_access_cold).

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>

namespace {

using namespace zilkworm;
using silkworm::ByteView;

uint8_t hex_nib(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + c - 'a');
    return 0;
}

bytes32 parse_key(const char* s) {
    bytes32 k{};
    for (size_t i = 0; i < 32; ++i) {
        k.bytes[i] = static_cast<uint8_t>((hex_nib(s[2 * i]) << 4) | hex_nib(s[2 * i + 1]));
    }
    return k;
}

bytes32 hashbuilder_root(std::span<const TrieNodeFlat> updates) {
    silkworm::trie::HashBuilder hb;
    for (const auto& u : updates) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{u.key.bytes, 32}), u.current_value());
    }
    return hb.root_hash();
}

}  // namespace

TEST_CASE("GridMPT: ext-split fold bug", "[trie][gridmpt]") {
    static constexpr const char* kKeys[] = {
        "00028929fd935f4a47c4f35372f1494b33b122c97368e23a6482db0b16149db2",
        "00089936d6f8866fdbcb373720029ed6c076263e72bb11506447776f2764afdb",
        "00cf6dd9ca492b2524e0ea638be9c262d4fdea6df0bce8e2c86cddbc7590d0a1",
        "011b3a3ec45f0dcd0248ba42f0d525306055eb077bac40e6bed2ff7261c13834",
    };
    constexpr size_t N = sizeof(kKeys) / sizeof(*kKeys);

    std::vector<TrieNodeFlat> updates(N);
    for (size_t i = 0; i < N; ++i) {
        updates[i].key = parse_key(kKeys[i]);
        updates[i].self_initial_len = 0;
        updates[i].current_off = 0;
        updates[i].current_len = 33;
        updates[i].buf[0] = 0xa0;
        std::memset(updates[i].buf + 1, 0xff, 32);
    }

    auto empty_state_blob = DirectState::build_blob_from_accounts({}, {}, {});
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    auto empty_nodes = std::move(nb).finalize();
    DirectState ds{std::span<uint8_t>{empty_state_blob}, std::span<uint8_t>{empty_nodes}};

    const bytes32 expected = hashbuilder_root({updates.data(), updates.size()});
    GridMPT<true, DirectState> grid{ds, silkworm::kEmptyRoot};
    const bytes32 got = grid.calc_root_from_updates({updates.data(), updates.size()});

    CHECK_FALSE(grid.failed());
    CHECK(got == expected);
}
