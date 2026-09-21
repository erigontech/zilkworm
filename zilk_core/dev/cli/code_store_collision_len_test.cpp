// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// A code-store entry's only length is its data-section header; a sidecar entry has none.

#include <catch2/catch_test_macros.hpp>

#include <bit>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace zilkworm {
namespace {

/// Rebuild a single-key code store so its only entry is reached through the collision
/// sidecar; `plant` writes header_len + *plant into entry bytes 12..16, the offset high half.
std::vector<uint8_t> route_via_sidecar(const std::vector<uint8_t>& in, uint64_t key,
                                       std::optional<uint32_t> plant) {
    const auto* h = reinterpret_cast<const MphfMapHeader*>(in.data());
    constexpr uint32_t kEntry = sizeof(MphfCollisionEntry);
    REQUIRE(h->collisions_size == 0);  // the builder placed it in a slot

    std::vector<uint8_t> out(in.size() + kEntry, 0);
    std::memcpy(out.data(), in.data(), h->data_offset);  // header + displacement + slots
    auto* oh = reinterpret_cast<MphfMapHeader*>(out.data());
    oh->collisions_offset = h->data_offset;  // sidecar sits just before the data section
    oh->collisions_size = kEntry;
    oh->data_offset = h->data_offset + kEntry;
    std::memcpy(out.data() + oh->data_offset, in.data() + h->data_offset, h->data_size);

    auto* slots = reinterpret_cast<uint32_t*>(out.data() + oh->slot_offsets_offset);
    uint32_t off = 0;
    for (uint32_t i = 0; i < oh->n_keys; ++i) {
        if (slots[i] != 0) {
            off = slots[i];
            slots[i] = 0;  // 0 == "resolve through the sidecar"
            break;
        }
    }
    REQUIRE(off != 0);

    uint64_t header_len = 0;
    std::memcpy(&header_len, out.data() + oh->data_offset + off, 8);

    const MphfCollisionEntry entry{key, off};
    std::memcpy(out.data() + oh->collisions_offset, &entry, kEntry);
    if (plant) {
        const uint32_t lie = static_cast<uint32_t>(header_len) + *plant;
        std::memcpy(out.data() + oh->collisions_offset + 12, &lie, 4);
    }
    return out;
}

struct Bundle {
    std::vector<uint8_t> blob;
    std::vector<uint8_t> nodestore;
    evmc::address addr{};
};

Bundle make_bundle(const std::vector<uint8_t>& code_store, const bytes32& code_hash,
                   uint32_t code_len) {
    Bundle b{};
    b.addr.bytes[19] = 0x11;
    std::vector<DirectState::AccountInfo> accounts{
        test_util::make_contract(b.addr, 1, intx::uint256{0}, code_hash, code_len)};
    b.blob = DirectState::build_blob_from_accounts(accounts, {}, code_store);
    return b;
}

}  // namespace

TEST_CASE("a length planted in a code-store sidecar entry's offset high half is rejected",
          "[state_zz][direct_state][soundness]") {
    Bytes code;
    for (int i = 0; i < 6; ++i)
        code.push_back(static_cast<uint8_t>(0x60 + i));
    const auto code_hash =
        std::bit_cast<bytes32>(silkworm::keccak256(ByteView{code.data(), code.size()}));
    const auto honest_store = test_util::build_code_store({{code_hash, code}});
    const uint64_t key = hash_key8(code_hash);

    SECTION("slot-routed entry (the ordinary case) is accepted and reads back exactly") {
        auto b = make_bundle(honest_store, code_hash, static_cast<uint32_t>(code.size()));
        DirectState ds{std::span<uint8_t>{b.blob}, std::span<uint8_t>{b.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(ds.read_code(b.addr).size() == code.size());
    }

    SECTION("honest sidecar entry is still accepted") {
        const auto store = route_via_sidecar(honest_store, key, std::nullopt);
        REQUIRE(validate_mphf<32>(std::span<const uint8_t>{store}, 0,
                                  static_cast<uint32_t>(store.size()), kMphfCodeStoreMagic));
        auto b = make_bundle(store, code_hash, static_cast<uint32_t>(code.size()));
        DirectState ds{std::span<uint8_t>{b.blob}, std::span<uint8_t>{b.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(ds.read_code(b.addr).size() == code.size());
    }

    // 0 plants the honest length: a reader still using bytes 12..16 as a length accepts it.
    // validate_mphf<32> is the check DirectState runs on the code store at construction.
    for (const uint32_t extra : {0u, 40u}) {
        DYNAMIC_SECTION("a value planted in the offset high half is rejected (extra=" << extra << ")") {
            const auto store = route_via_sidecar(honest_store, key, extra);
            CHECK_FALSE(validate_mphf<32>(std::span<const uint8_t>{store}, 0,
                                          static_cast<uint32_t>(store.size()), kMphfCodeStoreMagic));
        }
    }
}

}  // namespace zilkworm
