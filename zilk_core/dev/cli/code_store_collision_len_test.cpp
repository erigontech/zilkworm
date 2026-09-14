// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// A code-store entry carries its length twice:
//
//   * the 8-byte data-section header, which MphfMap::for_each() reads -- this is what
//     DirectState::sanitize() hashes, and (since execute-in-place) what it zeroes the
//     padding of;
//   * MphfCollisionEntry::len, which MphfMap::resolve_collision() returns as the span
//     length for any entry routed through the collision sidecar.
//
// For a slot entry both come from the data header, so they cannot disagree. For a sidecar
// entry they are independent, and nothing cross-checks them: validate_prestate_layout()'s
// per-entry check covers the address map only, and validates .offset, never .len.
//
// A prover can therefore inflate a sidecar entry's len. sanitize() then hashes and zeroes
// the honest region -- so the code hash still verifies -- while read_code() hands the EVM
// the authenticated prefix followed by unauthenticated, prover-chosen trailing bytes.
// Those bytes are executed and are observable through EXTCODESIZE / EXTCODECOPY.

#include <catch2/catch_test_macros.hpp>

#include <bit>
#include <cstring>
#include <span>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace zilkworm {
namespace {

/// Rebuild a single-key code store so its only entry is reached through the collision
/// sidecar, adding `extra` to the length the sidecar reports. `extra == 0` yields an
/// honest sidecar entry, which must still be accepted.
std::vector<uint8_t> route_via_sidecar(const std::vector<uint8_t>& in, uint64_t key,
                                       uint32_t extra) {
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

    auto* entry = reinterpret_cast<MphfCollisionEntry*>(out.data() + oh->collisions_offset);
    entry->key = key;
    entry->offset = off;
    // Poke the inflated length into the 4 bytes after `offset` as raw memory, not through a
    // struct field: those bytes are whatever the bundle's author put there, and a prover
    // authors them freely. The reader must take its length from the data-section header.
    const uint32_t lie = static_cast<uint32_t>(header_len) + extra;
    std::memcpy(out.data() + oh->collisions_offset + 12, &lie, 4);
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

TEST_CASE("a code-store sidecar entry cannot overstate its length",
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
        const auto store = route_via_sidecar(honest_store, key, /*extra=*/0);
        auto b = make_bundle(store, code_hash, static_cast<uint32_t>(code.size()));
        DirectState ds{std::span<uint8_t>{b.blob}, std::span<uint8_t>{b.nodestore}};
        REQUIRE(ds.sanitize());
        CHECK(ds.read_code(b.addr).size() == code.size());
    }

    SECTION("a length planted beside a sidecar entry must not affect what is read") {
        constexpr uint32_t kExtra = 40;  // > kCodePadding, so it reaches past the padding too
        const auto store = route_via_sidecar(honest_store, key, kExtra);
        auto b = make_bundle(store, code_hash, static_cast<uint32_t>(code.size()));
        DirectState ds{std::span<uint8_t>{b.blob}, std::span<uint8_t>{b.nodestore}};

        // The code hash verifies either way: sanitize() hashes the data-header range.
        // The invariant is that the planted value cannot widen what read_code() serves --
        // anything past the hashed range was never authenticated.
        REQUIRE(ds.sanitize());
        CHECK(ds.read_code(b.addr).size() == code.size());
    }
}

}  // namespace zilkworm
