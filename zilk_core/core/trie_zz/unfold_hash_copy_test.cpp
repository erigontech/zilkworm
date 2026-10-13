// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The copy of a witness child hash that unfold_slot makes before it looks the child up. On the guest
// the 32 bytes at any alignment go to a word-aligned buffer through copy32_to_aligned (a word funnel
// over aligned-down loads); the native build sets -DEVMONE_RV32_DISPATCH_TEST, which compiles that
// helper and its call in unfold_slot on the host.
//
// The helper is checked against memcpy, which it replaces, on every source phase, on crafted and
// random bytes, with canaries around the destination and the source unmodified, and with the source
// placed against an unreadable page on each side to show it reads no word that holds none of the 32
// bytes. unfold_slot is checked on branch nodes placed in memory at every phase: the exact child hash
// must unfold, and a hash that differs in any one byte must not, whatever the witness holds.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <random>
#include <span>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/fold_unfold.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

#if defined(EVMONE_RV32_DISPATCH_TEST) || (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32)

namespace {

// The destination as unfold_slot has it (8-aligned raw storage), between canaries.
struct Dest {
    unsigned char before[24];
    alignas(8) unsigned char bytes[32];
    unsigned char after[24];
    Dest() {
        std::memset(before, 0xC3, sizeof before);
        std::memset(bytes, 0x00, sizeof bytes);
        std::memset(after, 0x3C, sizeof after);
    }
    bool canaries_intact() const {
        for (auto b : before)
            if (b != 0xC3) return false;
        for (auto b : after)
            if (b != 0x3C) return false;
        return true;
    }
};
static_assert(offsetof(Dest, bytes) % 8 == 0);

// Copies 32 bytes at `src` with the helper and checks them against memcpy, the canaries and the source.
void check_copy(const uint8_t* src, const char* what) {
    std::array<uint8_t, 32> kept;
    std::memcpy(kept.data(), src, 32);
    Dest d;
    // Poison the destination so a copy that skips a word cannot pass by luck.
    std::memset(d.bytes, 0x99, sizeof d.bytes);
    copy32_to_aligned(d.bytes, src);
    INFO(what << ", source phase " << (reinterpret_cast<uintptr_t>(src) & 7));
    CHECK(std::memcmp(d.bytes, kept.data(), 32) == 0);
    CHECK(std::memcmp(src, kept.data(), 32) == 0);
    CHECK(d.canaries_intact());
}

}  // namespace

TEST_CASE("copy32_to_aligned equals memcpy on crafted bytes at every source phase", "[trie][gridmpt][unfold][copy32]") {
    // The window is surrounded by bytes that differ from every window byte, so a copy that shifts by
    // one byte, or takes a neighbour's, differs.
    for (size_t phase = 0; phase < 16; ++phase) {
        for (int pattern = 0; pattern < 8; ++pattern) {
            alignas(16) uint8_t buf[96];
            std::memset(buf, 0xA5, sizeof buf);
            uint8_t* const src = buf + 16 + phase;
            for (size_t i = 0; i < 32; ++i) {
                switch (pattern) {
                    case 0: src[i] = 0; break;
                    case 1: src[i] = 0xFF; break;
                    case 2: src[i] = static_cast<uint8_t>(i + 1); break;
                    case 3: src[i] = static_cast<uint8_t>(0x80 | i); break;
                    case 4: src[i] = i == 0 ? 0xFF : 0; break;  // only the first byte
                    case 5: src[i] = i == 31 ? 0xFF : 0; break;  // only the last byte
                    case 6: src[i] = (i & 1) ? 0x55 : 0xAA; break;
                    default: src[i] = static_cast<uint8_t>(i * 37 + 11); break;
                }
            }
            check_copy(src, "crafted");
        }
    }
}

TEST_CASE("copy32_to_aligned equals memcpy on random bytes", "[trie][gridmpt][unfold][copy32]") {
    std::mt19937_64 rng(0x32);
    for (int i = 0; i < 20000; ++i) {
        alignas(16) uint8_t buf[96];
        for (auto& b : buf) b = static_cast<uint8_t>(rng());
        check_copy(buf + (rng() % 56), "random");
    }
}

TEST_CASE("copy32_to_aligned single-byte sources each reach the right destination byte", "[trie][gridmpt][unfold][copy32]") {
    // One non-zero source byte at a time: it must land at the same index, at every phase.
    for (size_t phase = 0; phase < 4; ++phase) {
        for (size_t j = 0; j < 32; ++j) {
            alignas(16) uint8_t buf[80] = {};
            uint8_t* const src = buf + 16 + phase;
            src[j] = static_cast<uint8_t>(0x40 + j);
            Dest d;
            copy32_to_aligned(d.bytes, src);
            for (size_t i = 0; i < 32; ++i) CHECK(d.bytes[i] == (i == j ? 0x40 + j : 0));
            CHECK(d.canaries_intact());
        }
    }
}

TEST_CASE("copy32_to_aligned reads no word that holds none of the 32 bytes", "[trie][gridmpt][unfold][copy32]") {
    // The 32 bytes sit against an unreadable page, before and after, at each phase: a read of one
    // word too many on either side faults (the guest memory has no such guard, so this is the
    // stand-in for "no access beyond the bytes' own words").
    const long page = sysconf(_SC_PAGESIZE);
    REQUIRE(page >= 4096);
    uint8_t* const base = static_cast<uint8_t*>(mmap(nullptr, 3 * static_cast<size_t>(page), PROT_READ | PROT_WRITE,
                                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    REQUIRE(base != MAP_FAILED);
    REQUIRE(mprotect(base, static_cast<size_t>(page), PROT_NONE) == 0);
    REQUIRE(mprotect(base + 2 * page, static_cast<size_t>(page), PROT_NONE) == 0);
    uint8_t* const mid = base + page;
    std::mt19937_64 rng(0x33);
    for (auto* p = mid; p != mid + page; ++p) *p = static_cast<uint8_t>(rng());
    for (size_t j = 0; j < 8; ++j) {
        check_copy(mid + j, "page start");
        check_copy(mid + page - 32 - j, "page end");
    }
    munmap(base, 3 * static_cast<size_t>(page));
}

namespace {

struct Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept { return std::memcmp(a.bytes, b.bytes, 32) < 0; }
};
using Map = std::map<bytes32, Bytes, Less>;

std::vector<uint8_t> build_node_store(const Map& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : nodes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, rlp);
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

struct Witness {
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, {}, {});
    std::vector<uint8_t> store;
    DirectState state;
    explicit Witness(const Map& nodes)
        : store{build_node_store(nodes)}, state{std::span<uint8_t>{prestate}, std::span<uint8_t>{store}} {}
};

// A trie whose root is a full branch with 16 hashed children (a leaf per first nibble), every node
// captured as a complete witness.
struct Fixture {
    Map nodes;
    bytes32 root{};
    Bytes root_rlp;
    std::array<bytes32, 16> child{};  // hash of the child in each slot, read off the root's encoding

    Fixture() {
        std::mt19937_64 rng(0x34);
        Map leaves;
        for (unsigned nib = 0; nib < 16; ++nib) {
            bytes32 k;
            for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
            k.bytes[0] = static_cast<uint8_t>((nib << 4) | (k.bytes[0] & 0x0F));
            Bytes v(8 + rng() % 24, 0);
            for (auto& x : v) x = static_cast<uint8_t>(rng() | 1);
            leaves.emplace(k, v);
        }
        silkworm::trie::HashBuilder hb;
        hb.rlp_collector = [this](ByteView n) { nodes.emplace(keccak_bytes(n), Bytes{n}); };
        for (const auto& [k, v] : leaves) hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
        root = hb.root_hash();
        root_rlp = nodes.at(root);
        // list header (3 bytes: 0xf9 + 2 length bytes), then 16 x (0xa0 + 32) and an empty value (0x80)
        REQUIRE(root_rlp.size() == 3 + 16 * 33 + 1);
        for (unsigned i = 0; i < 16; ++i) {
            REQUIRE(root_rlp[3 + 33 * i] == 0xa0);
            std::memcpy(child[i].bytes, root_rlp.data() + 3 + 33 * i + 1, 32);
            REQUIRE(nodes.count(child[i]) == 1);
        }
    }
};

// Unfolds the branch `rlp`, placed in memory `offset` bytes past a 64-byte boundary (so that its child
// hashes, which start 4 + 33 * slot bytes in, take every phase), as the root of a trie over `witness`,
// then unfolds `slot`.
UnfoldResult unfold_slot_of(const Witness& witness, const Bytes& rlp, size_t offset, unsigned slot,
                            unsigned* missing = nullptr) {
    alignas(64) uint8_t buf[640] = {};
    std::memcpy(buf + offset, rlp.data(), rlp.size());
    GridMPT<false> trie{witness.state, silkworm::kEmptyRoot};
    REQUIRE(trie.unfold_node_from_rlp(ByteView{buf + offset, rlp.size()}, /*parent_slot=*/0, /*parent_depth=*/0));
    const UnfoldResult r = trie.unfold_slot(slot);
    if (missing) *missing = trie.missing_count();
    return r;
}

}  // namespace

TEST_CASE("unfold_slot unfolds a hashed child whose hash sits at any alignment", "[trie][gridmpt][unfold][copy32]") {
    const Fixture f;
    for (size_t offset = 0; offset < 8; ++offset) {
        for (unsigned slot = 0; slot < 16; ++slot) {
            Witness w{f.nodes};  // nothing verified yet: the hash is the only thing that selects the node
            unsigned missing = 99;
            CHECK(unfold_slot_of(w, f.root_rlp, offset, slot, &missing) == UnfoldResult::kSuccess);
            CHECK(missing == 0);
            // Unfolded again on a witness whose node is already verified (a different lookup path).
            CHECK(unfold_slot_of(w, f.root_rlp, offset, slot, &missing) == UnfoldResult::kSuccess);
            CHECK(missing == 0);
        }
    }
}

TEST_CASE("unfold_slot rejects a child hash that differs in any one byte", "[trie][gridmpt][unfold][copy32][forged]") {
    // A forged parent: its child hash has one byte flipped, while the witness holds the real child
    // (under its real hash). Any copy that took the wrong bytes would find a node by accident only if
    // it reproduced a stored hash, so the flip is the discriminator at every byte and phase.
    const Fixture f;
    for (size_t offset = 0; offset < 4; ++offset) {
        for (unsigned slot : {0u, 1u, 5u, 8u, 15u}) {
            for (size_t byte = 0; byte < 32; ++byte) {
                for (uint8_t flip : {uint8_t{0x01}, uint8_t{0x80}, uint8_t{0xFF}}) {
                    Bytes forged = f.root_rlp;
                    forged[3 + 33 * slot + 1 + byte] ^= flip;
                    Witness w{f.nodes};
                    unsigned missing = 0;
                    CHECK(unfold_slot_of(w, forged, offset, slot, &missing) == UnfoldResult::kMissing);
                    CHECK(missing == 1);
                }
            }
        }
    }
}

TEST_CASE("unfold_slot rejects a stored node filed under a forged hash", "[trie][gridmpt][unfold][copy32][forged]") {
    // The witness holds a different node's bytes under the (forged) hash the parent names: the node is
    // found by its key and must fail its keccak check, at every phase.
    const Fixture f;
    for (size_t offset = 0; offset < 4; ++offset) {
        for (unsigned slot : {0u, 7u, 15u}) {
            Bytes forged = f.root_rlp;
            bytes32 fake = f.child[slot];
            fake.bytes[31] ^= 0x5A;
            std::memcpy(forged.data() + 3 + 33 * slot + 1, fake.bytes, 32);
            Map nodes = f.nodes;
            nodes.emplace(fake, nodes.at(f.child[(slot + 1) % 16]));  // another real node's bytes
            Witness w{nodes};
            unsigned missing = 0;
            CHECK(unfold_slot_of(w, forged, offset, slot, &missing) == UnfoldResult::kMissing);
            CHECK(missing == 1);
        }
    }
}

TEST_CASE("unfold_slot does not take the hash of a neighbouring slot", "[trie][gridmpt][unfold][copy32][forged]") {
    // Two hashed children are 33 bytes apart: a copy that starts a byte early or late mixes the
    // hashes of slot k and k+-1. With the witness holding only slot k's node, every other slot is
    // missing and only slot k unfolds.
    const Fixture f;
    for (size_t offset = 0; offset < 4; ++offset) {
        for (unsigned k = 0; k < 16; ++k) {
            Map only;
            only.emplace(f.child[k], f.nodes.at(f.child[k]));
            Witness w{only};
            for (unsigned slot = 0; slot < 16; ++slot) {
                CHECK(unfold_slot_of(w, f.root_rlp, offset, slot) ==
                      (slot == k ? UnfoldResult::kSuccess : UnfoldResult::kMissing));
            }
        }
    }
}

#endif  // the helper is built
