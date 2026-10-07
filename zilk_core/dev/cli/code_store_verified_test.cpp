// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// sanitize() skips the hashing of the code-store entries the input reader marked (CodeStoreVerified),
// and only those: an entry is skipped for a bit set at its own 8-aligned offset in the data section
// the reader hashed, once. Everything else is hashed and a mismatch still fails the witness.

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <span>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace zilkworm {
namespace {

/// The handshake is process-wide: no test leaves one behind.
struct HandshakeGuard {
    HandshakeGuard() { g_code_store_verified = {}; }
    ~HandshakeGuard() { g_code_store_verified = {}; }
};

Bytes code_of(size_t n, uint8_t seed) {
    Bytes c(n, 0);
    for (size_t i = 0; i < n; ++i) c[i] = static_cast<uint8_t>(seed + i * 7);
    return c;
}

struct Witness {
    std::vector<uint8_t> blob;
    std::vector<uint8_t> nodestore;
    uint8_t* data{nullptr};  // The code store's data section in blob.
    uint32_t data_size{0};
    std::vector<uint64_t> offsets;  // Entry offsets in it.
    std::vector<uint32_t> slot_field_offsets;  // Where in blob each slot offset is stored.

    uint64_t offset_of_payload_size(size_t n) const {
        for (const auto off : offsets) {
            uint64_t len;
            std::memcpy(&len, data + off, 8);
            if (len == 32 + n) return off;
        }
        FAIL("no entry of that size");
        return 0;
    }
};

Witness make_witness(const std::vector<Bytes>& codes) {
    std::vector<std::pair<bytes32, Bytes>> store;
    for (const auto& c : codes)
        store.emplace_back(std::bit_cast<bytes32>(silkworm::keccak256(ByteView{c.data(), c.size()})), c);
    std::vector<DirectState::AccountInfo> accounts{
        test_util::make_eoa(test_util::make_addr(0, 0x11), 1, intx::uint256{0})};
    Witness w;
    w.blob = DirectState::build_blob_from_accounts(accounts, {}, test_util::build_code_store(store));
    const auto* meta = reinterpret_cast<const PreStateMeta*>(w.blob.data());
    auto* header = reinterpret_cast<MphfMapHeader*>(w.blob.data() + meta->code_store_offset);
    w.data = reinterpret_cast<uint8_t*>(header) + header->data_offset;
    w.data_size = header->data_size;
    MphfMap map{header};
    map.for_each_offset([&](uint64_t off) { w.offsets.push_back(off); });
    const auto* slots = reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(header) +
                                                          header->slot_offsets_offset);
    for (uint32_t i = 0; i < header->n_keys; ++i)
        if (slots[i] != 0)
            w.slot_field_offsets.push_back(static_cast<uint32_t>(
                reinterpret_cast<const uint8_t*>(slots + i) - w.blob.data()));
    return w;
}

bool sanitize(Witness& w) {
    DirectState ds{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
    return ds.sanitize();
}

struct Marks {
    std::vector<uint32_t> bits;
    uint32_t n_bits;

    explicit Marks(uint32_t n) : bits((n + 31) / 32, 0u), n_bits(n) {}
    void set(uint64_t off) { bits[off >> 8] |= uint32_t{1} << ((off >> 3) & 31); }
    CodeStoreVerified handshake(const Witness& w) const {
        return {w.data, w.data_size, bits.data(), n_bits};
    }
};

constexpr uint32_t kBits = 1u << 10;

}  // namespace

TEST_CASE("sanitize hashes every entry when nothing was verified", "[state_zz][direct_state][code_store_verified]") {
    HandshakeGuard guard;
    auto w = make_witness({code_of(200, 1), code_of(300, 2), code_of(20, 3)});
    SECTION("an honest code store passes") { CHECK(sanitize(w)); }
    SECTION("a corrupted payload fails") {
        w.data[w.offset_of_payload_size(200) + 8 + 32 + 100] ^= 1;
        CHECK_FALSE(sanitize(w));
    }
    SECTION("a corrupted key fails") {
        w.data[w.offset_of_payload_size(300) + 8 + 3] ^= 1;
        CHECK_FALSE(sanitize(w));
    }
    SECTION("a handshake with no data is no handshake") {
        w.data[w.offset_of_payload_size(200) + 8 + 32 + 100] ^= 1;
        Marks m{kBits};
        m.set(w.offset_of_payload_size(200));
        g_code_store_verified = {nullptr, w.data_size, m.bits.data(), m.n_bits};
        CHECK_FALSE(sanitize(w));
    }
}

TEST_CASE("sanitize skips the entries marked, and takes the marks once", "[state_zz][direct_state][code_store_verified]") {
    HandshakeGuard guard;
    auto w = make_witness({code_of(200, 1), code_of(300, 2), code_of(20, 3)});
    const uint64_t a = w.offset_of_payload_size(200);
    const uint64_t b = w.offset_of_payload_size(300);
    Marks m{kBits};

    SECTION("an honest store with all marks passes") {
        m.set(a);
        m.set(b);
        g_code_store_verified = m.handshake(w);
        CHECK(sanitize(w));
        CHECK(g_code_store_verified.data == nullptr);
    }
    SECTION("a corrupted entry with its mark is skipped: the mark stands for the hash") {
        w.data[a + 8 + 32 + 100] ^= 1;
        m.set(a);
        g_code_store_verified = m.handshake(w);
        CHECK(sanitize(w));
    }
    SECTION("a corrupted entry without a mark fails, whatever the marks of the others") {
        w.data[a + 8 + 32 + 100] ^= 1;
        m.set(b);
        g_code_store_verified = m.handshake(w);
        CHECK_FALSE(sanitize(w));
        CHECK(g_code_store_verified.data == nullptr);
    }
    SECTION("the marks are used once") {
        m.set(a);
        g_code_store_verified = m.handshake(w);
        w.data[a + 8 + 32 + 100] ^= 1;
        DirectState first{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
        CHECK(first.sanitize());
        DirectState second{std::span<uint8_t>{w.blob}, std::span<uint8_t>{w.nodestore}};
        CHECK_FALSE(second.sanitize());
    }
    SECTION("marks for the 20-byte entry are not needed: it is hashed") {
        m.set(a);
        m.set(b);
        const uint64_t c = w.offset_of_payload_size(20);
        w.data[c + 8 + 32 + 5] ^= 1;
        g_code_store_verified = m.handshake(w);
        CHECK_FALSE(sanitize(w));
    }
}

TEST_CASE("marks of another data section, size or capacity are not used", "[state_zz][direct_state][code_store_verified]") {
    HandshakeGuard guard;
    auto w = make_witness({code_of(200, 1), code_of(300, 2)});
    const uint64_t a = w.offset_of_payload_size(200);
    w.data[a + 8 + 32 + 100] ^= 1;
    Marks m{kBits};
    m.set(a);

    SECTION("the marks of the right section skip it") {
        g_code_store_verified = m.handshake(w);
        CHECK(sanitize(w));
    }
    SECTION("another base") {
        for (const auto delta : {1, 4, 8, -8}) {
            g_code_store_verified = {w.data + delta, w.data_size, m.bits.data(), m.n_bits};
            CHECK_FALSE(sanitize(w));
        }
    }
    SECTION("another data size") {
        for (const uint32_t size : {w.data_size - 8, w.data_size + 8, w.data_size - 1, 0u}) {
            g_code_store_verified = {w.data, size, m.bits.data(), m.n_bits};
            CHECK_FALSE(sanitize(w));
        }
    }
    SECTION("an entry beyond the bitmap's capacity") {
        const uint32_t idx = static_cast<uint32_t>(a >> 3);
        for (const uint32_t n_bits : {0u, idx, idx - 1}) {
            // The bit itself is there to be read; the capacity says it is not a mark.
            Marks wide{kBits};
            wide.set(a);
            g_code_store_verified = {w.data, w.data_size, wide.bits.data(), n_bits};
            CHECK_FALSE(sanitize(w));
        }
        Marks exact{kBits};
        exact.set(a);
        g_code_store_verified = {w.data, w.data_size, exact.bits.data(), idx + 1};
        CHECK(sanitize(w));
    }
}

TEST_CASE("a mark of an entry is not one of an offset inside it", "[state_zz][direct_state][code_store_verified][soundness]") {
    HandshakeGuard guard;
    // A code store whose one slot points 1 or 2 bytes into an entry: such an offset has the bit index
    // of the entry's own. The bytes at +shift are the upper bytes of the entry's length, then the
    // first bytes of its key (cleared here), so a payload of 9000 (or 2.1M) bytes makes them a length
    // of 35 (or 32) bytes and the layout check lets the offset by. What sits there is no entry: its
    // hash is no key.
    for (const auto& [shift, size] : {std::pair<uint32_t, size_t>{1, 9000}, {2, 2100000}}) {
        DYNAMIC_SECTION("offset 8 + " << shift) {
            auto w = make_witness({code_of(size, 5)});
            REQUIRE(w.offsets.size() == 1);
            const uint64_t entry = w.offsets[0];
            std::memset(w.data + entry + 8, 0, 8);
            Marks m{kBits};
            m.set(entry);
            m.set(entry + shift);  // Not a distinct bit: the same one.
            REQUIRE(m.bits[entry >> 8] == (uint32_t{1} << ((entry >> 3) & 31)));

            // The entry itself is skipped on its mark, whatever its key now is.
            g_code_store_verified = m.handshake(w);
            CHECK(sanitize(w));

            // Moved to the offset inside it, which only that is visited, it is hashed and fails.
            const uint32_t inside = static_cast<uint32_t>(entry + shift);
            std::memcpy(w.blob.data() + w.slot_field_offsets[0], &inside, 4);
            uint64_t len;
            std::memcpy(&len, w.data + inside, 8);
            REQUIRE(len >= 32);
            REQUIRE(len <= w.data_size - inside - 8);
            g_code_store_verified = m.handshake(w);
            CHECK_FALSE(sanitize(w));
        }
    }
}

}  // namespace zilkworm
