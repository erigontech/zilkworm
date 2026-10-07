// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// The input reader that hashes the code store's payloads as it reads them (code_store_stream.hpp),
// driven by a mock word source and a verify function written from its contract: the words reach
// memory as the input has them, nothing is read or written out of bounds, and a bit is set only
// for an entry whose payload hashes to the key beside it, in the bytes the reader left in memory.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <bit>
#include <cstring>
#include <random>
#include <vector>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/code_store_stream.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace zilkworm {
namespace {

namespace css = code_store_stream;

constexpr uint32_t kCanary = 0xA5A5A5A5u;
constexpr size_t kGuardWords = 8;

evmc::bytes32 hash_of(const uint8_t* p, size_t n) {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{p, n}));
}

/// The input as the oracle supplies it: exactly the words it has, no more.
struct MockInput {
    const uint32_t* words;
    size_t n;
    size_t pos{0};
    bool overrun{false};
    size_t verify_calls{0};

    uint32_t word() {
        if (pos >= n) {
            overrun = true;
            return 0;
        }
        return words[pos++];
    }
    void read(uint32_t* dst, size_t count) {
        for (size_t i = 0; i < count; ++i) dst[i] = word();
    }
    /// The contract of io.verify(): the words to dst, then the Keccak-256 of the first `size`
    /// bytes of them against the key. Whatever follows the payload in its last word is not hashed.
    bool verify(uint32_t* dst, uint32_t size, const uint32_t* key) {
        ++verify_calls;
        read(dst, (size + 3) / 4);
        const auto h = hash_of(reinterpret_cast<const uint8_t*>(dst), size);
        return std::memcmp(h.bytes, key, 32) == 0;
    }
};

struct Outcome {
    std::vector<uint64_t> mem;  // What the reader left in memory (the words, then the guard).
    CodeStoreVerified handshake;
    std::vector<uint32_t> bits;
    uint32_t n_bits{0};
    size_t full_words{0};
    size_t verify_calls{0};

    const uint8_t* bytes() const { return reinterpret_cast<const uint8_t*>(mem.data()); }
    bool bit(uint64_t off) const {
        return (off >> 3) < n_bits && ((bits[off >> 8] >> ((off >> 3) & 31)) & 1) != 0;
    }
    size_t marked() const {
        size_t n = 0;
        for (const auto w : bits) n += static_cast<size_t>(std::popcount(w));
        return n;
    }
};

/// Every bit set stands for an entry that is there in the memory left behind, and hashes to its
/// key: the property sanitize() relies on, checked from the bytes alone.
void check_marks_are_sound(const Outcome& o) {
    for (uint64_t idx = 0; idx < o.n_bits; ++idx) {
        if (((o.bits[idx >> 5] >> (idx & 31)) & 1) == 0) continue;
        const uint64_t off = idx * 8;
        REQUIRE(o.handshake.data != nullptr);
        REQUIRE(off + 8 + 32 + 33 <= o.handshake.data_size);
        REQUIRE(o.handshake.data >= o.bytes());
        REQUIRE(o.handshake.data + o.handshake.data_size <= o.bytes() + o.full_words * 4);
        uint64_t len;
        std::memcpy(&len, o.handshake.data + off, 8);
        REQUIRE(len > 64);
        REQUIRE(len <= o.handshake.data_size - off - 8);
        const uint8_t* body = o.handshake.data + off + 8;
        const auto h = hash_of(body + 32, len - 32);
        REQUIRE(std::memcmp(h.bytes, body, 32) == 0);
    }
}

/// Runs the reader on the first n_bytes of the input, as the guest does (it reads the whole words;
/// the last partial word is its caller's).
Outcome run(const std::vector<uint8_t>& input, size_t n_bytes, uint32_t n_bits = 1u << 17) {
    REQUIRE(n_bytes <= input.size());
    Outcome o;
    o.full_words = n_bytes / 4;
    o.n_bits = n_bits;
    o.bits.assign((n_bits + 31) / 32, 0u);
    std::vector<uint32_t> words(o.full_words);
    if (o.full_words != 0) std::memcpy(words.data(), input.data(), o.full_words * 4);
    o.mem.assign((o.full_words + 1) / 2 + kGuardWords / 2 + 1, 0);
    auto* dst = reinterpret_cast<uint32_t*>(o.mem.data());
    const size_t total_words = o.mem.size() * 2;
    for (size_t i = o.full_words; i < total_words; ++i) dst[i] = kCanary;

    MockInput io{words.data(), words.size()};
    css::read_input_words(io, dst, o.full_words, o.handshake, o.bits.data(), n_bits);
    o.verify_calls = io.verify_calls;

    REQUIRE_FALSE(io.overrun);
    REQUIRE(io.pos == o.full_words);
    for (size_t i = o.full_words; i < total_words; ++i) REQUIRE(dst[i] == kCanary);
    if (o.full_words != 0) REQUIRE(std::memcmp(dst, input.data(), o.full_words * 4) == 0);
    check_marks_are_sound(o);
    return o;
}

Bytes code_of(size_t n, uint64_t seed) {
    std::mt19937_64 rng{seed};
    Bytes c(n, 0);
    for (auto& b : c) b = static_cast<uint8_t>(rng());
    return c;
}

/// An MFBD input with one account and the code store of the given codes.
std::vector<uint8_t> make_input(const std::vector<Bytes>& codes) {
    std::vector<std::pair<bytes32, Bytes>> store;
    for (const auto& c : codes) store.emplace_back(hash_of(c.data(), c.size()), c);
    const auto code_store = test_util::build_code_store(store);
    std::vector<DirectState::AccountInfo> accounts{
        test_util::make_eoa(test_util::make_addr(0, 0x11), 1, intx::uint256{0})};
    const auto blob = DirectState::build_blob_from_accounts(accounts, {}, code_store);
    const std::vector<uint8_t> flat =
        build_flat_bundle(ByteView{}, std::span<const ByteView>{}, ByteView{}, blob, {}, "Shanghai");
    REQUIRE_FALSE(flat.empty());
    return test_util::wrap_mfbd(flat);
}

uint32_t u32_at(const std::vector<uint8_t>& v, size_t off) {
    uint32_t x;
    std::memcpy(&x, v.data() + off, 4);
    return x;
}
void set_u32(std::vector<uint8_t>& v, size_t off, uint32_t x) { std::memcpy(v.data() + off, &x, 4); }

/// Where the code store's headers and entries lie in an input made by make_input().
struct Layout {
    size_t meta, store, data;
    uint32_t data_size;
    std::vector<uint64_t> offsets;  // Entry offsets in the data section.
};

Layout layout_of(std::vector<uint8_t>& input) {
    Layout l{};
    l.meta = css::kEnvelopeSize + u32_at(input, css::kEnvelopeSize + offsetof(FlatBundleHeader, direct_state_off));
    l.store = l.meta + u32_at(input, l.meta + offsetof(PreStateMeta, code_store_offset));
    const auto* h = reinterpret_cast<const MphfMapHeader*>(input.data() + l.store);
    l.data = l.store + h->data_offset;
    l.data_size = h->data_size;
    MphfMap map{const_cast<MphfMapHeader*>(h)};
    map.for_each_offset([&](uint64_t off) { l.offsets.push_back(off); });
    std::sort(l.offsets.begin(), l.offsets.end());
    return l;
}

/// Whether the entry at the offset is one the reader marks: over 32 bytes and hashing to its key.
bool entry_hashes(const std::vector<uint8_t>& input, const Layout& l, uint64_t off) {
    uint64_t len;
    std::memcpy(&len, input.data() + l.data + off, 8);
    if (len <= 64 || len > l.data_size - off - 8) return false;
    const uint8_t* body = input.data() + l.data + off + 8;
    const auto h = hash_of(body + 32, len - 32);
    return std::memcmp(h.bytes, body, 32) == 0;
}

/// A mix of the sizes the code store has: the 23-byte delegation designators, small and large
/// contracts, and sizes on both sides of the 136-byte hash block and of the 4- and 8-byte words.
std::vector<Bytes> mixed_codes(uint64_t seed) {
    std::vector<Bytes> codes;
    uint64_t s = seed;
    for (const size_t n : {23u, 32u, 33u, 34u, 35u, 36u, 37u, 39u, 40u, 41u, 135u, 136u, 137u, 138u, 139u,
                           140u, 271u, 272u, 273u, 408u, 544u, 1001u, 4096u, 5000u, 24575u})
        codes.push_back(code_of(n, s++));
    return codes;
}

}  // namespace

TEST_CASE("every payload over 32 bytes of an honest code store is marked, whatever its size",
          "[state_zz][code_store_stream]") {
    for (size_t n = 0; n <= 600; ++n) {
        DYNAMIC_SECTION("one code of " << n << " bytes") {
            auto input = make_input({code_of(n, n + 1)});
            const auto l = layout_of(input);
            const auto o = run(input, input.size());
            REQUIRE(l.offsets.size() == 1);
            CHECK(o.bit(l.offsets[0]) == (n > 32));
            CHECK(o.marked() == (n > 32 ? 1u : 0u));
            CHECK(o.verify_calls == (n > 32 ? 1u : 0u));
            if (n > 32) {
                CHECK(o.handshake.data == o.bytes() + l.data);
                CHECK(o.handshake.data_size == l.data_size);
                CHECK(o.handshake.bits == o.bits.data());
                CHECK(o.handshake.n_bits == o.n_bits);
            }
        }
    }
    for (const size_t n : {136u * 2 - 1, 136u * 2, 136u * 2 + 1, 136u * 5, 136u * 5 + 3, 136u * 30 - 1,
                           24575u, 24576u, 30000u, 70000u}) {
        DYNAMIC_SECTION("one code of " << n << " bytes") {
            auto input = make_input({code_of(n, n)});
            const auto l = layout_of(input);
            const auto o = run(input, input.size(), 1u << 16);
            CHECK(o.bit(l.offsets[0]));
            CHECK(o.marked() == 1);
        }
    }
}

TEST_CASE("a code store of many codes is marked entry by entry", "[state_zz][code_store_stream]") {
    for (uint64_t seed = 1; seed <= 4; ++seed) {
        auto codes = mixed_codes(seed * 100);
        std::mt19937_64 rng{seed};
        for (int i = 0; i < 60; ++i) codes.push_back(code_of(rng() % 3000, rng()));
        auto input = make_input(codes);
        const auto l = layout_of(input);
        const auto o = run(input, input.size());
        size_t want = 0;
        for (const auto off : l.offsets) {
            const bool hashes = entry_hashes(input, l, off);
            CHECK(o.bit(off) == hashes);
            want += hashes;
        }
        CHECK(o.marked() == want);
        CHECK(want == o.verify_calls);
        CHECK(want > 60);
    }
}

TEST_CASE("an entry beyond the bitmap is read, not hashed, and the others are marked",
          "[state_zz][code_store_stream]") {
    auto input = make_input(mixed_codes(7));
    const auto l = layout_of(input);
    const uint32_t n_bits = static_cast<uint32_t>(l.data_size / 8 / 2);
    const auto o = run(input, input.size(), (n_bits + 31) & ~31u);
    size_t want = 0;
    for (const auto off : l.offsets) {
        const bool inside = (off >> 3) < o.n_bits;
        CHECK(o.bit(off) == (inside && entry_hashes(input, l, off)));
        want += o.bit(off);
    }
    CHECK(o.marked() == want);
    CHECK(want > 0);
}

TEST_CASE("a truncated input is read to its last whole word, with the marks it has earned",
          "[state_zz][code_store_stream]") {
    auto input = make_input(mixed_codes(11));
    const auto l = layout_of(input);
    const size_t first_entry = l.data;
    for (size_t n = 0; n <= input.size(); n += (n < first_entry + 400 ? 1 : 37)) {
        const auto o = run(input, n);
        if (n < l.data + l.data_size) CHECK(o.handshake.data == nullptr);
    }
    // The cut at the last byte and the byte count that is not a multiple of 4.
    for (size_t cut = 1; cut <= 7; ++cut) run(input, input.size() - cut);
}

TEST_CASE("an input that is not a bundle of the known layout is read plainly, with no marks",
          "[state_zz][code_store_stream]") {
    const auto base = make_input(mixed_codes(13));
    auto probe = base;
    const auto l = layout_of(probe);
    const size_t bundle = css::kEnvelopeSize;
    const size_t ds_field = bundle + offsetof(FlatBundleHeader, direct_state_off);
    const size_t cs_off_field = l.meta + offsetof(PreStateMeta, code_store_offset);
    const size_t cs_size_field = l.meta + offsetof(PreStateMeta, code_store_size);
    const size_t data_off_field = l.store + offsetof(MphfMapHeader, data_offset);
    const size_t data_size_field = l.store + offsetof(MphfMapHeader, data_size);

    struct Mutation {
        const char* name;
        size_t at;
        uint32_t value;
    };
    const std::vector<Mutation> mutations{
        {"MFBD magic", 0, 0x4E534A45u},
        {"MFBD version", 4, 2},
        {"two bundles", 8, 2},
        {"no bundle", 8, 0},
        {"n_bundles high half", 12, 1},
        {"FBND magic", bundle, 0},
        {"FBND version", bundle + 4, 13},
        {"direct_state_off not 8-aligned", ds_field, u32_at(probe, ds_field) + 4},
        {"direct_state_off inside the header", ds_field, 8},
        {"direct_state_off past the input", ds_field, 0x7ffffff8u},
        {"PRES magic", l.meta, 0},
        {"PRES version", l.meta + 4, 3},
        {"code_store_offset not 8-aligned", cs_off_field, u32_at(probe, cs_off_field) + 4},
        {"code_store_offset behind the header", cs_off_field, 8},
        {"code_store_offset past the input", cs_off_field, 0x7ffffff8u},
        {"code_store_size short of its header", cs_size_field, 48},
        {"MPHC magic", l.store, kMphfCodeStoreMagic ^ 1},
        {"MPHC version", l.store + 4, 2},
        {"MPHC no keys", l.store + 8, 0},
        {"data_offset not 8-aligned", data_off_field, u32_at(probe, data_off_field) + 4},
        {"data_offset inside the header", data_off_field, 48},
        {"data past the code store", data_size_field, u32_at(probe, cs_size_field)},
        {"data past the input", data_size_field, 0x7ffffff8u},
        {"data_size 32-bit wrap", data_size_field, 0xfffffff8u},
    };
    for (const auto& m : mutations) {
        DYNAMIC_SECTION(m.name) {
            auto input = base;
            set_u32(input, m.at, m.value);
            const auto o = run(input, input.size());
            CHECK(o.handshake.data == nullptr);
            CHECK(o.marked() == 0);
            CHECK(o.verify_calls == 0);
        }
    }
    SECTION("the unmutated input is marked") {
        const auto o = run(probe, probe.size());
        CHECK(o.marked() > 0);
    }
}

TEST_CASE("a changed payload or key unmarks its entry and no other", "[state_zz][code_store_stream]") {
    const auto base = make_input(mixed_codes(17));
    auto probe = base;
    const auto l = layout_of(probe);
    for (const auto victim : l.offsets) {
        uint64_t len;
        std::memcpy(&len, probe.data() + l.data + victim, 8);
        if (len <= 64) continue;
        for (const uint64_t rel : {uint64_t{8}, uint64_t{15}, uint64_t{39}, uint64_t{40}, len + 7}) {
            if (rel >= len + 8) continue;
            auto input = base;
            input[l.data + victim + rel] ^= 0x10;
            const auto o = run(input, input.size());
            for (const auto off : l.offsets) CHECK(o.bit(off) == (off != victim && entry_hashes(base, l, off)));
        }
        // The padding bytes are not part of the payload: changing them leaves the entry marked.
        const uint64_t padded = (len + 7) & ~uint64_t{7};
        if (padded != len) {
            auto input = base;
            input[l.data + victim + 8 + len] ^= 0xff;
            const auto o = run(input, input.size());
            CHECK(o.bit(victim));
        }
    }
}

TEST_CASE("an entry whose length does not describe an entry of the section ends the walk without a desync",
          "[state_zz][code_store_stream]") {
    const auto base = make_input(mixed_codes(19));
    auto probe = base;
    const auto l = layout_of(probe);
    for (const auto victim : l.offsets) {
        const size_t at = l.data + victim;
        uint64_t len;
        std::memcpy(&len, probe.data() + at, 8);
        for (const uint64_t lie : {uint64_t{0}, uint64_t{31}, uint64_t{32}, uint64_t{33}, len - 1, len + 1,
                                   len + 8, len - 8, uint64_t{1} << 32, (uint64_t{1} << 32) | len,
                                   uint64_t{0xffffffff}, uint64_t{0xfffffff8}, ~uint64_t{0}}) {
            auto input = base;
            std::memcpy(input.data() + at, &lie, 8);
            run(input, input.size());
        }
    }
}

TEST_CASE("random changes to the bytes before and in the code store keep the reader in step and sound",
          "[state_zz][code_store_stream]") {
    const auto base = make_input(mixed_codes(23));
    auto probe = base;
    const auto l = layout_of(probe);
    std::mt19937_64 rng{12345};
    for (int i = 0; i < 1500; ++i) {
        auto input = base;
        const int flips = 1 + static_cast<int>(rng() % 3);
        for (int k = 0; k < flips; ++k) {
            // The headers and the first entries, where a change moves the walk, or anywhere.
            const size_t at = (rng() & 1) ? rng() % (l.data + 600) : rng() % input.size();
            input[at] = static_cast<uint8_t>(rng());
        }
        const size_t n = (rng() % 4 == 0) ? rng() % (input.size() + 1) : input.size();
        run(input, n);
    }
}

TEST_CASE("the walk stops at the entry it cannot describe and returns the words it has read",
          "[state_zz][code_store_stream]") {
    // A data section of hand-made entries: [len][key][payload][pad], after the zero sentinel.
    auto region = [](const std::vector<std::pair<uint64_t, size_t>>& entries) {
        std::vector<uint8_t> r(8, 0);
        for (const auto& [len, payload_bytes] : entries) {
            const size_t at = r.size();
            r.resize(at + 40 + ((payload_bytes + 7) & ~size_t{7}), 0);
            std::memcpy(r.data() + at, &len, 8);
            std::vector<uint8_t> payload(payload_bytes);
            for (size_t i = 0; i < payload_bytes; ++i) payload[i] = static_cast<uint8_t>(at + i);
            std::memcpy(r.data() + at + 40, payload.data(), payload_bytes);
            const auto h = hash_of(payload.data(), payload_bytes);
            std::memcpy(r.data() + at + 8, h.bytes, 32);
        }
        return r;
    };
    auto walk = [](const std::vector<uint8_t>& r, uint32_t data_size, uint32_t n_bits,
                   uint32_t& bits_out, bool& overrun) {
        std::vector<uint32_t> words(r.size() / 4);
        std::memcpy(words.data(), r.data(), r.size());
        std::vector<uint64_t> mem(r.size() / 8 + 4, 0);
        std::vector<uint32_t> bits(n_bits / 32 + 1, 0);
        MockInput io{words.data(), words.size()};
        const uint32_t read = css::read_code_store(io, reinterpret_cast<uint32_t*>(mem.data()),
                                                   data_size, bits.data(), n_bits);
        overrun = io.overrun;
        bits_out = bits[0];
        REQUIRE(io.pos * 4 == read);
        REQUIRE(std::memcmp(mem.data(), r.data(), read) == 0);
        return read;
    };
    bool overrun = false;
    uint32_t bits = 0;

    SECTION("a whole section is read and marked") {
        const auto r = region({{32 + 40, 40}, {32 + 5, 5}, {32 + 100, 100}});
        CHECK(walk(r, static_cast<uint32_t>(r.size()), 64, bits, overrun) == r.size());
        CHECK_FALSE(overrun);
        CHECK(bits == ((1u << 1) | (1u << 17)));  // The entries at 8 and 136; the one at 88 is short.
    }
    SECTION("padding of 1 to 4 bytes of the 8 leaves a word the hash did not take") {
        for (size_t payload = 33; payload <= 48; ++payload) {
            const auto r = region({{32 + payload, payload}});
            CHECK(walk(r, static_cast<uint32_t>(r.size()), 64, bits, overrun) == r.size());
            CHECK_FALSE(overrun);
            CHECK(bits == 2);
        }
    }
    SECTION("a section shorter than its first entry's header") {
        const auto r = region({{32 + 40, 40}});
        for (uint32_t size = 0; size < 8 + 40; ++size)
            CHECK(walk(r, size, 64, bits, overrun) == (size < 8 ? 0u : 8u));
    }
    SECTION("the length does not fit the section") {
        const auto r = region({{32 + 40, 40}, {32 + 40, 40}});
        for (const uint64_t lie : {uint64_t{31}, uint64_t{0}, uint64_t{32 + 41}, uint64_t{1} << 32,
                                   uint64_t{0xfffffff0}}) {
            auto bad = r;
            std::memcpy(bad.data() + 88, &lie, 8);  // The second entry's length.
            const uint32_t read = walk(bad, static_cast<uint32_t>(bad.size()), 64, bits, overrun);
            CHECK(read == 8 + 80 + 40);
            CHECK_FALSE(overrun);
            CHECK(bits == 2);
        }
    }
    SECTION("the padded payload does not fit the section") {
        // 33 bytes of payload padded to 40, with only 36 left after the header.
        auto r = region({{32 + 33, 33}});
        r.resize(8 + 40 + 36);
        CHECK(walk(r, static_cast<uint32_t>(r.size()), 64, bits, overrun) == 8 + 40);
        CHECK_FALSE(overrun);
        CHECK(bits == 0);
    }
    SECTION("the last entry ends the section exactly") {
        const auto r = region({{32 + 33, 33}});
        CHECK(walk(r, static_cast<uint32_t>(r.size()), 64, bits, overrun) == r.size());
        CHECK(bits == 2);
    }
}

TEST_CASE("a key that hashes the payload and the bytes after it does not pass for the payload",
          "[state_zz][code_store_stream][soundness]") {
    // The last word of the payload carries 1 to 3 bytes that are not part of it: an absorb that
    // takes the word whole would let the key of payload||b pass for the payload when they are
    // (b ^ 1, 1, 0...). The contract of verify() is that they are not hashed.
    std::mt19937_64 rng{99};
    for (size_t payload_size = 33; payload_size < 300; ++payload_size) {
        const size_t pad_bytes = (4 - payload_size % 4) % 4;
        if (pad_bytes < 2) continue;
        std::vector<uint8_t> payload(payload_size);
        for (auto& b : payload) b = static_cast<uint8_t>(rng());
        const uint8_t b = static_cast<uint8_t>(rng());
        std::vector<uint8_t> extended = payload;
        extended.push_back(b);
        const auto forged_key = hash_of(extended.data(), extended.size());
        const size_t padded = (payload_size + 7) & ~size_t{7};

        std::vector<uint8_t> input(8 + 40 + padded, 0);
        const uint64_t len = 32 + payload_size;
        std::memcpy(input.data() + 8, &len, 8);
        std::memcpy(input.data() + 16, forged_key.bytes, 32);
        std::memcpy(input.data() + 48, payload.data(), payload_size);
        input[48 + payload_size] = b ^ 1;
        input[48 + payload_size + 1] = 1;

        std::vector<uint32_t> words(input.size() / 4);
        std::memcpy(words.data(), input.data(), input.size());
        std::vector<uint64_t> mem(input.size() / 8 + 1, 0);
        std::vector<uint32_t> bits(2, 0);
        MockInput io{words.data(), words.size()};
        css::read_code_store(io, reinterpret_cast<uint32_t*>(mem.data()),
                             static_cast<uint32_t>(input.size()), bits.data(), 64);
        CHECK(io.verify_calls == 1);
        CHECK(bits[0] == 0);
        // The words are stored whole, the extra bytes included.
        CHECK(std::memcmp(mem.data(), input.data(), input.size()) == 0);
    }
}

}  // namespace zilkworm
