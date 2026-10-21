// Tests for the packed nibble paths: nibble i at bits 4*(i%16) of word i/16.
#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

#include <array>
#include <random>
#include <vector>

namespace {

using zilkworm::bytes32;
using zilkworm::nibbles64;

bytes32 rand_key(std::mt19937& rng) {
    bytes32 k{};
    for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
    return k;
}

std::vector<uint8_t> key_nibbles(const bytes32& k) {
    std::vector<uint8_t> n(64);
    for (size_t i = 0; i < 32; ++i) {
        n[2 * i] = static_cast<uint8_t>(k.bytes[i] >> 4);
        n[2 * i + 1] = static_cast<uint8_t>(k.bytes[i] & 0xF);
    }
    return n;
}

size_t naive_lcp(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, size_t off, size_t max) {
    size_t i = 0;
    while (i < max && a[i] == b[off + i]) ++i;
    return i;
}

// The reference HP encoder: flag nibble (leaf 2 | odd 1), then ceil(n/2) pair bytes.
std::vector<uint8_t> naive_hp(const std::vector<uint8_t>& nib, size_t n, bool leaf) {
    const bool odd = (n & 1);
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(((leaf ? 2 : 0) | (odd ? 1 : 0)) << 4) | (odd && n ? nib[0] : 0));
    for (size_t i = odd ? 1 : 0; i < n; i += 2) {
        uint8_t b = static_cast<uint8_t>(nib[i] << 4);
        if (i + 1 < n) b = static_cast<uint8_t>(b | nib[i + 1]);
        out.push_back(b);
    }
    return out;
}

}  // namespace

namespace zilkworm {

TEST_CASE("nibbles64 packs bytes32 like the byte arrays did", "[trie][packed]") {
    std::mt19937 rng{20261021};
    for (int t = 0; t < 500; ++t) {
        const bytes32 k = rand_key(rng);
        const nibbles64 p = nibbles64::from_bytes32(k);
        const std::vector<uint8_t> ref = key_nibbles(k);
        REQUIRE(p.len == 64);
        for (unsigned i = 0; i < 64; ++i) REQUIRE(p.at(i) == ref[i]);
        nibbles64 q;
        q.assign_bytes32(k);
        REQUIRE(q.w == p.w);
    }
    // The unaligned fallback expands identically.
    alignas(8) uint8_t buf[40];
    for (unsigned shift = 1; shift < 8; ++shift) {
        const bytes32 k = rand_key(rng);
        std::memcpy(buf + shift, k.bytes, 32);
        nibbles64 p;
        p.assign_bytes32(*reinterpret_cast<const bytes32*>(buf + shift));
        const nibbles64 q = nibbles64::from_bytes32(k);
        REQUIRE(p.w == q.w);
    }
}

TEST_CASE("lcp_packed matches a nibble walk at every position, cursor and cap", "[trie][packed]") {
    std::mt19937 rng{20261022};
    // A difference at every single nibble position.
    const bytes32 base = rand_key(rng);
    const std::vector<uint8_t> base_n = key_nibbles(base);
    for (unsigned d = 0; d < 64; ++d) {
        bytes32 other = base;
        other.bytes[d / 2] ^= static_cast<uint8_t>(1u << (4 * ((d & 1) ^ 1)));  // flip nibble d: even -> high, odd -> low
        const nibbles64 a = nibbles64::from_bytes32(base);
        const nibbles64 b = nibbles64::from_bytes32(other);
        REQUIRE(lcp_packed(a.w.data(), b.w.data(), 0, 64) == d);
        REQUIRE(lcp_packed(b.w.data(), a.w.data(), 0, 64) == d);
        for (const size_t max : {size_t{0}, size_t{d}, size_t{d + 1}, size_t{64}}) {
            REQUIRE(lcp_packed(a.w.data(), b.w.data(), 0, max) == std::min<size_t>(d, max));
        }
    }
    // Random keys against cursors: lcp of a vs s[off..], capped.
    for (int t = 0; t < 200; ++t) {
        const bytes32 ka = rand_key(rng), ks = rand_key(rng);
        const nibbles64 a = nibbles64::from_bytes32(ka);
        const nibbles64 s = nibbles64::from_bytes32(ks);
        const std::vector<uint8_t> an = key_nibbles(ka), sn = key_nibbles(ks);
        for (unsigned trial = 0; trial < 4; ++trial) {
            const size_t off = rng() % 64;
            const size_t max = rng() % (64 - off + 1);
            REQUIRE(lcp_packed(a.w.data(), s.w.data(), off, max) == naive_lcp(an, sn, off, max));
        }
    }
}

TEST_CASE("slice and append reproduce byte-array slicing at every offset and length", "[trie][packed]") {
    std::mt19937 rng{20261023};
    for (int t = 0; t < 60; ++t) {
        const bytes32 k = rand_key(rng);
        const nibbles64 p = nibbles64::from_bytes32(k);
        const std::vector<uint8_t> ref = key_nibbles(k);
        for (unsigned trial = 0; trial < 8; ++trial) {
            const size_t off = rng() % 65;
            const size_t n = off + rng() % (65 - off) - off;
            const nibbles64 s = p.slice(off, n);
            REQUIRE(s.len == n);
            for (size_t i = 0; i < n; ++i) REQUIRE(s.at(i) == ref[off + i]);
            // Words hold nothing above len: repacking the same nibbles agrees.
            nibbles64 r;
            r.len = static_cast<uint8_t>(n);
            for (size_t i = 0; i < n; ++i) r.set(i, ref[off + i]);
            REQUIRE(s.w == r.w);
        }
        // append at every parity of the destination length
        for (size_t keep = 0; keep <= 64; keep += 7) {
            const nibbles64 head = p.slice(0, keep);
            for (size_t tail = 0; keep + tail <= 64; tail += 11) {
                const nibbles64 rest = p.slice(keep, tail);
                nibbles64 c = head;
                c.append(rest);
                REQUIRE(c.len == keep + tail);
                for (size_t i = 0; i < keep + tail; ++i) REQUIRE(c.at(i) == ref[i]);
                nibbles64 r;
                r.len = static_cast<uint8_t>(keep + tail);
                for (size_t i = 0; i < keep + tail; ++i) r.set(i, ref[i]);
                REQUIRE(c.w == r.w);  // nothing above len
            }
        }
    }
}

TEST_CASE("hp_encode/hp_decode round-trip every length, parity and flag", "[trie][packed]") {
    std::mt19937 rng{20261024};
    for (const bool leaf : {false, true}) {
        for (size_t n = 0; n <= 64; ++n) {
            const bytes32 k = rand_key(rng);
            const nibbles64 p = nibbles64::from_bytes32(k).slice(0, n);
            const std::vector<uint8_t> ref_n = key_nibbles(k);
            alignas(8) uint8_t buf[80];
            uint8_t* end = encode_hp_path(buf, p, leaf);
            const std::vector<uint8_t> ref = naive_hp(ref_n, n, leaf);
            REQUIRE(static_cast<size_t>(end - buf) == ref.size());
            REQUIRE(std::equal(ref.begin(), ref.end(), buf));
            // decode back
            bool is_leaf = !leaf;
            nibbles64 d;
            uint8_t plen = 99;
            REQUIRE(hp_decode(ByteView{buf, static_cast<size_t>(end - buf)}, is_leaf, d, plen));
            REQUIRE(is_leaf == leaf);
            REQUIRE(plen == n);
            REQUIRE(d.len == n);
            REQUIRE(d.w == p.w);
        }
    }
    // single() and push()
    for (unsigned nib = 0; nib < 16; ++nib) {
        const nibbles64 s = nibbles64::single(nib);
        REQUIRE(s.len == 1);
        REQUIRE(s.at(0) == nib);
        REQUIRE(s.w[1] == 0);
        REQUIRE(s.w[2] == 0);
        REQUIRE(s.w[3] == 0);
    }
    nibbles64 g;
    for (unsigned nib = 0; nib < 16; ++nib) g.push(nib);
    REQUIRE(g.len == 16);
    for (unsigned nib = 0; nib < 16; ++nib) REQUIRE(g.at(nib) == nib);
}

TEST_CASE("hp_decode rejects malformed input and keeps paths zeroed above len", "[trie][packed]") {
    bool is_leaf = false;
    uint8_t plen = 0;
    nibbles64 d;
    REQUIRE_FALSE(hp_decode(ByteView{}, is_leaf, d, plen));
    const uint8_t too_long_even[34] = {0x00};  // flag even, 33 payload bytes -> 66 nibbles
    REQUIRE_FALSE(hp_decode(ByteView{too_long_even, 34}, is_leaf, d, plen));
    const uint8_t too_long_odd[34] = {0x01};  // flag odd, 33 payload bytes -> 67 nibbles
    REQUIRE_FALSE(hp_decode(ByteView{too_long_odd, 34}, is_leaf, d, plen));
    // A short even path leaves the words above len zero even over dirty memory.
    alignas(8) uint8_t buf[8] = {0x20, 0x12, 0x34};  // leaf, 4 nibbles
    d.len = 64;
    for (auto& x : d.w) x = ~uint64_t{0};
    REQUIRE(hp_decode(ByteView{buf, 3}, is_leaf, d, plen));
    REQUIRE(is_leaf);
    REQUIRE(plen == 4);
    REQUIRE(d.w[0] == 0x4321ULL);  // nibbles 1,2,3,4 in ascending nibble order
    REQUIRE(d.w[1] == 0);
    REQUIRE(d.w[2] == 0);
    REQUIRE(d.w[3] == 0);
}

TEST_CASE("key_lcp_nibbles agrees with lcp_packed over the expanded keys", "[trie][packed]") {
    std::mt19937 rng{20261025};
    for (int t = 0; t < 300; ++t) {
        const TrieNodeFlat a{rand_key(rng)};
        const TrieNodeFlat b{rand_key(rng)};
        const nibbles64 na = nibbles64::from_bytes32(a.key);
        const nibbles64 nb = nibbles64::from_bytes32(b.key);
        const size_t ref = lcp_packed(na.w.data(), nb.w.data(), 0, 64);
        REQUIRE(key_lcp_nibbles(a, b) == ref);
        REQUIRE(key_lcp_nibbles(b, a) == ref);
    }
}

}  // namespace zilkworm
