// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The RLP header read of fast_decode_header (one 32-bit load of a word-aligned payload, four copied
// bytes otherwise). The guest takes that path on rv32 only; the native test build sets
// -DEVMONE_RV32_DISPATCH_TEST, which compiles it on the host (a build without the macro runs the
// 8-byte memcpy read, and these tests then check that read against itself). Checked
//  - against a verbatim copy of the 8-byte memcpy header read it replaces, on every first byte with
//    up to three length bytes, at every payload alignment and on short payloads;
//  - end to end, through GridMPT, against the canonical root of silkworm::trie::HashBuilder, on
//    batches whose consecutive keys share exactly p nibbles for p around every word boundary of an
//    8-byte or 4-byte compare, and on random batches with clustered keys (regression tests for the
//    seek's prefix compare, which this change leaves as it was);
//  - with forged node RLP, which must be rejected at every alignment as it is at the aligned one,
//    and with a tampered witness, which must never yield the canonical root.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <random>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/fold_unfold.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

// ---------------------------------------------------------------------------------------------
// fast_decode_header against the code it replaced.
// ---------------------------------------------------------------------------------------------

// fast_decode_header as it was before the word load: an 8-byte memcpy, bytes 0..3 used.
silkworm::rlp::Header ref_decode_header(ByteView& from) noexcept {
    if (from.size() < 8) {
        return {false, from.size()};
    }
    uint64_t word;
    std::memcpy(&word, from.data(), 8);
    uint8_t first = word & 0xFF;

    if (first < 0x80) return {false, 1};

    bool is_list = first >= 0xC0;
    uint8_t offset = first & 0x3Fu;

    from.remove_prefix(1);
    if (offset <= 55) return {is_list, offset};

    size_t len_bytes = offset - 55;
    size_t length = ((word >> 8) & 0xFF) << 16 | ((word >> 16) & 0xFF) << 8 | ((word >> 24) & 0xFF);
    length >>= (8 * (3 - len_bytes));
    from.remove_prefix(len_bytes);
    return {is_list, length};
}

// A buffer whose first byte is at address = (4-aligned base) + `misalign`.
struct Placed {
    std::vector<uint32_t> storage;
    uint8_t* at{};
    Placed(size_t size, unsigned misalign) : storage((size + misalign + 3) / 4 + 2) {
        at = reinterpret_cast<uint8_t*>(storage.data()) + misalign;
    }
};

void compare_decode(const uint8_t* bytes, size_t size, unsigned misalign) {
    Placed p{size + 8, misalign};
    std::memcpy(p.at, bytes, size);
    ByteView a{p.at, size};
    ByteView b{p.at, size};
    const auto got = fast_decode_header(a);
    const auto want = ref_decode_header(b);
    INFO("first=" << (size ? int(bytes[0]) : -1) << " size=" << size << " misalign=" << misalign);
    REQUIRE(got.list == want.list);
    REQUIRE(got.payload_length == want.payload_length);
    REQUIRE(a.data() == b.data());
    REQUIRE(a.size() == b.size());
}

}  // namespace

// Every first byte with random bytes after it, at every alignment and on both sides of the size
// check. A first byte whose length field has more than three bytes (0xbb..0xbf, 0xfb..0xff)
// shifts by a negative amount in the original and in the word-load version alike, which is not
// defined on the host; the guest's shift takes the amount mod 32 and so does not differ either, but
// those first bytes are not compared here.
TEST_CASE("fast_decode_header equals the 8-byte memcpy read", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c01};
    for (unsigned first = 0; first < 256; ++first) {
        if (first >= 0x80 && (first & 0x3F) > 58) continue;  // four or more length bytes
        for (size_t size : {size_t{0}, size_t{1}, size_t{3}, size_t{4}, size_t{7}, size_t{8}, size_t{9}, size_t{16}}) {
            for (unsigned misalign = 0; misalign < 4; ++misalign) {
                for (int rep = 0; rep < 8; ++rep) {
                    std::array<uint8_t, 16> bytes{};
                    for (auto& b : bytes) b = static_cast<uint8_t>(rng());
                    if (size > 0) bytes[0] = static_cast<uint8_t>(first);
                    compare_decode(bytes.data(), size, misalign);
                }
            }
        }
    }
}

// The headers encode_header writes decode to what was encoded, with the same cursor, at every alignment.
TEST_CASE("fast_decode_header decodes encoded headers at every alignment", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c02};
    std::vector<size_t> lens{0, 1, 2, 31, 32, 54, 55, 56, 57, 127, 128, 255, 256, 257, 4095, 4096, 65535, 65536, 65537,
                             (size_t{1} << 24) - 1};
    for (int i = 0; i < 64; ++i) lens.push_back(rng() & 0xFFFFFF);
    for (const size_t len : lens) {
        for (const bool list : {false, true}) {
            Bytes enc;
            silkworm::rlp::encode_header(enc, {.list = list, .payload_length = len});
            const size_t header_size = enc.size();
            for (unsigned misalign = 0; misalign < 4; ++misalign) {
                // Random payload bytes follow, at least 8 of them.
                Bytes buf = enc;
                for (int i = 0; i < 12; ++i) buf.push_back(static_cast<uint8_t>(rng()));
                Placed p{buf.size(), misalign};
                std::memcpy(p.at, buf.data(), buf.size());
                ByteView v{p.at, buf.size()};
                const auto h = fast_decode_header(v);
                INFO("len=" << len << " list=" << list << " misalign=" << misalign);
                REQUIRE(h.list == list);
                REQUIRE(h.payload_length == len);
                REQUIRE(v.data() == p.at + header_size);
                compare_decode(buf.data(), buf.size(), misalign);
            }
        }
    }
}

namespace {

// ---------------------------------------------------------------------------------------------
// Roots through GridMPT against HashBuilder.
// ---------------------------------------------------------------------------------------------

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

// A storage-leaf value RLP: a short integer, or (always, with `big`) 32 bytes with a non-zero first byte.
// A leaf below a deep branch is embedded in it when its RLP is under 32 bytes, and an embedded node
// of under 8 bytes is not decoded (fast_decode_header takes a payload that short for a string), which
// the base does as well: crafted trees with such leaves use big values.
Bytes value_rlp(std::mt19937_64& rng, bool big = false) {
    Bytes out;
    if (big || rng() % 3 == 0) {
        bytes32 v{};
        for (auto& b : v.bytes) b = static_cast<uint8_t>(rng());
        if (v.bytes[0] == 0) v.bytes[0] = 1;
        silkworm::rlp::encode(out, ByteView{v.bytes, 32});
    } else {
        const uint64_t x = (rng() % 0xFFFFFF) + 1;
        bytes32 v{};
        for (int i = 0; i < 8; ++i) v.bytes[31 - i] = static_cast<uint8_t>(x >> (8 * i));
        silkworm::rlp::encode(out, silkworm::zeroless_view(ByteView{v.bytes, 32}));
    }
    return out;
}

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) {
            sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp});
        };
    }
    for (const auto& [k, v] : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
    }
    return hb.root_hash();
}

std::vector<uint8_t> build_node_store(const Bytes32Map& nodes) {
    MphfBuilder<32> nb{kMphfNodeStoreMagic, kMphfMapVersion};
    for (const auto& [h, rlp] : nodes) {
        std::vector<uint8_t> body;
        FlatKv::encode(body, h, rlp);
        nb.add(hash_key8(h), ByteView{body.data(), body.size()});
    }
    return std::move(nb).finalize();
}

// One update: the key's pre value (empty: absent) and its new value (empty: delete).
struct Op {
    bytes32 key;
    Bytes pre;
    Bytes now;
};

// A key sharing exactly `shared` nibbles with `base`: the nibble at index `shared` differs, the
// rest is `fill`.
bytes32 key_sharing(const bytes32& base, size_t shared, std::mt19937_64& rng) {
    bytes32 k{};
    for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
    for (size_t i = 0; i < shared; ++i) {
        uint8_t nib = (i % 2 == 0) ? (base.bytes[i / 2] >> 4) : (base.bytes[i / 2] & 0x0F);
        uint8_t& dst = k.bytes[i / 2];
        dst = (i % 2 == 0) ? static_cast<uint8_t>((dst & 0x0F) | (nib << 4)) : static_cast<uint8_t>((dst & 0xF0) | nib);
    }
    const uint8_t bn = (shared % 2 == 0) ? (base.bytes[shared / 2] >> 4) : (base.bytes[shared / 2] & 0x0F);
    uint8_t& dst = k.bytes[shared / 2];
    const uint8_t cur = (shared % 2 == 0) ? (dst >> 4) : (dst & 0x0F);
    if (cur == bn) {
        const uint8_t flipped = (bn + 1 + rng() % 15) & 0x0F;
        dst = (shared % 2 == 0) ? static_cast<uint8_t>((dst & 0x0F) | (flipped << 4))
                                : static_cast<uint8_t>((dst & 0xF0) | flipped);
    }
    return k;
}

// Runs `ops` (sorted here) against a complete witness of `pre` and returns the root. `post` is
// filled with the trie the ops produce.
struct RunResult {
    bytes32 got;
    bytes32 expected;
    unsigned missing;
    bool failed;
};

template <bool Del>
RunResult run_ops(const Bytes32Map& pre, std::vector<Op> ops, const std::function<void(Bytes32Map&)>& tamper = {}) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    if (tamper) tamper(nodes);
    std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    std::ranges::sort(ops, [](const Op& a, const Op& b) { return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0; });
    Bytes32Map post = pre;
    std::vector<TrieNodeFlat> updates;
    updates.reserve(ops.size());
    for (const auto& op : ops) {
        auto& node = updates.emplace_back(op.key);
        node.self_initial_len = static_cast<uint8_t>(op.pre.size());
        std::memcpy(node.buf, op.pre.data(), op.pre.size());
        node.current_off = 40;
        if (op.now.empty()) {
            node.buf[40] = 0x80;
            node.current_len = 1;
            post.erase(op.key);
        } else {
            node.current_len = static_cast<uint8_t>(op.now.size());
            std::memcpy(node.buf + 40, op.now.data(), op.now.size());
            post[op.key] = op.now;
        }
    }
    GridMPT<Del> trie{direct, pre_root};
    RunResult r;
    r.got = trie.calc_root_from_updates({updates.data(), updates.size()});
    r.expected = hashbuilder_root(post, nullptr);
    r.missing = trie.missing_count();
    r.failed = false;
#ifndef NDEBUG
    r.failed = trie.failed();
#endif
    return r;
}

template <bool Del>
void check_ops(const Bytes32Map& pre, const std::vector<Op>& ops) {
    const auto r = run_ops<Del>(pre, ops);
    CAPTURE(silkworm::to_hex(r.got), silkworm::to_hex(r.expected));
    CHECK(r.missing == 0);
#ifndef NDEBUG
    CHECK_FALSE(r.failed);
#endif
    REQUIRE(r.got == r.expected);
}

// Every shared-prefix length at which a word-wise prefix compare changes behaviour: a word boundary, one
// either side of it, and the ends.
const std::vector<size_t> kShared = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 23, 24, 25, 31, 32,
                                     33, 47, 48, 49, 55, 56, 57, 60, 61, 62, 63};

#define CHECK_OPS(del, ...) \
    do { INFO("CHECK_OPS line " << __LINE__ << " deletion=" #del); check_ops<del>(__VA_ARGS__); } while (0)

}  // namespace

// Three keys: a, b sharing exactly p nibbles with a, c sharing exactly q with a. The pre trie holds a and b
// (a branch p nibbles down) or a only; the batch updates both and adds c, so the seek between consecutive
// keys compares prefixes of every length against a branch of every depth. A regression test of the seek's
// compare, which this change leaves as it was.
TEST_CASE("GridMPT roots match HashBuilder for prefixes around every word boundary", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c03};
    for (const size_t p : kShared) {
        for (const size_t q : kShared) {
            const bytes32 a = [&] {
                bytes32 k{};
                for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
                return k;
            }();
            const bytes32 b = key_sharing(a, p, rng);
            const bytes32 c = key_sharing(a, q, rng);
            if (std::memcmp(b.bytes, c.bytes, 32) == 0) continue;
            INFO("p=" << p << " q=" << q);

            const bool big = std::max(p, q) >= 52;
            const Bytes va = value_rlp(rng, big), vb = value_rlp(rng, big), vc = value_rlp(rng, big),
                        va2 = value_rlp(rng, big), vb2 = value_rlp(rng, big);

            Bytes32Map pre_ab{{a, va}, {b, vb}};
            CHECK_OPS(true, pre_ab, {{a, va, va2}, {b, vb, vb2}, {c, {}, vc}});
            CHECK_OPS(false, pre_ab, {{a, va, va2}, {b, vb, vb2}, {c, {}, vc}});
            // b modified only, c inserted: the seek after b compares against b's path.
            CHECK_OPS(true, pre_ab, {{b, vb, vb2}, {c, {}, vc}});
            CHECK_OPS(false, pre_ab, {{b, vb, vb2}, {c, {}, vc}});
            // deletes
            CHECK_OPS(true, pre_ab, {{a, va, {}}, {c, {}, vc}});
            CHECK_OPS(true, pre_ab, {{a, va, {}}, {b, vb, {}}, {c, {}, vc}});
            CHECK_OPS(true, pre_ab, {{b, vb, {}}, {c, {}, vc}});

            Bytes32Map pre_a{{a, va}};
            CHECK_OPS(true, pre_a, {{a, va, va2}, {b, {}, vb}, {c, {}, vc}});
            CHECK_OPS(false, pre_a, {{a, va, va2}, {b, {}, vb}, {c, {}, vc}});
            CHECK_OPS(false, {}, {{a, {}, va}, {b, {}, vb}, {c, {}, vc}});
            CHECK_OPS(true, {}, {{a, {}, va}, {b, {}, vb}, {c, {}, vc}});
        }
    }
}

// The same with a key that goes on past the branch: b shares exactly p nibbles with a, d shares exactly r > p
// with b, so after b (or d) the seek's compare reaches all of the parent's path and the leaf has to be split,
// the case where the compare's length decides between "same child" and "common parent".
TEST_CASE("GridMPT roots match HashBuilder when the next key shares the whole parent path",
          "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c07};
    for (const size_t p : kShared) {
        for (const size_t r : kShared) {
            if (r <= p) continue;
            bytes32 a{};
            for (auto& x : a.bytes) x = static_cast<uint8_t>(rng());
            const bytes32 b = key_sharing(a, p, rng);
            const bytes32 d = key_sharing(b, r, rng);
            const bytes32 e = key_sharing(d, std::min<size_t>(63, r + 1 + rng() % 3), rng);
            INFO("p=" << p << " r=" << r);
            const bool big = r >= 52;
            const Bytes va = value_rlp(rng, big), vb = value_rlp(rng, big), vd = value_rlp(rng, big),
                        ve = value_rlp(rng, big), vb2 = value_rlp(rng, big), va2 = value_rlp(rng, big);

            const Bytes32Map pre_ab{{a, va}, {b, vb}};
            CHECK_OPS(true, pre_ab, {{d, {}, vd}});
            CHECK_OPS(false, pre_ab, {{d, {}, vd}});
            CHECK_OPS(true, pre_ab, {{b, vb, vb2}, {d, {}, vd}});
            CHECK_OPS(false, pre_ab, {{b, vb, vb2}, {d, {}, vd}});
            CHECK_OPS(true, pre_ab, {{a, va, va2}, {b, vb, vb2}, {d, {}, vd}, {e, {}, ve}});
            CHECK_OPS(false, pre_ab, {{a, va, va2}, {b, vb, vb2}, {d, {}, vd}, {e, {}, ve}});
            CHECK_OPS(true, pre_ab, {{b, vb, {}}, {d, {}, vd}, {e, {}, ve}});
            CHECK_OPS(true, pre_ab, {{a, va, {}}, {b, vb, {}}, {d, {}, vd}});
            CHECK_OPS(false, {}, {{a, {}, va}, {b, {}, vb}, {d, {}, vd}, {e, {}, ve}});
            CHECK_OPS(true, {}, {{a, {}, va}, {b, {}, vb}, {d, {}, vd}, {e, {}, ve}});
        }
    }
}

// Random pre tries and batches over keys drawn from a few clusters whose members share long prefixes
// (so branches sit deep and the compare runs over many words), with modified, deleted and inserted
// keys.
TEST_CASE("GridMPT roots match HashBuilder on random clustered batches", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c04};
    for (int iter = 0; iter < 150; ++iter) {
        const size_t clusters = 1 + rng() % 4;
        std::vector<bytes32> centres(clusters);
        for (auto& c : centres)
            for (auto& b : c.bytes) b = static_cast<uint8_t>(rng());
        const auto draw = [&] {
            const bytes32& c = centres[rng() % clusters];
            return key_sharing(c, rng() % 49, rng);  // pairs sharing 56+ nibbles are out of reach
        };

        Bytes32Map pre;
        const size_t pre_n = rng() % 60;
        for (size_t i = 0; i < pre_n; ++i) pre[draw()] = value_rlp(rng);

        std::map<bytes32, Op, Bytes32Less> ops;
        const size_t ops_n = 1 + rng() % 80;
        for (size_t i = 0; i < ops_n; ++i) {
            const bool existing = !pre.empty() && rng() % 2;
            bytes32 k;
            if (existing) {
                auto it = pre.begin();
                std::advance(it, rng() % pre.size());
                k = it->first;
            } else {
                k = draw();
            }
            Op op{k, {}, {}};
            if (auto it = pre.find(k); it != pre.end()) op.pre = it->second;
            op.now = (!op.pre.empty() && rng() % 3 == 0) ? Bytes{} : value_rlp(rng);
            if (op.pre.empty() && op.now.empty()) continue;
            ops[k] = op;
        }
        std::vector<Op> v;
        for (auto& [k, op] : ops) v.push_back(op);
        INFO("iter=" << iter << " pre=" << pre.size() << " ops=" << v.size());
        CHECK_OPS(true, pre, v);
        // GridMPT<false> takes no deletes: turn them into updates.
        for (auto& op : v)
            if (op.now.empty()) op.now = value_rlp(rng);
        CHECK_OPS(false, pre, v);
    }
}

// ---------------------------------------------------------------------------------------------
// Forged witness nodes.
// ---------------------------------------------------------------------------------------------

namespace {

bool unfolds_at(const uint8_t* node, size_t size, unsigned misalign) {
    static std::vector<uint8_t> prestate =
        DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    DirectState direct{std::span<uint8_t>{prestate}};
    GridMPT<false> trie{direct, silkworm::kEmptyRoot};
    Placed p{size, misalign};
    std::memcpy(p.at, node, size);
    return trie.unfold_node_from_rlp(ByteView{p.at, size}, /*parent_slot=*/0, /*parent_depth=*/0);
}

Bytes list_of(const Bytes& inner) {
    Bytes node;
    silkworm::rlp::encode_header(node, {.list = true, .payload_length = inner.size()});
    node.append(inner);
    return node;
}

// A leaf: list(HP path of 64 nibbles, value of `value_len` bytes).
Bytes leaf_with_value(size_t value_len) {
    Bytes inner;
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = 33});
    inner.push_back(0x20);
    inner.append(32, 0x11);
    silkworm::rlp::encode_header(inner, {.list = false, .payload_length = value_len});
    inner.append(value_len, 0x5A);
    return list_of(inner);
}

// A branch: 16 hash children of 33 bytes and an empty value (532 bytes of payload, a 3-byte header).
Bytes full_branch() {
    Bytes inner;
    for (int i = 0; i < 16; ++i) {
        inner.push_back(0xa0);
        inner.append(32, static_cast<uint8_t>(0x30 + i));
    }
    inner.push_back(0x80);
    return list_of(inner);
}

}  // namespace

// A valid node unfolds, and a forged one does not, whatever the payload's alignment: the header read must
// not make acceptance depend on it. Covers outer headers with one, two and three length bytes.
TEST_CASE("unfold_node_from_rlp accepts and rejects the same at every alignment", "[trie][gridmpt][wordload]") {
    // Valid nodes: leaf (1-byte length header: 0xf8 xx), branch (0xf9 xx xx), extension.
    const std::vector<Bytes> valid = {leaf_with_value(4), leaf_with_value(40), full_branch()};
    REQUIRE(valid[0][0] < 0xf8);
    REQUIRE(valid[1][0] == 0xf8);
    REQUIRE(valid[2][0] == 0xf9);
    for (const auto& node : valid)
        for (unsigned m = 0; m < 4; ++m) CHECK(unfolds_at(node.data(), node.size(), m));

    // Forged: a header length off by one or two, a truncated node, a string header in place of the list, an
    // empty list followed by junk. The verdict must be the same at every alignment; the ones that cannot
    // be a node at all (not a list, empty, cut inside the header or the path) must be rejected.
    for (const auto& node : valid) {
        std::vector<std::pair<Bytes, bool>> forged;  // node, must be rejected
        // The last byte of the header is the low byte of the length (or the length itself, in the short form).
        const size_t last = node[0] == 0xf9 ? 2 : node[0] == 0xf8 ? 1 : 0;
        for (int delta : {-1, 1, 2}) {
            Bytes f = node;
            f[last] = static_cast<uint8_t>(f[last] + delta);
            forged.emplace_back(f, false);
        }
        forged.emplace_back(Bytes{node.begin(), node.end() - 1}, false);
        forged.emplace_back(Bytes{node.begin(), node.begin() + 7}, true);
        forged.emplace_back(Bytes{node.begin(), node.begin() + 3}, true);
        {
            Bytes f = node;
            f[0] = static_cast<uint8_t>(f[0] - 0x40);  // 0xf8 -> 0xb8, 0xe7 -> 0xa7: a string, not a list
            forged.emplace_back(f, true);
        }
        {
            Bytes f = node;
            f[0] = 0xc0;  // an empty list followed by junk
            forged.emplace_back(f, true);
        }
        for (const auto& [f, must_reject] : forged) {
            const bool aligned = unfolds_at(f.data(), f.size(), 0);
            INFO("forged node of " << f.size() << " bytes, first byte " << int(f[0]));
            if (must_reject) CHECK_FALSE(aligned);
            for (unsigned m = 1; m < 4; ++m) CHECK(unfolds_at(f.data(), f.size(), m) == aligned);
        }
    }
}

// Every single-byte corruption of a valid node, at every alignment: the verdict is the same at all four.
TEST_CASE("unfold_node_from_rlp verdict is alignment independent under byte flips", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c05};
    for (const Bytes& node : {leaf_with_value(4), full_branch()}) {
        for (size_t pos = 0; pos < std::min<size_t>(node.size(), 40); ++pos) {
            for (int rep = 0; rep < 6; ++rep) {
                Bytes f = node;
                f[pos] = static_cast<uint8_t>(f[pos] ^ (1 + rng() % 255));
                const bool aligned = unfolds_at(f.data(), f.size(), 0);
                for (unsigned m = 1; m < 4; ++m) {
                    INFO("pos=" << pos << " misalign=" << m);
                    CHECK(unfolds_at(f.data(), f.size(), m) == aligned);
                }
            }
        }
    }
}

// A witness node is bound to its hash: with one byte of a node flipped under the original hash, the node
// is not used, whatever the byte (the header bytes the word load reads included), so the root of the
// batch is not the canonical one. The batch touches every leaf but `a`, so no node but the one holding
// `a` is left unread (it stays a hash in its parent, and a flip in it changes nothing), and the root
// cannot be rebuilt from the batch alone. Each node is therefore either read, and then every flip of it
// is rejected, or unread, and then none is; at most one node is unread.
TEST_CASE("a tampered witness never yields the canonical root", "[trie][gridmpt][wordload]") {
    std::mt19937_64 rng{0x6d77'6c06};
    const bytes32 a = [&] {
        bytes32 k{};
        for (auto& b : k.bytes) b = static_cast<uint8_t>(rng());
        return k;
    }();
    Bytes32Map pre;
    std::vector<Op> ops;
    for (const size_t shared : {size_t{2}, size_t{3}, size_t{4}, size_t{9}, size_t{31}}) {
        const bytes32 k = key_sharing(a, shared, rng);
        pre[k] = value_rlp(rng);
    }
    pre[a] = value_rlp(rng, /*big=*/true);
    for (const auto& [k, v] : pre)
        if (std::memcmp(k.bytes, a.bytes, 32) != 0) ops.push_back({k, v, value_rlp(rng)});

    {  // The untampered batch gives the canonical root.
        const auto r = run_ops<true>(pre, ops);
        REQUIRE(r.got == r.expected);
        REQUIRE(r.missing == 0);
    }

#ifdef NDEBUG
    // A tampered node makes failed() true in a Debug build, where calc_root_from_updates asserts on it
    // before the batch is applied; the release build is the one that has to reject the root.
    size_t tampers = 0;
    size_t unread_nodes = 0;
    Bytes32Map nodes;
    hashbuilder_root(pre, &nodes);
    for (const auto& [h, rlp] : nodes) {
        size_t rejected = 0;
        for (size_t pos = 0; pos < rlp.size(); ++pos) {
            const auto r = run_ops<true>(pre, ops, [&](Bytes32Map& n) {
                n[h][pos] = static_cast<uint8_t>(n[h][pos] ^ (1 + (pos * 37 + 11) % 255));
            });
            ++tampers;
            if (r.got != r.expected || r.missing != 0 || r.failed) ++rejected;
        }
        INFO("node " << silkworm::to_hex(ByteView{h.bytes, 32}) << " of " << rlp.size() << " bytes, first byte "
                     << int(rlp[0]));
        CHECK((rejected == 0 || rejected == rlp.size()));
        if (rejected == 0) ++unread_nodes;
    }
    CHECK(unread_nodes <= 1);
    CHECK(nodes.size() >= 6);
    CHECK(tampers > 200);
#endif
}
