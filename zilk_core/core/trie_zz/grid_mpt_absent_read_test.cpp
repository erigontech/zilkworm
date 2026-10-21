// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// GridMPT<true, DirectState> regression tests: updates that read a key the trie does not have (no value to
// write; claimed as zero, 0x80, or as nothing), and lines that go away while the seek still
// climbs through them.
//
// A read of an absent key used to insert a leaf with an empty value at the point where the key
// leaves the trie, which folded away again. Folding it deleted it and every ancestor it left empty
// (cascade_delete), and the seek went on from lines it had just popped; and a branch left with a
// single child the walk had already folded could not absorb it, the new hash not being in the
// witness. A read of an absent key now inserts nothing, and a witness leaf without a value, the
// other way an empty line got into the grid, is rejected.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    if (leaves.empty()) return silkworm::kEmptyRoot;
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) { sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp}); };
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

bytes32 key_from_hex(const char* s) {
    const auto b = silkworm::from_hex(s);
    REQUIRE((b && b->size() == 32));
    bytes32 k;
    std::memcpy(k.bytes, b->data(), 32);
    return k;
}

// A hashed trie key: the given nibbles, then `fill` repeated.
bytes32 key_with_nibbles(std::initializer_list<uint8_t> nibs, uint8_t fill) {
    bytes32 k{};
    size_t i = 0;
    for (uint8_t n : nibs) {
        k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? n << 4 : n);
        ++i;
    }
    for (; i < 64; ++i) k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? fill << 4 : fill);
    return k;
}

Bytes value(uint8_t v) { return Bytes{0x84, v, v, v, v}; }

Bytes claim_of(ByteView cell) { return Bytes(cell.begin() + 1, cell.end()); }

// What an update claims as the value before the block for a key absent from the trie: a zero slot (0x80)
// or nothing. A claim of an empty value must not be a null view: a forged empty-valued leaf is compared
// against it.
enum class Claim { kZero, kNone };
const uint8_t kZeroRlp[1] = {0x80};

struct Update {
    bytes32 key;
    ByteView initial;
    Bytes current;  // empty: a read
};

// Runs `updates` (sorted here) against a complete witness of the trie `pre` (leaves as given, an
// empty value included) and returns the root. `valid`: the witness holds only nodes a trie can have.
bytes32 walk(const Bytes32Map& pre, std::vector<Update> updates, bool valid = true) {
    Bytes32Map nodes;
    const bytes32 pre_root = hashbuilder_root(pre, &nodes);
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};

    std::ranges::sort(updates, [](const Update& a, const Update& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });
    std::vector<TrieNodeFlat> flat;  // must never reallocate: GridMPT keeps views into TrieNodeFlat::buf
    flat.reserve(updates.size());
    for (const auto& u : updates) {
        auto& node = flat.emplace_back(u.key);
        node.ext_initial = u.initial;
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(u.current.size());
        if (!u.current.empty()) std::memcpy(node.buf + 40, u.current.data(), u.current.size());
    }
    GridMPT<true, DirectState> trie{direct, pre_root};
    const bytes32 got = trie.calc_root_from_updates({flat.data(), flat.size()});
    if (valid) {
        CHECK(trie.missing_count() == 0);
        CHECK_FALSE(trie.failed());
    } else {
        CHECK(trie.failed());
    }
    return got;
}

}  // namespace

// Two reads of absent keys that share 8 nibbles, after an insert: the second read split the first one's
// empty leaf into an extension over a branch of the two, all of it empty. The next update's seek folded
// both leaves, the cascade took the branch and the extension, and the seek went on to the popped
// extension's line and descended from it, into std::unreachable() in fold_line.
TEST_CASE("GridMPT<true, DirectState> reads of absent keys that share a prefix", "[trie][gridmpt]") {
    const bytes32 k1 = key_from_hex("6d6c288fd01ac4893bdbcdc3b9717bba13a845056ba772398a7eaae0fffa47d9");
    const bytes32 a1 = key_from_hex("8600baa419999186f17a33e3b26008a6485f6a918223719d7d3a6f39092c4621");
    const bytes32 a2 = key_from_hex("8600baa43020cf1673e00210b7a2eccfc4fb8711dbda71bddfe0d69722b4aa79");
    const bytes32 k4 = key_from_hex("895ee3e68994cc766f08bfa57440dc818ebc401ba875058cc9e979ef89f132f1");
    for (const Claim claim : {Claim::kZero, Claim::kNone}) {
        const ByteView absent = claim == Claim::kZero ? ByteView{kZeroRlp, 1} : ByteView{};
        CAPTURE(claim == Claim::kZero);
        const bytes32 got = walk({}, {{k1, {}, value(1)}, {a1, absent, {}}, {a2, absent, {}}, {k4, {}, value(4)}});
        CHECK(got == hashbuilder_root({{k1, value(1)}, {k4, value(4)}}, nullptr));
    }
}

// A read of an absent key that leaves an extension inside its path, then a write below that extension.
// The read split the extension into a branch over its empty leaf and the extension's child; the write
// folded that child into the branch with a new hash, and only then did the empty leaf fold away, leaving
// the branch a single child to absorb whose hash the witness does not have.
TEST_CASE("GridMPT<true, DirectState> read of an absent key inside an extension before a write below it", "[trie][gridmpt]") {
    // branch{2 -> ext(0,2) -> branch{0 -> K0, 1 -> ext(2) -> branch{0 -> K1, 1 -> K2}}, 7 -> R}; the absent
    // key goes 2,0,2,1 then 0, where the inner extension has 2.
    const bytes32 k0 = key_with_nibbles({2, 0, 2, 0}, 1);
    const bytes32 k1 = key_with_nibbles({2, 0, 2, 1, 2, 0}, 2);
    const bytes32 k2 = key_with_nibbles({2, 0, 2, 1, 2, 1}, 3);
    const bytes32 r = key_with_nibbles({7}, 4);
    const bytes32 absent_key = key_with_nibbles({2, 0, 2, 1, 0}, 5);
    const Bytes32Map pre{{k0, value(1)}, {k1, value(2)}, {k2, value(3)}, {r, value(4)}};
    for (const Claim claim : {Claim::kZero, Claim::kNone}) {
        const ByteView absent = claim == Claim::kZero ? ByteView{kZeroRlp, 1} : ByteView{};
        CAPTURE(claim == Claim::kZero);
        const Bytes v3 = pre.at(k2);
        const bytes32 got = walk(pre, {{absent_key, absent, {}}, {k2, ByteView{v3}, value(9)}});
        Bytes32Map post = pre;
        post[k2] = value(9);
        CHECK(got == hashbuilder_root(post, nullptr));
    }
}

// A forged witness: two leaves without a value under an extension, which the batch reads as such. As
// with the empty leaves above, the next update's seek folded them, the cascade took the branch and the
// extension too, and the seek descended from the popped extension's line, into std::unreachable(). No
// trie has a leaf without a value: decode_node() rejects it, and the walk fails.
TEST_CASE("GridMPT<true, DirectState> rejects a witness leaf without a value", "[trie][gridmpt]") {
    const bytes32 k1 = key_from_hex("6d6c288fd01ac4893bdbcdc3b9717bba13a845056ba772398a7eaae0fffa47d9");
    const bytes32 a1 = key_from_hex("8600baa419999186f17a33e3b26008a6485f6a918223719d7d3a6f39092c4621");
    const bytes32 a2 = key_from_hex("8600baa43020cf1673e00210b7a2eccfc4fb8711dbda71bddfe0d69722b4aa79");
    const bytes32 k4 = key_from_hex("895ee3e68994cc766f08bfa57440dc818ebc401ba875058cc9e979ef89f132f1");
    const Bytes32Map pre{{k1, value(1)}, {a1, Bytes{}}, {a2, Bytes{}}};
    const ByteView empty{kZeroRlp, 0};
    CHECK(walk(pre, {{a1, empty, {}}, {a2, empty, {}}, {k4, {}, value(4)}}, /*valid=*/false) == bytes32{});
}

// hand-built shapes mainnet witnesses never emit

namespace {

Bytes rlp_str(ByteView s) {
    Bytes out;
    if (s.size() == 1 && s[0] < 0x80) {
        out.push_back(s[0]);
    } else if (s.size() < 56) {
        out.push_back(static_cast<uint8_t>(0x80 + s.size()));
        out.append(s);
    } else if (s.size() < 0x100) {
        out.push_back(0xf8);
        out.push_back(static_cast<uint8_t>(s.size()));
        out.append(s);
    } else {
        out.push_back(0xf9);
        out.push_back(static_cast<uint8_t>(s.size() >> 8));
        out.push_back(static_cast<uint8_t>(s.size() & 0xFF));
        out.append(s);
    }
    return out;
}

Bytes rlp_list(const std::vector<Bytes>& items) {
    size_t n = 0;
    for (const auto& i : items) n += i.size();
    Bytes out;
    if (n < 56) {
        out.push_back(static_cast<uint8_t>(0xc0 + n));
    } else if (n < 0x100) {
        out.push_back(0xf8);
        out.push_back(static_cast<uint8_t>(n));
    } else {
        out.push_back(0xf9);
        out.push_back(static_cast<uint8_t>(n >> 8));
        out.push_back(static_cast<uint8_t>(n & 0xFF));
    }
    for (const auto& i : items) out.append(i);
    return out;
}

Bytes hp_encode(std::vector<uint8_t> nibs, bool leaf) {
    Bytes p;
    size_t i = 0;
    if (nibs.size() % 2 != 0) {
        p.push_back(static_cast<uint8_t>((leaf ? 0x20 : 0x00) | 0x10 | nibs[0]));
        i = 1;
    } else {
        p.push_back(static_cast<uint8_t>(leaf ? 0x20 : 0x00));
    }
    for (; i + 1 < nibs.size(); i += 2) p.push_back(static_cast<uint8_t>(nibs[i] << 4 | nibs[i + 1]));
    return rlp_str(p);
}

Bytes node_leaf(std::vector<uint8_t> path, ByteView v) { return rlp_list({hp_encode(std::move(path), true), Bytes{v}}); }

Bytes node_ext(std::vector<uint8_t> path, ByteView child_item) {
    return rlp_list({hp_encode(std::move(path), false), Bytes{child_item}});
}

Bytes node_branch(std::vector<Bytes> child_items, ByteView value = {}) {
    child_items.resize(16, Bytes{0x80});
    child_items.push_back(value.empty() ? Bytes{0x80} : Bytes{value});
    return rlp_list(child_items);
}

Bytes child_hash_ref(const bytes32& h) {
    Bytes s;
    s.push_back(0xa0);
    s.append(h.bytes, 32);
    return s;
}

// branch cells: raw list, not wrapped
// ext child must be a string
Bytes child_embed(const Bytes& node) { return node; }

bytes32 put(Bytes32Map& nodes, const Bytes& rlp) {
    const bytes32 h = keccak_bytes(rlp);
    nodes.emplace(h, Bytes{rlp});
    return h;
}

struct ReadResult {
    bytes32 root;
    bool failed;
    unsigned missing;
};

ReadResult read_walk(const Bytes32Map& nodes, bytes32 root, std::vector<Update> reads, bool light) {
    std::ranges::sort(reads, [](const Update& a, const Update& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, {}, {});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    std::vector<TrieNodeFlat> flat;
    flat.reserve(reads.size());
    for (const auto& u : reads) {
        auto& node = flat.emplace_back(u.key);
        node.ext_initial = u.initial;
        node.current_off = 40;
        node.current_len = 0;
    }
    GridMPT<true, DirectState> trie{direct, root};
    if (light) trie.enable_light_read_only();
    const bytes32 got = trie.calc_root_from_updates({flat.data(), flat.size()});
    return {got, trie.failed(), trie.missing_count()};
}

bytes32 chain_to(Bytes32Map& nodes, const std::vector<uint8_t>& prefix, Bytes bottom) {
    Bytes node = std::move(bottom);
    for (size_t i = prefix.size(); i-- > 0;) {
        std::vector<Bytes> items(16, Bytes{0x80});
        items[prefix[i]] = child_hash_ref(put(nodes, node));
        items[(prefix[i] + 7u) % 16u] = child_hash_ref(bytes32{});  // two children, no absorb
        node = node_branch(std::move(items));
    }
    return put(nodes, node);
}

void expect_agree(const Bytes32Map& nodes, bytes32 root, std::vector<Update> reads, const bytes32& want) {
    const auto a = read_walk(nodes, root, reads, false);
    const auto b = read_walk(nodes, root, reads, true);
    CHECK(a.root == b.root);
    CHECK(a.failed == b.failed);
    CHECK(a.missing == b.missing);
    CHECK(a.root == want);
    CHECK(a.failed == (want == bytes32{}));
}

// lone-child fold fails soft; misses bump
void expect_soft(const Bytes32Map& nodes, bytes32 root, std::vector<Update> reads, unsigned missing) {
    const auto a = read_walk(nodes, root, reads, false);
    const auto b = read_walk(nodes, root, reads, true);
    CHECK(a.root == b.root);
    CHECK(a.root == root);
    CHECK(a.failed == b.failed);
    CHECK(a.failed);
    CHECK(a.missing == b.missing);
    CHECK(a.missing == missing);
}


struct MixResult {
    bytes32 root;
    bool failed;
    unsigned missing;
};

MixResult mix_walk(const Bytes32Map& nodes, bytes32 root, std::vector<Update> updates, bool light) {
    std::ranges::sort(updates, [](const Update& a, const Update& b) {
        return std::memcmp(a.key.bytes, b.key.bytes, 32) < 0;
    });
    std::vector<uint8_t> prestate = DirectState::build_blob_from_accounts({}, {}, {});
    std::vector<uint8_t> nodestore = build_node_store(nodes);
    DirectState direct{std::span<uint8_t>{prestate}, std::span<uint8_t>{nodestore}};
    std::vector<TrieNodeFlat> flat;
    flat.reserve(updates.size());
    for (const auto& u : updates) {
        auto& node = flat.emplace_back(u.key);
        node.ext_initial = u.initial;
        node.current_off = 40;
        node.current_len = static_cast<uint8_t>(u.current.size());
        if (!u.current.empty()) std::memcpy(node.buf + 40, u.current.data(), u.current.size());
    }
    GridMPT<true, DirectState> trie{direct, root};
    if (light) trie.enable_light_read_only();
    const bytes32 got = trie.calc_root_from_updates({flat.data(), flat.size()});
    return {got, trie.failed(), trie.missing_count()};
}

void expect_mix(const Bytes32Map& nodes, bytes32 root, std::vector<Update> updates, const bytes32& want) {
    const auto a = mix_walk(nodes, root, updates, false);
    const auto b = mix_walk(nodes, root, updates, true);
    CHECK(a.root == b.root);
    CHECK(a.failed == b.failed);
    CHECK(a.missing == b.missing);
    CHECK(a.root == want);
    CHECK(a.failed == (want == bytes32{}));
}

}  // namespace

TEST_CASE("GridMPT light read-only descent agrees with the grid walk, HashBuilder tries", "[trie][gridmpt]") {
    const bytes32 k0 = key_with_nibbles({2, 0}, 1);
    const bytes32 k1 = key_with_nibbles({2, 0, 2, 0}, 2);
    const bytes32 k2 = key_with_nibbles({2, 0, 2, 1}, 3);
    const bytes32 r = key_with_nibbles({7}, 4);
    Bytes32Map pre{{k0, value(1)}, {k1, value(2)}, {k2, value(3)}, {r, value(4)}};
    Bytes32Map nodes;
    const bytes32 root = hashbuilder_root(pre, &nodes);

    const ByteView z{kZeroRlp, 1};
    expect_agree(nodes, root, {{k0, value(1), {}}, {k1, value(2), {}}, {k2, value(3), {}}, {r, value(4), {}}}, root);
    expect_agree(nodes, root, {{key_with_nibbles({2, 0, 2, 5}, 5), z, {}},
                               {key_with_nibbles({2, 0, 1}, 6), z, {}},
                               {key_with_nibbles({2, 0, 2, 1, 9}, 7), z, {}}},
               root);
    expect_agree(nodes, root, {{k1, {}, {}}}, {});
    expect_agree(nodes, root, {{key_with_nibbles({2, 0, 2, 5}, 5), value(8), {}}}, {});
    expect_agree(nodes, root, {{k2, value(9), {}}}, {});
    Bytes32Map none;
    expect_agree(none, silkworm::kEmptyRoot, {{k0, z, {}}, {k2, ByteView{}, {}}}, silkworm::kEmptyRoot);
    expect_agree(none, silkworm::kEmptyRoot, {{k0, value(1), {}}}, {});
    expect_agree(nodes, root, {}, root);
    expect_agree(none, silkworm::kEmptyRoot, {}, silkworm::kEmptyRoot);
}

TEST_CASE("GridMPT light read-only descent agrees on embedded nodes, the 17th value, and full branches",
          "[trie][gridmpt]") {
    const ByteView z{kZeroRlp, 1};

// embedded leaf cells cap at 31 B
    const Bytes v3a{0x83, 0x11, 0x11, 0x11};
    const Bytes v3b{0x83, 0x22, 0x22, 0x22};
    const Bytes v4{0x84, 0x33, 0x33, 0x33, 0x33};

    std::vector<uint8_t> pre20;
    for (uint8_t i = 0; i < 20; ++i) pre20.push_back(static_cast<uint8_t>((i * 7 + 3) % 16));

    const auto key_of = [](std::vector<uint8_t> nibs, uint8_t fill) {
        nibs.resize(64, fill);
        bytes32 k{};
        for (size_t i = 0; i < 64; ++i) {
            k.bytes[i / 2] |= static_cast<uint8_t>(i % 2 == 0 ? nibs[i] << 4 : nibs[i]);
        }
        return k;
    };

    {
        Bytes32Map nodes;
        std::vector<uint8_t> emb_nibs = pre20;
        emb_nibs.push_back(4);
        const Bytes emb_leaf = node_leaf(std::vector<uint8_t>(43, 0xA), v3a);
        REQUIRE(emb_leaf.size() < 31);
        std::vector<uint8_t> hash_nibs = pre20;
        hash_nibs.push_back(9);
        const Bytes hash_leaf = node_leaf(std::vector<uint8_t>(43, 0xB), v3b);
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            if (i == 4) kids.push_back(child_embed(emb_leaf));
            else if (i == 9) kids.push_back(child_hash_ref(put(nodes, hash_leaf)));
            else kids.push_back(Bytes{0x80});
        }
        const bytes32 root = chain_to(nodes, pre20, node_branch(std::move(kids)));
        const bytes32 k_emb = key_of(emb_nibs, 0xA);
        const bytes32 k_hash = key_of(hash_nibs, 0xB);
        CHECK(emb_leaf.size() == 28);
        expect_agree(nodes, root, {{k_emb, claim_of(v3a), {}}, {k_hash, claim_of(v3b), {}}}, root);
        expect_agree(nodes, root, {{k_emb, claim_of(v3b), {}}}, {});  // wrong pre-value on the embedded leaf
        std::vector<uint8_t> empty_slot = pre20;
        empty_slot.push_back(7);
        expect_agree(nodes, root, {{key_of(empty_slot, 0xC), z, {}}}, root);
        auto diverge = emb_nibs;
        diverge.resize(64, 0xD);
        diverge[23] ^= 0xF;
        expect_agree(nodes, root, {{key_of(diverge, 0xD), z, {}}}, root);
    }

// fat cell rejects whole branch
    {
        Bytes32Map nodes;
        std::vector<uint8_t> fat_nibs = pre20;
        fat_nibs.push_back(12);
        const Bytes fat_leaf = node_leaf(std::vector<uint8_t>(43, 0xE), Bytes(20, 0x41));
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 12 ? child_embed(fat_leaf) : Bytes{0x80});
        }
        const bytes32 root = chain_to(nodes, pre20, node_branch(std::move(kids)));
        expect_agree(nodes, root, {{key_of(fat_nibs, 0xE), z, {}}}, {});
        std::vector<uint8_t> other = pre20;
        other.push_back(3);
        expect_agree(nodes, root, {{key_of(other, 0xC), z, {}}}, {});
    }

// ext fetches child only on full match
    {
        Bytes32Map nodes;
        std::vector<uint8_t> nibs = pre20;
        nibs.push_back(6);
        const Bytes leaf = node_leaf(std::vector<uint8_t>(43, 0xA), v3a);  
        CHECK(leaf.size() == 28);
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 6 ? child_hash_ref(put(nodes, leaf))
                                  : i == 1 ? child_hash_ref(bytes32{})  // never unfolded
                                           : Bytes{0x80});
        }
        const bytes32 br = put(nodes, node_branch(std::move(kids)));
        const Bytes ext = node_ext(pre20, child_hash_ref(br));
        const bytes32 root = put(nodes, ext);
        const bytes32 k = key_of(nibs, 0xA);
        expect_agree(nodes, root, {{k, claim_of(v3a), {}}}, root);
        expect_agree(nodes, root, {{k, {}, {}}}, {});  // present key claimed absent
        auto div_ext = pre20;
        div_ext[5] ^= 0xF;
        expect_agree(nodes, root, {{key_of(div_ext, 0xB), z, {}}}, root);  // diverges in the extension
        auto div_leaf = nibs;
        div_leaf.resize(64, 0xC);
        div_leaf[25] ^= 0xF;
        expect_agree(nodes, root, {{key_of(div_leaf, 0xC), z, {}}}, root);  // diverges in the leaf
    }

    {
        Bytes32Map nodes;
        std::vector<uint8_t> nibs = pre20;
        nibs.push_back(6);
        std::vector<uint8_t> leaf_path{6};
        leaf_path.insert(leaf_path.end(), 43, 0xA);
        const Bytes leaf = node_leaf(leaf_path, v3a);
        const Bytes ext = node_ext(pre20, rlp_str(leaf));  // decodes, never unfolds
        const bytes32 root = put(nodes, ext);
        const bytes32 k = key_of(nibs, 0xA);
        expect_agree(nodes, root, {{k, claim_of(v3a), {}}}, {});
        auto div_ext = pre20;
        div_ext[5] ^= 0xF;
        expect_agree(nodes, root, {{key_of(div_ext, 0xB), z, {}}}, root);  // diverges before the child
    }

    {
        Bytes32Map nodes;
        std::vector<uint8_t> nibs = pre20;
        const Bytes v6{0x86, 1, 2, 3, 4, 5, 6};
        const Bytes leaf32 = node_leaf(std::vector<uint8_t>(44, 0xA), v6);  // a list, not a string
        REQUIRE(leaf32.size() == 32);
        const bytes32 root32 = put(nodes, node_ext(pre20, child_embed(leaf32)));
        expect_agree(nodes, root32, {{key_of(nibs, 0xA), v6, {}}}, {});
        auto div = pre20;
        div[7] ^= 0xF;  // root itself rejected
        expect_agree(nodes, root32, {{key_of(div, 0xB), z, {}}}, {});
        const Bytes v7{0x87, 1, 2, 3, 4, 5, 6, 7};
        const Bytes leaf33 = node_leaf(std::vector<uint8_t>(44, 0xA), v7);
        REQUIRE(leaf33.size() == 33);
        const bytes32 root33 = put(nodes, node_ext(pre20, child_embed(leaf33)));
        expect_agree(nodes, root33, {{key_of(nibs, 0xA), z, {}}}, {});
        const bytes32 root_big = put(nodes, node_ext(pre20, rlp_str(leaf33)));  // 34 B overflows ext.child
        expect_agree(nodes, root_big, {{key_of(nibs, 0xA), z, {}}}, {});
        const bytes32 root_junk = put(nodes, node_ext(pre20, Bytes{0xc0}));  
        expect_agree(nodes, root_junk, {{key_of(nibs, 0xA), z, {}}}, {});
    }

    {
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 2 ? child_hash_ref(bytes32{}) : Bytes{0x80});
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        expect_soft(nodes, root, {{key_with_nibbles({7}, 7), z, {}}}, 1);
        expect_agree(nodes, root, {{key_with_nibbles({2}, 2), z, {}}}, {});  // the missing cell: hard fail
    }

    {
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 6 ? Bytes{0xc0} : Bytes{0x80});
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        expect_agree(nodes, root, {{key_with_nibbles({6}, 6), z, {}}}, {});
        expect_soft(nodes, root, {{key_with_nibbles({7}, 7), z, {}}}, 0);
    }

    {
        Bytes32Map nodes;
        std::vector<uint8_t> nibs = pre20;
        nibs.push_back(1);
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 1 ? child_embed(node_leaf(std::vector<uint8_t>(43, 0xA), v3a))
                                  : Bytes{0x80});
        }
        const bytes32 root = chain_to(nodes, pre20, node_branch(std::move(kids), v4));
        expect_agree(nodes, root, {{key_of(nibs, 0xA), v3a, {}}}, {});
    }

// exercises full-branch fast path
    {
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        std::vector<Update> reads;
        std::vector<Bytes> claims;
        claims.reserve(16);
        for (uint8_t i = 0; i < 16; ++i) {
            const Bytes leaf = node_leaf(std::vector<uint8_t>(63, i), value(i + 1));
            kids.push_back(child_hash_ref(put(nodes, leaf)));
            claims.push_back(claim_of(value(i + 1)));
            reads.push_back({key_with_nibbles({i}, i), ByteView{claims.back()}, {}});
        }
        const Bytes br = node_branch(kids);
        REQUIRE(br.size() == 16 * 33 + 4);  // 0xf9 long-form list header
        const bytes32 root = put(nodes, br);
        expect_agree(nodes, root, reads, root);
        auto bad = reads;
        claims.push_back(claim_of(value(99)));
        bad[3].initial = ByteView{claims.back()};
        expect_agree(nodes, root, bad, {});
    }

    {
        Bytes32Map nodes;
        const bytes32 root = put(nodes, node_leaf(std::vector<uint8_t>(64, 1), {}));
        expect_agree(nodes, root, {{key_with_nibbles({1}, 1), z, {}}}, {});

        Bytes32Map nodes2;
        const bytes32 bad_root = put(nodes2, Bytes{0x84, 1, 2, 3, 4});
        expect_agree(nodes2, bad_root, {{key_with_nibbles({0}, 0), z, {}}}, {});
        expect_agree(nodes2, bad_root, {}, {});
    }
}

// light takes only never-unfolded slots

TEST_CASE("GridMPT reads inside write walks agree with the grid walk, HashBuilder tries", "[trie][gridmpt][phase2]") {
    const bytes32 ka = key_with_nibbles({2, 0}, 1);
    const bytes32 kb = key_with_nibbles({2, 1, 2, 0}, 2);
    const bytes32 kc = key_with_nibbles({2, 1, 2, 1}, 3);
    const bytes32 kr = key_with_nibbles({7}, 4);
    const bytes32 ax = key_with_nibbles({2, 0, 5}, 5);
    const bytes32 ay = key_with_nibbles({2, 1, 3}, 6);
    const ByteView z{kZeroRlp, 1};
    Bytes32Map pre{{ka, value(1)}, {kb, value(2)}, {kc, value(3)}, {kr, value(4)}};
    Bytes32Map nodes;
    const bytes32 root = hashbuilder_root(pre, &nodes);

    {  // clean read beside a write
        Bytes32Map post = pre;
        post[kb] = value(9);
        const ByteView va{pre.at(ka)}, vb{pre.at(kb)};
        expect_mix(nodes, root, {{ka, va, {}}, {kb, vb, value(9)}}, hashbuilder_root(post, nullptr));
    }
    {  // interleaved reads and writes
        Bytes32Map post = pre;
        post[kb] = value(9);
        post[kc] = value(8);
        post[kr] = value(7);
        const ByteView va{pre.at(ka)}, vb{pre.at(kb)}, vc{pre.at(kc)}, vr{pre.at(kr)};
        expect_mix(nodes, root,
                   {{ka, va, {}}, {ax, z, {}}, {kb, vb, value(9)}, {ay, z, {}}, {kc, vc, value(8)}, {kr, vr, value(7)}},
                   hashbuilder_root(post, nullptr));
    }
    {  // lcp gate keeps grid walking
        Bytes32Map post = pre;
        post[kc] = value(8);
        const ByteView vc{pre.at(kc)};
        expect_mix(nodes, root, {{ay, z, {}}, {kc, vc, value(8)}}, hashbuilder_root(post, nullptr));
    }
    {  // slot unfolded by earlier write
        const bytes32 w = key_with_nibbles({2, 2}, 2);
        const bytes32 g = key_with_nibbles({2, 3}, 1);
        Bytes32Map pre2{{w, value(2)}, {g, value(1)}, {kr, value(4)}};
        Bytes32Map nodes2;
        const bytes32 root2 = hashbuilder_root(pre2, &nodes2);
        Bytes32Map post = pre2;
        post[w] = value(9);
        post[kr] = value(7);
        const ByteView vw{pre2.at(w)}, vg{pre2.at(g)};
        expect_mix(nodes2, root2, {{w, vw, value(9)}, {g, vg, {}}, {kr, ByteView{pre2.at(kr)}, value(7)}},
                   hashbuilder_root(post, nullptr));
    }
}

TEST_CASE("GridMPT a read under an extension splits below it inside a write walk", "[trie][gridmpt][phase2]") {
// lcp 5 == consumed at ext child
    const bytes32 k0 = key_with_nibbles({2, 0, 2, 0}, 1);
    const bytes32 k1 = key_with_nibbles({2, 0, 2, 1, 2, 0}, 2);
    const bytes32 k2 = key_with_nibbles({2, 0, 2, 1, 2, 1}, 3);
    const bytes32 r = key_with_nibbles({7}, 4);
    Bytes32Map pre{{k0, value(1)}, {k1, value(2)}, {k2, value(3)}, {r, value(4)}};
    Bytes32Map nodes;
    const bytes32 root = hashbuilder_root(pre, &nodes);
    Bytes32Map post = pre;
    post[k2] = value(9);
    post[r] = value(7);
    expect_mix(nodes, root,
               {{k1, ByteView{pre.at(k1)}, {}}, {k2, ByteView{pre.at(k2)}, value(9)}, {r, ByteView{pre.at(r)}, value(7)}},
               hashbuilder_root(post, nullptr));
}

TEST_CASE("GridMPT a write and a delete around a light read agree with the grid walk", "[trie][gridmpt][phase2]") {
    const bytes32 ka = key_with_nibbles({0}, 1);
    const bytes32 kb = key_with_nibbles({3}, 2);
    const bytes32 kc = key_with_nibbles({7}, 3);
    const bytes32 ax = key_with_nibbles({5}, 4);
    Bytes32Map leaves{{ka, value(1)}, {kb, value(2)}, {kc, value(3)}};
    Bytes32Map nodes;
    const bytes32 root = hashbuilder_root(leaves, &nodes);
    Bytes del{0x80};
    const ByteView z{kZeroRlp, 1};
    Bytes32Map post{{ka, value(9)}, {kb, value(2)}};
    expect_mix(nodes, root,
               {{ka, ByteView{leaves.at(ka)}, value(9)}, {kb, ByteView{leaves.at(kb)}, {}}, {ax, z, {}},
                {kc, ByteView{leaves.at(kc)}, del}},
               hashbuilder_root(post, nullptr));
}

TEST_CASE("GridMPT a light read's failed claim fails a write walk alike", "[trie][gridmpt][phase2]") {
    const bytes32 k1 = key_with_nibbles({2}, 1);
    const bytes32 r = key_with_nibbles({7}, 4);
    Bytes32Map pre{{k1, value(1)}, {r, value(4)}};
    Bytes32Map nodes;
    const bytes32 root = hashbuilder_root(pre, &nodes);
    const Bytes bad{0x84, 9, 9, 9, 9};
    expect_mix(nodes, root, {{k1, ByteView{bad}, {}}, {r, ByteView{pre.at(r)}, value(7)}}, bytes32{});
}

TEST_CASE("GridMPT a malformed extension child under a light read fails a write walk alike", "[trie][gridmpt][phase2]") {
    Bytes32Map nodes;
    const bytes32 ka = key_with_nibbles({0}, 1);
    const Bytes v1 = value(1);
    const bytes32 l0 = put(nodes, node_leaf(std::vector<uint8_t>(63, 1), rlp_str(v1)));
    const bytes32 je = put(nodes, node_ext({2}, rlp_str(Bytes{0xc0})));
    const bytes32 root = put(nodes, node_branch({child_hash_ref(l0), {}, child_hash_ref(je)}));
    const bytes32 read_key = key_with_nibbles({2, 2}, 5);
    const ByteView z{kZeroRlp, 1};
    expect_mix(nodes, root, {{ka, ByteView{v1}, value(9)}, {read_key, z, {}}}, bytes32{});
}


TEST_CASE("GridMPT the zero-update probe folds a single-child root branch like the grid walk", "[trie][gridmpt][probe]") {
    {  // lone hash absent: soft fail
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 2 ? child_hash_ref(bytes32{}) : Bytes{0x80});
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        expect_soft(nodes, root, {}, 1);
    }
    {  // malformed lone cell: no bump
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 6 ? Bytes{0xc0} : Bytes{0x80});
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        expect_soft(nodes, root, {}, 0);
    }
    {  // probe skips ext root's child
        Bytes32Map nodes;
        const bytes32 root = put(nodes, node_ext({2, 3}, child_hash_ref(bytes32{})));
        expect_agree(nodes, root, {}, root);
    }
}

TEST_CASE("GridMPT a raw byte string in a child cell fails the light descent like the grid unfold", "[trie][gridmpt][phase2]") {
    const ByteView z{kZeroRlp, 1};

    {  // raw ext child: hard, one bump
        Bytes32Map nodes;
        const bytes32 ka = key_with_nibbles({0}, 1);
        const Bytes v1 = value(1);
        const bytes32 l0 = put(nodes, node_leaf(std::vector<uint8_t>(63, 1), rlp_str(v1)));
        const bytes32 je = put(nodes, node_ext({2}, Bytes{0x41}));
        const bytes32 root = put(nodes, node_branch({child_hash_ref(l0), {}, child_hash_ref(je)}));
        const bytes32 read_key = key_with_nibbles({2, 2}, 5);
        expect_mix(nodes, root, {{ka, ByteView{v1}, value(9)}, {read_key, z, {}}}, bytes32{});
    }

    {  // raw branch cell: no bump
        Bytes32Map nodes;
        const bytes32 ka = key_with_nibbles({0}, 1);
        const Bytes v1 = value(1);
        const bytes32 l0 = put(nodes, node_leaf(std::vector<uint8_t>(63, 1), rlp_str(v1)));
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 3 ? Bytes{0x81, 0xAB} : (i == 0 ? child_hash_ref(l0) : Bytes{0x80}));
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        const bytes32 read_key = key_with_nibbles({3, 3}, 5);
        expect_mix(nodes, root, {{ka, ByteView{v1}, value(9)}, {read_key, z, {}}}, bytes32{});
    }

    {  // embedded ext child bumps both
        Bytes32Map nodes;
        std::vector<Bytes> kids;
        for (uint8_t i = 0; i < 16; ++i) {
            kids.push_back(i == 1 ? child_embed(node_ext({5, 5}, Bytes{0x41})) : Bytes{0x80});
        }
        const bytes32 root = put(nodes, node_branch(std::move(kids)));
        expect_agree(nodes, root, {{key_with_nibbles({1, 5, 5}, 5), z, {}}}, {});
    }
}
