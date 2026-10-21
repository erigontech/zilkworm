// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// decode_node defers the child_ptr fill of full branches (value carries the node, readers derive).
// Every observable of the deferred decode must equal the eager fill it replaces, on every input,
// including malformed RLP, before and after branch mutations.

#include <array>
#include <cstring>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

// The pre-deferral decode_node: eager child_ptr fill on the fast path, child_ptr null for empty and
// embedded slots, empty value. Kept verbatim as the differential reference.
inline bool fill_branch_child_ref(BranchNode& out, size_t i, uint8_t start_byte, const uint8_t* data, size_t len,
                                  unsigned& mask) {
    if (len == 0) {
        out.child_len[i] = 0;
        out.child_ptr[i] = nullptr;
        return true;
    }
    if (start_byte != 0xa0) {
        if (len > 31) return false;
        out.child_len[i] = static_cast<uint8_t>(len + 1);
        out.child[i].bytes[0] = start_byte;
        out.child_ptr[i] = nullptr;
        std::copy_n(data, len, &out.child[i].bytes[1]);
    } else {
        out.child_len[i] = 32;
        out.child_ptr[i] = data;
    }
    mask |= 1u << i;
    return true;
}

inline Kind decode_node_ref(ByteView payload, BranchNode& out_branch, bool& is_leaf, nibbles64& path, uint8_t& plen,
                            ByteView& second, unsigned& mask_out) {
    if (payload.size() == 16 * 33 + 1 && payload[16 * 33] == rlp::kEmptyStringCode) {
        const uint8_t* const p = payload.data();
        bool hashes = true;
        for (size_t i = 0; i < 16; ++i) {
            if (p[33 * i] != 0xa0) {
                hashes = false;
                break;
            }
        }
        if (hashes) {
            for (size_t i = 0; i < 16; ++i) out_branch.child_ptr[i] = p + 33 * i + 1;
            typedef uint32_t __attribute__((may_alias)) w32;
            w32* const cl = reinterpret_cast<w32*>(std::assume_aligned<8>(out_branch.child_len.data()));
            cl[0] = cl[1] = cl[2] = cl[3] = 0x20202020u;
            mask_out = 0xffff;
            out_branch.value = {};
            return kBranch;
        }
    }

    ByteView remaining = payload;
    const uint8_t e0_start = remaining.empty() ? 0 : *remaining.data();
    auto h0 = rlp::decode_header(remaining);
    if (!h0) return kInvalid;
    const ByteView e0_payload = remaining.substr(0, h0->payload_length);
    const bool e0_list = h0->list;
    remaining.remove_prefix(h0->payload_length);

    const uint8_t e1_start = remaining.empty() ? 0 : *remaining.data();
    const uint8_t* e1_start_ptr = remaining.data();
    auto h1 = rlp::decode_header(remaining);
    if (!h1) return kInvalid;
    const ByteView e1_payload = remaining.substr(0, h1->payload_length);
    const bool e1_list = h1->list;
    remaining.remove_prefix(h1->payload_length);

    if (remaining.empty()) {
        if (e0_list) return kInvalid;
        if (!hp_decode(e0_payload, is_leaf, path, plen)) return kInvalid;
        if (e1_list) return kInvalid;
        if (!is_leaf) {
            if (h1->payload_length == 32) {
                second = e1_payload;
            } else {
                size_t header_len = static_cast<size_t>(e1_payload.data() - e1_start_ptr);
                second = ByteView{e1_start_ptr, header_len + h1->payload_length};
            }
        } else {
            if (h1->payload_length == 0 || h1->payload_length > kMaxLeafValueSize) return kInvalid;
            second = e1_payload;
        }
        return kExtOrLeaf;
    }

    unsigned mask = 0;
    if (!fill_branch_child_ref(out_branch, 0, e0_start, e0_payload.data(), h0->payload_length, mask)) return kInvalid;
    if (!fill_branch_child_ref(out_branch, 1, e1_start, e1_payload.data(), h1->payload_length, mask)) return kInvalid;
    {
        const uint8_t* p = remaining.data();
        const uint8_t* const end = p + remaining.size();
        for (size_t i = 2; i < 16; ++i) {
            if (p == end) return kInvalid;
            const uint8_t b0 = *p;
            if (b0 == 0xa0) {
                if (end - p < 33) return kInvalid;
                out_branch.child_ptr[i] = p + 1;
                out_branch.child_len[i] = 32;
                mask |= 1u << i;
                p += 33;
            } else if (b0 == rlp::kEmptyStringCode) {
                out_branch.child_len[i] = 0;
                out_branch.child_ptr[i] = nullptr;
                ++p;
            } else if (b0 >= 0xc0 && b0 <= 0xf7) {
                const size_t plen_ = static_cast<size_t>(b0 - 0xc0);
                if (plen_ > 31) return kInvalid;
                if (static_cast<size_t>(end - p) < 1 + plen_) return kInvalid;
                out_branch.child[i].bytes[0] = b0;
                std::copy_n(p + 1, plen_, &out_branch.child[i].bytes[1]);
                out_branch.child_len[i] = static_cast<uint8_t>(plen_ + 1);
                out_branch.child_ptr[i] = nullptr;
                mask |= 1u << i;
                p += 1 + plen_;
            } else {
                return kInvalid;
            }
        }
        mask_out = mask;
        remaining = ByteView{p, static_cast<size_t>(end - p)};
    }
    if (remaining.size() == 1 && remaining[0] == rlp::kEmptyStringCode) {
        out_branch.value = {};
        return kBranch;
    }
    return kInvalid;
}

struct Decoded {
    Kind kind;
    BranchNode node;
    bool is_leaf;
    nibbles64 path;
    uint8_t plen;
    ByteView second;
    unsigned mask;
};

Decoded run_ref(ByteView payload) {
    Decoded d{};
    d.node = BranchNode{};
    d.kind = decode_node_ref(payload, d.node, d.is_leaf, d.path, d.plen, d.second, d.mask);
    return d;
}

Decoded run_new(ByteView payload) {
    Decoded d{};
    d.node = BranchNode{};
    d.kind = decode_node(payload, d.node, d.is_leaf, d.path, d.plen, d.second, d.mask);
    return d;
}

// The 32 hash bytes slot i resolves to on the reference (eager child_ptr), and via branch_hash_src on
// the deferred node. Both must be equal, and equal the payload bytes the slot was decoded from.
void check_equal(const Decoded& ref, const Decoded& now, ByteView payload, bool expect_fast) {
    CHECK(ref.kind == now.kind);
    if (ref.kind == kInvalid) {
        CHECK(now.kind == kInvalid);
        return;
    }
    CHECK(ref.mask == now.mask);
    CHECK(ref.is_leaf == now.is_leaf);
    CHECK(ref.plen == now.plen);
    CHECK(ref.path.len == now.path.len);
    for (size_t i = 0; i < 4; ++i) CHECK(ref.path.w[i] == now.path.w[i]);
    REQUIRE(ref.second.size() == now.second.size());
    if (ref.second.size() != 0) CHECK(std::memcmp(ref.second.data(), now.second.data(), ref.second.size()) == 0);
    if (ref.kind != kBranch) return;

    if (expect_fast) {
        CHECK(now.node.value.size() == kDeferredChildPtr);
        CHECK(now.node.value.data() == payload.data());
    } else {
        CHECK(now.node.value.size() == 0);
    }
    for (size_t i = 0; i < 16; ++i) {
        REQUIRE(ref.node.child_len[i] == now.node.child_len[i]);
        if (ref.node.child_len[i] == 32) {
            const uint8_t* r = ref.node.child_ptr[i] ? ref.node.child_ptr[i] : ref.node.child[i].bytes;
            CHECK(std::memcmp(r, branch_hash_src(now.node, i), 32) == 0);
        } else if (ref.node.child_len[i] != 0) {
            CHECK(std::memcmp(ref.node.child[i].bytes, now.node.child[i].bytes, ref.node.child_len[i]) == 0);
        }
    }
    // encode_branch hands out a view of the shared static_buffer: copy before the next call.
    CHECK(Bytes{encode_branch(ref.node)} == Bytes{encode_branch(now.node)});
}

void check(ByteView payload, bool expect_fast = false) {
    const Decoded a = run_ref(payload);
    const Decoded b = run_new(payload);
    check_equal(a, b, payload, expect_fast);
}

Bytes full_branch_payload(uint8_t seed = 0) {
    Bytes p;
    for (uint8_t i = 0; i < 16; ++i) {
        p.push_back(0xa0);
        for (uint8_t j = 0; j < 32; ++j) p.push_back(static_cast<uint8_t>(seed + 31 * i + j));
    }
    p.push_back(0x80);
    return p;
}

// Sparse branch: slots in `hashes` hold 0xa0+32, the others 0x80; then the value byte.
Bytes sparse_payload(const std::array<bool, 16>& hashes) {
    Bytes p;
    for (uint8_t i = 0; i < 16; ++i) {
        if (hashes[i]) {
            p.push_back(0xa0);
            for (uint8_t j = 0; j < 32; ++j) p.push_back(static_cast<uint8_t>(0x40 + 17 * i + j));
        } else {
            p.push_back(0x80);
        }
    }
    p.push_back(0x80);
    return p;
}

}  // namespace

TEST_CASE("decode deferred equals eager fill", "[decode]") {
    SECTION("full branch fast path") {
        const Bytes p = full_branch_payload();
        check(p, /*expect_fast=*/true);
        check(full_branch_payload(7), /*expect_fast=*/true);
    }

    SECTION("every marker corrupted falls back identically") {
        for (size_t i = 0; i < 16; ++i) {
            Bytes p = full_branch_payload();
            p[33 * i] = 0x80;  // empty slot: still a branch, general path
            check(p);
            p = full_branch_payload();
            p[33 * i] = 0xa1;  // not a branch child at all
            check(p);
            p = full_branch_payload();
            p[33 * i] = 0xc1;  // embedded one-byte list: shifts every offset after it
            p[33 * i + 1] = 0x7f;
            check(p);
            p = full_branch_payload();
            p[33 * i] = 0xf7;  // embedded 31-byte list: length class 32, disambiguated by child_ptr
            for (size_t j = 1; j <= 31; ++j) p[33 * i + j] = static_cast<uint8_t>(j);
            check(p);
        }
    }

    SECTION("length and value byte corruptions") {
        const Bytes p = full_branch_payload();
        check(ByteView{p.data(), p.size() - 1});
        Bytes q = p;
        q.back() = 0x81;
        check(q);
        q = p;
        q.push_back(0x80);
        check(q);  // trailing byte after the value: invalid
        check(ByteView{});
        Bytes e{0x80};
        check(e);
    }

    SECTION("sparse branches k = 0..15") {
        for (unsigned k = 0; k <= 15; ++k) {
            std::array<bool, 16> hashes{};
            for (unsigned j = 0; j < k; ++j) hashes[(j * 7 + 3) % 16] = true;
            check(sparse_payload(hashes));
        }
        std::array<bool, 16> all{};
        all.fill(true);
        check(sparse_payload(all), /*expect_fast=*/true);
    }

    SECTION("embedded children of every size, incl. length class 32") {
        for (size_t len = 0; len <= 32; ++len) {
            Bytes p;
            p.push_back(0xa0);
            for (size_t j = 0; j < 32; ++j) p.push_back(static_cast<uint8_t>(0x80 + j));
            p.push_back(static_cast<uint8_t>(0xc0 + len));
            for (size_t j = 0; j < len; ++j) p.push_back(static_cast<uint8_t>(0x20 + j));
            for (unsigned i = 2; i < 16; ++i) p.push_back(0x80);
            p.push_back(0x80);
            check(p);
            check(p.substr(0, p.size() - 1));  // cuts the value byte
        }
    }

    SECTION("leaf and extension shapes") {
        for (size_t vlen : {size_t{0}, size_t{1}, size_t{7}, size_t{8}, size_t{15}, size_t{32}, size_t{55},
                            size_t{56}, size_t{255}, size_t{256}, kMaxLeafValueSize, kMaxLeafValueSize + 1}) {
            Bytes p;
            p.push_back(0x82);  // 2-byte nibble string, odd hp, leaf flag set
            p.push_back(0x12);
            p.push_back(0x34);
            if (vlen < 56) {
                p.push_back(static_cast<uint8_t>(0x80 + vlen));
            } else if (vlen < 256) {
                p.push_back(0xb8);
                p.push_back(static_cast<uint8_t>(vlen));
            } else {
                p.push_back(0xb9);
                p.push_back(static_cast<uint8_t>(vlen >> 8));
                p.push_back(static_cast<uint8_t>(vlen & 0xff));
            }
            for (size_t j = 0; j < vlen; ++j) p.push_back(static_cast<uint8_t>(j));
            check(p);
        }
        Bytes ext;
        ext.push_back(0x82);
        ext.push_back(0x00);
        ext.push_back(0x0f);
        ext.push_back(0xa0);
        for (size_t j = 0; j < 32; ++j) ext.push_back(static_cast<uint8_t>(0x30 + j));
        check(ext);
        ext.pop_back();  // 31-byte hash payload: header+payload re-slice, not a bare payload
        ext.push_back(0x11);
        check(ext);
    }

    SECTION("mutations of a deferred node equal the eager node") {
        const Bytes p = full_branch_payload();
        Decoded a = run_ref(p);
        Decoded b = run_new(p);
        REQUIRE(a.kind == kBranch);
        REQUIRE(b.kind == kBranch);
        REQUIRE(b.node.value.size() == kDeferredChildPtr);

        const Bytes child_rlp{0xc1, 0x05};  // any child encoding to hash
        b.node.set_child_hash(5, child_rlp);
        a.node.set_child_hash(5, child_rlp);
        CHECK(b.node.dirty == a.node.dirty);
        CHECK(std::memcmp(branch_hash_src(b.node, 5), a.node.child_ptr[5] ? a.node.child_ptr[5] : a.node.child[5].bytes,
                          32) == 0);
        // Clean slots still derive the witness bytes; the dirty slot reads back the new hash.
        for (size_t i = 0; i < 16; ++i) {
            if (i == 5) continue;
            CHECK(std::memcmp(branch_hash_src(b.node, i), p.data() + 33 * i + 1, 32) == 0);
        }
        CHECK(Bytes{encode_branch(b.node)} == Bytes{encode_branch(a.node)});

        b.node.set_child(9, ByteView{});  // placeholder
        a.node.set_child(9, ByteView{});
        CHECK(Bytes{encode_branch(b.node)} == Bytes{encode_branch(a.node)});

        b.node.delete_child(0);
        a.node.delete_child(0);
        CHECK(Bytes{encode_branch(b.node)} == Bytes{encode_branch(a.node)});

        const Bytes embed{0x01, 0x02, 0x03};
        b.node.set_child(15, embed);
        a.node.set_child(15, embed);
        CHECK(Bytes{encode_branch(b.node)} == Bytes{encode_branch(a.node)});
    }
}
