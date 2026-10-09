// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Account leaf encoding and the trie's pre-value check:
//  - Account::rlp_into / rlp_into_cache against a reference RLP encoding built with the generic
//    silkworm encoder, over every bit length of the nonce and the balance, all destination
//    alignments, with guard bytes around the output;
//  - bytes_equal_any (the rv32 compare of a witness leaf value with the claimed pre-state value)
//    over all lengths up to 112, all 16 alignment pairs and a difference at every position;
//  - GridMPT rejecting a claimed pre-state value that differs from the hash-bound witness leaf in
//    one byte, or in its length, at several leaf shapes and claim alignments.
// The native test build sets -DEVMONE_RV32_DISPATCH_TEST, which compiles the rv32 account encoder
// and bytes_equal_any on the host; without it, the encoder cases test the generic encoder.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <map>
#include <new>
#include <random>
#include <span>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <zilk_core/core/common/endian.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using namespace zilkworm;
using silkworm::Bytes;
using silkworm::ByteView;

namespace {

struct AccountFields {
    uint64_t nonce;
    intx::uint256 balance;
    bytes32 storage_root;
    bytes32 code_hash;
};

// The account leaf as the generic silkworm RLP encoder writes it.
Bytes reference_rlp(const AccountFields& f) {
    Bytes payload;
    silkworm::rlp::encode(payload, f.nonce);
    silkworm::rlp::encode(payload, f.balance);
    silkworm::rlp::encode(payload, ByteView{f.storage_root.bytes, 32});
    silkworm::rlp::encode(payload, ByteView{f.code_hash.bytes, 32});
    Bytes out;
    silkworm::rlp::encode_header(out, {.list = true, .payload_length = payload.size()});
    out.append(payload);
    return out;
}

bytes32 random_hash(std::mt19937_64& rng) {
    bytes32 h;
    for (auto& b : h.bytes) b = static_cast<uint8_t>(rng());
    return h;
}

// A value of exactly `bits` significant bits (0 gives 0).
uint64_t random_u64_bits(std::mt19937_64& rng, unsigned bits) {
    if (bits == 0) return 0;
    const uint64_t v = rng() | (uint64_t{1} << 63);
    return v >> (64 - bits);
}

intx::uint256 random_u256_bits(std::mt19937_64& rng, unsigned bits) {
    if (bits == 0) return 0;
    intx::uint256 v;
    for (size_t i = 0; i < 4; ++i) v[i] = rng();
    v[3] |= uint64_t{1} << 63;
    return v >> (256 - bits);
}

Account make_account(const AccountFields& f) {
    Account a{};
    a.nonce = f.nonce;
    std::memcpy(a.balance, &f.balance, 32);
    std::memcpy(a.code_hash, f.code_hash.bytes, 32);
    std::memcpy(a.storage_root, f.storage_root.bytes, 32);
    return a;
}

std::vector<AccountFields> encoder_cases() {
    std::mt19937_64 rng{0xacc0};
    const std::vector<uint64_t> edge_nonces{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff,
                                            uint64_t{1} << 32, ~uint64_t{0}};
    const std::vector<intx::uint256> edge_balances{0,
                                                   1,
                                                   0x7f,
                                                   0x80,
                                                   0xff,
                                                   0x100,
                                                   0xffffffff,
                                                   intx::uint256{1} << 32,
                                                   ~uint64_t{0},
                                                   intx::uint256{1} << 64,
                                                   intx::uint256{1} << 224,
                                                   (intx::uint256{1} << 224) - 1,
                                                   intx::uint256{1} << 255,
                                                   ~intx::uint256{0}};
    std::vector<AccountFields> cases;
    for (unsigned bits = 0; bits <= 64; ++bits)
        cases.push_back({random_u64_bits(rng, bits), random_u256_bits(rng, static_cast<unsigned>(rng() % 257)),
                         random_hash(rng), random_hash(rng)});
    for (unsigned bits = 0; bits <= 256; ++bits)
        cases.push_back({random_u64_bits(rng, static_cast<unsigned>(rng() % 65)), random_u256_bits(rng, bits),
                         random_hash(rng), random_hash(rng)});
    for (const uint64_t n : edge_nonces)
        for (const auto& b : edge_balances) cases.push_back({n, b, random_hash(rng), random_hash(rng)});
    return cases;
}

}  // namespace

TEST_CASE("Account leaf RLP matches the generic encoder", "[account][rlp]") {
    constexpr uint8_t kGuard = 0x5A;
    size_t checked = 0;
    for (const auto& f : encoder_cases()) {
        const Bytes ref = reference_rlp(f);
        REQUIRE(ref.size() <= kAccRlpBufSize);
        const Account acc = make_account(f);
        CAPTURE(f.nonce, intx::to_string(f.balance));

        // The destination is at every alignment. The storage root is a bytes32 object, which is
        // aligned (evmc_bytes32 is alignas(size_t)), so its words may be read directly.
        for (size_t dst_off = 0; dst_off < 4; ++dst_off) {
            for (size_t root_slot = 0; root_slot < 2; ++root_slot) {
                // An unstamped cache (acc_rlp_sroot_off == 0) makes rlp_into encode.
                alignas(evmc::bytes32) uint8_t root_buf[2 * sizeof(evmc::bytes32)];
                auto* const root = new (root_buf + root_slot * sizeof(evmc::bytes32)) evmc::bytes32{f.storage_root};
                alignas(8) uint8_t out[8 + kAccRlpBufSize + 8];
                std::memset(out, kGuard, sizeof(out));
                const uint8_t len = acc.rlp_into(out + 4 + dst_off, *root);
                CAPTURE(dst_off, root_slot);
                REQUIRE(len == ref.size());
                REQUIRE(ByteView{out + 4 + dst_off, len} == ByteView{ref});
                for (size_t i = 0; i < 4 + dst_off; ++i) REQUIRE(out[i] == kGuard);
                for (size_t i = 4 + dst_off + len; i < sizeof(out); ++i) REQUIRE(out[i] == kGuard);
                ++checked;
            }
        }

        // The stamped cache: the bytes, the length and the storage root's offset, which the
        // rlp_into fast path patches with the current root.
        const Account by_arg = acc;
        by_arg.rlp_into_cache(f.storage_root);
        const Account by_field = acc;
        by_field.rlp_into_cache();
        for (const Account* a : {&by_arg, &by_field}) {
            REQUIRE(a->acc_rlp_len == ref.size());
            REQUIRE(ByteView{a->acc_rlp_buf, a->acc_rlp_len} == ByteView{ref});
            REQUIRE(a->acc_rlp_sroot_off == ref.size() - 2 * (1 + 32));
            REQUIRE(a->acc_rlp_buf[a->acc_rlp_sroot_off] == 0xA0);
        }

        AccountFields moved = f;
        moved.storage_root.bytes[0] ^= 0xFF;
        moved.storage_root.bytes[31] ^= 0x01;
        uint8_t out[kAccRlpBufSize];
        REQUIRE(by_field.rlp_into(out, moved.storage_root) == ref.size());
        REQUIRE(ByteView{out, ref.size()} == ByteView{reference_rlp(moved)});
    }
    CHECK(checked > 3000);
}

namespace {

// encode_account_into as it was before the fixed-layout encoder (the generic path that host builds
// still use), kept verbatim as the reference for random and crafted accounts.
struct BaseEncoded { uint8_t len; uint8_t sroot_off; };
BaseEncoded base_encode_account_into(uint8_t* dst, const Account& a, const uint8_t* storage_root) {
    intx::uint256 balance_v;
    std::memcpy(&balance_v, a.balance, 32);

    const size_t payload_len =
        silkworm::rlp::length(a.nonce) + silkworm::rlp::length(balance_v)
        + (silkworm::kHashLength + 1) + (silkworm::kHashLength + 1);

    uint8_t* p = dst;
    const auto len_be = silkworm::endian::to_big_compact(payload_len);
    *p++ = static_cast<uint8_t>(0xF7u + len_be.size());
    std::memcpy(p, len_be.data(), len_be.size());
    p += len_be.size();

    p += silkworm::rlp::encode_uint_into(p, a.nonce);
    p += silkworm::rlp::encode_uint_into(p, balance_v);

    const uint8_t sroot_off = static_cast<uint8_t>(p - dst);
    *p++ = 0xA0u;
    std::memcpy(p, storage_root, silkworm::kHashLength);
    p += silkworm::kHashLength;

    *p++ = 0xA0u;
    std::memcpy(p, a.code_hash, silkworm::kHashLength);
    p += silkworm::kHashLength;

    return {static_cast<uint8_t>(p - dst), sroot_off};
}

// A 32-bit word of the kinds that matter to a top-word scan and to the minimal big-endian
// bytes: zero, one-byte values on both sides of 0x80, every byte count, all-ones, random.
uint32_t sparse_word(std::mt19937_64& rng) {
    static constexpr uint32_t kSpecial[] = {0,          0,          1,          0x7f,       0x80,
                                            0xff,       0x100,      0xffff,     0x10000,    0xffffff,
                                            0x1000000,  0x7fffffff, 0x80000000, 0xffffffff};
    switch (rng() % 4) {
        case 0: return kSpecial[rng() % std::size(kSpecial)];
        case 1: return static_cast<uint32_t>(rng());
        case 2: return static_cast<uint32_t>(rng()) >> (rng() % 32);
        default: return 0;
    }
}

}  // namespace

TEST_CASE("Account leaf RLP matches the previous encoder on random sparse accounts", "[account][rlp]") {
    constexpr uint8_t kGuard = 0xC3;
    std::mt19937_64 rng{0xba5e};
    for (size_t iter = 0; iter < 60000; ++iter) {
        Account acc{};
        uint32_t nonce_w[2] = {sparse_word(rng), sparse_word(rng)};
        std::memcpy(&acc.nonce, nonce_w, 8);
        uint32_t bal_w[8];
        for (auto& w : bal_w) w = sparse_word(rng);
        std::memcpy(acc.balance, bal_w, 32);
        const bytes32 code_hash = random_hash(rng);
        std::memcpy(acc.code_hash, code_hash.bytes, 32);
        const bytes32 root = random_hash(rng);
        std::memcpy(acc.storage_root, root.bytes, 32);
        CAPTURE(iter, acc.nonce);

        alignas(8) uint8_t want[kAccRlpBufSize];
        const BaseEncoded base = base_encode_account_into(want, acc, root.bytes);
        REQUIRE(base.len <= kAccRlpBufSize);

        const size_t dst_off = iter % 4;
        alignas(8) uint8_t out[8 + kAccRlpBufSize + 8];
        std::memset(out, kGuard, sizeof(out));
        const Account fresh = acc;  // unstamped cache: rlp_into encodes
        const uint8_t len = fresh.rlp_into(out + 4 + dst_off, root);
        REQUIRE(len == base.len);
        REQUIRE(ByteView{out + 4 + dst_off, len} == ByteView{want, base.len});
        for (size_t i = 0; i < 4 + dst_off; ++i) REQUIRE(out[i] == kGuard);
        for (size_t i = 4 + dst_off + len; i < sizeof(out); ++i) REQUIRE(out[i] == kGuard);

        // The stamp: length, storage root offset, and the cached bytes, whichever overload.
        const Account by_field = acc;
        REQUIRE(by_field.rlp_into_cache() == base.len);
        REQUIRE(by_field.acc_rlp_len == base.len);
        REQUIRE(by_field.acc_rlp_sroot_off == base.sroot_off);
        REQUIRE(by_field.acc_rlp_sroot_off >= 4);
        REQUIRE(ByteView{by_field.acc_rlp_buf, base.len} == ByteView{want, base.len});
    }
}

#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
TEST_CASE("bytes_equal_any at every length, alignment pair and difference", "[trie][compare]") {
    std::mt19937_64 rng{0xe9};
    size_t checked = 0;
    for (size_t n = 0; n <= 112; ++n) {
        for (size_t oa = 0; oa < 4; ++oa) {
            for (size_t ob = 0; ob < 4; ++ob) {
                // Blocks end exactly at the strings' ends, so that an AddressSanitizer build
                // reports any read past them.
                std::vector<uint8_t> block_a(oa + n), block_b(ob + n);
                uint8_t* const a = block_a.data() + oa;
                uint8_t* const b = block_b.data() + ob;
                for (size_t i = 0; i < n; ++i) a[i] = b[i] = static_cast<uint8_t>(rng());
                CAPTURE(n, oa, ob);
                REQUIRE(bytes_equal_any(a, b, n));
                for (size_t pos = 0; pos < n; ++pos) {
                    const uint8_t flip = static_cast<uint8_t>(1u << (rng() % 8));
                    CAPTURE(pos, flip);
                    b[pos] ^= flip;
                    REQUIRE_FALSE(bytes_equal_any(a, b, n));
                    REQUIRE_FALSE(bytes_equal_any(b, a, n));
                    b[pos] ^= flip;
                    ++checked;
                }
                REQUIRE(bytes_equal_any(b, a, n));
            }
        }
    }
    CHECK(checked == 16 * 112 * 113 / 2);
}

TEST_CASE("bytes_equal_any agrees with memcmp on random data and ignores bytes outside the range",
          "[trie][compare]") {
    std::mt19937_64 rng{0x3b9};
    for (size_t iter = 0; iter < 200000; ++iter) {
        const size_t n = rng() % 300;
        const size_t oa = rng() % 8, ob = rng() % 8;
        // Different junk before and after each string: the compare must not depend on it.
        std::vector<uint8_t> block_a(oa + n + 8), block_b(ob + n + 8);
        for (auto& x : block_a) x = static_cast<uint8_t>(rng());
        for (auto& x : block_b) x = static_cast<uint8_t>(rng());
        const uint8_t* const a = block_a.data() + oa;
        uint8_t* const b = block_b.data() + ob;
        std::memcpy(b, a, n);
        // Several differences, or none, so that the first mismatching word varies.
        const size_t flips = (rng() % 3 == 0) ? 0 : 1 + rng() % 4;
        for (size_t f = 0; f < flips && n > 0; ++f) b[rng() % n] ^= static_cast<uint8_t>(1 + rng() % 255);
        const bool want = std::memcmp(a, b, n) == 0;
        CAPTURE(iter, n, oa, ob, flips);
        REQUIRE(bytes_equal_any(a, b, n) == want);
        REQUIRE(bytes_equal_any(b, a, n) == want);
    }
}
#endif

namespace {

struct Bytes32Less {
    bool operator()(const bytes32& a, const bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using Bytes32Map = std::map<bytes32, Bytes, Bytes32Less>;

bytes32 hashbuilder_root(const Bytes32Map& leaves, Bytes32Map* sink) {
    silkworm::trie::HashBuilder hb;
    if (sink != nullptr) {
        hb.rlp_collector = [sink](ByteView node_rlp) { sink->emplace(keccak_bytes(node_rlp), Bytes{node_rlp}); };
    }
    for (const auto& [k, v] : leaves) hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{k.bytes, 32}), v);
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

// A pre-state trie with a complete witness, against which one leaf is updated to `next` with a
// claimed pre-state value given at a chosen alignment.
class PreValueTrie {
  public:
    explicit PreValueTrie(Bytes32Map pre)
        : pre_{std::move(pre)},
          pre_root_{hashbuilder_root(pre_, &nodes_)},
          prestate_{DirectState::build_blob_from_accounts({}, /*block_hashes=*/{}, /*code_store=*/{})},
          nodestore_{build_node_store(nodes_)},
          direct_{std::span<uint8_t>{prestate_}, std::span<uint8_t>{nodestore_}} {}

    const Bytes32Map& pre() const { return pre_; }

    // The root after updating `key` to `next`, given `claimed` as its pre-state value at
    // `claim_off` bytes past a word boundary; all zero when calc_root rejects the claim.
    bytes32 update(const bytes32& key, ByteView claimed, size_t claim_off, ByteView next) {
        alignas(8) uint8_t claim_buf[4 + 128];
        REQUIRE(claimed.size() <= 128);
        std::memcpy(claim_buf + claim_off, claimed.data(), claimed.size());
        TrieNodeFlat node{key};
        node.ext_initial = ByteView{claim_buf + claim_off, claimed.size()};
        node.current_off = 0;
        node.current_len = static_cast<uint8_t>(next.size());
        std::memcpy(node.buf, next.data(), next.size());
        GridMPT<true> trie{direct_, pre_root_};
        return trie.calc_root_from_updates({&node, 1});
    }

    bytes32 expected_root(const bytes32& key, ByteView next) const {
        Bytes32Map post = pre_;
        post[key] = Bytes{next};
        return hashbuilder_root(post, nullptr);
    }

  private:
    Bytes32Map pre_;
    Bytes32Map nodes_;
    bytes32 pre_root_;
    std::vector<uint8_t> prestate_;
    std::vector<uint8_t> nodestore_;
    DirectState direct_;
};

bytes32 leaf_key(uint64_t i) {
    bytes32 raw{};
    for (int b = 0; b < 8; ++b) raw.bytes[31 - b] = static_cast<uint8_t>(i >> (8 * b));
    return keccak_bytes(ByteView{raw.bytes, 32});
}

// Every one-byte change of the claimed pre-state value, a byte added or removed, at every claim
// alignment, must be rejected; the honest claim must give the canonical post root.
void check_pre_value_binding(PreValueTrie& t, const bytes32& key, ByteView next) {
    const Bytes honest = t.pre().at(key);
    const bytes32 expected = t.expected_root(key, next);
    REQUIRE(expected != bytes32{});
    for (size_t off = 0; off < 4; ++off) {
        CAPTURE(honest.size(), off);
        REQUIRE(t.update(key, honest, off, next) == expected);
        Bytes forged = honest;
        for (size_t pos = 0; pos < honest.size(); ++pos) {
            CAPTURE(pos);
            forged[pos] ^= 0x01;
            REQUIRE(t.update(key, forged, off, next) == bytes32{});
            forged[pos] ^= 0x01;
        }
        forged.push_back(0x00);
        REQUIRE(t.update(key, forged, off, next) == bytes32{});
        REQUIRE(t.update(key, ByteView{honest}.substr(0, honest.size() - 1), off, next) == bytes32{});
    }
}

}  // namespace

TEST_CASE("GridMPT rejects a claimed account pre-state that differs from the witness leaf", "[trie][gridmpt]") {
    std::mt19937_64 rng{0x1eaf};
    // Leaf counts give different leaf path lengths, so the witness value sits at different
    // offsets in its node; nonce and balance lengths vary the value's size (70..110 bytes).
    for (const size_t n_leaves : std::initializer_list<size_t>{1, 2, 3, 6, 17}) {
        Bytes32Map pre;
        for (size_t i = 0; i < n_leaves; ++i) {
            const AccountFields f{random_u64_bits(rng, static_cast<unsigned>(rng() % 65)),
                                  random_u256_bits(rng, static_cast<unsigned>(rng() % 257)), random_hash(rng),
                                  random_hash(rng)};
            pre[leaf_key(i)] = reference_rlp(f);
        }
        PreValueTrie t{pre};
        const AccountFields next{7, 1000, random_hash(rng), random_hash(rng)};
        CAPTURE(n_leaves);
        check_pre_value_binding(t, leaf_key(0), reference_rlp(next));
        check_pre_value_binding(t, leaf_key(n_leaves - 1), reference_rlp(next));
    }
}

TEST_CASE("GridMPT rejects a claimed storage pre-value that differs from the witness leaf", "[trie][gridmpt]") {
    std::mt19937_64 rng{0x5107};
    for (const size_t n_leaves : std::initializer_list<size_t>{1, 2, 5, 17}) {
        Bytes32Map pre;
        for (size_t i = 0; i < n_leaves; ++i) {
            // Slot values of 1..32 significant bytes, RLP strings as check_root builds them.
            Bytes v;
            silkworm::rlp::encode(v, random_u256_bits(rng, 8 * (1 + static_cast<unsigned>(i * 7 % 32))));
            pre[leaf_key(1000 + i)] = v;
        }
        PreValueTrie t{pre};
        const Bytes next{0x82, 0x12, 0x34};
        CAPTURE(n_leaves);
        for (size_t i = 0; i < n_leaves; ++i) check_pre_value_binding(t, leaf_key(1000 + i), next);
    }
}
