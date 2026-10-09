// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "account.hpp"

#include <bit>
#include <cstring>

#include <intx/intx.hpp>

#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/endian.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

namespace zilkworm {

namespace {

struct EncodeResult { uint8_t len; uint8_t sroot_off; };

#if (defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32) || defined(EVMONE_RV32_DISPATCH_TEST)
// The generic encoder below costs about 480 instructions per account on rv32: a memcpy of the
// balance into a uint256, a __clzdi2 call and a to_big_compact copy per integer of 0x80 or more, and memcpy
// calls of 32 bytes or less to destinations that are rarely co-aligned with their source. Every field has
// a fixed place in Account, so the encoding is written straight from its words instead. The
// native test build (EVMONE_RV32_DISPATCH_TEST) compiles this encoder too, for the tests.
static_assert(std::endian::native == std::endian::little, "balance and hash words are read little-endian");

typedef uint32_t __attribute__((may_alias)) w32;

// The encoder reads these fields as words.
static_assert(offsetof(Account, nonce) % 4 == 0 && offsetof(Account, balance) % 4 == 0 &&
              offsetof(Account, code_hash) % 4 == 0 && offsetof(Account, storage_root) % 4 == 0);

// The payload is [nonce (1..9 bytes), balance (1..33), 0xA0 + root, 0xA0 + hash]: 68..108 bytes,
// so the list header is always the two bytes 0xF8, payload length.
inline constexpr size_t kAccPayloadMin = 1 + 1 + 2 * (1 + silkworm::kHashLength);
inline constexpr size_t kAccPayloadMax = 9 + 33 + 2 * (1 + silkworm::kHashLength);
static_assert(kAccPayloadMin >= 56 && kAccPayloadMax <= 0xFF);
static_assert(2 + kAccPayloadMax <= kAccRlpBufSize);

// The RLP string of the integer whose little-endian words are w[0..nw).
[[gnu::always_inline]] inline uint8_t* put_uint_words(uint8_t* d, const w32* w, int nw) noexcept {
    int t = nw - 1;
    if (nw > 2) {
        // Balances mostly fit in two words (a quarter are zero): test the words above those
        // together instead of one at a time.
        uint32_t high = 0;
        for (int i = 2; i < nw; ++i) high |= w[i];
        if (high == 0) t = 1;
    }
    while (t >= 0 && w[t] == 0) --t;
    if (t < 0) {
        *d = 0x80;
        return d + 1;
    }
    const uint32_t top = w[t];
    if (t == 0 && top < 0x80) {
        *d = static_cast<uint8_t>(top);
        return d + 1;
    }
    const unsigned top_bytes = top >= 0x10000u ? (top >= 0x1000000u ? 4u : 3u) : (top >= 0x100u ? 2u : 1u);
    *d++ = static_cast<uint8_t>(0x80u + 4u * static_cast<unsigned>(t) + top_bytes);
    switch (top_bytes) {
        case 4: *d++ = static_cast<uint8_t>(top >> 24); [[fallthrough]];
        case 3: *d++ = static_cast<uint8_t>(top >> 16); [[fallthrough]];
        case 2: *d++ = static_cast<uint8_t>(top >> 8); [[fallthrough]];
        default: *d++ = static_cast<uint8_t>(top);
    }
    for (int i = t - 1; i >= 0; --i) {
        const uint32_t v = w[i];
        d[0] = static_cast<uint8_t>(v >> 24);
        d[1] = static_cast<uint8_t>(v >> 16);
        d[2] = static_cast<uint8_t>(v >> 8);
        d[3] = static_cast<uint8_t>(v);
        d += 4;
    }
    return d;
}

// 0xA0 and the 32 bytes of the word-aligned s, at any alignment of d: the bytes up to d's next
// word boundary, then aligned word stores of s's words shifted together, then the rest.
[[gnu::always_inline]] inline uint8_t* put_hash_words(uint8_t* d, const w32* s) noexcept {
    *d++ = 0xA0;
    const unsigned off = reinterpret_cast<uintptr_t>(d) & 3;
    if (off == 0) {
        w32* const dw = reinterpret_cast<w32*>(d);
#pragma GCC unroll 8
        for (int i = 0; i < 8; ++i) dw[i] = s[i];
        return d + 32;
    }
    // The head and tail are switches: GCC's loop unrolling turns a loop of 1..3 bytes into an
    // 8-way unrolled one behind a dispatch that costs more than the stores.
    const unsigned lead = 4 - off;  // bytes before d's next word boundary
    const unsigned rs = 8 * lead, ls = 32 - rs;
    uint32_t v = s[0];
    switch (lead) {
        case 3: d[2] = static_cast<uint8_t>(v >> 16); [[fallthrough]];
        case 2: d[1] = static_cast<uint8_t>(v >> 8); [[fallthrough]];
        default: d[0] = static_cast<uint8_t>(v);
    }
    v >>= rs;
    w32* const dw = reinterpret_cast<w32*>(d + lead);
#pragma GCC unroll 7
    for (int i = 0; i < 7; ++i) {
        const uint32_t next = s[i + 1];
        dw[i] = v | (next << ls);
        v = next >> rs;
    }
    uint8_t* const t = d + lead + 28;
    switch (off) {
        case 3: t[2] = static_cast<uint8_t>(v >> 16); [[fallthrough]];
        case 2: t[1] = static_cast<uint8_t>(v >> 8); [[fallthrough]];
        default: t[0] = static_cast<uint8_t>(v);
    }
    return d + 32;
}

EncodeResult encode_account_into(uint8_t* dst, const Account& a, const uint8_t* storage_root) noexcept {
    uint8_t* p = put_uint_words(dst + 2, reinterpret_cast<const w32*>(&a.nonce), 2);
    p = put_uint_words(p, reinterpret_cast<const w32*>(a.balance), 8);

    const uint8_t sroot_off = static_cast<uint8_t>(p - dst);
    // The caller's root is a bytes32, which is alignas(size_t) and so word-aligned on rv32; the check
    // keeps the encoder correct for any pointer, should that type's alignment ever drop.
    if ((reinterpret_cast<uintptr_t>(storage_root) & 3) == 0) [[likely]] {
        p = put_hash_words(p, reinterpret_cast<const w32*>(storage_root));
    } else {
        *p++ = 0xA0u;
        std::memcpy(p, storage_root, silkworm::kHashLength);
        p += silkworm::kHashLength;
    }
    p = put_hash_words(p, reinterpret_cast<const w32*>(a.code_hash));

    const uint8_t len = static_cast<uint8_t>(p - dst);
    dst[0] = 0xF8u;
    dst[1] = static_cast<uint8_t>(len - 2);
    return {len, sroot_off};
}
#else
EncodeResult encode_account_into(uint8_t* dst, const Account& a, const uint8_t* storage_root) noexcept {
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
#endif

}  // namespace

silkworm::Bytes Account::rlp(const evmc::bytes32& storage_root_arg) const {
    silkworm::Bytes out;
    out.resize(kAccRlpBufSize);
    const auto n = rlp_into(out.data(), storage_root_arg);
    out.resize(n);
    return out;
}

uint8_t Account::rlp_into(uint8_t* dst, const evmc::bytes32& storage_root_arg) const {
    // Bound injected cache fields; on overrun fall through to safe re-encode.
    if (acc_rlp_sroot_off != 0 && acc_rlp_len != 0 && acc_rlp_len <= kAccRlpBufSize &&
        acc_rlp_sroot_off + 1 + silkworm::kHashLength <= acc_rlp_len) [[likely]] {
        std::memcpy(dst, acc_rlp_buf, acc_rlp_len);
        // +1 skips the 0xA0 tag byte.
        std::memcpy(dst + acc_rlp_sroot_off + 1, storage_root_arg.bytes, silkworm::kHashLength);
        return acc_rlp_len;
    }
    return encode_account_into(dst, *this, storage_root_arg.bytes).len;
}

uint8_t Account::rlp_into_cache(const evmc::bytes32& storage_root_arg) const {
    const auto r = encode_account_into(acc_rlp_buf, *this, storage_root_arg.bytes);
    acc_rlp_len = r.len;
    acc_rlp_sroot_off = r.sroot_off;
    return r.len;
}

uint8_t Account::rlp_into_cache() const {
    const auto r = encode_account_into(acc_rlp_buf, *this, storage_root);
    acc_rlp_len = r.len;
    acc_rlp_sroot_off = r.sroot_off;
    return r.len;
}

bool decode_trie_account(silkworm::ByteView leaf_value, Account& out) {
    auto outer = silkworm::rlp::decode_header(leaf_value);
    if (!outer || !outer->list) return false;
    silkworm::ByteView body = leaf_value.substr(0, outer->payload_length);

    intx::uint256 balance_v;
    evmc::bytes32 storage_root_v;
    evmc::bytes32 code_hash_v;
    if (!silkworm::rlp::decode(body, out.nonce, silkworm::rlp::Leftover::kAllow))      return false;
    if (!silkworm::rlp::decode(body, balance_v, silkworm::rlp::Leftover::kAllow))      return false;
    if (!silkworm::rlp::decode(body, storage_root_v, silkworm::rlp::Leftover::kAllow)) return false;
    if (!silkworm::rlp::decode(body, code_hash_v, silkworm::rlp::Leftover::kAllow))    return false;
    std::memcpy(out.balance, &balance_v, 32);
    std::memcpy(out.storage_root, storage_root_v.bytes, 32);
    std::memcpy(out.code_hash, code_hash_v.bytes, 32);
    return true;
}

}  // namespace zilkworm
