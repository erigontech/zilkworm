// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "account.hpp"

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

EncodeResult encode_account_into(uint8_t* dst, const Account& a,
                                 const evmc::bytes32& storage_root_arg) noexcept {
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
    std::memcpy(p, storage_root_arg.bytes, silkworm::kHashLength);
    p += silkworm::kHashLength;

    *p++ = 0xA0u;
    std::memcpy(p, a.code_hash, silkworm::kHashLength);
    p += silkworm::kHashLength;

    return {static_cast<uint8_t>(p - dst), sroot_off};
}

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
    return encode_account_into(dst, *this, storage_root_arg).len;
}

uint8_t Account::rlp_into_cache(const evmc::bytes32& storage_root_arg) const {
    const auto r = encode_account_into(acc_rlp_buf, *this, storage_root_arg);
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
