// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/bytes.hpp>

namespace zilkworm {

// Max RLP encoding of list[nonce, balance, storage_root, code_hash].
inline constexpr uint8_t kAccRlpBufSize = 112u;

// Slots live inline immediately after this struct (slots_for == &acc+1).
// Code lives in MphfCodeStore; code_offset resolved by sanitize().
// Keyed by addr_hash = keccak256(address), i.e. the account trie key. The raw
// 20-byte address is NOT stored: it may be unknown to the witness producer
// (e.g. counterfactual CREATE2 addresses without a key preimage); lookups
// hash the queried address instead.
struct alignas(8) Account {
    uint8_t  addr_hash[32];              // keccak256(address) == account trie key
    bool     deleted;                    // destructed this bundle; masks the record
    mutable uint8_t  acc_rlp_len;
    mutable uint8_t  acc_rlp_sroot_off;  // offset of 0xA0 tag preceding storage_root; 0 = unstamped
    bool     modified;
    uint32_t code_store_offset;          // points to [hash:32][code]; code_for() skips FlatKv::kPayloadOffset
    uint64_t nonce;
    uint8_t  balance[32];                // native-endian
    uint8_t  code_hash[32];
    uint8_t  storage_root[32];
    uint32_t code_store_len;
    uint32_t slot_count;
    mutable uint8_t  acc_rlp_buf[kAccRlpBufSize];

    silkworm::Bytes rlp(const evmc::bytes32& storage_root_arg) const;

    // Fast path memcpy+patch storage_root when cache is valid (acc_rlp_sroot_off != 0).
    uint8_t rlp_into(uint8_t* dst, const evmc::bytes32& storage_root_arg) const;

    // Encodes into acc_rlp_buf and stamps acc_rlp_len + acc_rlp_sroot_off. Returns length.
    uint8_t rlp_into_cache(const evmc::bytes32& storage_root_arg) const;
};

bool decode_trie_account(silkworm::ByteView leaf_value, Account& out);

static_assert(std::is_trivially_copyable_v<Account>);
static_assert(alignof(Account) == 8);
static_assert(sizeof(Account) % 8 == 0);
static_assert(sizeof(Account) == 264);

static_assert(offsetof(Account, addr_hash) == 0);
static_assert(offsetof(Account, deleted) == 32);
static_assert(offsetof(Account, acc_rlp_len) == 33);
static_assert(offsetof(Account, acc_rlp_sroot_off) == 34);
static_assert(offsetof(Account, modified) == 35);
static_assert(offsetof(Account, nonce) == 40);
static_assert(offsetof(Account, nonce) + sizeof(Account::nonce) <= 64,
              "addr_hash/find_pre_account hot fields + nonce must fit in line 0");
static_assert(offsetof(Account, balance) == 48);
static_assert(offsetof(Account, code_hash) == 80);
static_assert(offsetof(Account, storage_root) == 112);
static_assert(offsetof(Account, storage_root) + sizeof(Account::storage_root) <= 144,
              "balance + code_hash + storage_root must fit in lines 1-2");

}  // namespace zilkworm
