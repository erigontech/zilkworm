// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "direct_state.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <utility>
#include <vector>

#include <zilk_core/core/common_zz/mphf_builder.hpp>

namespace zilkworm {

namespace detail {
std::array<uint8_t, 32> keccak_addr(const evmc::address& addr) noexcept;
}  // namespace detail

namespace {

    inline void copy32(uint8_t (&dst)[32], const evmc::bytes32& src) noexcept {
        std::memcpy(dst, src.bytes, 32);
    }

    inline std::vector<uint8_t> account_info_to_pre_account_bytes(
        DirectState::AccountInfo& info) {
        const uint32_t slot_count = static_cast<uint32_t>(info.storage.size());
        const uint32_t code_len = static_cast<uint32_t>(info.account.code_store_len);
        const size_t body_size = sizeof(Account) + static_cast<size_t>(slot_count) * sizeof(Slot);
        std::vector<uint8_t> body(body_size, 0);

        auto* pa = reinterpret_cast<Account*>(body.data());
        std::memcpy(pa->addr, info.addr.bytes, 20);
        pa->nonce = info.account.nonce;
        std::memcpy(pa->balance, info.account.balance, 32);
        std::memcpy(pa->code_hash, info.account.code_hash, 32);
        std::memcpy(pa->storage_root, info.account.storage_root, 32);
        pa->code_store_offset = 0;
        pa->code_store_len = code_len;
        pa->slot_count = slot_count;

        if (slot_count > 0) {
            auto kv_sorted = std::move(info.storage);
            std::sort(kv_sorted.begin(), kv_sorted.end(),
                      [](const auto& x, const auto& y) {
                          return std::memcmp(x.first.bytes, y.first.bytes, 32) < 0;
                      });
            auto* slot_base = reinterpret_cast<Slot*>(body.data() + sizeof(Account));
            for (uint32_t s = 0; s < slot_count; ++s) {
                Slot slot{};
                copy32(slot.key, kv_sorted[s].first);
                copy32(slot.initial, kv_sorted[s].second);
                copy32(slot.current, kv_sorted[s].second);
                slot_base[s] = slot;
            }
        }
        return body;
    }

}  // namespace

std::vector<uint8_t> DirectState::build_blob_from_accounts(std::vector<AccountInfo> accounts,
                                                           std::vector<BlockHashEntry> block_hashes,
                                                           std::vector<uint8_t> code_store_blob) {
    std::sort(accounts.begin(), accounts.end(),
              [](const AccountInfo& x, const AccountInfo& y) {
                  return std::memcmp(x.addr.bytes, y.addr.bytes, 20) < 0;
              });

    const uint32_t n_accounts = static_cast<uint32_t>(accounts.size());

    std::vector<uint64_t> addr_key8_entries;
    addr_key8_entries.reserve(n_accounts);
    for (uint32_t i = 0; i < n_accounts; ++i) {
        addr_key8_entries.push_back(addr_key8(accounts[i].addr));
    }

    std::vector<AddrHashEntry> addr_hashes;
    std::vector<std::vector<uint8_t>> acc_body_bytes;
    addr_hashes.reserve(n_accounts);
    acc_body_bytes.reserve(n_accounts);

    for (uint32_t i = 0; i < n_accounts; ++i) {
        AddrHashEntry ahe{};
        std::memcpy(ahe.addr_hash, silkworm::keccak256(ByteView{accounts[i].addr.bytes, 20}).bytes, 32);
        std::memcpy(ahe.addr, accounts[i].addr.bytes, 20);
        addr_hashes.push_back(ahe);
        acc_body_bytes.emplace_back(account_info_to_pre_account_bytes(accounts[i]));
    }

    std::vector<uint8_t> mphf_bytes;
    if (n_accounts > 0) {
        MphfBuilder<20> mphf_builder{kMphfAddrMapMagic, kMphfMapVersion};
        for (uint32_t i = 0; i < n_accounts; ++i) {
            mphf_builder.add(addr_key8_entries[i],
                             ByteView{acc_body_bytes[i].data(), acc_body_bytes[i].size()});
        }
        mphf_bytes = std::move(mphf_builder).finalize();
        if (mphf_bytes.empty()) {
            sys_println("DirectState::build_blob_from_accounts: addr MPHF construction failed");
            return {};
        }
    }
    const uint32_t mphf_size = static_cast<uint32_t>(mphf_bytes.size());
    const uint32_t code_store_size = static_cast<uint32_t>(code_store_blob.size());

    std::sort(block_hashes.begin(), block_hashes.end(),
              [](const BlockHashEntry& a, const BlockHashEntry& b) noexcept {
                  return a.block_number < b.block_number;
              });
    const uint32_t n_block_hashes = static_cast<uint32_t>(block_hashes.size());

    // Layout: meta | prestate-MphfMapHeader | addr_hashes | block_hashes | code_store.
    uint32_t off = align8(static_cast<uint32_t>(sizeof(PreStateMeta)));
    const uint32_t prestate_offset = off;
    off += align8(mphf_size);
    const uint32_t addr_hashes_offset = off;
    off += align8(n_accounts * static_cast<uint32_t>(sizeof(AddrHashEntry)));
    const uint32_t block_hashes_offset = off;
    off += align8(n_block_hashes * static_cast<uint32_t>(sizeof(BlockHashEntry)));
    const uint32_t code_store_offset = off;
    off += align8(code_store_size);
    const uint32_t total_size = off;

    std::vector<uint8_t> blob(total_size, 0);

    {
        auto* meta = reinterpret_cast<PreStateMeta*>(blob.data());
        meta->magic = kMagic;
        meta->version = kVersion;
        meta->n_accounts = n_accounts;
        meta->n_block_hashes = n_block_hashes;
        meta->prestate_offset = prestate_offset;
        meta->addr_hashes_offset = addr_hashes_offset;
        meta->block_hashes_offset = block_hashes_offset;
        meta->code_store_offset = code_store_offset;
        meta->code_store_size = code_store_size;
    }
    if (code_store_size > 0) {
        std::memcpy(blob.data() + code_store_offset, code_store_blob.data(), code_store_size);
    }
    if (n_block_hashes > 0) {
        std::memcpy(blob.data() + block_hashes_offset, block_hashes.data(),
                    n_block_hashes * sizeof(BlockHashEntry));
    }

    if (mphf_size > 0) {
        std::memcpy(blob.data() + prestate_offset, mphf_bytes.data(), mphf_size);
    }
    const auto* mphf_hdr = mphf_size > 0
                               ? reinterpret_cast<const MphfMapHeader*>(blob.data() + prestate_offset)
                               : nullptr;

    auto entry_offset_for_addr = [&](const uint8_t addr20[20]) -> uint32_t {
        if (!mphf_hdr) return 0u;
        uint64_t k8;
        std::memcpy(&k8, addr20, 8);
        k8 = (k8 & 0x00FFFFFFFFFFFFFFull) | (uint64_t(addr20[19]) << 56);
        const uint32_t idx = mphf_hdr->index_lookup(k8);
        const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
            reinterpret_cast<const uint8_t*>(mphf_hdr) + mphf_hdr->slot_offsets_offset);
        const uint32_t off_singleton = slot_offsets[idx];
        const uint8_t* data = reinterpret_cast<const uint8_t*>(mphf_hdr) + mphf_hdr->data_offset;
        if (off_singleton != 0) {
            if (std::memcmp(data + off_singleton + 8u, addr20, 20) == 0) return off_singleton;
        }
        if (mphf_hdr->collisions_size > 0) {
            const auto* entries = reinterpret_cast<const MphfCollisionEntry*>(
                reinterpret_cast<const uint8_t*>(mphf_hdr) + mphf_hdr->collisions_offset);
            const uint32_t n_c = mphf_hdr->collisions_size / static_cast<uint32_t>(sizeof(MphfCollisionEntry));
            auto it = std::lower_bound(
                entries, entries + n_c, k8,
                [](const MphfCollisionEntry& e, uint64_t k) noexcept { return e.key < k; });
            for (; it != entries + n_c && it->key == k8; ++it) {
                if (std::memcmp(data + it->offset + 8u, addr20, 20) == 0) return it->offset;
            }
        }
        return 0u;
    };

    auto* ahe_base = reinterpret_cast<AddrHashEntry*>(blob.data() + addr_hashes_offset);
    for (uint32_t s = 0; s < n_accounts; ++s) {
        AddrHashEntry e = addr_hashes[s];
        e.entry_offset = entry_offset_for_addr(e.addr);
        ahe_base[s] = e;
    }

    std::sort(ahe_base, ahe_base + n_accounts);

    return blob;
}

}  // namespace zilkworm
