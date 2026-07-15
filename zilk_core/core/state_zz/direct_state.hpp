// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone/test/state/state_view.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/hash_maps.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state/block_state.hpp>
#include <zilk_core/core/state_zz/pre_state.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>
#include <zilk_core/print.hpp>

namespace evmone::state {
struct StateDiff;
}

namespace zilkworm {

using ::silkworm::BlockBody;
using ::silkworm::BlockHeader;
using ::silkworm::BlockNum;
using ::silkworm::BlockState;
using ::silkworm::Bytes;
using ::silkworm::ByteView;
using ::silkworm::FlatHashMap;
using ::silkworm::FlatHashSet;
using ::silkworm::kEmptyHash;
using ::silkworm::kEmptyRoot;

[[gnu::always_inline]] inline uint64_t hash_key8(const uint8_t (&h)[32]) noexcept {
    uint64_t v; std::memcpy(&v, h, 8); return v;
}
[[gnu::always_inline]] inline uint64_t hash_key8(const evmc::bytes32& hash) noexcept { return hash_key8(hash.bytes); }

// 7 MSBs + 19th byte (LSB): precompile addrs vary only in byte 19.
// Legacy raw-address key reduction; the pre-state map is now keyed by
// keccak256(address) via hash_key8. Kept for generic MphfMap tests.
[[gnu::always_inline]] inline uint64_t addr_key8(const uint8_t (&a)[20]) noexcept {
    uint64_t k; std::memcpy(&k, a, 8);
    k = (k & 0x00FFFFFFFFFFFFFFull) | (uint64_t(a[19]) << 56); return k;
}
[[gnu::always_inline]] inline uint64_t addr_key8(const evmc::address& a) noexcept { return addr_key8(a.bytes); }

inline constexpr uint32_t kMphfAddrMapMagic = 0x4148504Du;    // 'MPHA'
inline constexpr uint32_t kMphfCodeStoreMagic = 0x4348504Du;  // 'MPHC'
inline constexpr uint32_t kMphfNodeStoreMagic = 0x4E48504Du;  // 'MPHN'

// Sentinel: in-block created code; look up via created_code_[key8].
inline constexpr uint32_t kCreatedCodeOffset = ~uint32_t{0};

struct CreatedCodeEntry {
    evmc::bytes32 full_hash;
    std::vector<uint8_t> bytes;
};

class DirectState : public BlockState {
  private:
    std::span<uint8_t> prestate_view_;
    const PreStateMeta* pre_state_meta_{nullptr};
    MphfMap pre_state_map_;
    MphfMap node_store_map_;
    MphfMap code_store_map_;

    std::span<const AddrHashEntry> addr_hashes_;
    std::span<const BlockHashEntry> block_hashes_;

    FlatHashMap<evmc::address, Account> created_accounts_;
    // Keyed by keccak256(address); inner map by keccak256(slot key) — the same
    // trie keys the pre-state blob uses, so root computation needs no preimage.
    FlatHashMap<evmc::bytes32, FlatHashMap<evmc::bytes32, evmc::bytes32>> overflow_slots_;
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;
    FlatHashSet<evmc::address> touched_;
    FlatHashMap<evmc::bytes32, BlockHeader> headers_;
    std::vector<BlockHashEntry> created_block_hashes_;
    FlatHashSet<evmc::address> delegated_designations_;

    bool multi_block_{false};
    // Journal only used for multi-block cases
    FlatHashSet<evmc::address> changed_addresses_journal_;
    FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>> changed_storage_journal_;

    // Memoized trie-key hashing: one keccak per unique address / slot key.
    mutable FlatHashMap<evmc::address, evmc::bytes32> addr_hash_cache_;
    mutable FlatHashMap<evmc::bytes32, evmc::bytes32> slot_hash_cache_;

    Account* find_or_create_pre_account_slow(const evmc::address& addr);
    bool revive_if_deleted_slow(const evmc::address& addr, Account& pa);
    void reserve_block_maps_() noexcept;

  public:
    explicit DirectState(std::span<uint8_t> prestate_bytes) noexcept;
    DirectState(std::span<uint8_t> prestate_bytes,
                std::span<uint8_t> nodestore_bytes) noexcept;

    DirectState(const DirectState&) = delete;
    DirectState& operator=(const DirectState&) = delete;
    DirectState(DirectState&& other) noexcept;
    DirectState& operator=(DirectState&& other) noexcept;

    [[gnu::always_inline]] inline const Account* read_account(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account* read_account(const evmc::address& addr) noexcept;
    evmc::bytes32 read_storage(const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept;
    ByteView read_code(const evmc::address& addr) const noexcept;
    ByteView read_code(const evmc::address& addr, const evmc::bytes32& /*code_hash*/) const noexcept {
        return read_code(addr);
    }
    evmc::bytes32 get_block_hash(BlockNum n) const noexcept;
    [[gnu::always_inline]] inline bool has_storage(const evmc::address& addr) const noexcept {
        const evmc::bytes32 ah = hashed_address(addr);
        if (const auto* pa = find_pre_account_by_hash(ah); pa != nullptr) {
            if (pa->deleted) [[unlikely]]
                return false;
            if (pa->slot_count > 0) return true;
        }
        if (auto it = overflow_slots_.find(ah); it != overflow_slots_.end() && !it->second.empty()) return true;
        return false;
    }

    void apply_state_diff(const evmone::state::StateDiff& diff);

    intx::uint256 get_balance(const evmc::address& addr) const noexcept;
    uint64_t get_nonce(const evmc::address& addr) const noexcept;
    void set_balance(const evmc::address& addr, const intx::uint256& value);
    void add_to_balance(const evmc::address& addr, const intx::uint256& addend);
    void subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend);
    void set_nonce(const evmc::address& addr, uint64_t nonce);
    void set_code(const evmc::address& addr, ByteView code);
    void destruct(const evmc::address& addr);

    bool is_dead(const evmc::address& addr) const noexcept;
    bool is_deleted(const evmc::address& addr) const noexcept;
    bool is_empty_account(const evmc::address& addr) const noexcept;
    void destruct_dead_among(const FlatHashSet<evmc::address>& addrs);

    const FlatHashSet<evmc::address>& touched() const noexcept { return touched_; }
    void clear_touched() noexcept { touched_.clear(); }

    evmc::bytes32 account_storage_root(const evmc::address& addr) const;
    // Storage root from a pre-state record (may be nullptr) merged with the
    // overflow slots registered under addr_hash. Slot keys are trie keys.
    evmc::bytes32 storage_root_from(const Account* pa,
                                    const evmc::bytes32& addr_hash) const;
    std::optional<evmc::bytes32> state_root_hash() const;

    std::optional<BlockHeader> read_header(BlockNum block_num,
                                           const evmc::bytes32& block_hash) const noexcept override;
    [[nodiscard]] bool read_body(BlockNum block_num, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;
    std::optional<intx::uint256> total_difficulty(uint64_t block_num,
                                                  const evmc::bytes32& block_hash) const noexcept override;
    void insert_header(const BlockHeader& header);

    bool sanitize();

    // Producer-side account description. Either the raw address (hashed by
    // build_blob_from_accounts) or the trie key addr_hash directly may be
    // given; addr_hash == 0 means "derive from addr". storage keys are raw
    // slot keys unless storage_keys_hashed is set (then keccak256(slot key)).
    struct AccountInfo {
        evmc::address addr;
        evmc::bytes32 addr_hash;
        Account account;
        std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage;
        bool storage_keys_hashed{false};
    };

    static std::vector<uint8_t> build_blob_from_accounts(
        std::vector<AccountInfo> accounts,
        std::vector<BlockHashEntry> block_hashes,
        std::vector<uint8_t> code_store_blob);

    const PreStateMeta& meta() const noexcept { return *pre_state_meta_; }
    const MphfMapHeader* mphf() const noexcept { return pre_state_map_.header(); }
    std::span<const AddrHashEntry> addr_hashes() const noexcept { return addr_hashes_; }
    std::span<const BlockHashEntry> block_hashes() const noexcept { return block_hashes_; }

    [[gnu::always_inline]] inline Account*
    account_at_offset(uint32_t entry_offset) noexcept {
        return reinterpret_cast<Account*>(pre_state_map_.data() + entry_offset + 8u);
    }
    [[gnu::always_inline]] inline const Account*
    account_at_offset(uint32_t entry_offset) const noexcept {
        return reinterpret_cast<const Account*>(pre_state_map_.data() + entry_offset + 8u);
    }

    [[gnu::always_inline]] inline std::span<Slot>
    slots_for(Account& pa) noexcept {
        if (pa.slot_count == 0) return {};
        return {reinterpret_cast<Slot*>(&pa + 1),
                pa.slot_count};
    }
    [[gnu::always_inline]] inline std::span<const Slot>
    slots_for(const Account& pa) const noexcept {
        if (pa.slot_count == 0) return {};
        return {reinterpret_cast<const Slot*>(&pa + 1),
                pa.slot_count};
    }
    [[gnu::always_inline]] inline ByteView
    code_for(const Account& pa) const noexcept {
        if (pa.code_store_len == 0) return {};
        return ByteView{code_store_map_.data() + pa.code_store_offset + FlatKv::kPayloadOffset,
                        pa.code_store_len};
    }

    // keccak256 of a queried address / slot key, memoized so each unique key
    // costs one keccak (relevant inside the zkVM guest).
    evmc::bytes32 hashed_address(const evmc::address& addr) const noexcept;
    evmc::bytes32 hashed_slot_key(const evmc::bytes32& key) const noexcept;

    // True iff the record satisfies the EIP-161 empty-account predicate.
    [[gnu::always_inline]] static inline bool
    account_is_empty(const Account& pa) noexcept {
        intx::uint256 bal;
        std::memcpy(&bal, pa.balance, 32);
        return pa.nonce == 0 && eq_hash32(pa.code_hash, kEmptyHash.bytes) && bal == 0;
    }

    [[gnu::always_inline]] inline const Account*
    find_pre_account(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account*
    find_pre_account(const evmc::address& addr) noexcept;

    [[gnu::always_inline]] inline const Account*
    find_pre_account_by_hash(const evmc::bytes32& addr_hash) const noexcept;
    [[gnu::always_inline]] inline Account*
    find_pre_account_by_hash(const evmc::bytes32& addr_hash) noexcept;

    [[gnu::always_inline]] inline const Account*
    find_pre_account_unchecked(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account*
    find_pre_account_unchecked(const evmc::address& addr) noexcept;

    [[gnu::always_inline]] inline const Account*
    read_account_unchecked(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account*
    read_account_unchecked(const evmc::address& addr) noexcept;

    [[gnu::always_inline]] inline const Account*
    find_created_account(const evmc::address& addr) const noexcept {
        const auto it = created_accounts_.find(addr);
        if (it == created_accounts_.end()) return nullptr;
        return &it->second;
    }
    [[gnu::always_inline]] inline Account*
    find_created_account(const evmc::address& addr) noexcept {
        const auto it = created_accounts_.find(addr);
        if (it == created_accounts_.end()) return nullptr;
        return &it->second;
    }

    [[gnu::always_inline]] inline std::span<const Slot>
    existing_slots_for(const evmc::address& addr) const noexcept {
        const auto* pa = find_pre_account(addr);
        if (pa == nullptr || pa->slot_count == 0) return {};
        return slots_for(*pa).first(pa->slot_count);
    }

    [[gnu::always_inline]] inline const FlatHashMap<evmc::bytes32, evmc::bytes32>*
    overflow_slots_for(const evmc::bytes32& addr_hash) const noexcept {
        const auto it = overflow_slots_.find(addr_hash);
        if (it == overflow_slots_.end()) return nullptr;
        return &it->second;
    }

    const FlatHashMap<evmc::address, Account>& created_accounts() const noexcept { return created_accounts_; }

    void set_multi_block(bool v) noexcept { multi_block_ = v; }

    void journal_address_changed(const evmc::address& a) {
        if (!multi_block_) return;
        changed_addresses_journal_.insert(a);
    }
    void journal_slot_changed(const evmc::address& a, const evmc::bytes32& k) {
        if (!multi_block_) return;
        changed_addresses_journal_.insert(a);
        changed_storage_journal_[a].insert(k);
    }
    void clear_change_journal() noexcept {
        changed_addresses_journal_.clear();
        changed_storage_journal_.clear();
    }
    const FlatHashSet<evmc::address>& changed_addresses_journal() const noexcept {
        return changed_addresses_journal_;
    }
    const FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>>&
    changed_storage_journal() const noexcept {
        return changed_storage_journal_;
    }

    [[gnu::always_inline]] inline Account*
    find_or_create_pre_account(const evmc::address& addr) {
        // Unchecked: a deleted blob record is revived in place, never shadowed.
        if (auto* pa = find_pre_account_unchecked(addr)) return pa;
        if (!created_accounts_.empty()) [[unlikely]] {
            if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
                return &it->second;
        }
        return find_or_create_pre_account_slow(addr);
    }

    [[gnu::always_inline]] inline bool
    revive_if_deleted(const evmc::address& addr, Account& pa) {
        if (!pa.deleted) [[likely]]
            return false;
        return revive_if_deleted_slow(addr, pa);
    }

    void set_account_from_diff(Account& pa, uint64_t nonce,
                               const intx::uint256& balance) noexcept;
    void set_storage_slot(const evmc::address& addr, Account& pa,
                          const evmc::bytes32& key, const evmc::bytes32& value);
    void apply_code_diff(const evmc::address& addr, Account& pa,
                         const evmc::bytes& code);

    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash) const noexcept;
};

[[gnu::always_inline]] inline const Account*
DirectState::find_pre_account(const evmc::address& addr) const noexcept {
    const auto* pa = find_pre_account_unchecked(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

[[gnu::always_inline]] inline const Account*
DirectState::find_pre_account_by_hash(const evmc::bytes32& addr_hash) const noexcept {
    if (auto b = pre_state_map_.find<32, 0, &hash_key8>(addr_hash.bytes))
        return reinterpret_cast<const Account*>(b->data());
    return nullptr;
}

[[gnu::always_inline]] inline Account*
DirectState::find_pre_account_by_hash(const evmc::bytes32& addr_hash) noexcept {
    if (auto b = pre_state_map_.find<32, 0, &hash_key8>(addr_hash.bytes))
        return reinterpret_cast<Account*>(b->data());
    return nullptr;
}

[[gnu::always_inline]] inline const Account*
DirectState::find_pre_account_unchecked(const evmc::address& addr) const noexcept {
    if (!pre_state_map_.valid()) return nullptr;
    return find_pre_account_by_hash(hashed_address(addr));
}

[[gnu::always_inline]] inline Account*
DirectState::find_pre_account_unchecked(const evmc::address& addr) noexcept {
    if (!pre_state_map_.valid()) return nullptr;
    return find_pre_account_by_hash(hashed_address(addr));
}

[[gnu::always_inline]] inline Account*
DirectState::find_pre_account(const evmc::address& addr) noexcept {
    auto* pa = find_pre_account_unchecked(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
    if (auto b = node_store_map_.find<32, 0, &hash_key8>(node_hash.bytes))
        return ByteView{b->data() + FlatKv::kPayloadOffset, b->size() - FlatKv::kPayloadOffset};
    return std::nullopt;
}

[[gnu::always_inline]] inline ByteView
DirectState::read_code(const evmc::address& addr) const noexcept {
    const Account* pa = find_pre_account_unchecked(addr);
    if (!pa) {
        if (!created_accounts_.empty()) [[unlikely]] {
            if (auto it = created_accounts_.find(addr); it != created_accounts_.end()) {
                pa = &it->second;
            } else {
                return {};
            }
        } else {
            return {};
        }
    }
    if (pa->deleted) [[unlikely]]
        return {};

    if (pa->code_store_len == 0) {
        // Pre-state already checked, the following not necessary
        // if (std::memcmp(pa->code_hash, kEmptyHash.bytes, 32) != 0) [[unlikely]] {
        //     // Witness producer dropped this account's bytecode — abort.
        //     [&]() __attribute__((cold, noreturn)) {
        //         sys_println("ERROR: read_code on account whose code was omitted from witness");
        //         std::abort();
        //     }();
        // }
        return {};
    }

    if (pa->code_store_offset == kCreatedCodeOffset) [[unlikely]] {
        const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa->code_hash);
        const uint64_t k8 = hash_key8(h);
        if (auto it = created_code_.find(k8); it != created_code_.end() &&
                                              std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) [[likely]] {
            return ByteView{it->second.bytes.data(), it->second.bytes.size()};
        }
        if (auto cit = created_code_collisions_.find(h);
            cit != created_code_collisions_.end()) {
            return ByteView{cit->second.data(), cit->second.size()};
        }
        return {};
    }

    return code_for(*pa);
}

[[gnu::always_inline]] inline const Account*
DirectState::read_account(const evmc::address& addr) const noexcept {
    const auto* pa = read_account_unchecked(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

[[gnu::always_inline]] inline const Account*
DirectState::read_account_unchecked(const evmc::address& addr) const noexcept {
    if (const auto* pa = find_pre_account_unchecked(addr)) return pa;
    if (!created_accounts_.empty()) [[unlikely]] {
        if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
            return &it->second;
    }
    return nullptr;
}

[[gnu::always_inline]] inline Account*
DirectState::read_account(const evmc::address& addr) noexcept {
    auto* pa = read_account_unchecked(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

[[gnu::always_inline]] inline Account*
DirectState::read_account_unchecked(const evmc::address& addr) noexcept {
    if (auto* pa = find_pre_account_unchecked(addr)) return pa;
    if (!created_accounts_.empty()) [[unlikely]] {
        if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
            return &it->second;
    }
    return nullptr;
}

class DirectStateView final : public evmone::state::StateView {
  public:
    explicit DirectStateView(const DirectState& s) noexcept : state_{s} {}

    std::optional<Account> get_account(const evmc::address& addr) const noexcept override {
        const auto* pa = state_.read_account(addr);
        if (pa == nullptr) return std::nullopt;
        intx::uint256 balance_v;
        std::memcpy(&balance_v, pa->balance, 32);
        return Account{
            .nonce = pa->nonce,
            .balance = balance_v,
            .code_hash = std::bit_cast<evmc::bytes32>(pa->code_hash),
            .has_storage = state_.has_storage(addr),
        };
    }

    evmc::bytes get_account_code(const evmc::address& addr) const noexcept override {
        const auto bv = state_.read_code(addr);
        return evmc::bytes{bv.data(), bv.size()};
    }

    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
        return state_.read_storage(addr, key);
    }

  private:
    const DirectState& state_;
};

}  // namespace zilkworm
