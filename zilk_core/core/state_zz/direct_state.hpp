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
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone/test/state/state_view.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/hash_maps.hpp>
#include <zilk_core/core/common_zz/keccak_prefix.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state/block_state.hpp>
#include <zilk_core/core/state_zz/pre_state.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>
#include <zilk_core/print.hpp>

// CMake option; default only for out-of-tree parses.
#ifndef USE_HASH_KEY
#define USE_HASH_KEY 0
#endif

#if USE_HASH_KEY
#include <array>
#include <expected>
#endif

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

#if USE_HASH_KEY
struct nibbles64;  // trie_zz/mpt.hpp
#endif

[[gnu::always_inline]] inline uint64_t hash_key8(const uint8_t (&h)[32]) noexcept {
    uint64_t v; std::memcpy(&v, h, 8); return v;
}
[[gnu::always_inline]] inline uint64_t hash_key8(const evmc::bytes32& hash) noexcept { return hash_key8(hash.bytes); }

// 7 MSBs + 19th byte (LSB): precompile addrs vary only in byte 19
[[gnu::always_inline]] inline uint64_t addr_key8(const uint8_t (&a)[20]) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    // The same key from two word loads: with strict alignment the memcpy below is eight byte
    // loads through a stack temporary, and the callers' addresses are word-aligned.
    if ((reinterpret_cast<uintptr_t>(a) & 3) == 0) [[likely]] {
        typedef uint32_t __attribute__((may_alias)) w32;
        const w32* const w = reinterpret_cast<const w32*>(a);
        return w[0] | (uint64_t{(w[1] & 0x00FFFFFFu) | (uint32_t{a[19]} << 24)} << 32);
    }
#endif
    uint64_t k; std::memcpy(&k, a, 8);
    k = (k & 0x00FFFFFFFFFFFFFFull) | (uint64_t(a[19]) << 56); return k;
}
[[gnu::always_inline]] inline uint64_t addr_key8(const evmc::address& a) noexcept { return addr_key8(a.bytes); }

inline constexpr uint32_t kMphfAddrMapMagic = 0x4148504Du;    // 'MPHA'
inline constexpr uint32_t kMphfCodeStoreMagic = 0x4348504Du;  // 'MPHC'
inline constexpr uint32_t kMphfNodeStoreMagic = 0x4E48504Du;  // 'MPHN'

/// The code-store entries whose hashes the input reader has already checked, see
/// code_store_stream.hpp: bit entry_offset / 8 of @c bits is set for a [len:u64][hash:32][payload]
/// entry at entry_offset in the data section at @c data (of @c data_size bytes) whose payload it
/// hashed as it read it, to the hash stored there. sanitize() takes it once and skips the hashing
/// of those entries. Null (no entry verified) except in the Airbender guest.
struct CodeStoreVerified {
    const uint8_t* data{nullptr};
    uint32_t data_size{0};
    const uint32_t* bits{nullptr};
    uint32_t n_bits{0};
};
extern CodeStoreVerified g_code_store_verified;

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
    /// One bit per 8-aligned node-store data offset: set once the node there has been looked up
    /// and its keccak matched the key, see find_node_rlp(). Lazily verifying what is used costs
    /// the hashing of only those nodes; sanitize() hashed every node of the witness, a tenth of
    /// which no block ever unfolds.
    mutable std::vector<uint32_t> node_verified_;
    MphfMap code_store_map_;

    std::span<const AddrHashEntry> addr_hashes_;
    std::span<const BlockHashEntry> block_hashes_;

    // Mutable: read-only accessors memoize "this address was observed" by
    // materializing an absent record; the observation is logically const.
    mutable FlatHashMap<evmc::address, Account> created_accounts_;
    // DirectStateView hands out pointers to these records (StateView::Account::handle) that must
    // survive the materializing inserts of the rest of the transaction, so they need node stability,
    // which hash_maps.hpp does not promise of FlatHashMap.
    static_assert(std::is_same_v<FlatHashMap<evmc::address, Account>,
                                 std::unordered_map<evmc::address, Account>>);
    FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, evmc::bytes32>> overflow_slots_;
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;
    FlatHashSet<evmc::address> touched_;
    FlatHashMap<evmc::bytes32, BlockHeader> headers_;
    std::vector<BlockHashEntry> created_block_hashes_;

    bool multi_block_{false};
    // Journal only used for multi-block cases
    FlatHashSet<evmc::address> changed_addresses_journal_;
    FlatHashMap<evmc::address, FlatHashSet<evmc::bytes32>> changed_storage_journal_;

    [[gnu::always_inline]] inline const Account*
    lookup_account_(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account*
    lookup_account_(const evmc::address& addr) noexcept;

    // Never returns nullptr: a total miss leaves a deleted record behind.
    [[gnu::always_inline]] inline const Account*
    observe_account_(const evmc::address& addr) const noexcept;

    Account* materialize_absent_account_(const evmc::address& addr) const;
    bool revive_if_deleted_slow(const evmc::address& addr, Account& pa);
    void reserve_block_maps_() noexcept;

#if USE_HASH_KEY
    // Preimage-gap fallback; see USE_HASH_KEY option.
    mutable std::vector<std::unique_ptr<Account>> recovered_accounts_;
    const Account* recover_account_from_nodestore(const evmc::address& addr) const;
    struct RecoveredSlot {
        evmc::bytes32 initial;
        evmc::bytes32 current;  // == initial until an SSTORE lands
        bool found;             // false = walk proved absence
    };
    mutable FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, RecoveredSlot>> recovered_slots_;
    enum class WalkMiss : uint8_t { kAbsent, kInvalid };  // kInvalid halts; see fatal()
    std::expected<ByteView, WalkMiss> walk_nodestore_leaf(const evmc::bytes32& root, const nibbles64& want,
                                                          std::array<uint8_t, 32>& embedded_scratch) const;
    const RecoveredSlot* recover_slot_from_nodestore(const Account& pa, const evmc::address& addr,
                                                     const evmc::bytes32& key) const;
#endif

  public:
    explicit DirectState(std::span<uint8_t> prestate_bytes) noexcept;
    DirectState(std::span<uint8_t> prestate_bytes,
                std::span<uint8_t> nodestore_bytes) noexcept;

    DirectState(const DirectState&) = delete;
    DirectState& operator=(const DirectState&) = delete;
    DirectState(DirectState&& other) noexcept;

    [[gnu::always_inline]] inline const Account* read_account(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account* read_account(const evmc::address& addr) noexcept;
    evmc::bytes32 read_storage(const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept;
    /// read_storage() for the record `pa` of `addr` that the caller already holds.
    evmc::bytes32 read_storage(const Account& pa, const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept;
    ByteView read_code(const evmc::address& addr) const noexcept;
    /// read_code() for a record the caller already holds.
    [[gnu::always_inline]] inline ByteView read_code(const Account& pa) const noexcept;
    ByteView read_code(const evmc::address& addr, const evmc::bytes32& /*code_hash*/) const noexcept {
        return read_code(addr);
    }
    evmc::bytes32 get_block_hash(BlockNum n) const noexcept;
    [[gnu::always_inline]] inline bool has_storage(const evmc::address& addr) const noexcept {
        // Materializing, and overlay-aware: a detached account must not report
        // "no storage" just because it is missing from the blob map.
        const Account* pa = observe_account_(addr);
        if (pa->deleted) [[unlikely]]
            return false;
        return has_storage(addr, *pa);
    }
    /// has_storage() for the live record `pa` of `addr` that the caller already holds.
    [[gnu::always_inline]] inline bool has_storage(const evmc::address& addr, const Account& pa) const noexcept {
        // Only blob records carry inline slots; overlay records use overflow_slots_.
        if (pa.slot_count > 0) return true;
        if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end() && !it->second.empty()) return true;
        return false;
    }

    void apply_state_diff(const evmone::state::StateDiff& diff);

#if !defined(AIRBENDER)
    /// Host builds check every account handle against the lookup it replaces, so the whole test
    /// suite exercises the invariant that the handle is the record of `addr`.
    void check_account_handle(const evmc::address& addr, const void* handle) const noexcept {
        if (handle != nullptr && handle != lookup_account_(addr)) [[unlikely]]
            fatal("ERROR: account handle differs from the lookup of its address");
    }
#endif

    intx::uint256 get_balance(const evmc::address& addr) const noexcept;
    uint64_t get_nonce(const evmc::address& addr) const noexcept;
    void set_balance(const evmc::address& addr, const intx::uint256& value);
    void add_to_balance(const evmc::address& addr, const intx::uint256& addend);
    void subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend);
    void set_nonce(const evmc::address& addr, uint64_t nonce);
    void destruct(const evmc::address& addr);

    bool is_dead(const evmc::address& addr) const noexcept;
    bool is_deleted(const evmc::address& addr) const noexcept;
    bool is_empty_account(const evmc::address& addr) const noexcept;
    void destruct_dead_among(const FlatHashSet<evmc::address>& addrs);

    const FlatHashSet<evmc::address>& touched() const noexcept { return touched_; }
    void clear_touched() noexcept { touched_.clear(); }

    evmc::bytes32 account_storage_root(const evmc::address& addr) const;
    std::optional<evmc::bytes32> state_root_hash() const;

    std::optional<BlockHeader> read_header(BlockNum block_num,
                                           const evmc::bytes32& block_hash) const noexcept override;
    [[nodiscard]] bool read_body(BlockNum block_num, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;
    std::optional<intx::uint256> total_difficulty(uint64_t block_num,
                                                  const evmc::bytes32& block_hash) const noexcept override;
    void insert_header(const BlockHeader& header);

    bool sanitize();

    struct AccountInfo {
        evmc::address addr;
        Account account;
        std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage;
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

    [[gnu::always_inline]] inline const Account*
    find_pre_account_unchecked(const evmc::address& addr) const noexcept;
    [[gnu::always_inline]] inline Account*
    find_pre_account_unchecked(const evmc::address& addr) noexcept;

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

    [[gnu::always_inline]] inline const FlatHashMap<evmc::bytes32, evmc::bytes32>*
    overflow_slots_for(const evmc::address& addr) const noexcept {
        const auto it = overflow_slots_.find(addr);
        if (it == overflow_slots_.end()) return nullptr;
        return &it->second;
    }

    const FlatHashMap<evmc::address, Account>& created_accounts() const noexcept { return created_accounts_; }
#if USE_HASH_KEY
    const std::vector<std::unique_ptr<Account>>& recovered_accounts() const noexcept { return recovered_accounts_; }

    [[gnu::always_inline]] inline const FlatHashMap<evmc::bytes32, RecoveredSlot>*
    recovered_slots_for(const evmc::address& addr) const noexcept {
        const auto it = recovered_slots_.find(addr);
        if (it == recovered_slots_.end()) return nullptr;
        return &it->second;
    }
    [[gnu::always_inline]] inline RecoveredSlot*
    find_recovered_slot(const evmc::address& addr, const evmc::bytes32& key) noexcept {
        const auto it = recovered_slots_.find(addr);
        if (it == recovered_slots_.end()) return nullptr;
        const auto kv = it->second.find(key);
        if (kv == it->second.end()) return nullptr;
        return &kv->second;
    }
#endif

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
    find_or_create_account(const evmc::address& addr) {
        // Unchecked: a deleted blob record is revived in place, never shadowed.
        if (auto* pa = lookup_account_(addr)) return pa;
        return materialize_absent_account_(addr);
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
    // find_node_rlp() that, when it has to hash a full branch, also saves the keccak state of its
    // first blocks before a slot in a row of the kprefix pool. `request` is called then, and only then,
    // for the kprefix::SnapRequest: the slot (kNoSlot for no snapshot) and the row.
    template <class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash, SnapRequestFn&& request) const noexcept;

  private:
    template <bool kSnap, class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp_impl(const evmc::bytes32& node_hash, SnapRequestFn&& request) const noexcept;
};

[[gnu::always_inline]] inline const Account*
DirectState::find_pre_account_unchecked(const evmc::address& addr) const noexcept {
    if (auto b = pre_state_map_.find<20, 0, &addr_key8>(addr.bytes))
        return reinterpret_cast<const Account*>(b->data());
    return nullptr;
}

[[gnu::always_inline]] inline Account*
DirectState::find_pre_account_unchecked(const evmc::address& addr) noexcept {
    if (auto b = pre_state_map_.find<20, 0, &addr_key8>(addr.bytes))
        return reinterpret_cast<Account*>(b->data());
    return nullptr;
}

[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
    return find_node_rlp_impl<false>(node_hash, 0);
}

template <class SnapRequestFn>
[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp(const evmc::bytes32& node_hash, SnapRequestFn&& request) const noexcept {
    return find_node_rlp_impl<true>(node_hash, request);
}

template <bool kSnap, class SnapRequestFn>
[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp_impl(const evmc::bytes32& node_hash, [[maybe_unused]] SnapRequestFn&& request) const noexcept {
    if (auto b = node_store_map_.find<32, 0, &hash_key8>(node_hash.bytes)) {
        // SOUNDNESS-CRITICAL: a node is used only if its keccak is the hash it was asked for, so
        // every node that reaches the trie is bound to a hash reference in a verified parent (or
        // the pre-state root). Checked on the first lookup; nodes never looked up never matter.
        const auto bit = static_cast<uint32_t>(b->data() - node_store_map_.data_base()) >> 3;
        auto& word = node_verified_[bit >> 5];
        const auto mask = uint32_t{1} << (bit & 31);
        if ((word & mask) == 0) {
            const ByteView payload = FlatKv::payload(ByteView{b->data(), b->size()});
            // The snapshot hash is the same keccak of the same bytes, compared in full all the same.
            bool verified;
            if constexpr (kSnap) {
                const bool full = payload.size() == kprefix::kNodeSize && (reinterpret_cast<uintptr_t>(payload.data()) & 7) == 0;
                const kprefix::SnapRequest snap = full ? request() : kprefix::SnapRequest{kprefix::kNoSlot, 0};
                const unsigned blocks = kprefix::first_blocks(snap.slot);
                verified = blocks != 0
                               ? kprefix::verify_and_snap(payload.data(), snap.row, blocks, node_hash.bytes)
                               : bytes_equal<32>(silkworm::keccak256(payload).bytes, node_hash.bytes);
            } else {
                verified = bytes_equal<32>(silkworm::keccak256(payload).bytes, node_hash.bytes);
            }
            if (!verified) [[unlikely]]
                return std::nullopt;  // As a node missing from the witness.
            word |= mask;
        }
        return ByteView{b->data() + FlatKv::kPayloadOffset, b->size() - FlatKv::kPayloadOffset};
    }
    return std::nullopt;
}

[[gnu::always_inline]] inline ByteView
DirectState::read_code(const evmc::address& addr) const noexcept {
    // Materializing: system contracts (EIP-4788/2935/7002/7251) reach an account
    // only through its code, and that read must leave a record all the same.
    return read_code(*observe_account_(addr));
}

[[gnu::always_inline]] inline ByteView
DirectState::read_code(const Account& pa) const noexcept {
    if (pa.deleted) [[unlikely]]
        return {};

    if (pa.code_store_len == 0) {
        // witness omitted code that is read
        if (std::memcmp(pa.code_hash, silkworm::kEmptyHash.bytes, 32) != 0) [[unlikely]]
            fatal("ERROR: read_code: code omitted from witness for non-empty code_hash");
        return {};
    }

    if (pa.code_store_offset == kCreatedCodeOffset) [[unlikely]] {
        const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa.code_hash);
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

    return code_for(pa);
}

[[gnu::always_inline]] inline const Account*
DirectState::lookup_account_(const evmc::address& addr) const noexcept {
    if (const auto* pa = find_pre_account_unchecked(addr)) return pa;
    if (!created_accounts_.empty()) [[unlikely]] {
        if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
            return &it->second;
    }
#if USE_HASH_KEY
    if (const auto* rec = recover_account_from_nodestore(addr)) [[unlikely]] return rec;
#endif
    return nullptr;
}

[[gnu::always_inline]] inline Account*
DirectState::lookup_account_(const evmc::address& addr) noexcept {
    if (auto* pa = find_pre_account_unchecked(addr)) return pa;
    if (!created_accounts_.empty()) [[unlikely]] {
        if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
            return &it->second;
    }
#if USE_HASH_KEY
    if (const auto* rec = recover_account_from_nodestore(addr)) [[unlikely]]
        return const_cast<Account*>(rec);
#endif
    return nullptr;
}

// The const-callable half of find_or_create_account: records the observation of
// `addr` without reviving anything, so a read-only access is still provable
// (non-membership) at root-check time. An existing record — deleted or not — is
// returned as is.
[[gnu::always_inline]] inline const Account*
DirectState::observe_account_(const evmc::address& addr) const noexcept {
    if (const auto* pa = lookup_account_(addr)) return pa;
    return materialize_absent_account_(addr);
}

[[gnu::always_inline]] inline const Account*
DirectState::read_account(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

[[gnu::always_inline]] inline Account*
DirectState::read_account(const evmc::address& addr) noexcept {
    auto* pa = lookup_account_(addr);
    if (pa != nullptr && pa->deleted) [[unlikely]]
        return nullptr;
    return pa;
}

class DirectStateView final : public evmone::state::StateView {
  public:
    explicit DirectStateView(DirectState& s) noexcept : state_{s} {}

    std::optional<Account> get_account(const evmc::address& addr) const noexcept override {
        auto* pa = state_.find_or_create_account(addr);
        if (pa->deleted) return std::nullopt;
        intx::uint256 balance_v;
        std::memcpy(&balance_v, pa->balance, 32);
        return Account{
            .nonce = pa->nonce,
            .balance = balance_v,
            .code_hash = std::bit_cast<evmc::bytes32>(pa->code_hash),
            // From the record in hand: has_storage(addr) would look it up again.
            .has_storage = state_.has_storage(addr, *pa),
            // Records are never erased or replaced and nothing mutates the state between this
            // call and apply_state_diff(), the handle's last use.
            .handle = pa,
        };
    }

    /// Borrowed from the code store, which lives for the whole block, so the EVM can read the
    /// EIP-7702 delegation prefix without materializing the contract.
    evmc::bytes_view get_account_code(const evmc::address& addr) const noexcept override {
        return state_.read_code(addr);  // ByteView derives from evmc::bytes_view.
    }

    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
        return state_.read_storage(addr, key);
    }

    /// A null handle (access-list placeholder, account made by CREATE) takes the lookup.
    evmc::bytes_view get_account_code_at(const void* handle, const evmc::address& addr) const noexcept override {
        if (handle == nullptr) return get_account_code(addr);
#if !defined(AIRBENDER)
        state_.check_account_handle(addr, handle);
#endif
        return state_.read_code(*static_cast<const zilkworm::Account*>(handle));
    }

    evmc::bytes32 get_storage_at(const void* handle, const evmc::address& addr,
                                 const evmc::bytes32& key) const noexcept override {
        if (handle == nullptr) return get_storage(addr, key);
#if !defined(AIRBENDER)
        state_.check_account_handle(addr, handle);
#endif
        return state_.read_storage(*static_cast<const zilkworm::Account*>(handle), addr, key);
    }

  private:
    DirectState& state_;
};

}  // namespace zilkworm
