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
#include <evmone/baseline.hpp>
#include <evmone/test/state/state_view.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/hash_maps.hpp>
#include <zilk_core/core/common_zz/index_key.hpp>
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

// sanitize() pads the code store's payloads for the EVM where they lie, see code_store_seal.hpp.
// With USE_HASH_KEY, account recovery looks code up after that in an index sanitize() keeps.
#if EVMONE_IN_PLACE_CODE
#define ZILK_SEAL_CODE_STORE 1
#else
#define ZILK_SEAL_CODE_STORE 0
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

#if defined(Z6M_GUEST_PROFILE) || defined(Z6M_HOST_PROFILE)
// Profiling counters, defined in evmone_precompiles/keccak.c.
extern "C" uint64_t z6mprof_node_verify;
extern "C" uint64_t z6mprof_node_verify_bytes;
#endif

/// Whether the keccak of `payload` is the 32 bytes at `expected` (any alignment). On the Airbender
/// guest the hash is compared inside the keccak state, so it is never stored out and loaded back.
[[gnu::always_inline]] inline bool keccak256_equals(ByteView payload, const uint8_t* expected) noexcept {
#if defined(Z6M_GUEST_PROFILE) || defined(Z6M_HOST_PROFILE)
    ++z6mprof_node_verify;
    z6mprof_node_verify_bytes += payload.size();
#endif
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    return ethash_keccak256_eq(expected, payload.data(), payload.size());
#else
    return bytes_equal<32>(silkworm::keccak256(payload).bytes, expected);
#endif
}

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

/// A read of a slot the witness does not carry, which DirectState answers with zero: a claim that the key
/// is absent from the storage trie of the record it was read from, which check_root walks. The witness
/// carries the slots an account has, and only the walk shows that it did not leave out the one read.
/// The reads of a record are a list, newest first, from Account::absent_reads.
struct AbsentRead {
    evmc::bytes32 key;
    uint32_t prev;  // 1 + the index of the record's previous read, 0 for none
};

/// The witness slots of a pre-state account whose storage the block wiped, and the storage root of the
/// account's pre-state leaf they have to be bound to, as do its reads of slots the witness does not carry
/// (`absent_reads`, the head of their list, see AbsentRead).
struct WipedStorage {
    std::span<const Slot> slots;
    evmc::bytes32 storage_root;
    uint32_t absent_reads;
};

// Bounds + alignment + magic/version checks against malicious blob input: the same
// checks the DirectState constructor performs (aborting on failure), exposed without
// the abort so a host can pre-check and route the failure to a clean rejection.
[[nodiscard]] bool validate_prestate_layout(std::span<const uint8_t> blob) noexcept;
[[nodiscard]] bool validate_nodestore_layout(std::span<const uint8_t> ns) noexcept;

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
#if ZILK_SEAL_CODE_STORE
    /// Set once sanitize() has zeroed the bytes after each code-store payload, which takes the
    /// lengths and parts of the keys of the entries: code_store_map_ then serves code_for() only,
    /// and no lookup by hash. The region it registered with evmone is reset with this object.
    bool code_store_sealed_{false};
    /// The key, body offset and body size of every code-store entry, taken by sanitize() after it
    /// bound each payload to its key and before the seal zeroes the lengths and keys: read_code()
    /// for a record without a code length, and account recovery (USE_HASH_KEY), look code up here
    /// once the map cannot.
    struct SealedCodeEntry {
        uint8_t key[32];
        uint32_t body_off;
        uint32_t body_len;
    };
    std::vector<SealedCodeEntry> sealed_code_index_;
#endif
#if USE_HASH_KEY || ZILK_SEAL_CODE_STORE
    // The code-store entry body ([key][payload]) for a code hash, sealed or not.
    std::optional<std::span<const uint8_t>> code_entry_by_hash_(const uint8_t (&hash)[32]) const noexcept;
#endif

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
    // Deleting an account or deploying code to it wipes its storage, so the post-state holds none of
    // the slots the witness carried for it, yet the block can have read them first: check_root still
    // binds them to the pre-state.
    std::vector<WipedStorage> wiped_storage_;
    // Mutable: read_storage() notes the reads it answers with zero, see AbsentRead.
    mutable std::vector<AbsentRead> absent_reads_;
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;
    FlatHashSet<evmc::address> touched_;
    FlatHashMap<evmc::bytes32, BlockHeader> headers_;
    // Set once a block has asked for the hash of an ancestor its headers do not lead to, see get_block_hash().
    mutable bool ancestor_missing_{false};
    // get_block_hash()'s walk so far, for the header of number ancestors_number_ and parent hash
    // ancestors_[0]: ancestors_[d] is the hash of block number - 1 - d. ancestors_end_ is set once the
    // headers held do not lead past the last. insert_header() drops it.
    mutable std::vector<evmc::bytes32> ancestors_;
    mutable BlockNum ancestors_number_{0};
    mutable bool ancestors_end_{false};
    // Set for stateless new-payload inputs, see require_block_hash_headers().
    bool require_block_hash_headers_{false};
    // Set when execution reads code the witness lacks; the block is then invalid.
    mutable bool witness_incomplete_{false};
    // Keeps sizeof(DirectState) a multiple of 16 on the rv32 guest (528 with USE_HASH_KEY, 464 without): 8 bytes
    // off that moved the buffers placed after it off their phase, and the guest's CSR copies of them took about
    // 1k more BigInt calls and 30-40k more cycles a block on nearly every mainnet block (504 bytes against
    // 512 or 528). A member added here should keep the size a multiple of 16 (the static_assert after the
    // class checks it), or be measured. The two flags above take 2 of its 8 bytes.
    [[maybe_unused]] uint8_t ancestors_pad_[6]{};

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
    // Called before the storage of `pa` is wiped, while its slots and storage root are the pre-state's.
    void note_wiped_storage_(const Account& pa);
    void note_absent_read_(const Account& pa, const evmc::bytes32& key) const;
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
    bool recovery_ended_{false};  // see end_recovery()
    enum class WalkMiss : uint8_t { kAbsent, kInvalid };  // kInvalid halts; see fatal()
    std::expected<ByteView, WalkMiss> walk_nodestore_leaf(const evmc::bytes32& root, const nibbles64& want,
                                                          std::array<uint8_t, 32>& embedded_scratch) const;
    const RecoveredSlot* recover_slot_from_nodestore(const Account& pa, const evmc::address& addr,
                                                     const evmc::bytes32& key) const;
    // The keccak states the walks save while they verify a branch (kprefix::kAddrRow, see
    // keccak_prefix.hpp), for check_root's folds to resume from: a row per node address (kprefix::addr_row()),
    // its tag the node's bytes' address and its block count. Allocated with the node store, whose nodes the
    // tags name, so that no tag outlives the bytes it names; the tags start null.
    mutable std::unique_ptr<kprefix::StateRow[]> walk_states_;
    mutable std::unique_ptr<const uint8_t*[]> walk_tags_;
    mutable std::unique_ptr<uint8_t[]> walk_sb_;
    [[gnu::noinline]] bool walk_verify_and_snap(const uint8_t* node, size_t size, unsigned blocks,
                                                const uint8_t* want) const noexcept;
#endif

  public:
    explicit DirectState(std::span<uint8_t> prestate_bytes) noexcept;
    DirectState(std::span<uint8_t> prestate_bytes,
                std::span<uint8_t> nodestore_bytes) noexcept;

    DirectState(const DirectState&) = delete;
    DirectState& operator=(const DirectState&) = delete;
    DirectState(DirectState&& other) noexcept;
#if ZILK_SEAL_CODE_STORE
    ~DirectState() override;
#endif

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
    /// The hash of block `n`, an ancestor of the block `header` heads, as BLOCKHASH reads it. Zero, and
    /// ancestor_missing() set, if the headers held (genesis, ancestors, the blocks run) do not lead from
    /// `header` back to block n + 1.
    evmc::bytes32 get_block_hash(const BlockHeader& header, BlockNum n) const noexcept;
    bool ancestor_missing() const noexcept { return ancestor_missing_; }
    /// get_block_hash() also requires the header of block n itself, as stateless validation derives
    /// BLOCKHASH from the witness headers; a missing one sets ancestor_missing().
    void require_block_hash_headers(bool on) noexcept { require_block_hash_headers_ = on; }
    // True once execution has read code the witness does not supply.
    bool witness_incomplete() const noexcept { return witness_incomplete_; }
    // Clears witness_incomplete() and ancestor_missing() before a block runs.
    void reset_witness_incomplete() noexcept {
        witness_incomplete_ = false;
        ancestor_missing_ = false;
    }
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
        // SOUNDNESS-CRITICAL: decides EIP-7610 create collisions, by the storage root and never by the
        // witness slots: a zero slot is what an absent key holds, and the collision check reads no slot,
        // so the witness need not carry any. A pre-state record's root is the one its account leaf
        // commits to, which check_root binds; a created or revived record's is the empty root, as is that
        // of one a deployment wiped. Only code running at the address clears the storage under a non-empty
        // root, and that leaves the account code or a nonce, a collision either way, until it is
        // destructed. The root of an (8-aligned) record is compared by words: with strict alignment it
        // would be copied out byte by byte first.
        if (!eq_hash32(std::assume_aligned<8>(pa.storage_root), kEmptyRoot.bytes)) return true;
        // Under the empty root, what the block has written: into a witness slot, which check_root binds
        // to a zero initial value, or into overflow_slots_, which holds no zero.
        for (const Slot& slot : slots_for(pa)) {
            if (!evmc::is_zero(std::bit_cast<evmc::bytes32>(slot.current))) return true;
        }
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
    // The MFBD witness carries every code the block reads (sanitize): nothing to keep.
    void note_created_code(ByteView) noexcept {}

    /// Binds the witness: false if it does not hold. Once per blob: on the Airbender guest (and
    /// the rv32 test build) it then zeroes bytes of the code store's entry headers, which a second
    /// DirectState over the blob rejects as malformed.
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
    std::span<const WipedStorage> wiped_storage() const noexcept { return wiped_storage_; }
    std::span<const AbsentRead> absent_reads() const noexcept { return absent_reads_; }
    /// Drops the reads of slots the witness does not carry once check_root has walked them; the lists of
    /// the records must be empty by then.
    void clear_absent_reads() noexcept { absent_reads_.clear(); }
#if USE_HASH_KEY
    const std::vector<std::unique_ptr<Account>>& recovered_accounts() const noexcept { return recovered_accounts_; }
    /// Ends the recovery of accounts and slots from the node store, once check_root has walked the bundle's
    /// first block. The node store holds the tries of the state before that block, and the next block runs
    /// on the state it leaves, which the guest has checked the records it holds rebuild to that block's root:
    /// the witness's, and those the block created or recovered. An account or slot a later block does not
    /// find among them is absent, as without USE_HASH_KEY. What was recovered stays.
    void end_recovery() noexcept { recovery_ended_ = true; }

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
    // `code_hash`, when not null, is keccak256(code), as the EVM's State computed it when it set the code.
    void apply_code_diff(const evmc::address& addr, Account& pa,
                         const evmc::bytes& code, const evmc::bytes32* code_hash = nullptr);

    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash) const noexcept;
#if USE_HASH_KEY
    /// The state a walk saved for the first blocks of the node at `node` (a branch), if it covers at most
    /// `allowed` blocks: taken out of the table, as the resume permutes it in place. {nullptr, 0} if none.
    kprefix::Resume take_walk_state(const uint8_t* node, unsigned allowed) const noexcept {
        if (!walk_tags_) return {nullptr, 0};
        const size_t r = kprefix::addr_row(node);
        if (walk_tags_[r] != node) return {nullptr, 0};
        const unsigned blocks = walk_sb_[r];
        if (blocks == 0 || blocks > allowed) return {nullptr, 0};
        walk_tags_[r] = nullptr;
        return {walk_states_[r].lanes, blocks};
    }
    /// For tests: the block count of the state the table holds for the node at `node`, 0 if none.
    unsigned walk_state_blocks(const uint8_t* node) const noexcept {
        if (!walk_tags_) return 0;
        const size_t r = kprefix::addr_row(node);
        return walk_tags_[r] == node ? walk_sb_[r] : 0;
    }
#endif
    // find_node_rlp() that, when it has to hash a node of a block or more, also saves the keccak state of its
    // first blocks before a slot (kprefix::blocks_before_slot()) in a row of the kprefix pool, or of the table
    // of the walks for kprefix::kAddrRow. `request` is called then, and only then, for the
    // kprefix::SnapRequest: the slot (kNoSlot for no snapshot) and the row.
    template <class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash, SnapRequestFn&& request) const noexcept;
    // The same for a hash that is not a bytes32 object: the caller's copy of it keeps its type as the plain bytes it is.
    template <class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const uint8_t (&node_hash)[32], SnapRequestFn&& request) const noexcept;

  private:
    template <bool kSnap, class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp_impl(const uint8_t (&node_hash)[32], SnapRequestFn&& request) const noexcept;
};

#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
static_assert(sizeof(DirectState) % 16 == 0, "keep the rv32 guest's DirectState a multiple of 16 bytes, see ancestors_pad_");
#endif

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
    return find_node_rlp_impl<false>(node_hash.bytes, 0);
}

template <class SnapRequestFn>
[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp(const evmc::bytes32& node_hash, SnapRequestFn&& request) const noexcept {
    return find_node_rlp_impl<true>(node_hash.bytes, request);
}

template <class SnapRequestFn>
[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp(const uint8_t (&node_hash)[32], SnapRequestFn&& request) const noexcept {
    return find_node_rlp_impl<true>(node_hash, request);
}

template <bool kSnap, class SnapRequestFn>
[[gnu::always_inline]] inline std::optional<ByteView>
DirectState::find_node_rlp_impl(const uint8_t (&node_hash)[32], [[maybe_unused]] SnapRequestFn&& request) const noexcept {
    if (auto b = node_store_map_.find<32, 0, &hash_key8>(node_hash)) {
        // SOUNDNESS-CRITICAL: a node is used only if its keccak is the hash it was asked for, so
        // every node that reaches the trie is bound to a hash reference in a verified parent (or
        // the pre-state root). Checked on the first lookup; nodes never looked up never matter.
        // The bit is the body offset / 8: validate_mphf rejects any entry not 8-aligned, so no two
        // bodies share one.
        const auto bit = static_cast<uint32_t>(b->data() - node_store_map_.data_base()) >> 3;
        auto& word = node_verified_[bit >> 5];
        const auto mask = uint32_t{1} << (bit & 31);
        if ((word & mask) == 0) {
            const ByteView payload = FlatKv::payload(ByteView{b->data(), b->size()});
            // The snapshot hash is the same keccak of the same bytes, compared in full all the same.
            bool verified;
            if constexpr (kSnap) {
                // A node of a block or more and no larger than a full branch: a full branch (532 bytes) or any other
                // branch encode_branch() copies and patches, whose hashes fold_line() resumes; rarely a long leaf,
                // whose state no fold uses. Three blocks at most, as the tags' invariant has it (keccak_prefix.hpp).
                const bool big = payload.size() >= kprefix::kBlock && payload.size() <= kprefix::kNodeSize &&
                                 (reinterpret_cast<uintptr_t>(payload.data()) & 7) == 0;
                const kprefix::SnapRequest snap = big ? request() : kprefix::SnapRequest{kprefix::kNoSlot, 0};
                const unsigned blocks = big ? kprefix::blocks_before_slot(payload.data(), payload.size(), snap.slot) : 0;
                if (blocks == 0) {
                    verified = keccak256_equals(payload, node_hash);
                } else {
                    const size_t row = snap.row;
#if USE_HASH_KEY
                    if (row == kprefix::kAddrRow) {
                        verified = walk_verify_and_snap(payload.data(), payload.size(), blocks, node_hash);
                    } else
#endif
                    {
                        verified = kprefix::verify_and_snap(payload.data(), payload.size(), kprefix::pool[row],
                                                            kprefix::tag_orig[row], kprefix::tag_sb[row], blocks,
                                                            node_hash);
                    }
                }
            } else {
                verified = keccak256_equals(payload, node_hash);
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

    if (pa.code_store_len != 0 && pa.code_store_offset != kCreatedCodeOffset) [[likely]]
        return code_for(pa);

    if (std::memcmp(pa.code_hash, kEmptyHash.bytes, 32) == 0)
        return {};

    // Code is content-addressed: the witness may omit a body that an earlier write in the
    // block already supplied (EIP-7928 code_writes satisfy the read), so look it up by hash
    // in the witness code store, then in the in-block created code. A sealed code store is
    // searchable only through the index sanitize() keeps, see code_entry_by_hash_().
    const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa.code_hash);
#if USE_HASH_KEY || ZILK_SEAL_CODE_STORE
    if (const auto e = code_entry_by_hash_(pa.code_hash))
        return ByteView{e->data() + FlatKv::kPayloadOffset, e->size() - FlatKv::kPayloadOffset};
#else
    if (auto b = code_store_map_.find<32, 0, &hash_key8>(h.bytes))
        return ByteView{b->data() + FlatKv::kPayloadOffset, b->size() - FlatKv::kPayloadOffset};
#endif
    if (auto it = created_code_.find(hash_key8(h)); it != created_code_.end() &&
                                                    bytes_equal<32>(it->second.full_hash.bytes, h.bytes)) [[likely]] {
        return ByteView{it->second.bytes.data(), it->second.bytes.size()};
    }
    if (auto cit = created_code_collisions_.find(h); cit != created_code_collisions_.end())
        return ByteView{cit->second.data(), cit->second.size()};

    sys_println("ERROR: read_code: code omitted from witness for non-empty code_hash");
    witness_incomplete_ = true;
    return {};
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
