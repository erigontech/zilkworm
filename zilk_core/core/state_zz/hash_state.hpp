// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// HashState: the SSZ-input-path state backend, parallel to DirectState.

#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <deque>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common_zz/hash_index.hpp>
#include <zilk_core/core/common_zz/index_key.hpp>
#include <zilk_core/core/common_zz/keccak_prefix.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/state_zz/active_state.hpp>

namespace zilkworm {

// Derives from BlockState so it can stand in for DirectState wherever a `const BlockState&` is taken.
class HashState : public BlockState {
  public:
    // kMissingNode iff the seeding account root was absent; kMalformed: over-64-nibble path or undecodable node.
    enum class BuildStatus : std::uint8_t { kOk, kMissingNode, kMalformed };

    explicit HashState(std::uint32_t expected_nodes = 1024,
                       std::uint32_t expected_codes = 256,
                       std::uint32_t expected_accounts = 1024,
                       std::uint32_t expected_storage_slots = 4096);

    // The stores hold views into owned_bytes_ or the input blob, so a copy would dangle.
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;

    // Bounds zero-fill a hostile count can force.
    static constexpr std::uint32_t kMaxReserve = 1u << 16;

    // Hints only; each is capped at kMaxReserve.
    void reserve_stores(std::uint32_t nodes, std::uint32_t codes,
                        std::uint32_t accounts, std::uint32_t storage_slots);

    // Stores a copy under its keccak256 and returns the hash; a repeated node is deduped.
    evmc::bytes32 add_node(ByteView rlp);

    evmc::bytes32 add_code(ByteView code);

    // Borrowed: `rlp` / `code` must outlive this HashState.
    evmc::bytes32 add_node_borrowed(ByteView rlp);
    evmc::bytes32 add_code_borrowed(ByteView code);

    // Caller guarantees 32 readable bytes; any alignment.
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const uint8_t* hash32) const noexcept {
        if (auto v = node_index_.find_ptr(hash32)) return ByteView{v->data, v->size};
        return std::nullopt;
    }

    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
        return find_node_rlp(node_hash.bytes);
    }

    // A snapshot request is ignored: HashState keeps no walk states, so no resume state is handed out.
    template <class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash, SnapRequestFn&&) const noexcept {
        return find_node_rlp(node_hash);
    }
    template <class SnapRequestFn>
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const uint8_t (&node_hash)[32], SnapRequestFn&&) const noexcept {
        return find_node_rlp(static_cast<const uint8_t*>(node_hash));
    }
    kprefix::Resume take_walk_state(const uint8_t*, unsigned) const noexcept { return {nullptr, 0}; }

    // A miss returns an EMPTY ByteView (not optional), as DirectState::read_code does.
    [[gnu::always_inline]] inline ByteView
    find_code(const evmc::bytes32& code_hash) const noexcept {
        if (auto v = code_index_.find(code_hash.bytes)) return ByteView{v->data, v->size};
        return {};
    }

    std::uint32_t node_count() const noexcept { return node_index_.size(); }
    std::uint32_t code_count() const noexcept { return code_index_.size(); }
    std::array<std::uint32_t, 4> index_capacities() const noexcept {
        return {node_index_.capacity(), code_index_.capacity(), account_index_.capacity(),
                storage_index_.capacity()};
    }

    // Derives the account and storage caches from prev_root in one read-only trie sweep.
    BuildStatus build_state_from_trie(const evmc::bytes32& prev_root);

    // A miss returns nullptr after confirming absence; an unprovable miss is counted.
    [[gnu::always_inline]] inline const Account*
    get_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes)) {
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        }
        note_account_miss_(addr_hash);
        return nullptr;
    }

    // A miss reads zero after confirming absence; an unprovable miss is counted.
    [[gnu::always_inline]] inline evmc::bytes32
    get_storage(const evmc::bytes32& addr_hash, const evmc::bytes32& slot_hash) const noexcept {
        // 8-aligned: note_storage_miss_ casts the slot half.
        alignas(8) std::uint8_t key[64];
        std::memcpy(key, addr_hash.bytes, 32);
        std::memcpy(key + 32, slot_hash.bytes, 32);
        if (auto off = storage_index_.find(key)) {
            evmc::bytes32 v;
            std::memcpy(v.bytes, storage_arena_.data() + *off, 32);
            return v;
        }
        note_storage_miss_(key);
        return {};
    }

    std::uint32_t account_count() const noexcept { return account_index_.size(); }
    std::uint32_t storage_count() const noexcept { return storage_index_.size(); }
    std::uint32_t leaf_count() const noexcept { return leaf_count_; }
    std::uint32_t storage_slot_count() const noexcept { return storage_slot_count_; }
    // Seeding account root absent from the store: > 0 means the witness anchor is missing and the accept gate must reject (a pruned child boundary is caught at read or fold time).
    std::uint32_t missing_count() const noexcept { return missing_count_; }
    // Read misses that could not be proven absent (a needed node was missing); the accept gate accepts only when this and missing_count() are both zero.
    std::uint32_t unconfirmed_read_count() const noexcept { return unconfirmed_read_count_; }
    std::uint32_t absent_slot_count() const noexcept { return absent_slots_.size(); }

    void insert_header(const BlockHeader& header);

    // SOUNDNESS-CRITICAL: hashes are walked back by parent hash through the held headers from `header`, so every returned hash is bound to the block; an unreachable ancestor sets ancestor_missing() and records an unconfirmed read.
    static constexpr std::size_t kBlockHashDepth = 256;
    evmc::bytes32 get_block_hash(const BlockHeader& header, BlockNum n) const noexcept;
    bool ancestor_missing() const noexcept { return ancestor_missing_; }

    // block_num is unused (as in DirectState); read_body / total_difficulty are stubs (always false / nullopt).
    std::optional<BlockHeader> read_header(BlockNum block_num,
                                           const evmc::bytes32& block_hash) const noexcept override;
    [[nodiscard]] bool read_body(BlockNum block_num, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;
    std::optional<intx::uint256> total_difficulty(uint64_t block_num,
                                                  const evmc::bytes32& block_hash) const noexcept override;

    // A built-cache miss routes through get_account / get_storage, so an unprovable miss is recorded fail-closed.
    const Account* read_account(const evmc::address& addr) const noexcept;
    evmc::bytes32 read_storage(const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept;
    // FAIL-CLOSED: a non-empty code_hash resolving to no bytes bumps unconfirmed_read_count_, so the accept gate rejects a witness that omits bytecode.
    ByteView read_code(const evmc::address& addr) const noexcept;
    ByteView read_code(const evmc::address& addr, const evmc::bytes32& /*code_hash*/) const noexcept {
        return read_code(addr);
    }
    intx::uint256 get_balance(const evmc::address& addr) const noexcept;
    uint64_t get_nonce(const evmc::address& addr) const noexcept;
    bool has_storage(const evmc::address& addr) const noexcept;

    void apply_state_diff(const evmone::state::StateDiff& diff);
    void set_balance(const evmc::address& addr, const intx::uint256& value);
    void add_to_balance(const evmc::address& addr, const intx::uint256& addend);
    void subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend);
    void set_nonce(const evmc::address& addr, uint64_t nonce);
    void set_code(const evmc::address& addr, ByteView code);
    // Keeps `code` by its keccak so a read of an account whose code the witness omits is served when the block derives it elsewhere; sound by the hash binding.
    void note_created_code(ByteView code);
    void destruct(const evmc::address& addr);

    bool is_dead(const evmc::address& addr) const noexcept;
    bool is_deleted(const evmc::address& addr) const noexcept;
    bool is_empty_account(const evmc::address& addr) const noexcept;
    void destruct_dead_among(const FlatHashSet<evmc::address>& addrs);

    const FlatHashSet<evmc::address>& touched() const noexcept { return touched_; }
    void clear_touched() noexcept { touched_.clear(); }

    // A total miss materializes a fresh (deleted) record and confirms absence; an unprovable miss bumps unconfirmed_read_count_, yet a usable record is always returned.
    Account* find_or_create_account(const evmc::address& addr);

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

    void journal_address_changed(const evmc::address&) noexcept {}
    void journal_slot_changed(const evmc::address&, const evmc::bytes32&) noexcept {}

    // Side-effect-free probe (no confirm-on-miss): get_account here would bump unconfirmed_read_count_ on a legitimate miss.
    [[gnu::always_inline]] inline const Account*
    find_built_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes))
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        return nullptr;
    }

    // Side-effect-free probe (no confirm-on-miss) of the pre-state storage.
    [[gnu::always_inline]] inline bool
    find_built_storage(const evmc::bytes32& addr_hash,
                       const evmc::bytes32& slot_hash) const noexcept {
        alignas(8) std::uint8_t key[64];
        std::memcpy(key, addr_hash.bytes, 32);
        std::memcpy(key + 32, slot_hash.bytes, 32);
        return storage_index_.find(key).has_value();
    }

    const FlatHashMap<evmc::address, Account>& created_accounts() const noexcept {
        return created_accounts_;
    }
    const FlatHashMap<evmc::bytes32, evmc::bytes32>*
    overflow_slots_for(const evmc::address& addr) const noexcept {
        const auto it = overflow_slots_.find(addr);
        if (it == overflow_slots_.end()) return nullptr;
        return &it->second;
    }
    bool storage_wiped(const evmc::address& addr) const noexcept {
        return storage_wiped_.contains(addr);
    }

    // Never executed on the HashState path; nullopt is fail-closed (a caller reaching it gets kWrongStateRoot).
    std::optional<evmc::bytes32> state_root_hash() const { return std::nullopt; }

  private:
    // Explicit-stack DFS over one trie, calling emit_leaf(path, value) at each leaf.
    template <class EmitLeaf>
    bool sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf);

    struct SweepFrame {
        const std::uint8_t* cur;
        const std::uint8_t* end;
        std::uint8_t next_slot;
        std::uint8_t path_len;
    };

    // Single-path walk toward target_hash; true only when it proves the key absent below root.
    bool confirm_absent(const evmc::bytes32& root, const evmc::bytes32& target_hash) const noexcept;

    // Counts a miss that cannot be proven empty.
    void note_account_miss_(const evmc::bytes32& addr_hash) const noexcept;
    void note_storage_miss_(const std::uint8_t (&key)[64]) const noexcept;

    // Decodes an account leaf into the cache; the pointer is valid only until the next emit grows the arena; an undecodable leaf is counted, not cached (nullptr).
    const Account* emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value);

    // Caches the 32-byte word of a storage leaf (RLP string, big-endian zero-trimmed); a value wider than 32 bytes is counted, not cached.
    void emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                    ByteView leaf_value);

    // Views of node/code bytes keyed by keccak256; `data` is never null for a stored entry (empty input points at kNoBytes), so a stored view never equals the empty-bucket sentinel.
    struct StoredBytes {
        const std::uint8_t* data = nullptr;
        std::uint32_t size = 0;
        friend bool operator==(const StoredBytes&, const StoredBytes&) = default;
    };
    static constexpr std::uint8_t kNoBytes = 0;
    static StoredBytes stored_view_(ByteView bytes) noexcept {
        return {bytes.data() != nullptr ? bytes.data() : &kNoBytes,
                static_cast<std::uint32_t>(bytes.size())};
    }
    // `bytes` must already be stable; first wins.
    evmc::bytes32 add_view_(HashIndex<32, &hash_key8_at, StoredBytes>& index, ByteView bytes);

    std::deque<Bytes> owned_bytes_;
    HashIndex<32, &hash_key8_at, StoredBytes> node_index_;
    HashIndex<32, &hash_key8_at, StoredBytes> code_index_;

    // Account cache: bare Account POD (256 B, alignof 8) at 8-aligned arena offsets, front-padded 8 bytes so no offset equals the empty-bucket sentinel 0.
    std::vector<std::uint8_t> accounts_arena_;
    HashIndex<32, &hash_key8_at> account_index_;

    // Storage cache keyed by addr_hash || slot_hash: a bare 32-byte word per entry, front-padded 8 bytes so no offset equals the empty-bucket sentinel 0.
    std::vector<std::uint8_t> storage_arena_;
    HashIndex<64, &storage_key8_at> storage_index_;

    FlatHashMap<evmc::bytes32, BlockHeader> headers_;
    // Set once a block asked for the hash of an ancestor the headers held do not lead to.
    mutable bool ancestor_missing_{false};
    // Memoized BLOCKHASH walk: the contiguous held headers below the block, parent first.
    mutable std::vector<evmc::bytes32> ancestors_;
    mutable BlockNum ancestors_number_{0};
    mutable evmc::bytes32 ancestors_anchor_{};

    // Account-trie root of the last build; seeds confirm_absent on a read miss. Zero until the first build.
    evmc::bytes32 prev_root_{};

    // missing_count_ counts every referenced node absent from an included trie, so an incomplete witness is observable.
    std::uint32_t missing_count_{0};
    bool malformed_witness_{false};
    std::uint32_t leaf_count_{0};
    std::uint32_t storage_slot_count_{0};
    // mutable: const reads record misses here; reset by build_state_from_trie.
    mutable std::uint32_t unconfirmed_read_count_{0};

    // Proven misses only; cleared per build.
    mutable HashIndex<64, &storage_key8_at, std::uint8_t> absent_slots_{1024};

    // Reserved once in the ctor; not reentrant.
    std::vector<SweepFrame> sweep_stack_;

    // Write overlay: copy-on-write over the built caches, keyed by 20-byte address (the built caches use addr_hash); reads consult the overlay first. Leaf changes must set modified.
    FlatHashMap<evmc::address, Account> created_accounts_;
    FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, evmc::bytes32>> overflow_slots_;  // every storage write (zeros RETAINED — divergence a)
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;
    FlatHashSet<evmc::address> touched_;
    // A wiped account reads all pre-state slots as zero and folds its storage from kEmptyRoot.
    FlatHashSet<evmc::address> storage_wiped_;

    // In-block created-code lookup by code_hash; a miss returns empty.
    ByteView find_created_code_(const evmc::bytes32& code_hash) const noexcept;
    void stash_created_code_(const evmc::bytes32& code_hash, ByteView code);

    // Non-recording lookup: no materialize, no confirm; nullptr when in neither store.
    const Account* lookup_account_(const evmc::address& addr) const noexcept;
    // Overlay hit (nullptr if deleted), else get_account(keccak(addr)), which records an unprovable miss.
    const Account* resolve_for_read_(const evmc::address& addr) const noexcept;
    Account* materialize_absent_account_(const evmc::address& addr);
    bool revive_if_deleted_slow(const evmc::address& addr, Account& pa);
};

class HashStateView final : public evmone::state::StateView {
  public:
    explicit HashStateView(HashState& s) noexcept : state_{s} {}

    std::optional<Account> get_account(const evmc::address& addr) const noexcept override {
        auto* pa = state_.find_or_create_account(addr);
        if (pa->deleted) return std::nullopt;
        intx::uint256 balance_v;
        std::memcpy(&balance_v, pa->balance, 32);
        return Account{
            .nonce = pa->nonce,
            .balance = balance_v,
            .code_hash = std::bit_cast<evmc::bytes32>(pa->code_hash),
            .has_storage = state_.has_storage(addr),
        };
    }

    /// Borrowed from the code store, which lives for the whole block.
    evmc::bytes_view get_account_code(const evmc::address& addr) const noexcept override {
        return state_.read_code(addr);
    }

    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
        return state_.read_storage(addr, key);
    }

  private:
    HashState& state_;
};

// HashState's accept update set carries no initial_value and no read-only entries (reads are bound to prev_root at derive time), so the fold drops the pre-value check.
template <>
inline constexpr bool state_keeps_prevalue_check<HashState> = false;

}  // namespace zilkworm
