// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// HashState: the SSZ-input-path state substrate, parallel to DirectState.
// See docs/hashstate.md, "HashState".

#pragma once

#include <cstdint>
#include <cstring>
#include <deque>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common_zz/hash_index.hpp>
#include <zilk_core/core/common_zz/index_key.hpp>  // hash_key8, storage_key8
// Reuse the Bytes/ByteView/bytes32 aliases from DirectState.
#include <zilk_core/core/state_zz/direct_state.hpp>
// Primary state_keeps_prevalue_check trait (defaults true); specialised to false for
// HashState at the bottom of this header so the trie fold compiles the pre-value /
// read-only check out for the HashState instantiation.
#include <zilk_core/core/state_zz/active_state.hpp>

namespace zilkworm {

// Derives from silkworm::BlockState (as DirectState does, direct_state.hpp:69) so it can
// later stand in as ActiveState for the block-running code that receives the state as a
// `const BlockState&` (rule sets, header validation). The three BlockState virtuals plus
// the header/blockhash store below give HashState the block-header side of that interface,
// mirroring DirectState verbatim so the eventual retype is a drop-in.
class HashState : public BlockState {
  public:
    // Outcome of build_state_from_trie: kMissingNode iff the seeding account root was absent.
    // See docs/hashstate.md, "Fail-closed policy".
    enum class BuildStatus : std::uint8_t { kOk, kMissingNode };

    // Sizes are best-effort hints for the open-addressed tables (~2x -> load factor
    // <= 0.5). HashIndex has no default ctor, so all four are initialized in the .cpp; the
    // account and storage arenas are front-padded there too (see below).
    explicit HashState(std::uint32_t expected_nodes = 1024,
                       std::uint32_t expected_codes = 256,
                       std::uint32_t expected_accounts = 1024,
                       std::uint32_t expected_storage_slots = 4096);

    // The node and code stores hold views (into owned_bytes_ or a borrowed input blob), so
    // a copy would point back into the source's storage.
    HashState(const HashState&) = delete;
    HashState& operator=(const HashState&) = delete;

    // Store a copy of `rlp` under its real keccak256 and return that hash. A repeated node
    // is deduped (no second copy) and the same hash is returned. Defined in the .cpp
    // because it computes keccak.
    evmc::bytes32 add_node(ByteView rlp);

    // Store a copy of `code` under its real keccak256 (the code_hash) and return it; deduped.
    evmc::bytes32 add_code(ByteView code);

    // As add_node / add_code, but the store keeps a view of the caller's bytes instead of a
    // copy: `rlp` / `code` must stay alive and unchanged for as long as this HashState is
    // used. parse_stateless_input feeds the decoded input blob through these.
    evmc::bytes32 add_node_borrowed(ByteView rlp);
    evmc::bytes32 add_code_borrowed(ByteView code);

    // Hot lookup: EXACT DirectState::find_node_rlp seam shape — hit -> ByteView over
    // the stored RLP, miss -> std::nullopt (NOT an empty ByteView).
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
        if (auto v = node_index_.find(node_hash.bytes)) return ByteView{v->data, v->size};
        return std::nullopt;
    }

    // Hot lookup: matches DirectState::read_code miss semantics — hit -> ByteView over
    // the stored code, miss -> EMPTY ByteView (NOT optional).
    [[gnu::always_inline]] inline ByteView
    find_code(const evmc::bytes32& code_hash) const noexcept {
        if (auto v = code_index_.find(code_hash.bytes)) return ByteView{v->data, v->size};
        return {};
    }

    std::uint32_t node_count() const noexcept { return node_index_.size(); }
    std::uint32_t code_count() const noexcept { return code_index_.size(); }

    // Derive the account and storage caches from prev_root in one read-only trie sweep.
    // See docs/hashstate.md, "Building state from the trie".
    BuildStatus build_state_from_trie(const evmc::bytes32& prev_root);

    // Account-cache lookup by addr_hash; a miss returns nullptr and is confirmed.
    // See docs/hashstate.md, "Account and storage caches".
    [[gnu::always_inline]] inline const Account*
    get_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes)) {
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        }
        note_account_miss_(addr_hash);
        return nullptr;
    }

    // Storage-cache lookup by (addr_hash, slot_hash); a miss reads zero and is confirmed.
    // See docs/hashstate.md, "Account and storage caches".
    [[gnu::always_inline]] inline evmc::bytes32
    get_storage(const evmc::bytes32& addr_hash, const evmc::bytes32& slot_hash) const noexcept {
        std::uint8_t key[64];
        std::memcpy(key, addr_hash.bytes, 32);
        std::memcpy(key + 32, slot_hash.bytes, 32);
        if (auto off = storage_index_.find(key)) {
            evmc::bytes32 v;
            std::memcpy(v.bytes, storage_arena_.data() + *off, 32);
            return v;
        }
        note_storage_miss_(addr_hash, slot_hash);
        return {};
    }

    std::uint32_t account_count() const noexcept { return account_index_.size(); }
    // Distinct (addr_hash, slot_hash) storage entries the last sweep cached.
    std::uint32_t storage_count() const noexcept { return storage_index_.size(); }
    // Leaves the last sweep reached (decodable or not). account_count() is the subset
    // that decoded into a cached Account; the difference is undecodable leaves.
    std::uint32_t leaf_count() const noexcept { return leaf_count_; }
    // Storage leaves reached across all storage passes of the last sweep (diagnostic,
    // parallel to leaf_count_ but for the storage tries).
    std::uint32_t storage_slot_count() const noexcept { return storage_slot_count_; }
    // Genuinely broken seeding ACCOUNT root the last sweep found ABSENT from the store (B2).
    // > 0 means the anchor of the whole witness was missing — the accept gate must reject.
    // A pruned CHILD boundary (a bare hash ref into an omitted subtree) is NOT counted here;
    // it is caught at read time (unconfirmed_read_count_) or fold time (non-matching root).
    std::uint32_t missing_count() const noexcept { return missing_count_; }
    // Read misses (get_account / get_storage) whose confirmation walk could NOT prove the
    // key absent because a node it needed was missing from the store. Reset by
    // build_state_from_trie, then accumulated across the reads that follow it. Surfaced the
    // same way as missing_count(): the accept gate accepts only when BOTH are zero, i.e.
    // every read either hit the cache or was confirmed genuinely empty (fail-closed).
    std::uint32_t unconfirmed_read_count() const noexcept { return unconfirmed_read_count_; }

    // --- silkworm::BlockState interface + BLOCKHASH store ------------------------------
    // See docs/hashstate.md, "Block headers and BLOCKHASH".

    // Record a header under its keccak hash and keep created_block_hashes_ sorted ascending
    // by block number for the log-n BLOCKHASH lookup. Verbatim DirectState::insert_header
    // (direct_state.cpp:703-722).
    void insert_header(const BlockHeader& header);

    // BLOCKHASH(n): sorted lookup in created_block_hashes_ (the inserted witness / genesis
    // ancestors), all-zero bytes32 on a miss. Mirrors DirectState::get_block_hash
    // (direct_state.cpp:818-840) MINUS the witness block_hashes_ span branch (:819-828):
    // HashState has no such span — the slib witness supplies ancestor headers as RLP that
    // the runner decodes and insert_header's, so created_block_hashes_ alone covers it.
    evmc::bytes32 get_block_hash(BlockNum n) const noexcept;

    // read_header: the header cached under `block_hash`, else nullopt (block_num is unused,
    // exactly as in DirectState). read_body / total_difficulty are the DirectState stubs:
    // always false / always nullopt — the slib path needs neither
    // (direct_state.cpp:696-701, :724-730).
    std::optional<BlockHeader> read_header(BlockNum block_num,
                                           const evmc::bytes32& block_hash) const noexcept override;
    [[nodiscard]] bool read_body(BlockNum block_num, const evmc::bytes32& block_hash,
                                 BlockBody& out) const noexcept override;
    std::optional<intx::uint256> total_difficulty(uint64_t block_num,
                                                  const evmc::bytes32& block_hash) const noexcept override;

    // --- Write overlay + mutators + address-keyed readers -----------------------------
    // See docs/hashstate.md, "Write overlay".

    // Address-keyed readers (overlay-then-built). A built-cache miss routes through
    // get_account / get_storage, so an unprovable miss is recorded fail-closed.
    const Account* read_account(const evmc::address& addr) const noexcept;
    evmc::bytes32 read_storage(const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept;
    // read_code: resolve the account, then its code_hash -> in-block created-code overlay,
    // else the witness code store (find_code). FAIL-CLOSED: a non-empty code_hash that
    // resolves to no bytes bumps unconfirmed_read_count_ — HashState has no sanitize-time
    // code binding like DirectState (direct_state.cpp:762-777), so the accept gate rejects a
    // witness that omitted an account's bytecode instead of silently executing empty code.
    ByteView read_code(const evmc::address& addr) const noexcept;
    ByteView read_code(const evmc::address& addr, const evmc::bytes32& /*code_hash*/) const noexcept {
        return read_code(addr);
    }
    intx::uint256 get_balance(const evmc::address& addr) const noexcept;
    uint64_t get_nonce(const evmc::address& addr) const noexcept;
    bool has_storage(const evmc::address& addr) const noexcept;

    // Mutators — signatures identical to DirectState (direct_state.hpp:140-285).
    void apply_state_diff(const evmone::state::StateDiff& diff);
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

    // find_or_create_account: overlay hit -> return it; built hit -> copy-on-write into the
    // overlay; total miss -> materialize a fresh (deleted) record, the analog of
    // DirectState::materialize_absent_account_. A usable record is ALWAYS returned (never
    // null). The miss is not walked here: the record's account-trie update claims the key
    // absent, and the accept check's fold proves or refutes the claim (check_root_hashstate,
    // HashStateAccountWrite::absent). See docs/hashstate.md, "Read-miss confirmation".
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

    // Single-block slib runs have no cross-block journal; keep the names so the mutators and
    // apply_state_diff port from DirectState line-for-line (direct_state.cpp:678-694).
    void journal_address_changed(const evmc::address&) noexcept {}
    void journal_slot_changed(const evmc::address&, const evmc::bytes32&) noexcept {}

    // Side-effect-free built-cache probe (NO confirm-on-miss) for the mutators and the write
    // gather — a get_account here would bump unconfirmed_read_count_ on a legitimate miss.
    [[gnu::always_inline]] inline const Account*
    find_built_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes))
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        return nullptr;
    }

    // Side-effect-free probe (no confirm-on-miss): does the pre-state storage hold this slot?
    // See docs/hashstate.md, "Write overlay".
    [[gnu::always_inline]] inline bool
    find_built_storage(const evmc::bytes32& addr_hash,
                       const evmc::bytes32& slot_hash) const noexcept {
        std::uint8_t key[64];
        std::memcpy(key, addr_hash.bytes, 32);
        std::memcpy(key + 32, slot_hash.bytes, 32);
        return storage_index_.find(key).has_value();
    }

    // Overlay gather accessors (mirror DirectState hpp:234-241) — read-only views for tests
    // and the write-set gather.
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

    // Compile-compat stub (§2f), mirroring DirectState::state_root_hash()
    // (direct_state.hpp:160 / direct_state.cpp:638). The slib accept path uses
    // check_root_hashstate (an incremental fold over prev_root), never the Yellow-Paper
    // full-trie root, and always passes check_state_root=false into Blockchain, so this is
    // never executed on the HashState path. It exists only so blockchain.cpp:95 compiles
    // under the DirectState->ActiveState retype; returning nullopt is fail-closed (a caller
    // that ever reaches it gets kWrongStateRoot).
    std::optional<evmc::bytes32> state_root_hash() const { return std::nullopt; }

  private:
    // Explicit-stack DFS over one trie, calling emit_leaf(path, value) at each leaf.
    // See docs/hashstate.md, "Building state from the trie".
    template <class EmitLeaf>
    bool sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf);

    // Single-path walk toward target_hash; true only when it proves the key absent below root.
    // See docs/hashstate.md, "Read-miss confirmation".
    bool confirm_absent(const evmc::bytes32& root, const evmc::bytes32& target_hash) const noexcept;

    // Miss handlers for get_account / get_storage: count a miss that cannot be proven empty.
    // See docs/hashstate.md, "Read-miss confirmation".
    void note_account_miss_(const evmc::bytes32& addr_hash) const noexcept;
    void note_storage_miss_(const evmc::bytes32& addr_hash,
                            const evmc::bytes32& slot_hash) const noexcept;

    // Decode `leaf_value` (an account-leaf RLP) and cache it under `addr_hash`. Bumps
    // leaf_count_ for every leaf reached; on a successful decode also inserts into the
    // account cache and returns a pointer to the cached Account (valid only until the next
    // emit grows the arena — build_state_from_trie reads its storage_root immediately). A leaf whose
    // value does not decode as an account (e.g. a small embedded non-account leaf) is
    // counted, not cached, and returns nullptr — never a crash.
    const Account* emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value);

    // Decode a storage-trie leaf value and cache the resulting 32-byte word under
    // (account_key || slot_hash). `leaf_value` is the trie leaf's value content, i.e. the
    // RLP string of the big-endian, zero-trimmed word (direct_state.cpp:627,
    // rlp::encode(zeroless_view(value))) — the mirror of how emit_account_'s leaf_value is
    // the account list RLP. Strips that one string header and right-aligns the payload into
    // the word; a value wider than 32 bytes (malformed) is counted but not cached. Bumps
    // storage_slot_count_ for every storage leaf reached.
    void emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                    ByteView leaf_value);

    // Node and code stores: the index maps the content's keccak256 straight to a view of
    // the bytes, so a lookup is one probe with no length decode. The bytes live either in the
    // caller's input blob (add_*_borrowed) or in owned_bytes_ (add_node / add_code), whose
    // elements never move once added. `data` is never null for a stored entry (an empty
    // input is pointed at kNoBytes), so a stored view never equals HashIndex's empty
    // sentinel, the value-initialized {nullptr, 0}.
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
    // Dedupe on the real keccak256, then index `bytes` (which must already be stable).
    evmc::bytes32 add_view_(HashIndex<32, &hash_key8, StoredBytes>& index, ByteView bytes);

    std::deque<Bytes> owned_bytes_;
    HashIndex<32, &hash_key8, StoredBytes> node_index_;
    HashIndex<32, &hash_key8, StoredBytes> code_index_;

    // Account cache — the "recovered" pre-state bucket the design (§1.1) calls for: the
    // accounts build_state_from_trie unfolds out of the node trie. Arena entry layout is a bare
    // Account POD (fixed 256 B, alignof 8) at an 8-aligned offset; the index maps the
    // 32-byte addr_hash (the trie path) to that offset. Front-padded 8 bytes in the ctor
    // so the first real offset is >= 8 (never the HashIndex empty-bucket sentinel, 0).
    std::vector<std::uint8_t> accounts_arena_;
    HashIndex<32, &hash_key8> account_index_;

    // Storage cache — the recovered per-account slot overlay (the role DirectState fills
    // with overflow_slots_ + inline blob slots). One combined store rather than a table
    // per account: the index key is the 64-byte addr_hash || slot_hash (storage_key8), the
    // arena holds a bare 32-byte word per entry at an 8-aligned offset (32 is a multiple of
    // 8). Front-padded 8 bytes in the ctor so the first real offset is >= 8 (never the
    // HashIndex empty-bucket sentinel, 0).
    std::vector<std::uint8_t> storage_arena_;
    HashIndex<64, &storage_key8> storage_index_;

    // Block-header store (the BlockState side), mirroring DirectState (direct_state.hpp:87-88):
    // headers_ answers read_header keyed by the header's keccak hash; created_block_hashes_ is
    // kept sorted ascending by block number for the BLOCKHASH lookup in get_block_hash. Both
    // are populated by insert_header (the runner glue feeds it the witness ancestor headers).
    FlatHashMap<evmc::bytes32, BlockHeader> headers_;
    std::vector<BlockHashEntry> created_block_hashes_;

    // The account-trie root the last build_state_from_trie ran from, stored so a read miss can
    // seed a confirm_absent walk down the account trie (the storage passes confirm against each
    // account's own storage_root instead). Zero until the first build.
    evmc::bytes32 prev_root_{};

    // Diagnostics for the last build_state_from_trie sweep. missing_count_ mirrors GridMPT's
    // homonym (mpt.hpp:235): every referenced node absent from an included trie is counted,
    // so an incomplete witness is observable rather than silently skipped.
    std::uint32_t missing_count_{0};
    std::uint32_t leaf_count_{0};
    std::uint32_t storage_slot_count_{0};
    // Read-miss confirmations that could not prove absence (a needed node was missing).
    // mutable: reads are logically const over the caches but still record this diagnostic.
    // Reset by build_state_from_trie so it scopes to the reads following one build.
    mutable std::uint32_t unconfirmed_read_count_{0};

    // --- Write overlay (S2): copy-on-write over the pristine built caches ---------------
    // Reuses DirectState's container TYPES exactly (direct_state.hpp:82-89) so the later
    // DirectState->ActiveState retype is a drop-in. Keyed by the 20-byte address (as
    // DirectState is), while the built caches above are keyed by the 32-byte addr_hash;
    // reads consult the overlay first, the built cache second.
    // Invariant the accept check's gather relies on (check_root_hashstate.hpp): a built account
    // enters created_accounts_ on its first READ as a verbatim copy of its leaf with `modified`
    // false; any change to a leaf field (nonce, balance, code_hash, storage) and any wipe or
    // revive sets `modified`, and destruct sets `deleted`. A built record with neither flag is
    // its unchanged pre-state leaf and is not folded. Every future mutator must preserve this.
    FlatHashMap<evmc::address, Account> created_accounts_;                                  // every loaded account, read or written
    FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, evmc::bytes32>> overflow_slots_;  // every storage write (zeros RETAINED — divergence a)
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;                                  // in-block created code (fills the old TODO)
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;              // key8-collision spill
    FlatHashSet<evmc::address> touched_;                                                    // EIP-158 touch set
    FlatHashSet<evmc::address> delegated_designations_;                                     // EIP-7702 wipe-exemption set
    // DIVERGENCE (b): per-account storage-wiped marker replacing DirectState's in-place
    // inline-slot wipe (direct_state.cpp:410-412, :568). A wiped account reads all pre-state
    // (built-cache) slots as zero and its storage fold seeds from kEmptyRoot.
    FlatHashSet<evmc::address> storage_wiped_;

    // In-block created-code lookup by code_hash (created_code_ + collision spill); miss -> empty.
    // See docs/hashstate.md, "Created code lookup".
    ByteView find_created_code_(const evmc::bytes32& code_hash) const noexcept;

    // Non-recording overlay-or-built lookup (the DirectState lookup_account_ analog): NO
    // materialize, NO confirm. Returns nullptr when the address is in neither store.
    const Account* lookup_account_(const evmc::address& addr) const noexcept;
    // Read resolver shared by read_account / read_code / get_balance / get_nonce: overlay hit
    // (nullptr if deleted), else get_account(keccak(addr)) — which records an unprovable miss.
    const Account* resolve_for_read_(const evmc::address& addr) const noexcept;
    // Materialize a fresh (deleted) overlay record for a total miss (DirectState analog,
    // direct_state.cpp:327-335). Non-const: it writes the overlay.
    Account* materialize_absent_account_(const evmc::address& addr);
    bool revive_if_deleted_slow(const evmc::address& addr, Account& pa);
};

// HashStateView: the per-transaction evmone read view over HashState, mirroring DirectStateView.
// See docs/hashstate.md, "HashStateView".
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

    /// Borrowed from the code store, which lives for the whole block, so the EVM can read the
    /// EIP-7702 delegation prefix without materializing the contract.
    evmc::bytes_view get_account_code(const evmc::address& addr) const noexcept override {
        return state_.read_code(addr);  // ByteView derives from evmc::bytes_view.
    }

    evmc::bytes32 get_storage(const evmc::address& addr, const evmc::bytes32& key) const noexcept override {
        return state_.read_storage(addr, key);
    }

  private:
    HashState& state_;
};

// The HashState fold (GridMPT<*, HashState>) drops the pre-value bind + read-only
// short-circuit: HashState's accept update set carries no initial_value and no
// read-only entries (reads are bound to prev_root at derive time). This specialises
// the active_state.hpp trait so grid_mpt.cpp's `if constexpr` compiles that block out
// for HashState while keeping it verbatim for DirectState. Kept here (not in mpt.hpp)
// so the DirectState build has no dependency on HashState at all.
template <>
inline constexpr bool state_keeps_prevalue_check<HashState> = false;

}  // namespace zilkworm
