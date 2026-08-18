// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// HashState: the SSZ-input-path state substrate, parallel to DirectState.
//
// This step builds ONLY the two owned content stores DirectState reads through a
// serialized MphfMap. Here they are built in-guest and indexed by the plain
// open-addressed HashIndex<32,&hash_key8> (no displacement/collision sidecar to
// serialize ahead of time):
//   - node store: keccak256(node) -> node RLP        (find_node_rlp)
//   - code store: keccak256(code) -> contract bytecode (find_code)
//
// Each store owns a byte arena of [u32 len][bytes...] entries; the index maps the
// content hash's key8 to the entry offset. The index key is the REAL keccak256 of
// the bytes, computed at add time (identity binding), and HashIndex confirms every
// probed bucket with a full-key memcmp — so a forged lookup hash can never surface
// the wrong entry.
//
// On top of those two stores this step adds the ACCOUNT cache and the storage cache,
// both filled by the standalone build_state_from_trie sweep (hashstate_design.md §2.6): a
// read-only / insert-only depth-first walk. First the account trie from prev_root emits
// each leaf's decoded account into the account cache; then, for every derived account
// carrying a non-empty storage_root, the SAME sweep walks that account's storage trie
// and emits each (slot_hash -> word) into the storage cache. The code cache remains the
// next step (see the TODO markers at the bottom of the class).

#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common_zz/hash_index.hpp>
// Reuse hash_key8(const uint8_t(&)[32]) and the Bytes/ByteView/bytes32 aliases from
// DirectState — do NOT redefine hash_key8 here (ODR clash if both headers meet in a TU).
#include <zilk_core/core/state_zz/direct_state.hpp>
// Primary state_keeps_prevalue_check trait (defaults true); specialised to false for
// HashState at the bottom of this header so the trie fold compiles the pre-value /
// read-only check out for the HashState instantiation.
#include <zilk_core/core/state_zz/active_state.hpp>

namespace zilkworm {

// key8 for the storage index. Its key is the 64-byte concatenation addr_hash || slot_hash
// (see emit_slot_ / get_storage). Both halves are keccak outputs, so their leading 8 bytes
// are effectively random; XORing them mixes BOTH the account and the slot into the home
// bucket. That matters because a single account owns many slots — keying on the addr_hash
// prefix alone would land every one of them in the same home bucket. HashIndex still
// confirms every hit with a full 64-byte memcmp, so this only affects distribution, never
// correctness. Signature matches HashIndex's Key8 param for KeySize == 64.
[[gnu::always_inline]] inline uint64_t storage_key8(const uint8_t (&k)[64]) noexcept {
    uint64_t a, s;
    std::memcpy(&a, k, 8);       // addr_hash prefix
    std::memcpy(&s, k + 32, 8);  // slot_hash prefix
    return a ^ s;
}

// Derives from silkworm::BlockState (as DirectState does, direct_state.hpp:69) so it can
// later stand in as ActiveState for the block-running code that receives the state as a
// `const BlockState&` (rule sets, header validation). The three BlockState virtuals plus
// the header/blockhash store below give HashState the block-header side of that interface,
// mirroring DirectState verbatim so the eventual retype is a drop-in.
class HashState : public BlockState {
  public:
    // Outcome of a build_state_from_trie sweep. kOk = the sweep ran and every node it needed
    // was either present or a legitimate PRUNED BOUNDARY (a bare hash ref into an untouched
    // subtree that a real EIP-8025 partial witness omits — see build_state_from_trie).
    // kMissingNode = the seeding ACCOUNT root itself was absent (B2), the one gap that is
    // never a legitimate omission; the sweep still emits everything reachable, but that gap
    // is recorded in missing_count_ so the accept gate can hard-reject it (fail-closed, never
    // silent — see hashstate_design.md §2.2 "Fail-closed rule"). A pruned child boundary does
    // NOT set this; witness completeness for pruned parts is enforced at read time
    // (confirm_absent -> unconfirmed_read_count_) and at fold time (a non-matching root).
    enum class BuildStatus : std::uint8_t { kOk, kMissingNode };

    // Sizes are best-effort hints for the open-addressed tables (~2x -> load factor
    // <= 0.5). HashIndex has no default ctor, so both are initialized in the .cpp; the
    // arenas are front-padded there too (see below).
    explicit HashState(std::uint32_t expected_nodes = 1024,
                       std::uint32_t expected_codes = 256,
                       std::uint32_t expected_accounts = 1024,
                       std::uint32_t expected_storage_slots = 4096);

    // Append `rlp` under its real keccak256 and return that hash. A repeated node is
    // deduped (no second append) and the same hash is returned. Defined in the .cpp
    // because it computes keccak.
    evmc::bytes32 add_node(ByteView rlp);

    // Append `code` under its real keccak256 (the code_hash) and return it; deduped.
    evmc::bytes32 add_code(ByteView code);

    // Hot lookup: EXACT DirectState::find_node_rlp seam shape — hit -> ByteView over
    // the stored RLP, miss -> std::nullopt (NOT an empty ByteView).
    [[gnu::always_inline]] inline std::optional<ByteView>
    find_node_rlp(const evmc::bytes32& node_hash) const noexcept {
        if (auto off = node_index_.find(node_hash.bytes)) {
            std::uint32_t len;
            std::memcpy(&len, node_arena_.data() + *off, sizeof(len));
            return ByteView{node_arena_.data() + *off + sizeof(len), len};
        }
        return std::nullopt;
    }

    // Hot lookup: matches DirectState::read_code miss semantics — hit -> ByteView over
    // the stored code, miss -> EMPTY ByteView (NOT optional).
    [[gnu::always_inline]] inline ByteView
    find_code(const evmc::bytes32& code_hash) const noexcept {
        if (auto off = code_index_.find(code_hash.bytes)) {
            std::uint32_t len;
            std::memcpy(&len, code_arena_.data() + *off, sizeof(len));
            return ByteView{code_arena_.data() + *off + sizeof(len), len};
        }
        return {};
    }

    std::uint32_t node_count() const noexcept { return node_index_.size(); }
    std::uint32_t code_count() const noexcept { return code_index_.size(); }

    // Standalone one-pass ACCOUNT + STORAGE derivation (hashstate_design.md §2.6). A
    // depth-first, left-to-right sweep through the node store with an EXPLICIT stack (no
    // recursion — rv64im-safe): push the root, unfold the leftmost child down to a leaf,
    // emit that leaf, fold back to the nearest parent with an unvisited child, and repeat
    // until the stack drains. It mirrors GridMPT's unfold/fold lingo but is read-only /
    // insert-only, so it has NONE of the delete / cascade / modified-flag machinery. It
    // reuses the shared node types (mpt.hpp) and the FREE RLP decoders (decode_node,
    // rlp::decode_header) but never calls a GridMPT method. The traversal itself lives in
    // one private helper, sweep(): the account pass runs sweep(prev_root, <emit account>),
    // then for every derived account with storage_root != kEmptyRoot a sibling pass runs
    // sweep(storage_root, <emit slot for that account>). The empty trie
    // (prev_root == kEmptyRoot) derives nothing and returns kOk. The prev_root is also
    // stored (prev_root_) so a later read miss can start a single-path confirmation walk
    // (confirm_absent) down the account trie.
    //
    // Fail-closed policy (asymmetric, and deliberately so — enforced at the two call
    // sites in the .cpp, not inside sweep): an absent ACCOUNT root is a missing node (B2,
    // the anchor of everything). An absent STORAGE root is NOT — a witness legitimately
    // omits the storage trie of an account the block never touches, so it is skipped, not
    // counted. A hash-ref child reached WHILE walking an included trie (account or storage)
    // whose node is absent is a PRUNED BOUNDARY — the EIP-8025 partial-witness case — so the
    // sweep stops there WITHOUT bumping missing_count_; it materializes exactly the touched
    // leaves that are included. missing_count_ therefore flags ONLY a broken account root,
    // never a pruned subtree.
    BuildStatus build_state_from_trie(const evmc::bytes32& prev_root);

    // Account-cache lookup keyed by the 32-byte trie path (addr_hash == keccak256(addr)).
    // Hit -> pointer to the derived Account POD in the arena; miss -> nullptr (a blank /
    // non-existent account). Mirrors DirectState::read_account's pointer-or-null shape. The
    // pointer is valid until the next emit grows the arena; a build_state_from_trie run
    // followed by reads is the intended usage. Note: Account::addr is left zero — the build
    // never sees the 20-byte preimage, only its hash (the trie path); the cache is keyed by
    // that hash.
    //
    // A miss is NOT trusted blindly: the build sweep only collected keys actually present in
    // the trie, so a missed key is either genuinely empty OR wrongly left out of the witness.
    // note_account_miss_ runs a single-path confirmation walk (confirm_absent) from prev_root_
    // to tell the two apart — proving emptiness records nothing, an unprovable gap records an
    // unconfirmed read (unconfirmed_read_count_). Either way the read returns nullptr so a
    // value-returning caller still gets a blank account; the accept gate rejects later iff the
    // unconfirmed count is non-zero (fail-closed, never a silent wrong-empty).
    [[gnu::always_inline]] inline const Account*
    get_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes)) {
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        }
        note_account_miss_(addr_hash);
        return nullptr;
    }

    // Storage-cache lookup, the hash-space analog of DirectState::read_storage(addr, key)
    // (direct_state.cpp:299): DirectState keys the pre-image (address, slot key); the
    // derive sweep only ever sees their trie paths, so HashState keys the HASHES instead.
    // `addr_hash` == keccak256(addr) (the account trie path, == a get_account key);
    // `slot_hash` == keccak256(slot key) (the storage trie path). Return shape matches
    // read_storage exactly: the 32-byte word on a hit, an all-zero bytes32 on a miss. Zero
    // is unambiguous as "absent" because the storage trie never carries a zero-valued leaf
    // (account_storage_root drops zero values, direct_state.cpp:610).
    //
    // A miss is confirmed exactly like get_account's: note_storage_miss_ decides whether the
    // zero is safe. If the account is absent or its storage_root is the empty-trie root the
    // slot is zero with no walk needed; otherwise a single-path confirmation walk down the
    // account's storage trie either proves the slot empty (record nothing) or hits a needed
    // node that is absent — including a storage root the build legitimately skipped because
    // its node was never added — in which case an unconfirmed read is recorded. The slot
    // always reads zero so a value-returning caller proceeds; the accept gate rejects later.
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
    // The block-header side of the state interface, mirroring DirectState so a later retype
    // of the execution surface from DirectState& to ActiveState& (== HashState under
    // -DZ6M_HASH_STATE) is a drop-in: identical signatures throughout. HashState holds the
    // witness ancestor headers here; a later step wires the parser to feed them in.
    //
    // TODO(hashstate-slib, runner glue): populate these from the parsed witness headers
    // (StatelessInputView::headers, slib_input.hpp:74) + the genesis header — S1 adds only
    // the storage and the methods, not the population.

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

    // --- Write overlay + mutators + address-keyed readers (S2) ------------------------
    // HashState grows into a full ActiveState WRITE backend here. The built account /
    // storage caches above stay PRISTINE — the pre-state "before" side. Every write lands
    // in a copy-on-write OVERLAY (created_accounts_ / overflow_slots_ / created_code_, which
    // reuse DirectState's container TYPES verbatim so the later DirectState->ActiveState
    // retype is a drop-in) and every read consults the overlay FIRST, the built cache
    // second, so a written value shadows the built one. Mutator bodies mirror
    // direct_state.cpp:337-694 line-for-line EXCEPT for two deliberate divergences, each
    // documented at its implementation site in hash_state.cpp:
    //   (a) set_storage_slot RETAINS zero writes (DirectState ERASES them,
    //       direct_state.cpp:391-397) so the fold can emit them as 0x80 deletes: the
    //       HashState fold is incremental over prev_root and needs the explicit delete,
    //       whereas DirectState recomputes each storage root from its live slots.
    //   (b) apply_code_diff / destruct / revive set a per-account storage_wiped_ flag
    //       instead of DirectState's in-place inline-slot wipe (the built cache is
    //       immutable — nothing to wipe in place). A wiped account reads all pre-state slots
    //       as zero and its storage fold seeds from kEmptyRoot.

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
    // overlay; total miss -> materialize a fresh (deleted) record AND confirm absence down
    // the account trie (confirm_absent). An unprovable miss (pruned boundary) bumps
    // unconfirmed_read_count_ so the accept gate rejects, but a usable record is ALWAYS
    // returned (never null) — the analog of DirectState::materialize_absent_account_.
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

  private:
    // Shared explicit-stack DFS over ONE trie rooted at `root`, the single traversal the
    // account pass and every storage pass run through (no recursion — rv64im-safe). At
    // each leaf it calls emit_leaf(path_packed_to_bytes32, leaf_value_ByteView); the
    // caller's emit decides how to decode/cache that leaf (account vs slot). A hash-ref child
    // reached WHILE walking whose node is absent is a PRUNED BOUNDARY: the sweep stops that
    // descent WITHOUT bumping missing_count_ (partial-witness rule). Returns false iff `root`
    // itself was absent from the node store (the caller decides whether that is
    // fail-closed — see build_state_from_trie), true if the sweep ran. Defined in the .cpp;
    // only instantiated there (from build_state_from_trie's two emit lambdas).
    template <class EmitLeaf>
    bool sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf);

    // Single-path descent through the node store toward `target_hash` (a 32-byte trie path:
    // an addr_hash for the account trie, or a slot_hash for a storage trie), rooted at
    // `root`. Returns true only when it PROVES `target_hash` is absent below `root`, false
    // when it cannot. It reuses the EXACT decoders the sweep uses — rlp::decode_header to
    // strip the outer list header, then decode_node (rlp_sw.hpp) for the branch / ext / leaf
    // split — so a read confirmation reads trie bytes byte-for-byte the way the build did.
    //
    // Proven absent (return true) in two shapes, mirroring the sweep's own node handling:
    //   - at a BRANCH, the child slot for the target's next nibble is the empty marker 0x80
    //     (decode_node reports it as child_len == 0), so nothing hangs below that nibble; or
    //   - at an EXTENSION or LEAF, the node's own path nibbles diverge from the target (a
    //     nibble mismatch, or a path that outlasts the target), so the target cannot lie
    //     below this node. The empty trie (root == kEmptyRoot) proves every key absent.
    // NOT proven (return false): a node the walk needs — the seeding root, a hash-referenced
    // child, or a malformed/undecodable node — is missing from the store, so emptiness is
    // unknown and must not be guessed (fail-closed). A leaf whose path matches the target
    // exactly means the key is actually PRESENT (not absent) and also returns false.
    bool confirm_absent(const evmc::bytes32& root, const evmc::bytes32& target_hash) const noexcept;

    // Read-miss handlers for get_account / get_storage (defined in the .cpp so the hot
    // header lookups stay tiny and the confirm/counter logic lives next to sweep). Each runs
    // confirm_absent and, when it cannot prove the key empty, bumps unconfirmed_read_count_.
    // note_storage_miss_ first consults the account cache: an absent account or an empty
    // storage_root needs no walk (the slot is zero), otherwise it confirms against the
    // account's storage_root — which also catches a storage root the build skipped because
    // its node was never added (find_node_rlp misses, so the read is recorded, never a silent
    // zero). const + mutable counter: a read never mutates the caches, only the diagnostic.
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

    // Arena entry layout: [uint32_t len][len bytes...]. The stored offset is the byte
    // index of the len field. Both arenas are front-padded with 8 zero bytes in the
    // ctor so the first real offset is >= 8 and can never equal HashIndex's empty-bucket
    // sentinel (offset 0). len is read/written via memcpy (rv64im: no unaligned ld/sd).
    std::vector<std::uint8_t> node_arena_;
    HashIndex<32, &hash_key8> node_index_;
    std::vector<std::uint8_t> code_arena_;
    HashIndex<32, &hash_key8> code_index_;

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
    FlatHashMap<evmc::address, Account> created_accounts_;                                  // every written account
    FlatHashMap<evmc::address, FlatHashMap<evmc::bytes32, evmc::bytes32>> overflow_slots_;  // every storage write (zeros RETAINED — divergence a)
    FlatHashMap<uint64_t, CreatedCodeEntry> created_code_;                                  // in-block created code (fills the old TODO)
    FlatHashMap<evmc::bytes32, std::vector<uint8_t>> created_code_collisions_;              // key8-collision spill
    FlatHashSet<evmc::address> touched_;                                                    // EIP-158 touch set
    FlatHashSet<evmc::address> delegated_designations_;                                     // EIP-7702 wipe-exemption set
    // DIVERGENCE (b): per-account storage-wiped marker replacing DirectState's in-place
    // inline-slot wipe (direct_state.cpp:410-412, :568). A wiped account reads all pre-state
    // (built-cache) slots as zero and its storage fold seeds from kEmptyRoot.
    FlatHashSet<evmc::address> storage_wiped_;

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

// The HashState fold (GridMPT<*, HashState>) drops the pre-value bind + read-only
// short-circuit: HashState's accept update set carries no initial_value and no
// read-only entries (reads are bound to prev_root at derive time). This specialises
// the active_state.hpp trait so grid_mpt.cpp's `if constexpr` compiles that block out
// for HashState while keeping it verbatim for DirectState. Kept here (not in mpt.hpp)
// so the DirectState build has no dependency on HashState at all.
template <>
inline constexpr bool state_keeps_prevalue_check<HashState> = false;

}  // namespace zilkworm
