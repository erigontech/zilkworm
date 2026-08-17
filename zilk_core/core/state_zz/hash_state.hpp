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
// both filled by the standalone derive_state sweep (hashstate_design.md §2.6): a
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

class HashState {
  public:
    // Outcome of a derive_state sweep. kOk = the whole account trie was walked and
    // every referenced node was present. kMissingNode = at least one node a path
    // needed (a referenced child hash, or the seeding root) was absent from the store;
    // the sweep still emits everything reachable, but the gap is recorded in
    // missing_count_ so the accept gate can hard-reject it (fail-closed, never silent —
    // see hashstate_design.md §2.2 "Fail-closed rule").
    enum class DeriveStatus : std::uint8_t { kOk, kMissingNode };

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
    // (prev_root == kEmptyRoot) derives nothing and returns kOk.
    //
    // Fail-closed policy (asymmetric, and deliberately so — enforced at the two call
    // sites in the .cpp, not inside sweep): an absent ACCOUNT root is a missing node (B2,
    // the anchor of everything). An absent STORAGE root is NOT — a witness legitimately
    // omits the storage trie of an account the block never touches, so it is skipped, not
    // counted. A dangling ref reached WHILE walking an included trie (account or storage)
    // always bumps missing_count_. missing_count_ accumulates across all passes.
    DeriveStatus derive_state(const evmc::bytes32& prev_root);

    // Account-cache lookup keyed by the 32-byte trie path (addr_hash == keccak256(addr)).
    // Hit -> pointer to the derived Account POD in the arena; miss -> nullptr (absent).
    // Mirrors DirectState::read_account's pointer-or-null shape. The pointer is valid
    // until the next emit grows the arena; a derive_state run followed by reads is the
    // intended usage. Note: Account::addr is left zero — derive never sees the 20-byte
    // preimage, only its hash (the trie path); the cache is keyed by that hash.
    [[gnu::always_inline]] inline const Account*
    get_account(const evmc::bytes32& addr_hash) const noexcept {
        if (auto off = account_index_.find(addr_hash.bytes)) {
            return reinterpret_cast<const Account*>(accounts_arena_.data() + *off);
        }
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
    // Referenced nodes (child hash refs or the seeding root) a sweep found ABSENT from
    // the store. > 0 means the witness was incomplete — the accept gate must reject.
    std::uint32_t missing_count() const noexcept { return missing_count_; }

  private:
    // Shared explicit-stack DFS over ONE trie rooted at `root`, the single traversal the
    // account pass and every storage pass run through (no recursion — rv64im-safe). At
    // each leaf it calls emit_leaf(path_packed_to_bytes32, leaf_value_ByteView); the
    // caller's emit decides how to decode/cache that leaf (account vs slot). A dangling
    // child ref reached WHILE walking bumps missing_count_. Returns false iff `root`
    // itself was absent from the node store (the caller decides whether that is
    // fail-closed — see derive_state), true if the sweep ran. Defined in the .cpp; only
    // instantiated there (from derive_state's two emit lambdas).
    template <class EmitLeaf>
    bool sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf);

    // Decode `leaf_value` (an account-leaf RLP) and cache it under `addr_hash`. Bumps
    // leaf_count_ for every leaf reached; on a successful decode also inserts into the
    // account cache and returns a pointer to the cached Account (valid only until the next
    // emit grows the arena — derive_state reads its storage_root immediately). A leaf whose
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
    // accounts derive_state unfolds out of the node trie. Arena entry layout is a bare
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

    // Diagnostics for the last derive_state sweep. missing_count_ mirrors GridMPT's
    // homonym (mpt.hpp:235): every referenced node absent from an included trie is counted,
    // so an incomplete witness is observable rather than silently skipped.
    std::uint32_t missing_count_{0};
    std::uint32_t leaf_count_{0};
    std::uint32_t storage_slot_count_{0};

    // TODO(hashstate-slib, next step): created-code cache — the role of
    // DirectState::created_code_ / created_code_collisions_ for in-block-created code.
    // Not built here.
};

}  // namespace zilkworm
