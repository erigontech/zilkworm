// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash_state.hpp"

#include <algorithm>  // std::lower_bound (insert_header / get_block_hash)
#include <array>
#include <bit>
#include <cstring>
#include <utility>
#include <vector>

#include <intx/intx.hpp>

#include <evmone/test/state/state_diff.hpp>         // evmone::state::StateDiff (apply_state_diff)
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>  // silkworm::kEmptyHash / kEmptyRoot
#include <zilk_core/core/common/util.hpp>           // silkworm::keccak256(ByteView)
#include <zilk_core/core/rlp/decode.hpp>            // rlp::decode_header (free helper)
#include <zilk_core/core/types/transaction.hpp>     // silkworm::eip7702::is_code_delegated
#include <zilk_core/core/types_zz/account.hpp>      // Account, decode_trie_account

// The standalone DFS mirrors the DECODE logic of GridMPT::unfold_node_from_rlp
// (fold_unfold.hpp:64) but calls no GridMPT method. It reuses the shared node types
// (BranchNode / LeafNode / nibbles64 / Kind) and the FREE single-pass node decoder
// decode_node (rlp_sw.hpp:315), which itself drives hp_decode (rlp_sw.hpp:62) and the
// branch-child iteration (fill_branch_child* rlp_sw.hpp:189,215).
#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm {

HashState::HashState(std::uint32_t expected_nodes, std::uint32_t expected_codes,
                     std::uint32_t expected_accounts, std::uint32_t expected_storage_slots)
    : node_index_{expected_nodes},
      code_index_{expected_codes},
      account_index_{expected_accounts},
      storage_index_{expected_storage_slots} {
    // Front-pad both arenas so the first real entry offset is >= 8 and can never
    // equal HashIndex's empty-bucket sentinel (offset 0). std::vector<uint8_t> data is
    // max_align_t-aligned, and every account entry is a whole Account (256 B, a multiple
    // of 8) starting at offset 8, so each stays 8-aligned for the reinterpret_cast. The
    // storage arena stores bare 32-byte words (32 is a multiple of 8) from offset 8, so
    // those stay 8-aligned too.
    accounts_arena_.resize(8, 0);
    storage_arena_.resize(8, 0);
}

void HashState::reserve_stores(std::uint32_t nodes, std::uint32_t codes,
                               std::uint32_t accounts, std::uint32_t storage_slots) {
    node_index_.reserve(nodes);
    code_index_.reserve(codes);
    account_index_.reserve(accounts);
    storage_index_.reserve(storage_slots);
    // The arenas hold the 8-byte front pad plus one fixed-size entry per cached account
    // (a whole Account) / slot (a 32-byte word); see emit_account_ / emit_slot_. Like the
    // index reserves, these are no-ops once a build has filled the stores: a reallocation
    // would move the records the overlay and the read path point into.
    if (account_index_.size() == 0)
        accounts_arena_.reserve(8u + static_cast<std::size_t>(accounts) * sizeof(Account));
    if (storage_index_.size() == 0)
        storage_arena_.reserve(8u + static_cast<std::size_t>(storage_slots) * 32u);
}

namespace {

// Inverse of nibbles64::from_bytes32 (mpt.hpp:50): pack a full 64-nibble path back into
// its 32-byte key. A well-formed account/storage leaf always accumulates exactly 64
// nibbles (fixed-length keys), so p.len == 64 here.
[[gnu::always_inline]] inline evmc::bytes32 path_to_bytes32(const nibbles64& p) noexcept {
    evmc::bytes32 out{};
    for (unsigned i = 0; i < 32; ++i) {
        out.bytes[i] = static_cast<std::uint8_t>((p.nib[2 * i] << 4) | (p.nib[2 * i + 1] & 0x0F));
    }
    return out;
}

}  // namespace

const Account* HashState::emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value) {
    ++leaf_count_;  // a leaf was reached, whether or not its value decodes as an account

    Account acc{};  // value-init: addr/deleted/slot_count/code_store_*/rlp cache all zero
    if (!decode_trie_account(leaf_value, acc)) {
        // Not an account-shaped leaf (e.g. a small embedded non-account leaf in a test
        // fixture, or a malformed witness). Do not cache; leave it observable via the
        // leaf_count_/account_count() gap. The account sweep never crashes on a leaf.
        return nullptr;
    }

    // Append the decoded Account POD to the arena (offset stays 8-aligned) and index it
    // by addr_hash. A duplicate addr_hash overwrites the offset (last write wins) but the
    // arena is append-only, matching add_node's dedupe-by-content spirit loosely enough
    // for a witness-derived, collision-free key set.
    const std::uint32_t off = static_cast<std::uint32_t>(accounts_arena_.size());
    accounts_arena_.resize(accounts_arena_.size() + sizeof(Account));
    std::memcpy(accounts_arena_.data() + off, &acc, sizeof(Account));
    account_index_.insert(addr_hash.bytes, off);
    return reinterpret_cast<const Account*>(accounts_arena_.data() + off);
}

void HashState::emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                           ByteView leaf_value) {
    ++storage_slot_count_;  // a storage leaf was reached

    // The trie leaf value is rlp::encode(zeroless_view(word)) — an RLP string whose payload
    // is the big-endian word with leading zeros trimmed (0..32 bytes). Peel that one string
    // header; decode_header advances `v` to the payload, exactly as decode_trie_account peels
    // the account list header. A single small byte (< 0x80) is its own payload (no header),
    // which decode_header reports as payload_length 1 without advancing — handled uniformly.
    ByteView v = leaf_value;
    auto h = rlp::decode_header(v);
    if (!h || h->list || h->payload_length > 32) return;  // not a <=32-byte string: skip
    evmc::bytes32 word{};
    if (h->payload_length) {
        std::memcpy(word.bytes + (32u - h->payload_length), v.data(), h->payload_length);
    }

    // Append the 32-byte word (offset stays 8-aligned) and index it by addr_hash||slot_hash.
    const std::uint32_t off = static_cast<std::uint32_t>(storage_arena_.size());
    storage_arena_.resize(storage_arena_.size() + sizeof(word));
    std::memcpy(storage_arena_.data() + off, word.bytes, sizeof(word));

    std::uint8_t key[64];
    std::memcpy(key, account_key.bytes, 32);
    std::memcpy(key + 32, slot_hash.bytes, 32);
    storage_index_.insert(key, off);
}

// One frame of the explicit DFS stack. A frame is only ever a BRANCH — the sole node
// kind that must be revisited (it fans out to <=16 children). Extensions and leaves are
// consumed inline in descend_() as the sweep walks down, so they never occupy a frame.
namespace {
struct WalkFrame {
    BranchNode branch;    // the decoded branch at this position
    nibbles64 path;       // nibble path from the root down to (not including) this branch's children
    std::uint8_t next_slot;  // next child slot (0..15) to visit, left to right
};
}  // namespace

template <class EmitLeaf>
bool HashState::sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf) {
    // Look up the seeding root by hash. Absence is REPORTED to the caller (return false),
    // never counted here: build_state_from_trie applies the fail-closed policy per trie kind
    // (an absent account root is fail-closed; an absent storage root is a legitimate omission).
    auto root_rlp = find_node_rlp(root);
    if (!root_rlp) return false;

    // Explicit stack, sized past the 64-nibble max trie depth so it never reallocates
    // during a well-formed sweep. That keeps every WalkFrame (and the ByteViews into a
    // frame's embedded child bytes) stable across a push in descend().
    std::vector<WalkFrame> stack;
    stack.reserve(128);

    // Chase down from a node's RLP at `path`: strip the outer list header, decode it,
    // then either push a branch frame, fold an extension's path in and descend into its
    // one child, or reach a leaf and hand it to emit_leaf. Written as a loop (not
    // recursion) so an extension chain never grows the C++ call stack. Mirrors
    // unfold_node_from_rlp: outer-header strip + decode_node, then the branch / ext / leaf
    // split. The leaf's meaning (account vs storage slot) is entirely the caller's emit —
    // the traversal is identical for both.
    const auto descend = [&](ByteView node_rlp, nibbles64 path) {
        while (true) {
            // Strip the outer list header. rlp::decode_header (the size-safe free helper
            // decode_node itself uses) is used rather than fold_unfold's fast_decode_header
            // because the sweep must also decode <8-byte embedded nodes, which the >=8-byte
            // fast path mis-reads.
            auto oh = rlp::decode_header(node_rlp);
            if (!oh || !oh->list) return;  // malformed node — not a list
            const ByteView list = node_rlp.substr(0, oh->payload_length);

            BranchNode branch;
            bool is_leaf = false;
            std::array<std::uint8_t, 64> np{};
            std::uint8_t plen = 0;
            ByteView second{};
            const Kind kind = decode_node(list, branch, is_leaf, np, plen, second);
            if (kind == kInvalid) return;
            if (kind == kBranch) {
                // A branch consumes one nibble per child, so a well-formed branch sits at
                // path.len <= 63 (its children land at <= 64). Reject a malformed deeper
                // branch: it has no room for a child nibble (would overflow nibbles64).
                if (path.len >= 64) return;
                stack.push_back(WalkFrame{std::move(branch), path, 0});
                return;
            }

            // kExtOrLeaf: append this node's own path nibbles, guarding the 64 bound so a
            // malformed over-long path can never overflow nibbles64 (its append assumes it).
            if (static_cast<unsigned>(path.len) + plen > 64) return;
            path.append(nibbles64{plen, np});

            if (is_leaf) {
                emit_leaf(path_to_bytes32(path), second);
                return;
            }

            // Extension: descend into its single child. decode_node returns `second` as
            // the raw 32-byte hash for a hash ref, or the full inline RLP for an embedded
            // (<32-byte) child — the exact distinction unfold_node_from_rlp draws. The
            // store is probed straight from the hash's bytes in the node RLP (the size
            // check above is the pointer overload's 32-byte guarantee).
            if (second.size() == 32) {
                auto child = find_node_rlp(second.data());
                if (!child) {
                    // PRUNED BOUNDARY: this extension points into a pruned subtree (same rule
                    // as the branch-child case below). Stop descending; do NOT bump
                    // missing_count_ — a pruned child is not a missing node.
                    return;
                }
                node_rlp = *child;
                continue;  // decode the fetched child in place
            }
            node_rlp = second;  // embedded inline child: decode directly, no store lookup
        }
    };

    descend(*root_rlp, nibbles64{});  // seed: push the root (or emit it if the root is a leaf)

    while (!stack.empty()) {
        const std::size_t top = stack.size() - 1;

        // Advance to the next present child slot, left to right. child_len == 0 is an
        // empty slot (decode_node leaves it so; mpt.hpp branch slots 0..15).
        unsigned s = stack[top].next_slot;
        while (s < 16 && stack[top].branch.child_len[s] == 0) ++s;
        if (s >= 16) {
            // No child left (slot 16, the branch value, is never populated for a
            // fixed-32-byte-key account/storage trie — every key ends at a leaf). Subtree
            // done: fold back to the parent.
            stack.pop_back();
            continue;
        }
        stack[top].next_slot = static_cast<std::uint8_t>(s + 1);

        // Path to this child = the branch's path + the child's nibble s.
        nibbles64 child_path = stack[top].path;
        child_path.nib[child_path.len++] = static_cast<std::uint8_t>(s);

        const std::uint8_t clen = stack[top].branch.child_len[s];
        if (clen == 32) {
            // 32-byte hash ref: resolve it through the store straight from where the hash
            // lies (child_ptr into the node RLP, or the inline child.bytes — exactly
            // unfold_slot's source pick, fold_unfold.hpp:524), no copy into a bytes32. The
            // clen == 32 check is the pointer overload's 32-byte guarantee, and the probe
            // completes before descend() can push a frame, so the frame's bytes are stable.
            const std::uint8_t* hsrc = stack[top].branch.child_ptr[s]
                                           ? stack[top].branch.child_ptr[s]
                                           : stack[top].branch.child[s].bytes;
            auto child = find_node_rlp(hsrc);
            if (!child) {
                // Pruned boundary (partial witness): do not descend, do not count as missing.
                // See docs/hashstate.md, "Fail-closed policy".
                continue;
            }
            descend(*child, child_path);
        } else {
            // Embedded (<32-byte) inline child: its RLP lives in the parent's child bytes
            // (copied there by decode_node); decode it directly, no store lookup.
            descend(ByteView{stack[top].branch.child[s].bytes, clen}, child_path);
        }
    }

    return true;
}

HashState::BuildStatus HashState::build_state_from_trie(const evmc::bytes32& prev_root) {
    missing_count_ = 0;
    leaf_count_ = 0;
    storage_slot_count_ = 0;
    // Reset the read-miss counter and remember the account-trie root so a later read miss
    // can seed confirm_absent. The reads that a caller runs after this build accumulate into
    // unconfirmed_read_count_ until the next build clears it again.
    unconfirmed_read_count_ = 0;
    prev_root_ = prev_root;

    // (addr_hash, storage_root) for every derived account carrying a non-empty storage
    // trie, captured during the account pass so the storage passes can run once it ends.
    // storage_root is copied out immediately: the Account* emit_account_ returns is only
    // valid until the next emit grows the accounts arena.
    std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage_roots;

    // --- account pass ---
    // Empty account trie derives nothing, cleanly (design §2.6): no root to fetch.
    if (prev_root != silkworm::kEmptyRoot) {
        const bool root_present =
            sweep(prev_root, [&](const evmc::bytes32& addr_hash, ByteView leaf_value) {
                if (const Account* acc = emit_account_(addr_hash, leaf_value)) {
                    evmc::bytes32 sroot;
                    std::memcpy(sroot.bytes, acc->storage_root, 32);
                    if (sroot != silkworm::kEmptyRoot)
                        storage_roots.emplace_back(addr_hash, sroot);
                }
            });
        // A missing ACCOUNT root is the B2 fail-closed case — the anchor of everything.
        if (!root_present) ++missing_count_;
    }

    // --- storage passes --- one sweep per derived account; an absent storage root is skipped.
    // See docs/hashstate.md, "Fail-closed policy".
    for (const auto& pr : storage_roots) {
        const evmc::bytes32 account_key = pr.first;
        const evmc::bytes32 sroot = pr.second;
        sweep(sroot, [this, account_key](const evmc::bytes32& slot_hash, ByteView leaf_value) {
            emit_slot_(account_key, slot_hash, leaf_value);
        });
    }

    return missing_count_ > 0 ? BuildStatus::kMissingNode : BuildStatus::kOk;
}

// Single-path confirmation walk — see the header for the full contract. It intentionally
// mirrors sweep()'s descend() one node at a time, but keeps only ONE position (no stack, no
// emit): the target's own nibbles pick the single child to follow at every branch.
bool HashState::confirm_absent(const evmc::bytes32& root,
                               const evmc::bytes32& target_hash) const noexcept {
    // The empty trie holds nothing, so every key is provably absent below it. (kEmptyRoot's
    // node is never in the store, so without this the fetch below would read as a missing
    // node and wrongly fail to confirm.)
    if (root == silkworm::kEmptyRoot) return true;

    const nibbles64 target = nibbles64::from_bytes32(target_hash);  // 64 nibbles
    unsigned consumed = 0;  // target nibbles matched on the way down so far

    auto cur = find_node_rlp(root);
    if (!cur) return false;  // seeding root missing -> cannot confirm absence
    ByteView node_rlp = *cur;

    // Stable backing for an embedded (<32-byte) inline child, whose bytes live inside the
    // transient decoded node and would dangle once the loop re-decodes. memmove (not memcpy)
    // because an ext's embedded child view can overlap this same buffer across iterations.
    std::array<std::uint8_t, 33> embedded{};

    while (true) {
        // Strip the outer list header exactly as descend() does (rlp::decode_header, the
        // size-safe helper that also handles <8-byte embedded nodes).
        auto oh = rlp::decode_header(node_rlp);
        if (!oh || !oh->list) return false;  // malformed node -> cannot confirm
        const ByteView list = node_rlp.substr(0, oh->payload_length);

        BranchNode branch;
        bool is_leaf = false;
        std::array<std::uint8_t, 64> np{};
        std::uint8_t plen = 0;
        ByteView second{};
        const Kind kind = decode_node(list, branch, is_leaf, np, plen, second);
        if (kind == kInvalid) return false;  // undecodable -> cannot confirm

        if (kind == kBranch) {
            if (consumed >= 64) return false;  // no nibble left to index a branch (malformed)
            const unsigned s = target.nib[consumed];
            // Empty child slot (decode_node's child_len == 0, i.e. the RLP 0x80 marker): the
            // target's next nibble leads nowhere -> proven absent.
            if (branch.child_len[s] == 0) return true;
            ++consumed;
            if (branch.child_len[s] == 32) {  // 32-byte hash ref -> resolve through the store
                // Probed in place (the == 32 check is the pointer overload's guarantee).
                const std::uint8_t* hsrc = branch.child_ptr[s] ? branch.child_ptr[s]
                                                               : branch.child[s].bytes;
                auto child = find_node_rlp(hsrc);
                if (!child) return false;  // needed node missing -> cannot confirm
                node_rlp = *child;
                continue;
            }
            // Embedded (<32-byte) inline child: its RLP lives in the parent's child bytes; copy
            // it out to stable storage before the loop re-decodes and destroys `branch`.
            const std::uint8_t len = branch.child_len[s];
            std::memmove(embedded.data(), branch.child[s].bytes, len);
            node_rlp = ByteView{embedded.data(), len};
            continue;
        }

        // kExtOrLeaf: match this node's own path nibbles against the target's remainder.
        const unsigned remaining = 64u - consumed;
        const unsigned overlap = plen < remaining ? plen : remaining;
        for (unsigned i = 0; i < overlap; ++i) {
            if (target.nib[consumed + i] != np[i]) return true;  // path diverges -> proven absent
        }
        if (plen > remaining) return true;  // node path outlasts the key -> divergence -> absent
        consumed += plen;

        if (is_leaf) {
            // Whole leaf path matched. Exactly consuming the key (consumed == 64) means the key
            // is PRESENT (not proven absent); a shorter leaf leaves the key hanging past a
            // terminal node (absent). A present key here is a cache-miss anomaly, so fail-closed.
            return consumed == 64 ? false : true;
        }

        // Extension: descend into its single child (hash ref -> store, probed in place;
        // embedded -> stable copy).
        if (second.size() == 32) {
            auto child = find_node_rlp(second.data());
            if (!child) return false;  // needed node missing -> cannot confirm
            node_rlp = *child;
            continue;
        }
        const std::size_t len = second.size();
        std::memmove(embedded.data(), second.data(), len);
        node_rlp = ByteView{embedded.data(), len};
    }
}

void HashState::note_account_miss_(const evmc::bytes32& addr_hash) const noexcept {
    // Cache miss on an account. If confirm_absent can prove the key empty in the account trie
    // the blank read is correct and nothing is recorded; otherwise a node the walk needed was
    // missing (or the key is unexpectedly present), so the read is unconfirmed — record it.
    if (!confirm_absent(prev_root_, addr_hash)) ++unconfirmed_read_count_;
}

void HashState::note_storage_miss_(const evmc::bytes32& addr_hash,
                                   const evmc::bytes32& slot_hash) const noexcept {
    // A storage slot is zero unless its account exists AND carries a non-empty storage trie.
    auto aoff = account_index_.find(addr_hash.bytes);
    if (!aoff) return;  // account not cached -> slot is zero, no storage trie to confirm against
    evmc::bytes32 sroot;
    std::memcpy(sroot.bytes,
                reinterpret_cast<const Account*>(accounts_arena_.data() + *aoff)->storage_root, 32);
    if (sroot == silkworm::kEmptyRoot) return;  // empty storage trie -> slot is zero, no walk

    // Confirm against the account's own storage_root. This is where a storage root the build
    // skipped (its node never added) is caught: find_node_rlp misses inside confirm_absent, so
    // it returns false and the read is recorded rather than passed off as a silent zero.
    if (!confirm_absent(sroot, slot_hash)) ++unconfirmed_read_count_;
}

evmc::bytes32 HashState::add_view_(HashIndex<32, &hash_key8, StoredBytes>& index,
                                   ByteView bytes) {
    // Identity binding: the index key IS the real keccak256 of the bytes (matches the
    // direct_state.cpp:417-418 idiom exactly). One probe inserts or finds the key present:
    // a repeat is the same content under the same hash, so the first view stays (first
    // wins, which is what a find followed by an insert-if-absent would do, at one probe).
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(bytes));
    index.try_insert(h.bytes, stored_view_(bytes));
    return h;
}

evmc::bytes32 HashState::add_node_borrowed(ByteView rlp) { return add_view_(node_index_, rlp); }

evmc::bytes32 HashState::add_code_borrowed(ByteView code) { return add_view_(code_index_, code); }

evmc::bytes32 HashState::add_node(ByteView rlp) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(rlp));
    if (node_index_.find(h.bytes)) return h;  // dedupe: already stored, no second copy
    const Bytes& copy = owned_bytes_.emplace_back(rlp);
    node_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

evmc::bytes32 HashState::add_code(ByteView code) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    if (code_index_.find(h.bytes)) return h;  // dedupe
    const Bytes& copy = owned_bytes_.emplace_back(code);
    code_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

// --- silkworm::BlockState interface + BLOCKHASH store ---------------------------------
// Near-verbatim copies of DirectState (direct_state.cpp:696-730, :818-840) so a later
// retype of the execution surface to ActiveState is a drop-in. See hash_state.hpp for the
// per-method contract and the one divergence (no witness block_hashes_ span in get_block_hash).

std::optional<BlockHeader> HashState::read_header(BlockNum,
                                                  const evmc::bytes32& block_hash) const noexcept {
    const auto it = headers_.find(block_hash);
    if (it == headers_.end()) return std::nullopt;
    return it->second;
}

void HashState::insert_header(const BlockHeader& header) {
    headers_[header.hash()] = header;

    // created_block_hashes_ kept sorted ascending for log-n BLOCKHASH lookup.
    const uint64_t block_num = header.number;
    const auto h = header.hash();
    auto it = std::lower_bound(created_block_hashes_.begin(),
                               created_block_hashes_.end(), block_num,
                               [](const BlockHashEntry& e, uint64_t n) {
                                   return e.block_number < n;
                               });
    if (it != created_block_hashes_.end() && it->block_number == block_num) {
        std::memcpy(it->block_hash, h.bytes, 32);
    } else {
        BlockHashEntry e{};
        e.block_number = block_num;
        std::memcpy(e.block_hash, h.bytes, 32);
        created_block_hashes_.insert(it, e);
    }
}

bool HashState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> HashState::total_difficulty(uint64_t,
                                                         const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

evmc::bytes32 HashState::get_block_hash(BlockNum n) const noexcept {
    // No witness block_hashes_ span here (see hash_state.hpp): created_block_hashes_ alone.
    if (!created_block_hashes_.empty()) {
        const auto it = std::lower_bound(created_block_hashes_.begin(),
                                         created_block_hashes_.end(), n,
                                         [](const BlockHashEntry& e, BlockNum k) {
                                             return e.block_number < k;
                                         });
        if (it != created_block_hashes_.end() && it->block_number == n) {
            return std::bit_cast<evmc::bytes32>(it->block_hash);
        }
    }

    // Fail-closed BLOCKHASH miss: record an unconfirmed read, still return zero.
    // See docs/hashstate.md, "Block headers and BLOCKHASH".
    ++unconfirmed_read_count_;
    return {};
}

// --- Write overlay + mutators + address-keyed readers (S2) ----------------------------
// Copy-on-write over the PRISTINE built caches: every write lands in the overlay
// (created_accounts_ / overflow_slots_ / created_code_) and a read sees overlay-then-built.
// Bodies mirror direct_state.cpp:337-694 line-for-line except the two divergences marked
// DIVERGENCE(a)/(b). See hash_state.hpp for the design rationale.

namespace {

namespace eip7702 = ::silkworm::eip7702;

// Balance is stored native-endian (Account::balance, account.hpp:28; see
// direct_state.cpp:203-212). memcpy in/out preserves the intx::uint256 byte layout.
inline void store_be_u256(uint8_t (&out)[32], const intx::uint256& v) noexcept {
    std::memcpy(out, &v, 32);
}
inline intx::uint256 load_be_u256(const uint8_t (&in)[32]) noexcept {
    intx::uint256 v;
    std::memcpy(&v, in, 32);
    return v;
}
inline void copy32(uint8_t (&dst)[32], const evmc::bytes32& src) noexcept {
    std::memcpy(dst, src.bytes, 32);
}
// keccak256(addr) — the 32-byte account-trie path that keys the built account cache.
inline evmc::bytes32 addr_hash_of(const evmc::address& addr) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{addr.bytes, 20}));
}
// keccak256(slot key) — the storage-trie path that keys the built storage cache.
inline evmc::bytes32 slot_hash_of(const evmc::bytes32& key) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{key.bytes, 32}));
}

}  // namespace

// Non-recording overlay-or-built probe (DirectState::lookup_account_ analog,
// direct_state.cpp:349-357): overlay first, then the built cache, no confirm side effect.
const Account* HashState::lookup_account_(const evmc::address& addr) const noexcept {
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    return find_built_account(addr_hash_of(addr));
}

// Read resolver: overlay hit (nullptr if deleted) else the RECORDING built-cache read path
// (get_account -> note_account_miss_), so an address-keyed read of a pruned account is
// recorded fail-closed rather than silently returning a wrong-empty.
const Account* HashState::resolve_for_read_(const evmc::address& addr) const noexcept {
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return it->second.deleted ? nullptr : &it->second;
    return get_account(addr_hash_of(addr));
}

const Account* HashState::read_account(const evmc::address& addr) const noexcept {
    return resolve_for_read_(addr);
}

evmc::bytes32 HashState::read_storage(const evmc::address& addr,
                                      const evmc::bytes32& key) const noexcept {
    // Overlay slot first: a written value — INCLUDING a retained zero (divergence a) —
    // shadows the built (pre-state) value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        if (auto kv = it->second.find(key); kv != it->second.end())
            return kv->second;
    }
    // A wiped account reads every pre-state slot as zero (divergence b).
    if (storage_wiped_.contains(addr)) [[unlikely]]
        return {};
    // Built storage cache: get_storage records an unprovable miss (note_storage_miss_).
    return get_storage(addr_hash_of(addr), slot_hash_of(key));
}

ByteView HashState::read_code(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return {};
    if (eq_hash32(pa->code_hash, kEmptyHash.bytes)) return {};  // empty code — not a fault

    const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa->code_hash);

    // In-block created code (set via set_code / apply_code_diff): the code_store_offset
    // sentinel, resolved through created_code_ (verbatim direct_state.cpp:332-344).
    if (pa->code_store_offset == kCreatedCodeOffset) [[unlikely]] {
        if (const ByteView cc = find_created_code_(h); !cc.empty()) [[likely]]
            return cc;
        // Created-code marker with no stored bytes (should not happen) -> fail-closed.
        ++unconfirmed_read_count_;
        return {};
    }

    // Witness code store (built accounts and set_code dedup hits): resolve by code_hash.
    if (const ByteView cv = find_code(h); !cv.empty())
        return cv;

    // Witness store miss. The bytes may still be legitimately DERIVABLE: a contract created
    // in-block with the SAME code_hash makes an omitted witness code available (EIP-8025
    // optional proofs — "create same hash then read"). This is exactly what DirectState gets
    // for free because it always holds the full pre-state; the partial slib witness prunes
    // such code, so fall back to the in-block created-code overlay before failing.
    if (const ByteView cc = find_created_code_(h); !cc.empty())
        return cc;

    // FAIL-CLOSED: a derived account carries a code_hash whose bytes the witness omitted AND
    // that no in-block creation reproduces. DirectState guarantees presence via sanitize
    // (direct_state.cpp:762-777); HashState has no such binding, so record the genuine gap for
    // the accept gate instead of silently executing empty code.
    ++unconfirmed_read_count_;
    return {};
}

// In-block created-code lookup by keccak code_hash (created_code_ + key8-collision spill).
// Verbatim shape of read_code's former created-code sentinel resolution, factored out so the
// witness-store-miss fallback can reuse it. Hit -> stored bytes; miss -> empty ByteView.
ByteView HashState::find_created_code_(const evmc::bytes32& h) const noexcept {
    const uint64_t k8 = hash_key8(h);
    if (auto it = created_code_.find(k8); it != created_code_.end() &&
            std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) [[likely]] {
        return ByteView{it->second.bytes.data(), it->second.bytes.size()};
    }
    if (auto cit = created_code_collisions_.find(h); cit != created_code_collisions_.end()) {
        return ByteView{cit->second.data(), cit->second.size()};
    }
    return {};
}

intx::uint256 HashState::get_balance(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);  // nullptr also covers deleted
    if (pa == nullptr) return 0;
    return load_be_u256(pa->balance);
}

uint64_t HashState::get_nonce(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr) return 0;
    return pa->nonce;
}

bool HashState::has_storage(const evmc::address& addr) const noexcept {
    const Account* pa = lookup_account_(addr);  // non-recording is enough here
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    // A live (non-zero) overlay slot means storage exists. Zero writes are RETAINED
    // (divergence a), so a bare non-empty test would misreport — scan for a live value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        for (const auto& [k, v] : it->second)
            if (!evmc::is_zero(v)) return true;
    }
    // Built pre-state storage, unless wiped (divergence b).
    if (storage_wiped_.contains(addr)) return false;
    return !eq_hash32(pa->storage_root, kEmptyRoot.bytes);
}

// "Not in state" is a materialized (deleted) overlay record, not a null pointer — verbatim
// DirectState::materialize_absent_account_ (direct_state.cpp:327-335) over the overlay.
Account* HashState::materialize_absent_account_(const evmc::address& addr) {
    Account fresh{};
    std::memcpy(fresh.addr, addr.bytes, 20);
    copy32(fresh.code_hash, kEmptyHash);
    copy32(fresh.storage_root, kEmptyRoot);
    fresh.deleted = true;
    auto [ins, _] = created_accounts_.emplace(addr, fresh);
    return &ins->second;
}

Account* HashState::find_or_create_account(const evmc::address& addr) {
    // Overlay hit (DirectState lookup finding a created record) — deleted or not.
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    const evmc::bytes32 h = addr_hash_of(addr);
    // Built hit -> copy-on-write into the overlay (the built cache stays pristine).
    if (const Account* built = find_built_account(h)) {  // side-effect-free: no confirm
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);          // the build leaves addr zero (hpp:152)
        auto [ins, _] = created_accounts_.emplace(addr, copy);
        return &ins->second;
    }
    // Total miss: materialize a fresh (deleted) record, never null. That the pre-state trie has
    // no leaf for the address is claimed by the record's account-trie update at accept time
    // (check_root_hashstate, HashStateAccountWrite::absent), which the fold checks where the
    // key leaves the trie: no confirm_absent walk here. A pruned boundary on the way, or a leaf
    // at the key, fails that walk, and the accept gate rejects.
    return materialize_absent_account_(addr);
}

// Caller guarantees pa.deleted; reset to a fresh account (DirectState:356-369).
bool HashState::revive_if_deleted_slow(const evmc::address& addr, Account& pa) {
    pa.deleted = false;
    copy32(pa.code_hash, kEmptyHash);
    copy32(pa.storage_root, kEmptyRoot);
    pa.slot_count = 0;
    pa.code_store_len = 0;
    pa.code_store_offset = 0;
    pa.nonce = 0;
    store_be_u256(pa.balance, intx::uint256{0});
    overflow_slots_.erase(addr);
    // DIVERGENCE (b): the built pre-state slots must now read zero (the DirectState in-place
    // slot_count=0 wipe has no analog on the immutable built cache).
    storage_wiped_.insert(addr);
    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
    return true;
}

void HashState::set_account_from_diff(Account& pa, uint64_t nonce,
                                      const intx::uint256& balance) noexcept {
    bool changed = false;
    if (pa.nonce != nonce) {
        pa.nonce = nonce;
        changed = true;
    }
    if (load_be_u256(pa.balance) != balance) {
        store_be_u256(pa.balance, balance);
        changed = true;
    }
    if (changed) {
        pa.modified = true;
        pa.acc_rlp_sroot_off = 0;  // invalidate the RLP cache — force re-encode
    }
}

void HashState::set_storage_slot(const evmc::address& addr, Account& pa,
                                 const evmc::bytes32& key, const evmc::bytes32& value) {
    pa.modified = true;
    // HashState has no inline blob slots; every write lands in the overlay. DIVERGENCE (a):
    // a zero write is RETAINED (DirectState erases it, direct_state.cpp:391-397) so the fold
    // emits it as a 0x80 delete — the incremental fold over prev_root needs the explicit
    // delete, whereas DirectState recomputes each storage root from its live slots.
    overflow_slots_[addr][key] = value;
}

void HashState::apply_code_diff(const evmc::address& addr, Account& pa,
                                const evmc::bytes& code) {
    const ByteView code_view{code.data(), code.size()};
    const bool is_delegated = eip7702::is_code_delegated(code_view);

    // Wipe storage on contract creation unless the new code is a delegation or the address
    // was already a delegation target (mirrors direct_state.cpp:406-415). DIVERGENCE (b):
    // set the storage_wiped_ flag + drop overlay slots instead of the in-place inline-slot
    // wipe (the built cache is immutable).
    if (!is_delegated && !delegated_designations_.contains(addr)) {
        overflow_slots_.erase(addr);
        storage_wiped_.insert(addr);
    }
    if (is_delegated) {
        delegated_designations_.insert(addr);
    }

    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code_view));
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the WITNESS code store via find_code — the HashState analog of
    // DirectState's code_store_map_.find (direct_state.cpp:424-427). Otherwise stash in
    // created_code_ keyed by key8(hash), spilling key8 collisions into
    // created_code_collisions_ (verbatim direct_state.cpp:428-440).
    if (!find_code(h).empty()) {
        pa.code_store_offset = 0;  // resolvable via find_code(code_hash) in read_code
    } else {
        pa.code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
            // Exact dedup hit (same hash, possibly different addr). Skip insert.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h); cins) {
                cit->second.assign(code.begin(), code.end());
            }
        }
    }

    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
}

void HashState::set_balance(const evmc::address& addr, const intx::uint256& value) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    bool changed = false;
    if (load_be_u256(pa->balance) != value) {
        store_be_u256(pa->balance, value);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::add_to_balance(const evmc::address& addr, const intx::uint256& addend) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    const auto cur = load_be_u256(pa->balance);
    bool changed = false;
    if (addend != 0) {
        store_be_u256(pa->balance, cur + addend);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    const auto cur = load_be_u256(pa->balance);
    bool changed = false;
    if (subtrahend != 0) {
        store_be_u256(pa->balance, cur - subtrahend);
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::set_nonce(const evmc::address& addr, uint64_t nonce) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);
    bool changed = false;
    if (pa->nonce != nonce) {
        pa->nonce = nonce;
        changed = true;
    }
    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::set_code(const evmc::address& addr, ByteView code) {
    auto* pa = find_or_create_account(addr);
    revive_if_deleted(addr, *pa);

    if (eip7702::is_code_delegated(code)) {
        delegated_designations_.insert(addr);
    }
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    bool changed = false;
    if (std::memcmp(pa->code_hash, h.bytes, 32) != 0) {
        std::memcpy(pa->code_hash, h.bytes, 32);
        changed = true;
    }
    pa->code_store_len = static_cast<uint32_t>(code.size());

    if (!find_code(h).empty()) {
        pa->code_store_offset = 0;  // resolvable via find_code(code_hash) in read_code
    } else {
        pa->code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
            // Exact dedup hit. Skip.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h); cins) {
                cit->second.assign(code.begin(), code.end());
            }
        }
    }

    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::destruct(const evmc::address& addr) {
    // The built cache is immutable, so mark the overlay record deleted (copy-on-write a
    // deleted marker if the account exists only in the built cache) so read_account sees it
    // gone. If it exists in neither store there is nothing to mask (mirrors
    // direct_state.cpp:566-570).
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end()) {
        it->second.deleted = true;
    } else if (const Account* built = find_built_account(addr_hash_of(addr))) {
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);
        copy.deleted = true;
        created_accounts_.emplace(addr, copy);
    }
    overflow_slots_.erase(addr);
    // DIVERGENCE (b): the built pre-state slots must now read zero (DirectState zeroes the
    // blob slot_count in place, direct_state.cpp:568; HashState cannot mutate the built cache).
    storage_wiped_.insert(addr);
    touched_.insert(addr);
    journal_address_changed(addr);
}

bool HashState::is_deleted(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    return pa == nullptr || pa->deleted;
}

bool HashState::is_empty_account(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    return pa->nonce == 0 && eq_hash32(pa->code_hash, kEmptyHash.bytes) &&
           load_be_u256(pa->balance) == 0;
}

bool HashState::is_dead(const evmc::address& addr) const noexcept {
    return is_deleted(addr) || is_empty_account(addr);
}

void HashState::destruct_dead_among(const FlatHashSet<evmc::address>& addrs) {
    for (const auto& addr : addrs) {
        if (is_dead(addr)) destruct(addr);
    }
}

void HashState::apply_state_diff(const evmone::state::StateDiff& diff) {
    for (const auto& m : diff.modified_accounts) {
        auto* pa = find_or_create_account(m.addr);
        revive_if_deleted(m.addr, *pa);
        journal_address_changed(m.addr);
        if (m.code) apply_code_diff(m.addr, *pa, *m.code);
        set_account_from_diff(*pa, m.nonce, m.balance);
        for (const auto& [k, v] : m.modified_storage) {
            journal_slot_changed(m.addr, k);
            set_storage_slot(m.addr, *pa, k, v);
        }
    }
    for (const auto& a : diff.deleted_accounts) {
        journal_address_changed(a);
        destruct(a);
    }
}

}  // namespace zilkworm
