// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "hash_state.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <utility>
#include <vector>

#include <intx/intx.hpp>

#include <evmone/test/state/state_diff.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/core/types_zz/account.hpp>

#include <zilk_core/core/trie_zz/rlp_sw.hpp>

namespace zilkworm {

HashState::HashState(std::uint32_t expected_nodes, std::uint32_t expected_codes,
                     std::uint32_t expected_accounts, std::uint32_t expected_storage_slots)
    : node_index_{expected_nodes},
      code_index_{expected_codes},
      account_index_{expected_accounts},
      storage_index_{expected_storage_slots} {
    // Front-padded so no real offset equals the empty-bucket sentinel 0; offsets stay 8-aligned (256 B Accounts, 32 B words).
    accounts_arena_.resize(8, 0);
    storage_arena_.resize(8, 0);
    sweep_stack_.reserve(80);
}

void HashState::reserve_stores(std::uint32_t nodes, std::uint32_t codes,
                               std::uint32_t accounts, std::uint32_t storage_slots) {
    nodes = std::min(nodes, kMaxReserve);
    codes = std::min(codes, kMaxReserve);
    accounts = std::min(accounts, kMaxReserve);
    storage_slots = std::min(storage_slots, kMaxReserve);
    node_index_.reserve(nodes);
    code_index_.reserve(codes);
    account_index_.reserve(accounts);
    storage_index_.reserve(storage_slots);
    // Reallocation would move records readers point into.
    if (account_index_.size() == 0)
        accounts_arena_.reserve(8u + static_cast<std::size_t>(accounts) * sizeof(Account));
    if (storage_index_.size() == 0)
        storage_arena_.reserve(8u + static_cast<std::size_t>(storage_slots) * 32u);
}

namespace {

[[gnu::always_inline]] inline evmc::bytes32 path_to_bytes32(const nibbles64& p) noexcept {
    evmc::bytes32 out{};
    for (unsigned i = 0; i < 32; ++i) {
        out.bytes[i] = static_cast<std::uint8_t>((p.nib[2 * i] << 4) | (p.nib[2 * i + 1] & 0x0F));
    }
    return out;
}

// 0 when the item is truncated.
[[gnu::always_inline]] inline std::size_t rlp_item_size(const std::uint8_t* p,
                                                        const std::uint8_t* end) noexcept {
    if (p >= end) return 0;
    const std::size_t avail = static_cast<std::size_t>(end - p);
    const std::uint8_t b0 = *p;
    if (b0 < 0x80) return 1;
    std::size_t len_of_len = 0;
    std::size_t n = 0;
    if (b0 < 0xb8) {
        n = b0 - 0x80u;
    } else if (b0 < 0xc0) {
        len_of_len = b0 - 0xb7u;
    } else if (b0 < 0xf8) {
        n = b0 - 0xc0u;
    } else {
        len_of_len = b0 - 0xf7u;
    }
    const std::size_t head = 1 + len_of_len;
    if (avail < head) return 0;
    for (std::size_t i = 1; i < head; ++i) n = (n << 8) | p[i];
    if (avail - head < n) return 0;
    return head + n;
}

enum class ChildKind : std::uint8_t { kEmpty, kHash, kEmbedded, kBad };

[[gnu::always_inline]] inline ChildKind next_branch_child(const std::uint8_t*& cur,
                                                          const std::uint8_t* end,
                                                          const std::uint8_t*& ptr,
                                                          std::uint8_t& len) noexcept {
    if (cur >= end) return ChildKind::kBad;
    const std::uint8_t b0 = *cur;
    if (b0 == rlp::kEmptyStringCode) {
        ++cur;
        return ChildKind::kEmpty;
    }
    if (b0 == 0xa0) {
        if (end - cur < 33) return ChildKind::kBad;
        ptr = cur + 1;
        cur += 33;
        return ChildKind::kHash;
    }
    if (b0 >= 0xc0 && b0 <= 0xf7) {
        const std::ptrdiff_t payload = b0 - 0xc0;
        if (payload > 30 || end - cur < 1 + payload) return ChildKind::kBad;  // embedded: under 32 bytes
        ptr = cur;
        len = static_cast<std::uint8_t>(1 + payload);
        cur += 1 + payload;
        return ChildKind::kEmbedded;
    }
    return ChildKind::kBad;
}

[[gnu::always_inline]] inline bool ends_with_empty_value(const std::uint8_t* cur,
                                                         const std::uint8_t* end) noexcept {
    return end - cur == 1 && *cur == rlp::kEmptyStringCode;
}

// Occupied child slots of a branch, counted up to two; cur ends past slot 15 if all were read.
struct BranchCount {
    unsigned occupied;
    bool bad;
    const std::uint8_t* cur;
};
[[gnu::always_inline]] inline BranchCount count_branch_children(const std::uint8_t* cur,
                                                                const std::uint8_t* end) noexcept {
    BranchCount r{0, false, cur};
    const std::uint8_t* ptr = nullptr;
    std::uint8_t len = 0;
    for (unsigned i = 0; i < 16 && r.occupied < 2; ++i) {
        const ChildKind k = next_branch_child(r.cur, end, ptr, len);
        if (k == ChildKind::kBad) {
            r.bad = true;
            return r;
        }
        if (k != ChildKind::kEmpty) ++r.occupied;
    }
    return r;
}

// The witness shape rule a leaf or extension must meet once a walk reaches it (execution-specs _check_secured_path).
[[gnu::always_inline]] inline bool secured_path_fits(bool is_leaf, unsigned depth, unsigned plen) noexcept {
    return is_leaf ? depth + plen == 64 : plen != 0 && depth + plen < 64;
}

[[gnu::always_inline]] inline unsigned target_nibble(const evmc::bytes32& key,
                                                     unsigned c) noexcept {
    return (static_cast<unsigned>(key.bytes[c >> 1]) >> ((c & 1u) ? 0u : 4u)) & 0xFu;
}

}  // namespace

const Account* HashState::emit_account_(const evmc::bytes32& addr_hash, ByteView leaf_value) {
    ++leaf_count_;

    // resize zero-fills: unset fields must stay zero.
    const std::uint32_t off = static_cast<std::uint32_t>(accounts_arena_.size());
    accounts_arena_.resize(accounts_arena_.size() + sizeof(Account));
    Account* const acc = reinterpret_cast<Account*>(accounts_arena_.data() + off);
    if (!decode_trie_account(leaf_value, *acc)) {
        accounts_arena_.resize(off);
        return nullptr;
    }

    account_index_.insert(addr_hash.bytes, off);
    return acc;
}

void HashState::emit_slot_(const evmc::bytes32& account_key, const evmc::bytes32& slot_hash,
                           ByteView leaf_value) {
    ++storage_slot_count_;

    ByteView v = leaf_value;
    auto h = rlp::decode_header(v);
    if (!h || h->list || h->payload_length > 32 || h->payload_length > v.size()) return;

    const std::uint32_t off = static_cast<std::uint32_t>(storage_arena_.size());
    storage_arena_.resize(storage_arena_.size() + 32);
    if (h->payload_length) {
        std::memcpy(storage_arena_.data() + off + (32u - h->payload_length), v.data(),
                    h->payload_length);
    }

    alignas(8) std::uint8_t key[64];
    std::memcpy(key, account_key.bytes, 32);
    std::memcpy(key + 32, slot_hash.bytes, 32);
    storage_index_.insert(key, off);
}

template <class EmitLeaf>
bool HashState::sweep(const evmc::bytes32& root, EmitLeaf&& emit_leaf) {
    sweep_stack_.clear();

    // Absence is reported (return false), not counted: build_state_from_trie applies the fail-closed policy per trie kind (an absent account root fails closed; an absent storage root is a legitimate omission).
    auto root_rlp = find_node_rlp(root);
    if (!root_rlp) return false;

    nibbles64 path{};

    const auto descend = [&](ByteView node_rlp) {
        bool via_ext = false;
        while (true) {
            // rlp::decode_header: fast_decode_header misreads <8-byte nodes.
            auto oh = rlp::decode_header(node_rlp);
            if (!oh || !oh->list) {
                malformed_witness_ = true;
                return;
            }
            const std::uint8_t* const p = node_rlp.data();
            const std::uint8_t* const end = p + std::min(oh->payload_length, node_rlp.size());

            const std::size_t s0 = rlp_item_size(p, end);
            const std::size_t s1 = s0 != 0 ? rlp_item_size(p + s0, end) : 0;
            if (s1 == 0) [[unlikely]] {
                malformed_witness_ = true;
                return;
            }

            if (p + s0 + s1 != end) {
                // Depth-64 branch: no room for a nibble.
                if (path.len >= 64) {
                    malformed_witness_ = true;
                    return;
                }
                if (const BranchCount bc = count_branch_children(p, end); !bc.bad && bc.occupied < 2) {
                    if (!ends_with_empty_value(bc.cur, end)) malformed_witness_ = true;
                    return;
                }
                sweep_stack_.push_back(SweepFrame{p, end, 0, path.len});
                return;
            }

            ByteView items{p, static_cast<std::size_t>(end - p)};
            auto h0 = rlp::decode_header(items);
            if (!h0 || h0->list || h0->payload_length == 0 || h0->payload_length > items.size()) {
                malformed_witness_ = true;
                return;
            }
            // decode_header leaves a bare byte in place.
            const std::uint8_t* const hp = items.data();
            const std::size_t hp_len = h0->payload_length;
            items.remove_prefix(hp_len);
            auto h1 = rlp::decode_header(items);
            if (!h1 || h1->list || h1->payload_length > items.size()) {
                malformed_witness_ = true;
                return;
            }
            const std::uint8_t* const second = items.data();
            const std::size_t second_len = h1->payload_length;

            // Keeps writes inside nibbles64.
            const std::uint8_t flag = hp[0] >> 4;
            const bool is_leaf = (flag & 0x2) != 0;
            const bool odd = (flag & 0x1) != 0;
            const std::size_t n = (odd ? 1u : 0u) + 2u * (hp_len - 1);
            if (path.len + n > 64) {
                malformed_witness_ = true;
                return;
            }
            if (is_leaf ? (second_len == 0 || second_len > kMaxLeafValueSize) : second_len != 32) {
                // decode_node rejects any non-hash extension child.
                malformed_witness_ = true;
                return;
            }
            // Derive nothing below a node a walk must refuse; confirm_absent refuses it on use.
            if (via_ext || !secured_path_fits(is_leaf, path.len, static_cast<unsigned>(n))) return;
            std::uint8_t* out = path.nib.data() + path.len;
            if (odd) *out++ = hp[0] & 0x0F;
            for (std::size_t i = 1; i < hp_len; ++i) {
                *out++ = hp[i] >> 4;
                *out++ = hp[i] & 0x0F;
            }
            path.len = static_cast<std::uint8_t>(path.len + n);

            if (is_leaf) {
                emit_leaf(path_to_bytes32(path), ByteView{second, second_len});
                return;
            }

            auto child = find_node_rlp(second);
            if (!child || child->size() < 32) {
                // Pruned boundary, not a missing node; a short node is refused on use.
                return;
            }
            node_rlp = *child;
            via_ext = true;
        }
    };

    descend(*root_rlp);

    while (!sweep_stack_.empty()) {
        // f dangles once descend() pushes.
        SweepFrame& f = sweep_stack_.back();
        unsigned s = f.next_slot;
        if (s >= 16) {
            // Fixed-length keys: branches carry no value.
            if (!ends_with_empty_value(f.cur, f.end)) malformed_witness_ = true;
            sweep_stack_.pop_back();
            continue;
        }

        const std::uint8_t* ptr = nullptr;
        std::uint8_t len = 0;
        ChildKind k;
        do {
            k = next_branch_child(f.cur, f.end, ptr, len);
            ++s;
        } while (k == ChildKind::kEmpty && s < 16);
        if (k == ChildKind::kBad) {
            malformed_witness_ = true;
            sweep_stack_.pop_back();
            continue;
        }
        if (k == ChildKind::kEmpty) {
            if (!ends_with_empty_value(f.cur, f.end)) malformed_witness_ = true;
            sweep_stack_.pop_back();
            continue;
        }
        f.next_slot = static_cast<std::uint8_t>(s);

        path.len = f.path_len;
        path.nib[path.len++] = static_cast<std::uint8_t>(s - 1);

        if (k == ChildKind::kHash) {
            auto child = find_node_rlp(ptr);
            if (!child || child->size() < 32) {
                // Pruned boundary (partial witness), or a short node refused on use: do not descend.
                continue;
            }
            descend(*child);
        } else {
            descend(ByteView{ptr, len});
        }
    }

    return true;
}

HashState::BuildStatus HashState::build_state_from_trie(const evmc::bytes32& prev_root) {
    missing_count_ = 0;
    leaf_count_ = 0;
    storage_slot_count_ = 0;
    unconfirmed_read_count_ = 0;
    ancestor_missing_ = false;
    malformed_witness_ = false;
    absent_slots_.clear();
    prev_root_ = prev_root;

    // storage_root is copied out immediately: the Account* from emit_account_ is valid only until the next emit grows the arena.
    std::vector<std::pair<evmc::bytes32, evmc::bytes32>> storage_roots;

    // An empty account trie derives nothing, cleanly.
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
        // A missing ACCOUNT root fails closed: it is the anchor of everything.
        if (!root_present) ++missing_count_;
    }

    // One storage sweep per derived account; an absent storage root is skipped.
    for (const auto& pr : storage_roots) {
        const evmc::bytes32 account_key = pr.first;
        const evmc::bytes32 sroot = pr.second;
        sweep(sroot, [this, account_key](const evmc::bytes32& slot_hash, ByteView leaf_value) {
            emit_slot_(account_key, slot_hash, leaf_value);
        });
    }

    if (malformed_witness_) return BuildStatus::kMalformed;
    return missing_count_ > 0 ? BuildStatus::kMissingNode : BuildStatus::kOk;
}

bool HashState::confirm_absent(const evmc::bytes32& root,
                               const evmc::bytes32& target_hash) const noexcept {
    // kEmptyRoot's node is never in the store, so the empty trie must be answered before the fetch.
    if (eq_hash32(root.bytes, silkworm::kEmptyRoot.bytes)) return true;

    auto cur = find_node_rlp(root);
    if (!cur) return false;
    const std::uint8_t* p = cur->data();
    std::size_t n = cur->size();
    unsigned consumed = 0;
    bool via_ext = false;

    while (true) {
        ByteView node_rlp{p, n};
        auto oh = rlp::decode_header(node_rlp);
        if (!oh || !oh->list) return false;
        const std::uint8_t* const q = node_rlp.data();
        const std::uint8_t* const end = q + std::min(oh->payload_length, node_rlp.size());

        const std::size_t s0 = rlp_item_size(q, end);
        if (s0 == 0) return false;
        const std::size_t s1 = rlp_item_size(q + s0, end);
        if (s1 == 0) return false;

        if (q + s0 + s1 != end) {
            if (consumed >= 64) return false;
            const unsigned s = target_nibble(target_hash, consumed);
            const std::uint8_t* c = q;
            const std::uint8_t* ptr = nullptr;
            std::uint8_t len = 0;
            if (const BranchCount bc = count_branch_children(q, end); bc.bad || bc.occupied < 2) return false;
            ChildKind k = ChildKind::kBad;
            for (unsigned i = 0; i <= s; ++i) {
                k = next_branch_child(c, end, ptr, len);
                if (k == ChildKind::kBad) return false;
            }
            via_ext = false;
            if (k == ChildKind::kEmpty) return true;
            ++consumed;
            if (k == ChildKind::kHash) {
                auto child = find_node_rlp(ptr);
                if (!child || child->size() < 32) return false;
                p = child->data();
                n = child->size();
                continue;
            }
            p = ptr;
            n = len;
            continue;
        }

        ByteView items{q, static_cast<std::size_t>(end - q)};
        auto h0 = rlp::decode_header(items);
        if (!h0 || h0->list || h0->payload_length == 0 || h0->payload_length > items.size())
            return false;
        // decode_header leaves a bare byte in place.
        const std::uint8_t* const hp = items.data();
        const std::size_t hp_len = h0->payload_length;
        items.remove_prefix(hp_len);
        auto h1 = rlp::decode_header(items);
        if (!h1 || h1->list || h1->payload_length > items.size()) return false;
        const std::uint8_t* const second = items.data();
        const std::size_t second_len = h1->payload_length;

        const std::uint8_t flag = hp[0] >> 4;
        const bool is_leaf = (flag & 0x2) != 0;
        const bool odd = (flag & 0x1) != 0;
        const unsigned plen = (odd ? 1u : 0u) + 2u * static_cast<unsigned>(hp_len - 1);
        if (plen > 64) return false;
        if (is_leaf && second_len == 0) return false;
        if (via_ext || !secured_path_fits(is_leaf, consumed, plen)) return false;

        const unsigned remaining = 64u - consumed;
        const unsigned overlap = plen < remaining ? plen : remaining;
        const std::uint8_t* b = odd ? hp : hp + 1;
        bool high = !odd;
        for (unsigned i = 0; i < overlap; ++i) {
            const unsigned nib = high ? (*b >> 4) : (*b & 0x0Fu);
            if (nib != target_nibble(target_hash, consumed + i)) return true;
            if (high) {
                high = false;
            } else {
                high = true;
                ++b;
            }
        }
        consumed += plen;

        if (is_leaf) {
            return false;  // the key is present, so a cache miss here fails closed
        }

        if (second_len != 32) return false;
        auto child = find_node_rlp(second);
        if (!child || child->size() < 32) return false;
        p = child->data();
        n = child->size();
        via_ext = true;
    }
}

void HashState::note_account_miss_(const evmc::bytes32& addr_hash) const noexcept {
    // An unprovable miss (needed node missing, or key unexpectedly present) is recorded as unconfirmed.
    if (!confirm_absent(prev_root_, addr_hash)) ++unconfirmed_read_count_;
}

void HashState::note_storage_miss_(const std::uint8_t (&key)[64]) const noexcept {
    auto aoff = account_index_.find_ptr(key);
    if (!aoff) return;
    const Account* const acc = reinterpret_cast<const Account*>(accounts_arena_.data() + *aoff);
    if (eq_hash32(acc->storage_root, silkworm::kEmptyRoot.bytes)) return;
    if (absent_slots_.find(key)) return;

    // Offset 96 of an 8-aligned Account.
    const auto& sroot = *reinterpret_cast<const evmc::bytes32*>(acc->storage_root);
    const auto& slot_hash = *reinterpret_cast<const evmc::bytes32*>(key + 32);
    if (!confirm_absent(sroot, slot_hash)) {
        ++unconfirmed_read_count_;
        return;
    }
    absent_slots_.insert(key, 1);
}

evmc::bytes32 HashState::add_view_(HashIndex<32, &hash_key8_at, StoredBytes>& index,
                                   ByteView bytes) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(bytes));
    index.try_insert(h.bytes, stored_view_(bytes));
    return h;
}

evmc::bytes32 HashState::add_node_borrowed(ByteView rlp) { return add_view_(node_index_, rlp); }

evmc::bytes32 HashState::add_code_borrowed(ByteView code) { return add_view_(code_index_, code); }

evmc::bytes32 HashState::add_node(ByteView rlp) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(rlp));
    if (node_index_.find(h.bytes)) return h;
    const Bytes& copy = owned_bytes_.emplace_back(rlp);
    node_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

evmc::bytes32 HashState::add_code(ByteView code) {
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    if (code_index_.find(h.bytes)) return h;
    const Bytes& copy = owned_bytes_.emplace_back(code);
    code_index_.insert(h.bytes, stored_view_(copy));
    return h;
}

std::optional<BlockHeader> HashState::read_header(BlockNum,
                                                  const evmc::bytes32& block_hash) const noexcept {
    const auto it = headers_.find(block_hash);
    if (it == headers_.end()) return std::nullopt;
    return it->second;
}

void HashState::insert_header(const BlockHeader& header) {
    headers_[header.hash()] = header;
    ancestors_.clear();
}

bool HashState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> HashState::total_difficulty(uint64_t,
                                                         const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

evmc::bytes32 HashState::get_block_hash(const BlockHeader& header, BlockNum n) const noexcept {
    if (n >= header.number) [[unlikely]]
        return {};
    // Memoized per block: ancestors_ holds the contiguous held headers below `header`, parent first; block n's own header must be in that run.
    if (ancestors_number_ != header.number || ancestors_anchor_ != header.parent_hash) {
        ancestors_.clear();
        ancestors_number_ = header.number;
        ancestors_anchor_ = header.parent_hash;
        evmc::bytes32 hash = header.parent_hash;
        for (auto it = headers_.find(hash); it != headers_.end() && ancestors_.size() < kBlockHashDepth;
             it = headers_.find(hash)) {
            ancestors_.push_back(hash);
            hash = it->second.parent_hash;
        }
    }
    const BlockNum depth = header.number - 1 - n;
    if (depth >= ancestors_.size()) [[unlikely]] {
        ancestor_missing_ = true;
        ++unconfirmed_read_count_;
        return {};
    }
    return ancestors_[static_cast<size_t>(depth)];
}

namespace {

namespace eip7702 = ::silkworm::eip7702;

// Balance is stored native-endian; memcpy preserves the intx::uint256 byte layout.
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
inline evmc::bytes32 addr_hash_of(const evmc::address& addr) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{addr.bytes, 20}));
}
inline evmc::bytes32 slot_hash_of(const evmc::bytes32& key) noexcept {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(ByteView{key.bytes, 32}));
}

}  // namespace

const Account* HashState::lookup_account_(const evmc::address& addr) const noexcept {
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    return find_built_account(addr_hash_of(addr));
}

// Overlay hit (nullptr if deleted), else the recording read path, so a read of a pruned account is recorded fail-closed.
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
    // A written overlay value, including a retained zero, shadows the built value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        if (auto kv = it->second.find(key); kv != it->second.end())
            return kv->second;
    }
    // A wiped account reads every pre-state slot as zero.
    if (storage_wiped_.contains(addr)) [[unlikely]]
        return {};
    return get_storage(addr_hash_of(addr), slot_hash_of(key));
}

ByteView HashState::read_code(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return {};
    if (eq_hash32(pa->code_hash, kEmptyHash.bytes)) return {};

    const auto& h = *reinterpret_cast<const evmc::bytes32*>(pa->code_hash);

    if (pa->code_store_offset == kCreatedCodeOffset) [[unlikely]] {
        if (const ByteView cc = find_created_code_(h); !cc.empty()) [[likely]]
            return cc;
        // Created-code marker with no stored bytes (should not happen) -> fail-closed.
        ++unconfirmed_read_count_;
        return {};
    }

    if (const ByteView cv = find_code(h); !cv.empty())
        return cv;

    // Witness miss: a contract created in-block with the same code_hash makes an omitted code available (EIP-8025).
    if (const ByteView cc = find_created_code_(h); !cc.empty())
        return cc;

    // FAIL-CLOSED: a code_hash whose bytes the witness omitted and no in-block creation reproduces is recorded for the accept gate.
    ++unconfirmed_read_count_;
    return {};
}

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
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr) return 0;
    return load_be_u256(pa->balance);
}

uint64_t HashState::get_nonce(const evmc::address& addr) const noexcept {
    const Account* pa = resolve_for_read_(addr);
    if (pa == nullptr) return 0;
    return pa->nonce;
}

bool HashState::has_storage(const evmc::address& addr) const noexcept {
    const Account* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    // Zero writes are retained, so scan for a live value.
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        for (const auto& [k, v] : it->second)
            if (!evmc::is_zero(v)) return true;
    }
    if (storage_wiped_.contains(addr)) return false;
    return !eq_hash32(pa->storage_root, kEmptyRoot.bytes);
}

// "Not in state" is a materialized (deleted) overlay record, never a null pointer.
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
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        return &it->second;
    const evmc::bytes32 h = addr_hash_of(addr);
    if (const Account* built = find_built_account(h)) {
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);
        auto [ins, _] = created_accounts_.emplace(addr, copy);
        return &ins->second;
    }
    // A total miss materializes a deleted record and confirms absence; an unprovable miss bumps unconfirmed_read_count_ yet a record is always returned.
    Account* pa = materialize_absent_account_(addr);
    if (!confirm_absent(prev_root_, h)) ++unconfirmed_read_count_;
    return pa;
}

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
    // The built pre-state slots must now read zero.
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
        pa.acc_rlp_sroot_off = 0;
    }
}

void HashState::set_storage_slot(const evmc::address& addr, Account& pa,
                                 const evmc::bytes32& key, const evmc::bytes32& value) {
    pa.modified = true;
    // A zero write is RETAINED so the fold emits a 0x80 delete (the incremental fold over prev_root needs it).
    overflow_slots_[addr][key] = value;
}

void HashState::apply_code_diff(const evmc::address& addr, Account& pa,
                                const evmc::bytes& code) {
    const ByteView code_view{code.data(), code.size()};
    if (code.empty()) [[unlikely]] {
        // Empty = a cleared EIP-7702 delegation; the authority's storage survives it.
        copy32(pa.code_hash, kEmptyHash);
        pa.code_store_len = 0;
        pa.code_store_offset = 0;
        pa.modified = true;
        pa.acc_rlp_sroot_off = 0;
        return;
    }

    // Creation is the only transition that wipes storage; post-London EIP-3541 keeps deployed code off the 0xef prefix, so it never looks like a delegation designation.
    if (!eip7702::is_code_delegated(code_view)) {
        overflow_slots_.erase(addr);
        storage_wiped_.insert(addr);
    }

    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code_view));
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the witness code store, else stash in created_code_ keyed by key8(hash) with key8 collisions spilled.
    if (!find_code(h).empty()) {
        pa.code_store_offset = 0;
    } else {
        pa.code_store_offset = kCreatedCodeOffset;
        stash_created_code_(h, code_view);
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

    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    bool changed = false;
    if (std::memcmp(pa->code_hash, h.bytes, 32) != 0) {
        std::memcpy(pa->code_hash, h.bytes, 32);
        changed = true;
    }
    pa->code_store_len = static_cast<uint32_t>(code.size());

    if (!find_code(h).empty()) {
        pa->code_store_offset = 0;
    } else {
        pa->code_store_offset = kCreatedCodeOffset;
        stash_created_code_(h, code);
    }

    if (changed) {
        pa->modified = true;
        pa->acc_rlp_sroot_off = 0;
        journal_address_changed(addr);
    }
    touched_.insert(addr);
}

void HashState::stash_created_code_(const evmc::bytes32& h, ByteView code) {
    const uint64_t k8 = hash_key8(h);
    if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
        it->second.full_hash = h;
        it->second.bytes.assign(code.begin(), code.end());
    } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) != 0) {
        if (auto [cit, cins] = created_code_collisions_.try_emplace(h); cins) {
            cit->second.assign(code.begin(), code.end());
        }
    }
}

void HashState::note_created_code(ByteView code) {
    if (code.empty()) return;
    const auto h = std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
    if (find_code(h).empty()) stash_created_code_(h, code);
}

void HashState::destruct(const evmc::address& addr) {
    // The built cache is immutable: mask an account existing only there with a deleted overlay record.
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end()) {
        it->second.deleted = true;
    } else if (const Account* built = find_built_account(addr_hash_of(addr))) {
        Account copy = *built;
        std::memcpy(copy.addr, addr.bytes, 20);
        copy.deleted = true;
        created_accounts_.emplace(addr, copy);
    }
    overflow_slots_.erase(addr);
    // The built pre-state slots must now read zero.
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
