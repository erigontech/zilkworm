// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "direct_state.hpp"

#include <zilk_core/core/common_zz/bytes_cmp.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <evmone/test/state/state_diff.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types/transaction.hpp>
#include <zilk_core/print.hpp>

#if ZILK_SEAL_CODE_STORE
#include <zilk_core/core/state_zz/code_store_seal.hpp>
#endif

#if USE_HASH_KEY
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>     // nibbles64, BranchNode
#include <zilk_core/core/trie_zz/rlp_sw.hpp>  // decode_node
#endif
namespace zilkworm {

CodeStoreVerified g_code_store_verified;

namespace trie = ::silkworm::trie;
using ::silkworm::keccak256;
using ::silkworm::to_bytes32;
using ::silkworm::zeroless_view;
namespace rlp = ::silkworm::rlp;
namespace eip7702 = ::silkworm::eip7702;

namespace {

    // Bounds + alignment + magic/version checks against malicious blob input.
    // Run once before any field of the blob is dereferenced.
    bool validate_prestate_layout(std::span<const uint8_t> blob) noexcept {
        if (blob.size() < sizeof(PreStateMeta)) [[unlikely]] {
            sys_println("DirectState: blob smaller than PreStateMeta");
            return false;
        }
        if ((reinterpret_cast<uintptr_t>(blob.data()) % 8u) != 0) [[unlikely]] {
            sys_println("DirectState: blob start not 8-byte aligned");
            return false;
        }

        const auto* meta = reinterpret_cast<const PreStateMeta*>(blob.data());
        const uint64_t blob_size = blob.size();

        if (meta->magic != kMagic) [[unlikely]] {
            sys_println("DirectState: bad PreStateMeta magic");
            return false;
        }
        if (meta->version != kVersion) [[unlikely]] {
            sys_println("DirectState: bad PreStateMeta version");
            return false;
        }

        auto bound_bytes = [&](uint64_t off, uint64_t byte_count, const char* msg) -> bool {
            if (off > blob_size || byte_count > blob_size || off + byte_count > blob_size) [[unlikely]] {
                sys_println(msg);
                return false;
            }
            return true;
        };

        auto bound_typed = [&](uint64_t off, uint64_t count, uint64_t elem_size,
                               uint64_t align, const char* msg) -> bool {
            uint64_t total;
            if (__builtin_mul_overflow(count, elem_size, &total)) [[unlikely]] {
                sys_println(msg);
                return false;
            }
            if ((off % align) != 0) [[unlikely]] {
                sys_println(msg);
                return false;
            }
            if (!bound_bytes(off, total, msg)) [[unlikely]]
                return false;
            return true;
        };

        if (!bound_typed(meta->addr_hashes_offset, meta->n_accounts, sizeof(AddrHashEntry),
                         alignof(AddrHashEntry),
                         "DirectState: addr_hashes section out of range")) [[unlikely]]
            return false;
        if (!bound_typed(meta->block_hashes_offset, meta->n_block_hashes, sizeof(BlockHashEntry),
                         alignof(BlockHashEntry),
                         "DirectState: block_hashes section out of range")) [[unlikely]]
            return false;
        // The addr map runs from prestate_offset up to addr_hashes_offset; a size-0
        // region would skip validate_mphf.
        if (meta->n_accounts > 0) {
            if (meta->addr_hashes_offset <= meta->prestate_offset) [[unlikely]] {
                sys_println("DirectState: prestate MphfMap region empty");
                return false;
            }
            if (!validate_mphf<20>(blob, meta->prestate_offset,
                                   meta->addr_hashes_offset - meta->prestate_offset,
                                   kMphfAddrMapMagic)) [[unlikely]] {
                return false;
            }
            const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data() + meta->prestate_offset);
            if (m->n_keys == 0) [[unlikely]] {
                sys_println("DirectState: prestate MphfMapHeader has zero keys but n_accounts > 0");
                return false;
            }
        }
        if (!validate_mphf<32>(blob, meta->code_store_offset, meta->code_store_size,
                               kMphfCodeStoreMagic)) [[unlikely]] {
            return false;
        }

        // The sections must not overlap. The account map's data is written through (Account
        // scratch, EVM state), so code-store bytes inside it, hashed and bound by sanitize(),
        // could change after it, and so could the code the EVM runs in place.
        {
            struct Section { uint64_t lo, hi; };
            const uint64_t n_acc = meta->n_accounts;
            const Section sections[] = {
                {0, sizeof(PreStateMeta)},
                {meta->prestate_offset, n_acc > 0 ? uint64_t{meta->addr_hashes_offset} : 0},
                {meta->addr_hashes_offset, meta->addr_hashes_offset + n_acc * sizeof(AddrHashEntry)},
                {meta->block_hashes_offset,
                 meta->block_hashes_offset + uint64_t{meta->n_block_hashes} * sizeof(BlockHashEntry)},
                {meta->code_store_offset, uint64_t{meta->code_store_offset} + meta->code_store_size},
            };
            for (size_t i = 0; i < std::size(sections); ++i) {
                for (size_t j = i + 1; j < std::size(sections); ++j) {
                    const Section& a = sections[i];
                    const Section& b = sections[j];
                    if (a.lo < a.hi && b.lo < b.hi && a.lo < b.hi && b.lo < a.hi) [[unlikely]] {
                        sys_println("DirectState: prestate sections overlap");
                        return false;
                    }
                }
            }
        }

        if (meta->n_accounts > 0) {
            const auto* mhdr = reinterpret_cast<const MphfMapHeader*>(
                blob.data() + meta->prestate_offset);
            const uint8_t* mbase = reinterpret_cast<const uint8_t*>(mhdr);
            const uint8_t* data = mbase + mhdr->data_offset;
            const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
                mbase + mhdr->slot_offsets_offset);
            // Account-specific, on top of validate_mphf<20>: 8-alignment for the in-place
            // Account, and the Account plus its inline slots must fit in the body its
            // header declares.
            auto check_entry = [&](uint64_t off) -> bool {
                if ((off % alignof(Account)) != 0) [[unlikely]] {
                    sys_println("DirectState: addr-map entry misaligned for Account");
                    return false;
                }
                uint64_t body_len; std::memcpy(&body_len, data + off, 8);
                if (body_len < sizeof(Account)) [[unlikely]] {
                    sys_println("DirectState: addr-map entry body smaller than Account");
                    return false;
                }
                const auto* acc = reinterpret_cast<const Account*>(data + off + 8u);
                const uint64_t slots_bytes = static_cast<uint64_t>(acc->slot_count) * sizeof(Slot);
                if (slots_bytes > body_len - sizeof(Account)) [[unlikely]] {
                    sys_println("DirectState: addr-map entry slots exceed body");
                    return false;
                }
                return true;
            };
            for (uint32_t i = 0; i < mhdr->n_keys; ++i) {
                const uint32_t off = slot_offsets[i];
                if (off == 0) continue;
                if (!check_entry(off)) [[unlikely]]
                    return false;
            }
            if (mhdr->collisions_size > 0) {
                const auto* entries = reinterpret_cast<const MphfCollisionEntry*>(
                    mbase + mhdr->collisions_offset);
                const uint32_t n_coll = mhdr->collisions_size /
                                        static_cast<uint32_t>(sizeof(MphfCollisionEntry));
                for (uint32_t i = 0; i < n_coll; ++i) {
                    if (!check_entry(entries[i].offset)) [[unlikely]]
                        return false;
                }
            }
        }
        return true;
    }

    // The node store is the third MphfMap this class builds. Checked here so every
    // caller of the constructor is covered, not only load_flat_bundle.
    bool validate_nodestore_layout(std::span<const uint8_t> ns) noexcept {
        if (ns.empty()) return true;
        if ((reinterpret_cast<uintptr_t>(ns.data()) % alignof(MphfMapHeader)) != 0) [[unlikely]] {
            sys_println("DirectState: node store not 8-byte aligned");
            return false;
        }
        if (ns.size() > UINT32_MAX) [[unlikely]] {
            sys_println("DirectState: node store larger than an MphfMap region");
            return false;
        }
        return validate_mphf<32>(ns, 0, static_cast<uint32_t>(ns.size()), kMphfNodeStoreMagic);
    }

    inline const PreStateMeta* validate_or_abort(std::span<const uint8_t> v) noexcept {
        if (!validate_prestate_layout(v)) [[unlikely]] {
            std::abort();
        }
        return reinterpret_cast<const PreStateMeta*>(v.data());
    }

    // Balance is stored native-endian — see pre_state.cpp::rlp_into.
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

    /// The slot std::lower_bound finds for `key` (memcmp order) if it holds `key`, else null.
    /// lower_bound's position is that of the last probe that moved left, so the equality of
    /// that comparison answers without a second compare. With strict alignment (rv32 Airbender)
    /// memcmp is a call per probe; the slot keys are 8-aligned, and a word-aligned key, the
    /// usual case, is compared a word at a time inline instead.
    template <typename S>
    [[gnu::always_inline]] inline S* find_slot(S* first, uint32_t n, const evmc::bytes32& key) noexcept {
        auto len = static_cast<std::ptrdiff_t>(n);
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
        if ((reinterpret_cast<uintptr_t>(key.bytes) & 3) == 0) [[likely]] {
            typedef uint32_t __attribute__((may_alias)) w32;
            const w32* const k = reinterpret_cast<const w32*>(key.bytes);
            bool eq = false;
            while (len > 0) {
                const std::ptrdiff_t half = len >> 1;
                S* const mid = first + half;
                const w32* const s = reinterpret_cast<const w32*>(mid->key);
                uint32_t a = 0, b = 0;
                int i = 0;
                for (; i < 8; ++i) {
                    a = s[i];
                    b = k[i];
                    if (a != b) break;
                }
                if (i == 8) {
                    len = half;
                    eq = true;
                    continue;
                }
                // Little-endian words: the first differing byte is the lowest nonzero byte of
                // a ^ b and the bytes below it are equal, so a and b masked up to the end of that
                // byte order as memcmp does (rv32im has no byte swap).
                const uint32_t d = a ^ b;
                const uint32_t m = (d & 0xffu)       ? 0xffu
                                   : (d & 0xffffu)   ? 0xffffu
                                   : (d & 0xffffffu) ? 0xffffffu
                                                     : ~uint32_t{0};
                if ((a & m) < (b & m)) {
                    first = mid + 1;
                    len = len - half - 1;
                } else {
                    len = half;
                    eq = false;
                }
            }
            return eq ? first : nullptr;
        }
#endif
        int last = 1;
        while (len > 0) {
            const std::ptrdiff_t half = len >> 1;
            S* const mid = first + half;
            const int c = ::zilkworm::cmp_bytes32(mid->key, key.bytes);
            if (c < 0) {
                first = mid + 1;
                len = len - half - 1;
            } else {
                len = half;
                last = c;
            }
        }
        return last == 0 ? first : nullptr;
    }

    /// Whether slot key `a` sorts before slot key `b` (memcmp order), the order find_slot() searches in.
    /// Both are 8-aligned, as every slot is; with strict alignment (rv32 Airbender) they are compared a
    /// word at a time inline, as find_slot() does, instead of by a call to memcmp.
    [[gnu::always_inline]] inline bool key_below(const uint8_t* a, const uint8_t* b) noexcept {
        return ::zilkworm::lt_bytes32(a, b);
    }

}  // namespace

// SOUNDNESS-CRITICAL: the entries of an MphfMap must tile its data section exactly as the
// MphfBuilder lays them out — contiguous from offset 8 (the reserved sentinel it leaves so
// slot_offsets[idx] == 0 means "empty"), each 8-aligned, with no gaps and no overlaps.
// find() and for_each() read bodies in place and sanitize() and the EVM write through the
// addr-map bodies, so an entry whose body overlapped another's would let a write into one
// change the other after it was bound. Checked once, before anything is written, by walking
// the chain the builder writes (self-bounded reads) and taking its marks with the map's own
// offsets: equal counts rule out a gap, an overlap, a duplicate and a stray alike.
[[nodiscard]] bool mphf_entries_tile(const MphfMap& m) noexcept {
    if (!m.valid() || m.n_keys() == 0) return true;
    const uint8_t* const data = m.data_base();
    const uint32_t data_size = m.data_size();
    // Marks chain starts; offsets take them.
    std::vector<uint8_t> seen(data_size / 64 + 1, 0);
    uint32_t off = 8u;  // data[0..8) is the sentinel the builder reserves
    uint32_t chain = 0;
    while (off < data_size) {
        if (data_size - off < 8u) return false;  // no room left for the [len] word
        const uint64_t body_len = load_u64_le(data + off);
        if (body_len > data_size - off - 8u) return false;
        seen[(off >> 3) >> 3] |= static_cast<uint8_t>(uint8_t{1} << ((off >> 3) & 7u));
        ++chain;
        off += mphf_align8(static_cast<uint32_t>(8u + body_len));
    }
    if (off != data_size) return false;
    uint32_t hits = 0, visits = 0;
    m.for_each_offset([&](uint64_t o) {
        ++visits;
        if ((o & 7u) != 0 || o >= data_size) return;
        uint8_t& word = seen[(o >> 3) >> 3];
        const uint8_t mask = static_cast<uint8_t>(uint8_t{1} << ((o >> 3) & 7u));
        if ((word & mask) == 0) return;
        word &= static_cast<uint8_t>(~mask);
        ++hits;
    });
    return hits == chain && visits == chain;
}

namespace detail {
    // Forces single-pass linkers to pull this TU when direct_state_builder.cpp is.
    std::array<uint8_t, 32> keccak_addr(const evmc::address& addr) noexcept {
        const auto h = silkworm::keccak256(ByteView{addr.bytes, 20});
        std::array<uint8_t, 32> out;
        std::memcpy(out.data(), h.bytes, 32);
        return out;
    }
}  // namespace detail

DirectState::DirectState(std::span<uint8_t> prestate_bytes) noexcept
    : DirectState{prestate_bytes, std::span<uint8_t>{}} {}

// Both layouts are validated before any field is read or any MphfMap is built.
// On failure it aborts; future wiring will route `false` to a 0-gas proof.
DirectState::DirectState(std::span<uint8_t> prestate_bytes,
                         std::span<uint8_t> nodestore_bytes) noexcept
    : prestate_view_{prestate_bytes},
      pre_state_meta_{validate_or_abort(prestate_view_)},
      pre_state_map_{pre_state_meta_->n_accounts > 0
                         ? reinterpret_cast<MphfMapHeader*>(prestate_view_.data() + pre_state_meta_->prestate_offset)
                         : nullptr},
      code_store_map_{pre_state_meta_->code_store_size > 0
                          ? reinterpret_cast<MphfMapHeader*>(prestate_view_.data() + pre_state_meta_->code_store_offset)
                          : nullptr},
      addr_hashes_{reinterpret_cast<const AddrHashEntry*>(prestate_view_.data() + pre_state_meta_->addr_hashes_offset), pre_state_meta_->n_accounts},
      block_hashes_{reinterpret_cast<const BlockHashEntry*>(prestate_view_.data() + pre_state_meta_->block_hashes_offset), pre_state_meta_->n_block_hashes} {
    if (!nodestore_bytes.empty()) {
        if (!validate_nodestore_layout(nodestore_bytes)) [[unlikely]] {
            std::abort();
        }
        node_store_map_.reset(reinterpret_cast<MphfMapHeader*>(nodestore_bytes.data()));
        node_verified_.assign((node_store_map_.data_size() / 8 + 63) / 64, 0u);
#if USE_HASH_KEY
        // The states are written before they are read (verify_and_snap()); only the tags need clearing.
        walk_states_.reset(new kprefix::StateRow[kprefix::kAddrRows]);
        walk_tags_.reset(new const uint8_t*[kprefix::kAddrRows]());
        walk_sb_.reset(new uint8_t[kprefix::kAddrRows]());
#endif
    }
    reserve_block_maps_();
}

void DirectState::reserve_block_maps_() noexcept {
    created_accounts_.reserve(256);
    overflow_slots_.reserve(128);
    absent_reads_.reserve(1024);
    created_code_.reserve(64);
    touched_.reserve(512);
    headers_.reserve(256);
}

// Rebuilds typed sub-views; blob bytes are caller-owned and pointer-stable.
DirectState::DirectState(DirectState&& other) noexcept
    : prestate_view_{other.prestate_view_} {
    pre_state_meta_ = reinterpret_cast<const PreStateMeta*>(prestate_view_.data());
    if (pre_state_meta_->n_accounts > 0) {
        pre_state_map_.reset(reinterpret_cast<MphfMapHeader*>(prestate_view_.data() + pre_state_meta_->prestate_offset));
    }
    addr_hashes_ = {reinterpret_cast<const AddrHashEntry*>(prestate_view_.data() + pre_state_meta_->addr_hashes_offset),
                    pre_state_meta_->n_accounts};
    block_hashes_ = {reinterpret_cast<const BlockHashEntry*>(prestate_view_.data() + pre_state_meta_->block_hashes_offset),
                     pre_state_meta_->n_block_hashes};
    if (pre_state_meta_->code_store_size > 0) {
        code_store_map_.reset(reinterpret_cast<MphfMapHeader*>(prestate_view_.data() + pre_state_meta_->code_store_offset));
    }
#if ZILK_SEAL_CODE_STORE
    code_store_sealed_ = std::exchange(other.code_store_sealed_, false);
    sealed_code_index_ = std::move(other.sealed_code_index_);
#endif
    node_store_map_ = other.node_store_map_;
    node_verified_ = std::move(other.node_verified_);
#if USE_HASH_KEY
    recovered_accounts_ = std::move(other.recovered_accounts_);
    recovered_slots_ = std::move(other.recovered_slots_);
    recovery_ended_ = other.recovery_ended_;
    walk_states_ = std::move(other.walk_states_);
    walk_tags_ = std::move(other.walk_tags_);
    walk_sb_ = std::move(other.walk_sb_);
#endif

    created_accounts_ = std::move(other.created_accounts_);
    overflow_slots_ = std::move(other.overflow_slots_);
    wiped_storage_ = std::move(other.wiped_storage_);
    absent_reads_ = std::move(other.absent_reads_);
    created_code_ = std::move(other.created_code_);
    created_code_collisions_ = std::move(other.created_code_collisions_);
    headers_ = std::move(other.headers_);
    ancestor_missing_ = other.ancestor_missing_;
    ancestors_ = std::move(other.ancestors_);
    ancestors_number_ = other.ancestors_number_;
    ancestors_end_ = other.ancestors_end_;
    witness_incomplete_ = other.witness_incomplete_;
    require_block_hash_headers_ = other.require_block_hash_headers_;
    touched_ = std::move(other.touched_);
    changed_addresses_journal_ = std::move(other.changed_addresses_journal_);
    changed_storage_journal_ = std::move(other.changed_storage_journal_);
    multi_block_ = other.multi_block_;
    other.prestate_view_ = {};
    other.pre_state_meta_ = nullptr;
    other.pre_state_map_ = {};
    other.node_store_map_ = {};
    other.addr_hashes_ = {};
    other.block_hashes_ = {};
    other.code_store_map_ = {};
}

#if ZILK_SEAL_CODE_STORE
DirectState::~DirectState() {
    // The blob may be freed and its memory reused next (not on the guest, whose heap never reuses
    // a byte), and other bytes there need not stay zero.
    if (code_store_sealed_) evmone::baseline::set_in_place_code_region(nullptr, nullptr);
}
#endif

evmc::bytes32 DirectState::read_storage(const evmc::address& addr,
                                        const evmc::bytes32& key) const noexcept {
    // Materializing: a storage read must leave the same record an account read
    // does. Only blob records carry inline slots; overlay records fall through.
    return read_storage(*observe_account_(addr), addr, key);
}

evmc::bytes32 DirectState::read_storage(const Account& pa, const evmc::address& addr,
                                        const evmc::bytes32& key) const noexcept {
    if (pa.slot_count > 0) {
        if (pa.deleted) [[unlikely]]
            return {};
        if (const Slot* s = find_slot(slots_for(pa).data(), pa.slot_count, key)) {
            return std::bit_cast<evmc::bytes32>(s->current);
        }
    }

    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        if (auto kv = it->second.find(key); kv != it->second.end()) {
            return kv->second;
        }
    }
#if USE_HASH_KEY
    if (!pa.deleted) {
        if (const auto* rs = recover_slot_from_nodestore(pa, addr, key); rs != nullptr) {
            return rs->current;  // zero where the walk showed the key absent
        }
    }
#endif
    if (!pa.deleted) note_absent_read_(pa, key);
    return {};
}

// SOUNDNESS-CRITICAL: a slot the witness does not carry reads as zero, and only check_root's walk of the
// key, against the storage root the zero was read under, shows that the witness did not leave it out.
// Under the empty root (no storage; a record created or revived by the block) every key is absent. The
// root of a pre-state record is the one its account leaf commits to until the block wipes its storage,
// which hands its reads over with its witness slots (note_wiped_storage_). Out of line: read_storage() is
// on the SLOAD path, and some 840 of its reads per block come here.
[[gnu::noinline]] void DirectState::note_absent_read_(const Account& pa, const evmc::bytes32& key) const {
    if (eq_hash32(std::assume_aligned<8>(pa.storage_root), kEmptyRoot.bytes)) return;
    absent_reads_.push_back({key, pa.absent_reads});
    pa.absent_reads = static_cast<uint32_t>(absent_reads_.size());
}

// "Not in state" is a materialized record, not a null pointer: the read itself
// must be provable (non-membership) at root-check time.
Account* DirectState::materialize_absent_account_(const evmc::address& addr) const {
    Account fresh{};
    std::memcpy(fresh.addr, addr.bytes, 20);
    copy32(fresh.code_hash, kEmptyHash);
    copy32(fresh.storage_root, kEmptyRoot);
    fresh.deleted = true;
    auto [ins, _] = created_accounts_.emplace(addr, fresh);
    return &ins->second;
}

void DirectState::set_account_from_diff(Account& pa, uint64_t nonce,
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
        // Invalidate acc_rlp_buf cache — forces rlp_into() to re-encode.
        pa.acc_rlp_sroot_off = 0;
    }
}

// Caller guarantees pa.deleted; reset to a fresh account.
bool DirectState::revive_if_deleted_slow(const evmc::address& addr, Account& pa) {
    pa.deleted = false;
    copy32(pa.code_hash, kEmptyHash);
    copy32(pa.storage_root, kEmptyRoot);
    pa.slot_count = 0;  // destruct() noted them for check_root
    pa.code_store_len = 0;
    pa.nonce = 0;
    store_be_u256(pa.balance, intx::uint256{0});
    overflow_slots_.erase(addr);
#if USE_HASH_KEY
    recovered_slots_.erase(addr);
#endif
    // created_code_ is hash-keyed and possibly shared across addresses.
    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
    return true;
}

void DirectState::set_storage_slot(const evmc::address& addr, Account& pa,
                                   const evmc::bytes32& key, const evmc::bytes32& value) {
    pa.modified = true;
    if (pa.slot_count > 0) {
        if (Slot* s = find_slot(slots_for(pa).data(), pa.slot_count, key)) {
            copy32(s->current, value);
            return;
        }
        // Builder enforces slot_capacity == slot_count, so no in-place insert.
    }

#if USE_HASH_KEY
    // Negative entries fall through to overflow.
    if (auto* r = find_recovered_slot(addr, key); r != nullptr && r->found) {
        r->current = value;
        return;
    }
#endif

    // Zero writes must remove from overflow so storage-trie iteration never
    // sees a stale zero slot.
    if (evmc::is_zero(value)) {
        if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
            it->second.erase(key);
            if (it->second.empty()) overflow_slots_.erase(it);
        }
        return;
    }
    overflow_slots_[addr][key] = value;
}

void DirectState::apply_code_diff(const evmc::address& addr, Account& pa,
                                  const evmc::bytes& code, const evmc::bytes32* code_hash) {
    if (code.empty()) [[unlikely]] {
        // Empty = a cleared EIP-7702 delegation; the authority's storage survives it.
        copy32(pa.code_hash, kEmptyHash);
        pa.code_store_len = 0;
        pa.modified = true;
        pa.acc_rlp_sroot_off = 0;
        return;
    }

    // Creation is the only transition that wipes storage, and post-London EIP-3541 keeps
    // deployed code off the 0xef prefix, so it can never look like a designation.
    if (!eip7702::is_code_delegated(code)) {
        note_wiped_storage_(pa);
        pa.slot_count = 0;
        // What is left is the empty trie, and what the block writes into it after: a read finds every
        // other key absent there (with USE_HASH_KEY too, whose recovery walks this root), and check_root
        // commits the post-state's storage from it. The pre-state's root went with the wiped storage.
        // (EIP-7610 makes a creation over a non-empty storage root collide, so a block can only get here
        // with the root empty already; DirectState does not rely on it.)
        copy32(pa.storage_root, kEmptyRoot);
        overflow_slots_.erase(addr);
#if USE_HASH_KEY
        recovered_slots_.erase(addr);
#endif
    }

    // The hash the EVM's State computed as it set the code, in this guest with the same keccak (evmone's
    // Host::create() and its EIP-7702 delegations): created code is hashed once, not again here. It names the code in
    // the account leaf and in the code stores below, as the hash computed here did.
    const evmc::bytes32 h = code_hash != nullptr ? *code_hash : std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
#if defined(NO_THREAD_LOCAL) || defined(SP1) || defined(QEMU_DEBUG) || defined(AIRBENDER)
    // The guests take the hash as it is.
#else
    if (code_hash != nullptr && std::bit_cast<evmc::bytes32>(silkworm::keccak256(code)) != h) [[unlikely]]
        fatal("ERROR: apply_code_diff: the diff's code hash is not the code's");
#endif
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the witness code_store; otherwise insert into created_code_
    // keyed by key8(hash). key8 collisions spill into created_code_collisions_.
    std::optional<std::span<uint8_t>> b;
#if ZILK_SEAL_CODE_STORE
    // Once sealed, the keys and lengths of the code store are partly zeroed: no lookup by hash,
    // created code goes to created_code_ even if the witness carries the same bytes.
    if (!code_store_sealed_)
#endif
        b = code_store_map_.find<32, 0, &hash_key8>(h.bytes);
    if (b) {
        pa.code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
    } else {
        pa.code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (bytes_equal<32>(it->second.full_hash.bytes, h.bytes)) {
            // Exact dedup hit (same hash, possibly different addr). Skip insert.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h);
                cins) {
                cit->second.assign(code.begin(), code.end());
            }
        }
    }

    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
}

intx::uint256 DirectState::get_balance(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) return 0;
    return load_be_u256(pa->balance);
}

uint64_t DirectState::get_nonce(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) return 0;
    return pa->nonce;
}

void DirectState::set_balance(const evmc::address& addr, const intx::uint256& value) {
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

void DirectState::add_to_balance(const evmc::address& addr, const intx::uint256& addend) {
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

void DirectState::subtract_from_balance(const evmc::address& addr, const intx::uint256& subtrahend) {
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

void DirectState::set_nonce(const evmc::address& addr, uint64_t nonce) {
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

// Out of line: since Cancun no account a block wipes carries witness slots, and inlined into
// apply_state_diff() the record cost its loop 0.31M cycles over the 200-block corpus.
[[gnu::noinline]] void DirectState::note_wiped_storage_(const Account& pa) {
    if (pa.slot_count == 0 && pa.absent_reads == 0) return;
    wiped_storage_.push_back({slots_for(pa), std::bit_cast<evmc::bytes32>(pa.storage_root), pa.absent_reads});
    // Handed over: a destructed record reads nothing, a revived one, or one a deployment wiped, reads under
    // the empty root.
    pa.absent_reads = 0;
}

void DirectState::destruct(const evmc::address& addr) {
    // Flag every record (blob AND overlay twin); none existing means nothing to mask.
    if (auto* pa = find_pre_account_unchecked(addr)) {
        // Once: a deleted record keeps its slots until revive_if_deleted() drops them.
        if (!pa->deleted) note_wiped_storage_(*pa);
        pa->deleted = true;
    }
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        it->second.deleted = true;
    overflow_slots_.erase(addr);
#if USE_HASH_KEY
    for (auto& up : recovered_accounts_) {
        if (std::memcmp(up->addr, addr.bytes, sizeof(addr.bytes)) == 0) up->deleted = true;
    }
    recovered_slots_.erase(addr);
#endif
    // created_code_ is hash-keyed and shared across addresses; do not erase here.
    touched_.insert(addr);
    journal_address_changed(addr);
}

bool DirectState::is_deleted(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    return pa == nullptr || pa->deleted;
}

bool DirectState::is_empty_account(const evmc::address& addr) const noexcept {
    const auto* pa = lookup_account_(addr);
    if (pa == nullptr || pa->deleted) [[unlikely]]
        return false;
    return pa->nonce == 0 && eq_hash32(pa->code_hash, kEmptyHash.bytes) && load_be_u256(pa->balance) == 0;
}

bool DirectState::is_dead(const evmc::address& addr) const noexcept {
    return is_deleted(addr) || is_empty_account(addr);
}

void DirectState::destruct_dead_among(const FlatHashSet<evmc::address>& addrs) {
    for (const auto& addr : addrs) {
        if (is_dead(addr)) destruct(addr);
    }
}

evmc::bytes32 DirectState::account_storage_root(const evmc::address& addr) const {
    // Merge first-map slots with overflow_slots_ (overflow wins), drop zero
    // values per Yellow-Paper trie semantics.
    std::map<evmc::bytes32, evmc::bytes32> live;

    if (const auto* pa = find_pre_account_unchecked(addr);
        pa != nullptr && !pa->deleted && pa->slot_count > 0) {
        const auto sl = slots_for(*pa);
        for (uint32_t i = 0; i < pa->slot_count; ++i) {
            const auto k = std::bit_cast<evmc::bytes32>(sl[i].key);
            const auto v = std::bit_cast<evmc::bytes32>(sl[i].current);
            if (!evmc::is_zero(v)) live.emplace(k, v);
        }
    }
    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        // Zero-current entries are erased on write, so anything here is live.
        for (const auto& [k, v] : it->second) {
            live[k] = v;
        }
    }
#if USE_HASH_KEY
    if (auto it = recovered_slots_.find(addr); it != recovered_slots_.end()) {
        // Keys never collide with flat/overflow (preimage was missing there).
        for (const auto& [k, rs] : it->second) {
            if (rs.found && !evmc::is_zero(rs.current)) live[k] = rs.current;
        }
    }
#endif

    if (live.empty()) return kEmptyRoot;

    std::map<evmc::bytes32, Bytes> storage_rlp;
    Bytes buffer;
    for (const auto& [location, value] : live) {
        const ethash::hash256 hash{silkworm::keccak256({location.bytes, 32})};
        buffer.clear();
        rlp::encode(buffer, zeroless_view(value.bytes));
        storage_rlp[to_bytes32(hash.bytes)] = buffer;
    }

    trie::HashBuilder hb;
    for (const auto& [hash, rlp_bytes] : storage_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash.bytes), rlp_bytes);
    }
    return hb.root_hash();
}

std::optional<evmc::bytes32> DirectState::state_root_hash() const {
    // HashBuilder requires leaves in keccak(addr) order.
    std::map<evmc::bytes32, Bytes> account_rlp;

    auto emit = [&](const evmc::address& addr, const Account& pa) {
        if (pa.deleted) [[unlikely]]
            return;
        const auto sr = account_storage_root(addr);
        const ethash::hash256 hash{silkworm::keccak256({addr.bytes, 20})};
        account_rlp[to_bytes32(hash.bytes)] = pa.rlp(sr);
    };

    if (pre_state_meta_->n_accounts > 0) {
        auto handle = [&](std::span<const uint8_t> body) {
            const auto* pa = reinterpret_cast<const Account*>(body.data());  // sized by validate_prestate_layout
            evmc::address addr;
            std::memcpy(addr.bytes, pa->addr, 20);
            emit(addr, *pa);
        };
        pre_state_map_.for_each<20>(
            [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                handle(std::span<const uint8_t>{body.data(), body.size()});
            });
    }
    for (const auto& [addr, pa] : created_accounts_) {
        emit(addr, pa);
    }
#if USE_HASH_KEY
    // The accounts recovered from the node store are in the state as well, though the witness carries no
    // record of them. No hash of theirs is a key above, see check_root_new_block().
    for (const auto& up : recovered_accounts_) {
        evmc::address addr;
        std::memcpy(addr.bytes, up->addr, sizeof(addr.bytes));
        emit(addr, *up);
    }
#endif

    if (account_rlp.empty()) return kEmptyRoot;

    trie::HashBuilder hb;
    for (const auto& [hash, rlp_bytes] : account_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash.bytes), rlp_bytes);
    }
    return hb.root_hash();
}

void DirectState::apply_state_diff(const evmone::state::StateDiff& diff) {
    for (const auto& m : diff.modified_accounts) {
        // The handle is the record of get_account(), which find_or_create_account() would return.
#if !defined(AIRBENDER) && !defined(ZISK)
        check_account_handle(m.addr, m.view_handle);
#endif
        auto* pa = m.view_handle ? const_cast<Account*>(static_cast<const Account*>(m.view_handle))
                                 : find_or_create_account(m.addr);
        revive_if_deleted(m.addr, *pa);
        journal_address_changed(m.addr);
        if (m.code) apply_code_diff(m.addr, *pa, *m.code, m.code_hash ? &*m.code_hash : nullptr);
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

std::optional<BlockHeader> DirectState::read_header(BlockNum,
                                                    const evmc::bytes32& block_hash) const noexcept {
    const auto it = headers_.find(block_hash);
    if (it == headers_.end()) return std::nullopt;
    return it->second;
}

#if USE_HASH_KEY
bool DirectState::walk_verify_and_snap(const uint8_t* node, size_t size, unsigned blocks,
                                       const uint8_t* want) const noexcept {
    const size_t r = kprefix::addr_row(node);
    return kprefix::verify_and_snap(node, size, walk_states_[r].lanes, walk_tags_[r], walk_sb_[r], blocks, want);
}

// Returned view may alias embedded_scratch.
std::expected<ByteView, DirectState::WalkMiss>
DirectState::walk_nodestore_leaf(const evmc::bytes32& root, const nibbles64& want,
                                 std::array<uint8_t, 32>& embedded_scratch) const {
    if (is_zero_quick(root) || root == kEmptyRoot) return std::unexpected{WalkMiss::kAbsent};

    evmc::bytes32 node_hash = root;
    ByteView node_rlp;
    bool node_is_embedded = false;
    size_t depth = 0;

    for (unsigned guard = 0; guard < 70; ++guard) {
        if (!node_is_embedded) {
            // A full branch verified here keeps the keccak state of its blocks before the slot the key goes
            // through, as check_root's walks keep theirs: an SSTORE after the SLOAD of a key changes that slot, and
            // check_root's fold of the branch then resumes from the state (see take_walk_state()).
            auto rlp = find_node_rlp(node_hash, [&]() noexcept {
                return kprefix::SnapRequest{depth < 64 ? want.at(depth) : kprefix::kNoSlot, kprefix::kAddrRow};
            });
            if (!rlp) return std::unexpected{WalkMiss::kInvalid};  // witness incomplete
            node_rlp = *rlp;
        }

        auto outer = silkworm::rlp::decode_header(node_rlp);
        if (!outer || !outer->list) return std::unexpected{WalkMiss::kInvalid};
        ByteView nbody = node_rlp.substr(0, outer->payload_length);

        BranchNode br{};
        bool is_leaf = false;
        nibbles64 ext_path{};
        uint8_t plen = 0;
        ByteView second{};
        unsigned mask = 0;
        const Kind kind = decode_node(nbody, br, is_leaf, ext_path, plen, second, mask);
        if (kind == ::zilkworm::kInvalid) return std::unexpected{WalkMiss::kInvalid};

        if (kind == kBranch) {
            if (depth >= 64) return std::unexpected{WalkMiss::kInvalid};
            const uint8_t nib = want.at(depth);
            if ((mask & (1u << nib)) == 0) return std::unexpected{WalkMiss::kAbsent};  // 0x80 child
            const uint8_t clen = br.child_len[nib];
            ++depth;
            if (clen == 32) {
                std::memcpy(node_hash.bytes, branch_hash_src(br, nib), 32);
                node_is_embedded = false;
            } else {
                std::memcpy(embedded_scratch.data(), br.child[nib].bytes, clen);
                node_rlp = ByteView{embedded_scratch.data(), clen};
                node_is_embedded = true;
            }
            continue;
        }

        if (depth + plen > 64) return std::unexpected{WalkMiss::kInvalid};
        for (uint8_t i = 0; i < plen; ++i) {
            if (want.at(depth + i) != ext_path.at(i)) return std::unexpected{WalkMiss::kAbsent};  // path diverges
        }
        depth += plen;

        if (is_leaf) {
            if (depth != 64) return std::unexpected{WalkMiss::kInvalid};
            return second;
        }

        if (second.size() == 32) {
            std::memcpy(node_hash.bytes, second.data(), 32);
            node_is_embedded = false;
        } else {
            if (second.size() > embedded_scratch.size()) return std::unexpected{WalkMiss::kInvalid};
            // memmove: second may already alias embedded_scratch
            std::memmove(embedded_scratch.data(), second.data(), second.size());
            node_rlp = ByteView{embedded_scratch.data(), second.size()};
            node_is_embedded = true;
        }
    }
    return std::unexpected{WalkMiss::kInvalid};
}

const Account*
DirectState::recover_account_from_nodestore(const evmc::address& addr) const {
    if (!node_store_map_.valid() || headers_.empty()) return nullptr;

    // Dedupe: a fresh walk would lose in-place writes and reallocate recovered_accounts_ under live iterators.
    for (const auto& up : recovered_accounts_) {
        if (std::memcmp(up->addr, addr.bytes, sizeof(addr.bytes)) == 0) {
            return up.get();
        }
    }
    if (recovery_ended_) return nullptr;  // a later block: the address is absent, see end_recovery()

    // Pre-root: highest header = pre-state parent.
    const BlockHeader* parent = nullptr;
    for (const auto& [h, hdr] : headers_) {
        if (!parent || hdr.number > parent->number) parent = &hdr;
    }
    if (!parent) return nullptr;

    const auto hashed = to_bytes32(keccak256(ByteView{addr.bytes, sizeof(addr.bytes)}).bytes);
    // Never an address the witness carries a record of (sanitize() bound addr_hashes_, ascending, to the
    // records): its lookup missed that record, which only a forged address map does. The absent record the
    // caller materializes for it then clashes with the witness's in check_root, as without USE_HASH_KEY;
    // a recovered one would put a second update for its key into the walk of the account trie.
    if (const auto it = std::lower_bound(addr_hashes_.begin(), addr_hashes_.end(), hashed,
                                         [](const AddrHashEntry& e, const evmc::bytes32& h) {
                                             return std::memcmp(e.addr_hash, h.bytes, 32) < 0;
                                         });
        it != addr_hashes_.end() && std::memcmp(it->addr_hash, hashed.bytes, 32) == 0) [[unlikely]] {
        return nullptr;
    }
    const nibbles64 want = nibbles64::from_bytes32(hashed);

    std::array<uint8_t, 32> embedded_scratch;  // embedded RLP outlives walker-local BranchNode
    const auto leaf = walk_nodestore_leaf(parent->state_root, want, embedded_scratch);
    if (!leaf) {
        if (leaf.error() == WalkMiss::kAbsent) return nullptr;  // valid empty; caller materializes
        [[unlikely]] fatal("ERROR: USE_HASH_KEY: account walk hit missing/malformed node");
    }

    auto acc = std::make_unique<Account>();
    std::memset(acc.get(), 0, sizeof(Account));
    std::memcpy(acc->addr, addr.bytes, sizeof(addr.bytes));
    std::memcpy(acc->storage_root, kEmptyRoot.bytes, 32);
    if (!decode_trie_account(*leaf, *acc)) [[unlikely]]
        fatal("ERROR: USE_HASH_KEY: malformed account leaf RLP");
    if (std::memcmp(acc->code_hash, kEmptyHash.bytes, 32) != 0) {
        // Setting acc->code_store_len is fine here, checked in read_code
        if (auto b = code_entry_by_hash_(acc->code_hash)) {
            acc->code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
            acc->code_store_len    = static_cast<uint32_t>(b->size() - FlatKv::kPayloadOffset);
        }
    }
    // Snapshot the pre-state leaf RLP before execution mutates the copy (mutators only clear acc_rlp_sroot_off).
    acc->rlp_into_cache();
    sys_println("USE_HASH_KEY: recovered account " +
                to_hex(ByteView{addr.bytes, sizeof(addr.bytes)}, true) +
                " from node-store (preimage missing from keys)");
    // Read-only prestate account; excluded from recompute.
    const Account* ret = acc.get();
    recovered_accounts_.push_back(std::move(acc));
    return ret;
}

const DirectState::RecoveredSlot*
DirectState::recover_slot_from_nodestore(const Account& pa, const evmc::address& addr,
                                         const evmc::bytes32& key) const {
    if (!node_store_map_.valid()) return nullptr;

    if (recovery_ended_) [[unlikely]] {
        // A later block: what was recovered stays, and any other key is absent, see end_recovery().
        const auto it = recovered_slots_.find(addr);
        if (it == recovered_slots_.end()) return nullptr;
        const auto kv = it->second.find(key);
        return kv != it->second.end() ? &kv->second : nullptr;
    }
    auto& per_acct = recovered_slots_[addr];
    if (auto it = per_acct.find(key); it != per_acct.end()) {
        return &it->second;
    }

    const auto sroot = std::bit_cast<evmc::bytes32>(pa.storage_root);
    // A trie with no root has no key: the walk below would say so before reading anything, so the
    // key's hash (a keccak permutation for each new key) is not taken for it.
    if (is_zero_quick(sroot) || sroot == kEmptyRoot) return &per_acct[key];  // negative, as the walk's kAbsent
    const nibbles64 want = nibbles64::from_bytes32(keccak_bytes32(key));
    std::array<uint8_t, 32> embedded_scratch;  // embedded RLP outlives walker-local BranchNode
    const auto leaf = walk_nodestore_leaf(sroot, want, embedded_scratch);
    if (!leaf) {
        if (leaf.error() == WalkMiss::kAbsent) return &per_acct[key];  // negative: walk proved absence
        [[unlikely]] fatal("ERROR: USE_HASH_KEY: slot walk hit missing/malformed node");
    }

    intx::uint256 v;
    ByteView body = *leaf;
    if (!silkworm::rlp::decode(body, v)) [[unlikely]]
        fatal("ERROR: USE_HASH_KEY: malformed slot leaf RLP");
    const auto value = intx::be::store<evmc::bytes32>(v);

    auto& e = per_acct[key];
    e.initial = value;
    e.current = value;
    e.found = true;
    sys_println("USE_HASH_KEY: recovered slot " + to_hex(ByteView{key.bytes, 32}, true) +
                " of account " + to_hex(ByteView{addr.bytes, sizeof(addr.bytes)}, true) +
                " = " + to_hex(ByteView{value.bytes, 32}, true) +
                " from node-store (preimage missing from keys)");
    return &e;
}
#endif

void DirectState::insert_header(const BlockHeader& header) {
    headers_[header.hash()] = header;
    ancestors_.clear();  // The header may lead get_block_hash() further now.
}

bool DirectState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> DirectState::total_difficulty(uint64_t, const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

#if defined(ZISK)
namespace {
constexpr uint32_t kCpGMaxM = 256;  // chain capped at 256 blocks
constexpr uint32_t kCpGMaxEnt = 4096;
constexpr uint32_t kCpGTabBits = 13;
constexpr uint32_t kCpGTabSize = 1u << kCpGTabBits;
constexpr uint32_t kCpGNil = 0xFFFFFFFFu;
struct CpGEnt {
    const uint8_t* p;
    uint32_t L;
    uint32_t m;
    uint32_t kstar;
    uint64_t hb1;
    uint32_t next;
};
CpGEnt cp_g_ents[kCpGMaxEnt];
uint32_t cp_g_tab[kCpGTabSize];  // head index + 1; 0 empty
uint32_t cp_g_used[kCpGMaxEnt];  // slots holding heads, so reset costs no table clear
uint32_t cp_g_nused = 0;
uint32_t cp_g_n = 0;
alignas(8) uint64_t cp_g_state[size_t{kCpGMaxM} * 25];
uint32_t cp_g_epoch[kCpGMaxM];
uint32_t cp_g_list[kCpGMaxEnt];

constexpr uint64_t kCpGHbMul[5] = {0x9E3779B97F4A7C15ull, 0xBF58476D1CE4E5B9ull,
                                   0x94D049BB133111EBull, 0xD6E8FEB86659FD93ull,
                                   0xA0761D6478BD642Full};

bool cp_g_blk_eq136(const uint8_t* a, const uint8_t* b) {
    const uint64_t* wa = reinterpret_cast<const uint64_t*>(a);
    const uint64_t* wb = reinterpret_cast<const uint64_t*>(b);
    for (uint32_t w = 0; w < 17; ++w)
        if (wa[w] != wb[w])
            return false;
    return true;
}

void cp_g_reset() {
    cp_g_n = 0;
    cp_g_nused = 0;
}

/// Defer whole-block 8-aligned entries; others hash now.
[[gnu::noinline]] bool cp_g_collect(const uint8_t* body, size_t body_len) {
    if (body_len < 168 || cp_g_n >= kCpGMaxEnt)
        return false;
    const uint8_t* const p = body + 32;
    if (((reinterpret_cast<uintptr_t>(p)) & 7) != 0)
        return false;
    const uint32_t L = static_cast<uint32_t>(body_len - 32);
    // exact uint32; wrap only bounds reuse
    const uint32_t m = static_cast<uint32_t>((uint64_t{L} * 2069668946402ull) >> 48);  // L/136
    if (m > kCpGMaxM)
        return false;
    const uint64_t* const w = reinterpret_cast<const uint64_t*>(p);
    const uint64_t hb = w[0] * kCpGHbMul[0] ^ w[4] * kCpGHbMul[1] ^ w[8] * kCpGHbMul[2] ^
                        w[12] * kCpGHbMul[3] ^ w[16] * kCpGHbMul[4];
    CpGEnt& e = cp_g_ents[cp_g_n];
    e.p = p;
    e.L = L;
    e.m = m;
    e.kstar = 0;
    e.hb1 = hb;
    const uint64_t x = (hb ^ (hb >> 32)) * kCpGHbMul[1];
    uint32_t s = static_cast<uint32_t>(x >> (64 - kCpGTabBits));
    for (uint32_t probe = 0; probe < kCpGTabSize; ++probe) {
        const uint32_t h = cp_g_tab[s];
        if (h == 0) {
            e.next = kCpGNil;
            cp_g_tab[s] = cp_g_n + 1;
            cp_g_used[cp_g_nused++] = s;
            ++cp_g_n;
            return true;
        }
        if (cp_g_ents[h - 1].hb1 == hb) {
            e.next = h - 1;
            cp_g_tab[s] = cp_g_n + 1;
            ++cp_g_n;
            return true;
        }
        s = (s + 1) & (kCpGTabSize - 1);
    }
    return false;  // probe run full: hash now
}

// Reuse needs adjacent full-byte compare chains.
[[gnu::noinline]] bool cp_g_run() {
    bool ok = true;
    for (uint32_t u = 0; u < cp_g_nused; ++u) {
        const uint32_t s = cp_g_used[u];
        const uint32_t head = cp_g_tab[s];
        cp_g_tab[s] = 0;
        if (head == 0)
            continue;
        uint32_t len = 0;
        for (uint32_t c = head - 1; c != kCpGNil; c = cp_g_ents[c].next)
            cp_g_list[len++] = c;
        for (uint32_t j = 1; j < len; ++j) {
            CpGEnt& e = cp_g_ents[cp_g_list[j]];
            const CpGEnt& q = cp_g_ents[cp_g_list[j - 1]];
            if (!cp_g_blk_eq136(e.p, q.p))
                continue;
            uint32_t k = 1;
            const uint32_t mm = e.m < q.m ? e.m : q.m;
            while (k < mm && cp_g_blk_eq136(e.p + size_t{k} * 136, q.p + size_t{k} * 136))
                ++k;
            e.kstar = k;
        }
        if (len == 1) {
            const CpGEnt& e = cp_g_ents[cp_g_list[0]];
            const auto h =
                silkworm::keccak256(FlatKv::payload(ByteView{e.p - 32, e.L + 32}));
            ok &= bytes_equal<32>(h.bytes, e.p - 32);
            continue;
        }
        std::memset(cp_g_epoch, 0, sizeof cp_g_epoch);
        for (uint32_t j = 0; j < len; ++j) {
            CpGEnt& e = cp_g_ents[cp_g_list[j]];
            const uint8_t* const key = e.p - 32;
            uint32_t d = e.kstar;
            if (d != 0) {
                const uint32_t u1 = cp_g_epoch[d - 1];
                for (uint32_t r = u1; r < j; ++r)
                    if (cp_g_ents[cp_g_list[r]].kstar < d) {
                        d = 0;
                        break;
                    }
            }
            uint32_t capture_at = 0;
            if (j + 1 < len && cp_g_ents[cp_g_list[j + 1]].kstar > d) {
                capture_at = cp_g_ents[cp_g_list[j + 1]].kstar;
                cp_g_epoch[capture_at - 1] = j + 1;
            }
            if (d == 0 && capture_at == 0) {
                const auto h = silkworm::keccak256(FlatKv::payload(ByteView{key, e.L + 32}));
                ok &= bytes_equal<32>(h.bytes, key);
                continue;
            }
            const ethash::hash256 h = ethash::keccak256_cap(
                e.p, e.L, d != 0 ? cp_g_state + size_t{d - 1} * 25 : nullptr, d, capture_at,
                capture_at != 0 ? cp_g_state + size_t{capture_at - 1} * 25 : nullptr);
            ok &= bytes_equal<32>(h.bytes, key);
        }
    }
    return ok;
}
}  // namespace
#endif

bool DirectState::sanitize() {
    // SOUNDNESS-CRITICAL: the pre-state blob's sections lie in builder order and do not overlap —
    // meta | prestate MphfMap | addr_hashes | block_hashes | code store — each ending at or before
    // the next begins and the last within the blob. validate_prestate_layout bounds every section on
    // its own; this rules out a producer pointing one into another, e.g. the code store onto a
    // record's writable slots, which would let the initial->current copy below (or an SSTORE) change
    // code after it was hashed, or a record's slots over another record's bound initial value.
    {
        const PreStateMeta& m = *pre_state_meta_;
        const uint64_t blob_size = prestate_view_.size();
        if (sizeof(PreStateMeta) > m.prestate_offset ||
            m.prestate_offset > m.addr_hashes_offset ||
            uint64_t{m.addr_hashes_offset} + uint64_t{m.n_accounts} * sizeof(AddrHashEntry) >
                m.block_hashes_offset ||
            uint64_t{m.block_hashes_offset} + uint64_t{m.n_block_hashes} * sizeof(BlockHashEntry) >
                m.code_store_offset ||
            uint64_t{m.code_store_offset} + m.code_store_size > blob_size) [[unlikely]] {
            sys_println("sanitize: pre-state sections overlap or out of builder order");
            return false;
        }
        // Within the addr map and the code store, every record/entry starts on an entry boundary and
        // none overlaps another (the node store is a separate, disjoint bundle section, and its nodes
        // are bound to their keccak on use, so an overlapping node cannot be mistaken for another).
        if (!mphf_entries_tile(pre_state_map_) || !mphf_entries_tile(code_store_map_)) [[unlikely]] {
            sys_println("sanitize: witness MphfMap entries overlap or leave gaps");
            return false;
        }
    }

    // SOUNDNESS-CRITICAL: binds each leaf's identity to its trie-key hash.
    //
    // The input reader may have hashed entries as it read them, see CodeStoreVerified. Its bits
    // stand for the bytes as read, so they apply only to this very data section, to the 8-aligned
    // offsets they were set for, and once: they are dropped here, before anything is written.
    const CodeStoreVerified verified = std::exchange(g_code_store_verified, CodeStoreVerified{});
    const bool verified_here = verified.data != nullptr && verified.data == code_store_map_.data() &&
                               verified.data_size == code_store_map_.data_size();
#if ZILK_SEAL_CODE_STORE
    // Code the EVM runs in place must lie in this blob, see the end.
    evmone::baseline::set_in_place_code_region(nullptr, nullptr);
    if (code_store_sealed_) [[unlikely]] {
        sys_println("sanitize: called again, after the code store was sealed");
        return false;
    }
    // Walked here, before anything is written, so that the hashing below tests on the way that
    // every entry the map refers to is an entry of the walk. With no keys validate_mphf has not
    // checked the data section, and nothing refers to it.
    const code_store_seal::DenseLayout layout =
        code_store_map_.n_keys() > 0
            ? code_store_seal::DenseLayout{code_store_map_.data(), code_store_map_.data_size()}
            : code_store_seal::DenseLayout{nullptr, 0};
    bool entries_in_layout = layout.dense();
#endif
    bool code_keccak_ok = true;
    const uint8_t* const code_data = code_store_map_.data();
#if defined(ZISK)
    cp_g_reset();
#endif
    code_store_map_.for_each_offset([&](uint64_t off) {
#if ZILK_SEAL_CODE_STORE
        entries_in_layout = entries_in_layout && layout.is_entry(off);
#endif
        // A misaligned offset is never one the reader walked: it would share the bit of the entry
        // it lies inside.
        if (verified_here && (off & 7) == 0 && (off >> 3) < verified.n_bits &&
            ((verified.bits[off >> 8] >> ((off >> 3) & 31)) & 1) != 0)
            return;
        const uint8_t* const body = code_data + off + 8u;
        const auto body_len = static_cast<size_t>(load_u64_le(code_data + off));
#if defined(ZISK)
        if (!cp_g_collect(body, body_len))
            code_keccak_ok &= bytes_equal<32>(
                silkworm::keccak256(FlatKv::payload(ByteView{body, body_len})).bytes, body);
#else
        code_keccak_ok &= bytes_equal<32>(
            silkworm::keccak256(FlatKv::payload(ByteView{body, body_len})).bytes, body);
#endif
    });
#if defined(ZISK)
    code_keccak_ok &= cp_g_run();
#endif
#if ZILK_SEAL_CODE_STORE
    // Every entry is bound to its key now (the reader's bits stood for the same bytes), and the
    // seal below takes the lengths and keys; read_code() and recover_account_from_nodestore()
    // look code up here.
    sealed_code_index_.clear();
    if (code_keccak_ok) {
        sealed_code_index_.reserve(code_store_map_.n_keys());
        code_store_map_.for_each_offset([&](uint64_t off) {
            SealedCodeEntry e;
            std::memcpy(e.key, code_data + off + 8u, 32);
            e.body_off = static_cast<uint32_t>(off + 8u);
            e.body_len = static_cast<uint32_t>(load_u64_le(code_data + off));
            sealed_code_index_.push_back(e);
        });
    }
#endif
    if (!code_keccak_ok) {
        sys_println("sanitize: code-hash mismatch in witness bundle ");
        return false;
    }

    // Trie nodes are bound to their hash on first lookup, see find_node_rlp(): a corrupt node
    // fails there as a missing one, and an unused one is never read.

    bool acc_walk_ok = true;
    auto handle_account_body = [&](std::span<uint8_t> body) {
        if (!acc_walk_ok) return;
        auto* pa = reinterpret_cast<Account*>(body.data());  // sized by validate_prestate_layout
        if (pa->code_store_len > 0) {
            const auto code_hash = std::bit_cast<evmc::bytes32>(pa->code_hash);
            if (auto b = code_store_map_.find<32, 0, &hash_key8>(code_hash.bytes)) {
                if (b->size() < FlatKv::kPayloadOffset ||
                    pa->code_store_len > b->size() - FlatKv::kPayloadOffset) [[unlikely]] {
                    sys_println("sanitize: code_len exceeds code store entry size");
                    acc_walk_ok = false;
                    return;
                }
                pa->code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
                pa->code_store_len    = static_cast<uint32_t>(b->size() - FlatKv::kPayloadOffset);
            } else {
                sys_println("sanitize: code missing for non-zero code_len account");
                acc_walk_ok = false;
                return;
            }
        }
        pa->deleted = false;
        pa->modified = true;    // To be unset during addr_hashes loop
        pa->absent_reads = 0;
        pa->rlp_into_cache();
        // Execution reads a slot's current value, but check_root binds only its initial one to the
        // storage root: the block starts from that, whatever current value the witness carries. Copied
        // by words (a Slot is 8-aligned): with strict alignment a 32-byte memcpy is a call per slot.
        //
        // SOUNDNESS-CRITICAL: find_slot() binary-searches the slots by key, so their keys have to ascend
        // strictly, which also rules out a key held twice. Out of order, a search can miss a slot the record
        // holds, and the block would read zero for it, whatever value check_root binds.
        typedef uint32_t __attribute__((may_alias)) w32;
        const std::span<Slot> slots = slots_for(*pa);
        for (size_t s = 0; s < slots.size(); ++s) {
            if (s > 0 && !key_below(slots[s - 1].key, slots[s].key)) [[unlikely]] {
                sys_println("sanitize: witness slot keys not in ascending order");
                acc_walk_ok = false;
                return;
            }
            const uint8_t* const f = slots[s].initial;
            uint8_t* const t = slots[s].current;
            if (((reinterpret_cast<uintptr_t>(f) | reinterpret_cast<uintptr_t>(t)) & 7) == 0) {
                typedef uint64_t __attribute__((may_alias)) w64;
                const w64* const from = reinterpret_cast<const w64*>(f);
                w64* const to = reinterpret_cast<w64*>(t);
                for (size_t i = 0; i < 4; ++i) to[i] = from[i];
            } else {
                const w32* const from = reinterpret_cast<const w32*>(f);
                w32* const to = reinterpret_cast<w32*>(t);
                for (size_t i = 0; i < 8; ++i) to[i] = from[i];
            }
        }
    };
    if (pre_state_meta_->n_accounts > 0) {
        pre_state_map_.for_each<20>(
            [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                handle_account_body(body);
            });
    }
    if (!acc_walk_ok) return false;

    const uint32_t data_size = pre_state_map_.valid() ? pre_state_map_.header()->data_size : 0u;
    const uint8_t* prev_hash = nullptr;
    for (const auto& e : addr_hashes_) {
        if (prev_hash != nullptr && ::zilkworm::cmp_bytes32(prev_hash, e.addr_hash) >= 0) return false;
        const auto h = silkworm::keccak256(ByteView{e.addr, 20});
        if (!bytes_equal<32>(h.bytes, e.addr_hash)) return false;
        if (static_cast<uint64_t>(e.entry_offset) + 8u + sizeof(Account) > data_size) return false;
        auto* pa = account_at_offset(e.entry_offset);
        if (!pa || !eq_addr20(pa->addr, e.addr)) return false;
        pa->modified = false;  // This account's hash now checked
        prev_hash = e.addr_hash;
    }

    bool addr_hash_skipped = false;
    if (pre_state_meta_->n_accounts > 0) {
        pre_state_map_.for_each<20>(
            [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                auto* pa = reinterpret_cast<Account*>(body.data());
                addr_hash_skipped = pa->modified || addr_hash_skipped;   // Should be all false
            });
    }
    if (addr_hash_skipped) return false;

#if ZILK_SEAL_CODE_STORE
    // Every payload is hashed and every account bound to its entry: the lengths and keys are not
    // read again. Zeroing the bytes after each payload but the last pads it for the EVM in place,
    // see code_store_seal.hpp. The region ends at the last entry, so the 36 bytes after any code
    // in it lie in the data section.
    if (entries_in_layout) {
        uint8_t* const data = code_store_map_.data();
        code_store_seal::zero_tails(data, layout.last());
        evmone::baseline::set_in_place_code_region(data + 8, data + layout.last());
        code_store_sealed_ = true;
    }
#endif
    return true;
}

#if USE_HASH_KEY || ZILK_SEAL_CODE_STORE
std::optional<std::span<const uint8_t>>
DirectState::code_entry_by_hash_(const uint8_t (&hash)[32]) const noexcept {
#if ZILK_SEAL_CODE_STORE
    if (code_store_sealed_) {
        // The map's lengths and keys are zeroed: sanitize() kept them, each key bound to its payload.
        for (const auto& e : sealed_code_index_) {
            if (e.body_len >= FlatKv::kPayloadOffset && bytes_equal<32>(e.key, hash))
                return std::span<const uint8_t>{code_store_map_.data() + e.body_off, e.body_len};
        }
        return std::nullopt;
    }
#endif
    if (auto b = code_store_map_.find<32, 0, &hash_key8>(hash)) return std::span<const uint8_t>{*b};
    return std::nullopt;
}
#endif

// SOUNDNESS-CRITICAL: an ancestor's hash is the parent hash of its child, from `header` back, and each child
// is the header keyed by the hash the one after it names (insert_header keys a header by its own hash), so
// every hash returned is bound to `header`. Neither the witness's block-hash section nor the numbers of the
// headers it carries are, and neither is read.
evmc::bytes32 DirectState::get_block_hash(const BlockHeader& header, BlockNum n) const noexcept {
    if (n >= header.number) [[unlikely]]
        return {};
    // The walk is kept for the header, which BLOCKHASH asks again and again (up to 256 lookups each):
    // ancestors_ holds the hashes it found, the parent's first, so a hash is looked up once a block.
    if (ancestors_.empty() || ancestors_number_ != header.number || ancestors_[0] != header.parent_hash) {
        ancestors_.clear();
        ancestors_.reserve(257);  // The parent and the 256 blocks BLOCKHASH reaches.
        ancestors_.push_back(header.parent_hash);
        ancestors_number_ = header.number;
        ancestors_end_ = false;
    }
    const BlockNum depth = header.number - 1 - n;
    while (ancestors_.size() <= depth) {
        const auto it = ancestors_end_ ? headers_.end() : headers_.find(ancestors_.back());
        if (it == headers_.end()) [[unlikely]] {
            ancestors_end_ = true;
            ancestor_missing_ = true;
            return {};
        }
        ancestors_.push_back(it->second.parent_hash);
    }
    const evmc::bytes32& hash = ancestors_[static_cast<size_t>(depth)];
    if (require_block_hash_headers_ && !headers_.contains(hash)) [[unlikely]] {
        ancestor_missing_ = true;
        return {};
    }
    return hash;
}

}  // namespace zilkworm
