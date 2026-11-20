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
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/trie_zz/rlp_sw.hpp>
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

    // Bounds, alignment and magic/version checks on untrusted blob input, before any field is dereferenced.
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
        // A size-0 region would skip validate_mphf.
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

        // Sections must not overlap: the account map's data is written through, so code-store bytes inside it could change after being hashed.
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
            // On top of validate_mphf<20>: an 8-aligned Account whose inline slots fit the declared body.
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

    /// The slot for `key` if present (lower_bound in memcmp order), else null; slot keys are 8-aligned, so word-aligned keys compare inline.
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
                // Little-endian words: the first differing byte is the lowest nonzero byte of a ^ b; masking up to it gives memcmp order (rv32im has no byte swap).
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
            const int c = std::memcmp(mid->key, key.bytes, 32);
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

    /// Whether slot key `a` sorts before `b` in memcmp order; both are 8-aligned.
    [[gnu::always_inline]] inline bool key_below(const uint8_t* a, const uint8_t* b) noexcept {
        return ::zilkworm::lt_bytes32(a, b);
    }

    // SOUNDNESS-CRITICAL: entries must tile the data section exactly as MphfBuilder lays them out (contiguous from offset 8, 8-aligned, no gaps or overlaps): bodies are written in place, so an overlap would let a write change another entry after it was bound.
    [[nodiscard]] bool mphf_entries_tile(const MphfMap& m) {
        if (!m.valid() || m.n_keys() == 0) return true;
        std::vector<uint32_t> offsets;
        offsets.reserve(m.n_keys());
        m.for_each_offset([&](uint64_t off) { offsets.push_back(static_cast<uint32_t>(off)); });
        std::sort(offsets.begin(), offsets.end());
        const uint8_t* const data = m.data_base();
        uint64_t expect = 8u;  // data[0..8) is the sentinel the builder reserves
        for (const uint32_t off : offsets) {
            if (off != expect) return false;
            const uint64_t body_len = load_u64_le(data + off);
            expect = off + mphf_align8(static_cast<uint32_t>(8u + body_len));
        }
        return expect == m.data_size();
    }

}  // namespace

namespace detail {
    std::array<uint8_t, 32> keccak_addr(const evmc::address& addr) noexcept {
        const auto h = silkworm::keccak256(ByteView{addr.bytes, 20});
        std::array<uint8_t, 32> out;
        std::memcpy(out.data(), h.bytes, 32);
        return out;
    }
}  // namespace detail

DirectState::DirectState(std::span<uint8_t> prestate_bytes) noexcept
    : DirectState{prestate_bytes, std::span<uint8_t>{}} {}

// Both layouts are validated before any field is read or any MphfMap is built; on failure it aborts.
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
        node_verified_.assign((node_store_map_.data_size() / 8 + 31) / 32, 0u);
#if USE_HASH_KEY
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
    // The blob may be freed and reused next, and other bytes there need not stay zero.
    if (code_store_sealed_) evmone::baseline::set_in_place_code_region(nullptr, nullptr);
}
#endif

evmc::bytes32 DirectState::read_storage(const evmc::address& addr,
                                        const evmc::bytes32& key) const noexcept {
    // Materializing: a storage read must leave the same record an account read does.
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
            return rs->current;
        }
    }
#endif
    if (!pa.deleted) note_absent_read_(pa, key);
    return {};
}

// SOUNDNESS-CRITICAL: a slot the witness lacks reads as zero, and only check_root's walk against the storage root the zero was read under shows it was not left out; under the empty root every key is absent.
[[gnu::noinline]] void DirectState::note_absent_read_(const Account& pa, const evmc::bytes32& key) const {
    if (eq_hash32(std::assume_aligned<8>(pa.storage_root), kEmptyRoot.bytes)) return;
    absent_reads_.push_back({key, pa.absent_reads});
    pa.absent_reads = static_cast<uint32_t>(absent_reads_.size());
}

// "Not in state" is a materialized record, never null: the read must be provable (non-membership) at root-check time.
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
        pa.acc_rlp_sroot_off = 0;
    }
}

bool DirectState::revive_if_deleted_slow(const evmc::address& addr, Account& pa) {
    pa.deleted = false;
    copy32(pa.code_hash, kEmptyHash);
    copy32(pa.storage_root, kEmptyRoot);
    pa.slot_count = 0;
    pa.code_store_len = 0;
    pa.nonce = 0;
    store_be_u256(pa.balance, intx::uint256{0});
    overflow_slots_.erase(addr);
#if USE_HASH_KEY
    recovered_slots_.erase(addr);
#endif
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
    }

#if USE_HASH_KEY
    if (auto* r = find_recovered_slot(addr, key); r != nullptr && r->found) {
        r->current = value;
        return;
    }
#endif

    // Zero writes remove from overflow so trie iteration never sees a stale zero slot.
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

    // Creation is the only transition that wipes storage, and post-London EIP-3541 keeps deployed code off the 0xef prefix.
    if (!eip7702::is_code_delegated(code)) {
        note_wiped_storage_(pa);
        pa.slot_count = 0;
        // What is left is the empty trie plus what the block writes into it; the pre-state's root went with the wiped storage.
        copy32(pa.storage_root, kEmptyRoot);
        overflow_slots_.erase(addr);
#if USE_HASH_KEY
        recovered_slots_.erase(addr);
#endif
    }

    // The hash the EVM's State computed when it set the code: created code is hashed once.
    const evmc::bytes32 h = code_hash != nullptr ? *code_hash : std::bit_cast<evmc::bytes32>(silkworm::keccak256(code));
#if defined(NO_THREAD_LOCAL) || defined(SP1) || defined(QEMU_DEBUG) || defined(AIRBENDER)
#else
    if (code_hash != nullptr && std::bit_cast<evmc::bytes32>(silkworm::keccak256(code)) != h) [[unlikely]]
        fatal("ERROR: apply_code_diff: the diff's code hash is not the code's");
#endif
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the witness code_store; else insert into created_code_ keyed by key8(hash), spilling collisions.
    std::optional<std::span<uint8_t>> b;
#if ZILK_SEAL_CODE_STORE
    // Once sealed there is no lookup by hash: created code goes to created_code_ even if the witness carries the same bytes.
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

[[gnu::noinline]] void DirectState::note_wiped_storage_(const Account& pa) {
    if (pa.slot_count == 0 && pa.absent_reads == 0) return;
    wiped_storage_.push_back({slots_for(pa), std::bit_cast<evmc::bytes32>(pa.storage_root), pa.absent_reads});
    // Handed over: a destructed record reads nothing; a revived or deployment-wiped one reads under the empty root.
    pa.absent_reads = 0;
}

void DirectState::destruct(const evmc::address& addr) {
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
    // Merge first-map slots with overflow_slots_ (overflow wins), dropping zeros.
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
        for (const auto& [k, v] : it->second) {
            live[k] = v;
        }
    }
#if USE_HASH_KEY
    if (auto it = recovered_slots_.find(addr); it != recovered_slots_.end()) {
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
            const auto* pa = reinterpret_cast<const Account*>(body.data());
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
    // Recovered accounts are in the state too; no hash of theirs is a key above (see check_root_new_block()).
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
#if !defined(AIRBENDER)
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
            // Keeps the keccak state of the blocks before the key's slot so check_root's fold of the branch resumes from it after an SSTORE.
            auto rlp = find_node_rlp(node_hash, [&]() noexcept {
                return kprefix::SnapRequest{depth < 64 ? want[depth] : kprefix::kNoSlot, kprefix::kAddrRow};
            });
            if (!rlp) return std::unexpected{WalkMiss::kInvalid};
            node_rlp = *rlp;
        }

        auto outer = silkworm::rlp::decode_header(node_rlp);
        if (!outer || !outer->list) return std::unexpected{WalkMiss::kInvalid};
        ByteView nbody = node_rlp.substr(0, outer->payload_length);

        BranchNode br{};
        bool is_leaf = false;
        std::array<uint8_t, 64> ext_path{};
        uint8_t plen = 0;
        ByteView second{};
        const Kind kind = decode_node(nbody, br, is_leaf, ext_path, plen, second);
        if (kind == ::zilkworm::kInvalid) return std::unexpected{WalkMiss::kInvalid};

        if (kind == kBranch) {
            if (depth >= 64) return std::unexpected{WalkMiss::kInvalid};
            const uint8_t nib = want[depth];
            if ((br.mask & (1u << nib)) == 0) return std::unexpected{WalkMiss::kAbsent};
            const uint8_t clen = br.child_len[nib];
            ++depth;
            if (clen == 32) {
                const uint8_t* href = br.child_ptr[nib] ? br.child_ptr[nib] : br.child[nib].bytes;
                std::memcpy(node_hash.bytes, href, 32);
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
            if (want[depth + i] != ext_path[i]) return std::unexpected{WalkMiss::kAbsent};
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
    if (recovery_ended_) return nullptr;

    // Pre-root = parent block's state_root: the highest-numbered header in headers_ (ancestors are inserted before execution).
    const BlockHeader* parent = nullptr;
    for (const auto& [h, hdr] : headers_) {
        if (!parent || hdr.number > parent->number) parent = &hdr;
    }
    if (!parent) return nullptr;

    const auto hashed = to_bytes32(keccak256(ByteView{addr.bytes, sizeof(addr.bytes)}).bytes);
    // Never an address the witness carries a record of: its lookup missed that record, which only a forged address map does, and a recovered one would put a second update for its key into the account-trie walk.
    if (const auto it = std::lower_bound(addr_hashes_.begin(), addr_hashes_.end(), hashed,
                                         [](const AddrHashEntry& e, const evmc::bytes32& h) {
                                             return std::memcmp(e.addr_hash, h.bytes, 32) < 0;
                                         });
        it != addr_hashes_.end() && std::memcmp(it->addr_hash, hashed.bytes, 32) == 0) [[unlikely]] {
        return nullptr;
    }
    const nibbles64 want = nibbles64::from_bytes32(hashed);

    std::array<uint8_t, 32> embedded_scratch;
    const auto leaf = walk_nodestore_leaf(parent->state_root, want, embedded_scratch);
    if (!leaf) {
        if (leaf.error() == WalkMiss::kAbsent) return nullptr;
        [[unlikely]] fatal("ERROR: USE_HASH_KEY: account walk hit missing/malformed node");
    }

    auto acc = std::make_unique<Account>();
    std::memset(acc.get(), 0, sizeof(Account));
    std::memcpy(acc->addr, addr.bytes, sizeof(addr.bytes));
    std::memcpy(acc->storage_root, kEmptyRoot.bytes, 32);
    if (!decode_trie_account(*leaf, *acc)) [[unlikely]]
        fatal("ERROR: USE_HASH_KEY: malformed account leaf RLP");
    if (std::memcmp(acc->code_hash, kEmptyHash.bytes, 32) != 0) {
        if (auto b = code_entry_by_hash_(acc->code_hash)) {
            acc->code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
            acc->code_store_len    = static_cast<uint32_t>(b->size() - FlatKv::kPayloadOffset);
        }
    }
    // Snapshot the pre-state leaf RLP before execution mutates the copy.
    acc->rlp_into_cache();
    sys_println("USE_HASH_KEY: recovered account " +
                to_hex(ByteView{addr.bytes, sizeof(addr.bytes)}, true) +
                " from node-store (preimage missing from keys)");
    // Read-only prestate account: its leaf is already in prev_root, so it is excluded from the state-root recompute updates.
    const Account* ret = acc.get();
    recovered_accounts_.push_back(std::move(acc));
    return ret;
}

const DirectState::RecoveredSlot*
DirectState::recover_slot_from_nodestore(const Account& pa, const evmc::address& addr,
                                         const evmc::bytes32& key) const {
    if (!node_store_map_.valid()) return nullptr;

    if (recovery_ended_) [[unlikely]] {
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
    // A trie with no root has no key; skip hashing the key.
    if (is_zero_quick(sroot) || sroot == kEmptyRoot) return &per_acct[key];
    const nibbles64 want = nibbles64::from_bytes32(keccak_bytes32(key));
    std::array<uint8_t, 32> embedded_scratch;
    const auto leaf = walk_nodestore_leaf(sroot, want, embedded_scratch);
    if (!leaf) {
        if (leaf.error() == WalkMiss::kAbsent) return &per_acct[key];
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
    ancestors_.clear();
}

bool DirectState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> DirectState::total_difficulty(uint64_t, const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

bool DirectState::sanitize() {
    // SOUNDNESS-CRITICAL: the blob's sections (meta | prestate map | addr_hashes | block_hashes | code store) must lie in order without overlap, or one aliasing a record's writable slots could change code after it was hashed.
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
        // Every record/entry starts on an entry boundary and none overlaps another (node-store nodes are bound to their keccak on use).
        if (!mphf_entries_tile(pre_state_map_) || !mphf_entries_tile(code_store_map_)) [[unlikely]] {
            sys_println("sanitize: witness MphfMap entries overlap or leave gaps");
            return false;
        }
    }

    // SOUNDNESS-CRITICAL: binds each leaf's identity to its trie-key hash. The reader's verified bits apply only to this data section, at the offsets they were set for, and once: they are dropped here.
    const CodeStoreVerified verified = std::exchange(g_code_store_verified, CodeStoreVerified{});
    const bool verified_here = verified.data != nullptr && verified.data == code_store_map_.data() &&
                               verified.data_size == code_store_map_.data_size();
#if ZILK_SEAL_CODE_STORE
    evmone::baseline::set_in_place_code_region(nullptr, nullptr);
    if (code_store_sealed_) [[unlikely]] {
        sys_println("sanitize: called again, after the code store was sealed");
        return false;
    }
    // Walked first, so the hashing below also tests that every entry the map refers to is an entry of the walk.
    const code_store_seal::DenseLayout layout =
        code_store_map_.n_keys() > 0
            ? code_store_seal::DenseLayout{code_store_map_.data(), code_store_map_.data_size()}
            : code_store_seal::DenseLayout{nullptr, 0};
    bool entries_in_layout = layout.dense();
#endif
    bool code_keccak_ok = true;
    const uint8_t* const code_data = code_store_map_.data();
    code_store_map_.for_each_offset([&](uint64_t off) {
#if ZILK_SEAL_CODE_STORE
        entries_in_layout = entries_in_layout && layout.is_entry(off);
#endif
        // A misaligned offset would share the bit of the entry it lies inside.
        if (verified_here && (off & 7) == 0 && (off >> 3) < verified.n_bits &&
            ((verified.bits[off >> 8] >> ((off >> 3) & 31)) & 1) != 0)
            return;
        const uint8_t* const body = code_data + off + 8u;
        const auto body_len = static_cast<size_t>(load_u64_le(code_data + off));
        code_keccak_ok &= bytes_equal<32>(
            silkworm::keccak256(FlatKv::payload(ByteView{body, body_len})).bytes, body);
    });
#if ZILK_SEAL_CODE_STORE
    // Every entry is bound to its key; read_code() and recover_account_from_nodestore() look code up here once the seal zeroes lengths and keys.
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

    // Nodes are bound to their hash on first lookup, so a corrupt node fails there as a missing one.

    bool acc_walk_ok = true;
    auto handle_account_body = [&](std::span<uint8_t> body) {
        if (!acc_walk_ok) return;
        auto* pa = reinterpret_cast<Account*>(body.data());
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
        // SOUNDNESS-CRITICAL: find_slot() binary-searches, so slot keys must ascend strictly (no duplicates), or a search could miss a slot and the block would read zero whatever check_root binds. Copied by words (8-aligned): a memcpy is a call per slot.
        typedef uint32_t __attribute__((may_alias)) w32;
        const std::span<Slot> slots = slots_for(*pa);
        for (size_t s = 0; s < slots.size(); ++s) {
            if (s > 0 && !key_below(slots[s - 1].key, slots[s].key)) [[unlikely]] {
                sys_println("sanitize: witness slot keys not in ascending order");
                acc_walk_ok = false;
                return;
            }
            const w32* const from = reinterpret_cast<const w32*>(slots[s].initial);
            w32* const to = reinterpret_cast<w32*>(slots[s].current);
            for (size_t i = 0; i < 8; ++i) to[i] = from[i];
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
        if (prev_hash != nullptr && std::memcmp(prev_hash, e.addr_hash, 32) >= 0) return false;
        const auto h = silkworm::keccak256(ByteView{e.addr, 20});
        if (!bytes_equal<32>(h.bytes, e.addr_hash)) return false;
        if (static_cast<uint64_t>(e.entry_offset) + 8u + sizeof(Account) > data_size) return false;
        auto* pa = account_at_offset(e.entry_offset);
        if (!pa || !eq_addr20(pa->addr, e.addr)) return false;
        pa->modified = false;
        prev_hash = e.addr_hash;
    }

    bool addr_hash_skipped = false;
    if (pre_state_meta_->n_accounts > 0) {
        pre_state_map_.for_each<20>(
            [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                auto* pa = reinterpret_cast<Account*>(body.data());
                addr_hash_skipped = pa->modified || addr_hash_skipped;
            });
    }
    if (addr_hash_skipped) return false;

#if ZILK_SEAL_CODE_STORE
    // Every payload is hashed and every account bound to its entry, so lengths and keys are not read again; zeroing pads each payload but the last for the EVM in place.
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

// SOUNDNESS-CRITICAL: hashes are walked back by parent hash from `header` through headers keyed by their own hash, so every hash returned is bound to `header`; the witness's block-hash section and header numbers are never read.
evmc::bytes32 DirectState::get_block_hash(const BlockHeader& header, BlockNum n) const noexcept {
    if (n >= header.number) [[unlikely]]
        return {};
    // Memoized per header: ancestors_ holds the hashes found, parent first, so a hash is looked up once a block.
    if (ancestors_.empty() || ancestors_number_ != header.number || ancestors_[0] != header.parent_hash) {
        ancestors_.clear();
        ancestors_.reserve(257);
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
