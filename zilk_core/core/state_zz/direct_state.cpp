// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "direct_state.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>

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

namespace zilkworm {

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
        if ((reinterpret_cast<uintptr_t>(blob.data()) % alignof(PreStateMeta)) != 0) [[unlikely]] {
            sys_println("DirectState: blob start misaligned for PreStateMeta");
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

        if (meta->n_accounts > 0) {
            if (!bound_bytes(meta->prestate_offset, sizeof(MphfMapHeader),
                             "DirectState: prestate MphfMapHeader header out of range")) [[unlikely]]
                return false;
            if ((meta->prestate_offset % alignof(MphfMapHeader)) != 0) [[unlikely]] {
                sys_println("DirectState: prestate_offset misaligned");
                return false;
            }
            const auto* m = reinterpret_cast<const MphfMapHeader*>(blob.data() + meta->prestate_offset);
            if (m->magic != kMphfAddrMapMagic) [[unlikely]] {
                sys_println("DirectState: prestate MphfMapHeader bad magic");
                return false;
            }
            if (m->version != kMphfMapVersion) [[unlikely]] {
                sys_println("DirectState: prestate MphfMapHeader bad version");
                return false;
            }
            if (m->n_keys == 0) [[unlikely]] {
                sys_println("DirectState: prestate MphfMapHeader has zero keys but n_accounts > 0");
                return false;
            }
            if (m->n_buckets == 0) [[unlikely]] {
                sys_println("DirectState: prestate MphfMapHeader n_buckets == 0");
                return false;
            }
            // displacement_factors[n_buckets] sits at displacement_offset.
            if (!bound_bytes(static_cast<uint64_t>(meta->prestate_offset) + m->displacement_offset,
                             static_cast<uint64_t>(m->n_buckets) * 8u,
                             "DirectState: prestate MphfMapHeader displacement table out of range")) [[unlikely]]
                return false;
        }

        if (!bound_typed(meta->addr_hashes_offset, meta->n_accounts, sizeof(AddrHashEntry),
                         alignof(AddrHashEntry),
                         "DirectState: addr_hashes section out of range")) [[unlikely]]
            return false;
        if (!bound_typed(meta->block_hashes_offset, meta->n_block_hashes, sizeof(BlockHashEntry),
                         alignof(BlockHashEntry),
                         "DirectState: block_hashes section out of range")) [[unlikely]]
            return false;
        if (!bound_bytes(meta->code_store_offset, meta->code_store_size,
                         "DirectState: code_store section out of range")) [[unlikely]]
            return false;
        if (meta->code_store_size > 0 &&
            (meta->code_store_offset % alignof(MphfMapHeader)) != 0) [[unlikely]] {
            sys_println("DirectState: code_store_offset misaligned for MphfMapHeader");
            return false;
        }

        if (meta->n_accounts > 0) {
            const uint32_t addr_mphf_size =
                meta->addr_hashes_offset > meta->prestate_offset
                    ? meta->addr_hashes_offset - meta->prestate_offset
                    : 0u;
            if (!validate_mphf<20>(blob, meta->prestate_offset, addr_mphf_size,
                                   kMphfAddrMapMagic)) [[unlikely]] {
                return false;
            }
        }
        if (meta->code_store_size > 0) {
            if (!validate_mphf<32>(blob, meta->code_store_offset, meta->code_store_size,
                                   kMphfCodeStoreMagic)) [[unlikely]] {
                return false;
            }
        }

        if (meta->n_accounts > 0) {
            const auto* mhdr = reinterpret_cast<const MphfMapHeader*>(
                blob.data() + meta->prestate_offset);
            const uint8_t* mbase = reinterpret_cast<const uint8_t*>(mhdr);
            const uint32_t data_size = mhdr->data_size;
            const auto* slot_offsets = reinterpret_cast<const uint32_t*>(
                mbase + mhdr->slot_offsets_offset);
            auto check_entry = [&](uint32_t off) -> bool {
                if ((off % alignof(Account)) != 0) [[unlikely]] {
                    sys_println("DirectState: addr-map entry misaligned for Account");
                    return false;
                }
                if (static_cast<uint64_t>(off) + 8u + sizeof(Account) > data_size) [[unlikely]] {
                    sys_println("DirectState: addr-map entry header OOB");
                    return false;
                }
                const auto* acc = reinterpret_cast<const Account*>(mbase + mhdr->data_offset + off + 8u);
                const uint64_t slots_end = static_cast<uint64_t>(off) + 8u + sizeof(Account) +
                                           static_cast<uint64_t>(acc->slot_count) * sizeof(Slot);
                if (slots_end > data_size) [[unlikely]] {
                    sys_println("DirectState: addr-map entry slots OOB");
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

}  // namespace

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

// validate_or_abort runs validate_prestate_layout before any field is read.
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
        node_store_map_.reset(reinterpret_cast<MphfMapHeader*>(nodestore_bytes.data()));
    }
    reserve_block_maps_();
}

void DirectState::reserve_block_maps_() noexcept {
    created_accounts_.reserve(256);
    overflow_slots_.reserve(128);
    created_code_.reserve(64);
    created_code_collisions_.reserve(0);
    touched_.reserve(512);
    headers_.reserve(256);
    created_block_hashes_.reserve(256);
    delegated_designations_.reserve(32);
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
    node_store_map_ = other.node_store_map_;

    created_accounts_ = std::move(other.created_accounts_);
    overflow_slots_ = std::move(other.overflow_slots_);
    created_code_ = std::move(other.created_code_);
    created_code_collisions_ = std::move(other.created_code_collisions_);
    delegated_designations_ = std::move(other.delegated_designations_);
    headers_ = std::move(other.headers_);
    created_block_hashes_ = std::move(other.created_block_hashes_);
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

evmc::bytes32 DirectState::read_storage(const evmc::address& addr,
                                        const evmc::bytes32& key) const noexcept {
    if (const auto* pa = find_pre_account_unchecked(addr); pa != nullptr && pa->slot_count > 0) {
        if (pa->deleted) [[unlikely]]
            return {};
        const auto storage_slots = slots_for(*pa);
        auto it = std::lower_bound(storage_slots.cbegin(), storage_slots.cend(), key,
                                   [](const Slot& s, const evmc::bytes32& k) {
                                       return std::memcmp(s.key, k.bytes, 32) < 0;
                                   });
        if (it != storage_slots.cend() && eq_hash32(it->key, key.bytes)) {
            return std::bit_cast<evmc::bytes32>(it->current);
        }
    }

    if (auto it = overflow_slots_.find(addr); it != overflow_slots_.end()) {
        if (auto kv = it->second.find(key); kv != it->second.end()) {
            return kv->second;
        }
    }
    return {};
}

Account* DirectState::find_or_create_pre_account_slow(const evmc::address& addr) {
    Account fresh{};
    std::memcpy(fresh.addr, addr.bytes, 20);
    copy32(fresh.code_hash, kEmptyHash);
    copy32(fresh.storage_root, kEmptyRoot);
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
    pa.slot_count = 0;
    pa.code_store_len = 0;
    pa.nonce = 0;
    store_be_u256(pa.balance, intx::uint256{0});
    overflow_slots_.erase(addr);
    // created_code_ is hash-keyed and possibly shared across addresses.
    pa.modified = true;
    pa.acc_rlp_sroot_off = 0;
    return true;
}

void DirectState::set_storage_slot(const evmc::address& addr, Account& pa,
                                   const evmc::bytes32& key, const evmc::bytes32& value) {
    pa.modified = true;
    if (pa.slot_count > 0) {
        const auto cap_slots = slots_for(pa);
        const auto begin = cap_slots.begin();
        const auto end = begin + static_cast<std::ptrdiff_t>(pa.slot_count);
        auto it = std::lower_bound(begin, end, key,
                                   [](const Slot& s, const evmc::bytes32& k) {
                                       return std::memcmp(s.key, k.bytes, 32) < 0;
                                   });
        if (it != end && eq_hash32(it->key, key.bytes)) {
            copy32(it->current, value);
            return;
        }
        // Builder enforces slot_capacity == slot_count, so no in-place insert.
    }

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
                                  const evmc::bytes& code) {
    const ByteView code_view{code.data(), code.size()};
    const bool is_delegated = eip7702::is_code_delegated(code_view);

    // Mirrors processor.cpp:377-385 — wipe storage on contract creation
    // unless the new code is a delegation or the address was already a
    // delegation target.
    if (!is_delegated && !delegated_designations_.contains(addr)) {
        pa.slot_count = 0;
        overflow_slots_.erase(addr);
    }
    if (is_delegated) {
        delegated_designations_.insert(addr);
    }

    const auto h_eth = silkworm::keccak256(code_view);
    const auto h = std::bit_cast<evmc::bytes32>(h_eth);
    std::memcpy(pa.code_hash, h.bytes, 32);
    pa.code_store_len = static_cast<uint32_t>(code.size());

    // Dedup against the witness code_store; otherwise insert into created_code_
    // keyed by key8(hash). key8 collisions spill into created_code_collisions_.
    if (auto b = code_store_map_.find<32, 0, &hash_key8>(h.bytes)) {
        pa.code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
    } else {
        pa.code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
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
    const auto* pa = read_account_unchecked(addr);
    if (pa == nullptr || pa->deleted) return 0;
    return load_be_u256(pa->balance);
}

uint64_t DirectState::get_nonce(const evmc::address& addr) const noexcept {
    const auto* pa = read_account_unchecked(addr);
    if (pa == nullptr || pa->deleted) return 0;
    return pa->nonce;
}

void DirectState::set_balance(const evmc::address& addr, const intx::uint256& value) {
    auto* pa = find_or_create_pre_account(addr);
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
    auto* pa = find_or_create_pre_account(addr);
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
    auto* pa = find_or_create_pre_account(addr);
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
    auto* pa = find_or_create_pre_account(addr);
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

void DirectState::set_code(const evmc::address& addr, ByteView code) {
    auto* pa = find_or_create_pre_account(addr);
    revive_if_deleted(addr, *pa);

    if (eip7702::is_code_delegated(code)) {
        delegated_designations_.insert(addr);
    }
    const auto h_eth = silkworm::keccak256(code);
    const auto h = std::bit_cast<evmc::bytes32>(h_eth);
    bool changed = false;
    if (std::memcmp(pa->code_hash, h.bytes, 32) != 0) {
        std::memcpy(pa->code_hash, h.bytes, 32);
        changed = true;
    }
    pa->code_store_len = static_cast<uint32_t>(code.size());

    if (auto b = code_store_map_.find<32, 0, &hash_key8>(h.bytes)) {
        pa->code_store_offset = static_cast<uint32_t>(b->data() - code_store_map_.data());
    } else {
        pa->code_store_offset = kCreatedCodeOffset;
        const uint64_t k8 = hash_key8(h);
        if (auto [it, inserted] = created_code_.try_emplace(k8); inserted) {
            it->second.full_hash = h;
            it->second.bytes.assign(code.begin(), code.end());
        } else if (std::memcmp(it->second.full_hash.bytes, h.bytes, 32) == 0) {
            // Exact dedup hit (same hash, possibly different addr). Skip insert.
        } else {
            if (auto [cit, cins] = created_code_collisions_.try_emplace(h);
                cins) {
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

void DirectState::destruct(const evmc::address& addr) {
    // Flag every record (blob AND overlay twin); none existing means nothing to mask.
    if (auto* pa = find_pre_account_unchecked(addr)) pa->deleted = true;
    if (auto it = created_accounts_.find(addr); it != created_accounts_.end())
        it->second.deleted = true;
    overflow_slots_.erase(addr);
    // created_code_ is hash-keyed and shared across addresses; do not erase here.
    touched_.insert(addr);
    journal_address_changed(addr);
}

bool DirectState::is_deleted(const evmc::address& addr) const noexcept {
    const auto* pa = read_account_unchecked(addr);
    return pa == nullptr || pa->deleted;
}

bool DirectState::is_empty_account(const evmc::address& addr) const noexcept {
    const auto* pa = read_account_unchecked(addr);
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

    if (const auto* pa = find_pre_account(addr); pa != nullptr && pa->slot_count > 0) {
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
            if (body.size() < sizeof(Account)) [[unlikely]]
                return;
            const auto* pa = reinterpret_cast<const Account*>(body.data());
            evmc::address addr;
            std::memcpy(addr.bytes, pa->addr, 20);
            emit(addr, *pa);
        };
        if (!pre_state_map_.for_each<20>(
                               [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                                   handle(std::span<const uint8_t>{body.data(), body.size()});
                               }))
            return std::nullopt;
    }
    for (const auto& [addr, pa] : created_accounts_) {
        emit(addr, pa);
    }

    if (account_rlp.empty()) return kEmptyRoot;

    trie::HashBuilder hb;
    for (const auto& [hash, rlp_bytes] : account_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash.bytes), rlp_bytes);
    }
    return hb.root_hash();
}

void DirectState::apply_state_diff(const evmone::state::StateDiff& diff) {
    for (const auto& m : diff.modified_accounts) {
        auto* pa = find_or_create_pre_account(m.addr);
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

std::optional<BlockHeader> DirectState::read_header(BlockNum,
                                                    const evmc::bytes32& block_hash) const noexcept {
    const auto it = headers_.find(block_hash);
    if (it == headers_.end()) return std::nullopt;
    return it->second;
}

void DirectState::insert_header(const BlockHeader& header) {
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

bool DirectState::read_body(BlockNum, const evmc::bytes32&, BlockBody&) const noexcept {
    return false;
}

std::optional<intx::uint256> DirectState::total_difficulty(uint64_t, const evmc::bytes32&) const noexcept {
    return std::nullopt;
}

bool DirectState::sanitize() {
    // SOUNDNESS-CRITICAL: binds each leaf's identity to its trie-key hash.
    bool code_keccak_ok = true;
    if (!code_store_map_.for_each([&](const uint8_t* hash_ptr, std::span<uint8_t> body) {
            code_keccak_ok &= std::memcmp(silkworm::keccak256(FlatKv::payload(ByteView{body.data(), body.size()})).bytes, hash_ptr, 32) == 0;
        }))
        return false;
    if (!code_keccak_ok) {
        sys_println("sanitize: code-hash mismatch in witness bundle ");
        return false;
    }

    bool nodes_keccak_ok = true;
    if (!node_store_map_.for_each([&](const uint8_t* hash_ptr, std::span<uint8_t> body) {
            nodes_keccak_ok &= std::memcmp(silkworm::keccak256(FlatKv::payload(ByteView{body.data(), body.size()})).bytes, hash_ptr, 32) == 0;
        }))
        return false;
    if (!nodes_keccak_ok) {
        sys_println("sanitize: node-hash mismatch in witness bundle ");
        return false;
    }

    bool acc_walk_ok = true;
    auto handle_account_body = [&](std::span<uint8_t> body) {
        if (!acc_walk_ok) return;
        if (body.size() < sizeof(Account)) [[unlikely]] {
            acc_walk_ok = false;
            return;
        }
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
        pa->rlp_into_cache(std::bit_cast<evmc::bytes32>(pa->storage_root));
    };
    if (pre_state_meta_->n_accounts > 0) {
        if (!pre_state_map_.for_each<20>(
                               [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                                   handle_account_body(body);
                               }))
            return false;
    }
    if (!acc_walk_ok) return false;

    const uint32_t data_size = pre_state_map_.valid() ? pre_state_map_.header()->data_size : 0u;
    const uint8_t* prev_hash = nullptr;
    for (const auto& e : addr_hashes_) {
        if (prev_hash != nullptr && std::memcmp(prev_hash, e.addr_hash, 32) >= 0) return false;
        const auto h = silkworm::keccak256(ByteView{e.addr, 20});
        if (std::memcmp(h.bytes, e.addr_hash, 32) != 0) return false;
        if (static_cast<uint64_t>(e.entry_offset) + 8u + sizeof(Account) > data_size) return false;
        auto* pa = account_at_offset(e.entry_offset);
        if (!pa || !eq_addr20(pa->addr, e.addr)) return false;
        pa->modified = false;  // This account's hash now checked
        prev_hash = e.addr_hash;
    }

    bool addr_hash_skipped = false;
    if (pre_state_meta_->n_accounts > 0) {
        if (!pre_state_map_.for_each<20>(
                               [&](const uint8_t* /*key_ptr*/, std::span<uint8_t> body) {
                                   auto* pa = reinterpret_cast<Account*>(body.data());
                                    addr_hash_skipped = pa->modified || addr_hash_skipped;   // Should be all false
                               })) return false;
    }
    if (addr_hash_skipped) return false;

    return true;
}

evmc::bytes32 DirectState::get_block_hash(BlockNum n) const noexcept {
    const auto bh = block_hashes();
    if (!bh.empty()) {
        const auto it = std::lower_bound(bh.begin(), bh.end(), n,
                                         [](const BlockHashEntry& e, BlockNum k) {
                                             return e.block_number < k;
                                         });
        if (it != bh.end() && it->block_number == n) {
            return std::bit_cast<evmc::bytes32>(it->block_hash);
        }
    }
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
    return {};
}

}  // namespace zilkworm
