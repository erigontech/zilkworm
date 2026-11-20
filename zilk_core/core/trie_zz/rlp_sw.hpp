// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <memory>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>

#include "mpt.hpp"

namespace zilkworm {

namespace rlp = ::silkworm::rlp;
namespace endian = ::silkworm::endian;

// A node's encoding, valid until the next call; decode_node() rejects branch values and over-long leaf values.
inline constexpr size_t kNodeBufferSize = 2048;
// Longest leaf value decode_node() accepts; it only has to keep the leaf's encoding in the buffer.
inline constexpr size_t kMaxLeafValueSize = kNodeBufferSize - 64;
static_assert(3 + 34 + 3 + kMaxLeafValueSize <= kNodeBufferSize, "a leaf must fit the encode buffer");
static_assert(31 + 3 + 16 * 33 + 1 <= kNodeBufferSize,
              "a branch copied at its witness phase must fit the encode buffer");
#if defined(__cpp_threadsafe_static_init) && !defined(NO_THREAD_LOCAL) && !defined(SP1) && !defined(QEMU_DEBUG) && !defined(AIRBENDER)
alignas(32) inline thread_local uint8_t static_buffer[kNodeBufferSize];
#else
alignas(32) inline uint8_t static_buffer[kNodeBufferSize];
#endif

// Kept for tests that reset state between runs; the buffer holds nothing between calls.
inline void clear_static_buffer() {}

inline const Bytes empty{silkworm::rlp::kEmptyStringCode};

inline uint8_t* encode_list_header(uint8_t* out, size_t len) noexcept {
    if (len < 56) {
        *out++ = static_cast<uint8_t>(rlp::kEmptyListCode + len);
    } else {
        auto be = endian::to_big_compact(len);
        *out++ = static_cast<uint8_t>(0xF7 + be.size());
        std::memcpy(out, be.data(), be.size());
        out += be.size();
    }
    return out;
}

inline size_t hp_size(size_t nibbles) noexcept { return 1 + ((nibbles + 1) >> 1); }

inline uint8_t* encode_hp_path(uint8_t* out, const uint8_t* nib, size_t n, bool leaf) noexcept {
    const bool odd = (n & 1);
    const uint8_t flag = (leaf ? 0x2 : 0x0) | (odd ? 0x1 : 0x0);
    *out++ = static_cast<uint8_t>((flag << 4) | (odd ? (n ? (nib[0] & 0x0F) : 0) : 0));
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    // nib is a 4-aligned nibbles64 array; t = x << 4 | x >> 8 holds n0 n1 in byte 0, n1 n2 in byte 1, n2 n3 in byte 2.
    typedef uint32_t __attribute__((may_alias)) w32;
    const w32* w = reinterpret_cast<const w32*>(std::assume_aligned<4>(nib));
    size_t bytes = n / 2;
    if (!odd) {
        for (; bytes >= 2; bytes -= 2, out += 2) {
            const uint32_t x = *w++ & 0x0F0F0F0Fu;
            const uint32_t t = (x << 4) | (x >> 8);
            out[0] = static_cast<uint8_t>(t);
            out[1] = static_cast<uint8_t>(t >> 16);
        }
        if (bytes != 0) {
            const uint32_t x = *w & 0x0F0F0F0Fu;
            *out++ = static_cast<uint8_t>((x << 4) | (x >> 8));
        }
    } else {
        // Pairs start at nib[1]: n1 n2 is byte 1 of t, and n3 (t >> 24) pairs with the next word's n0.
        uint32_t x = *w++ & 0x0F0F0F0Fu;
        for (; bytes >= 2; bytes -= 2, out += 2) {
            const uint32_t y = *w++ & 0x0F0F0F0Fu;
            const uint32_t t = (x << 4) | (x >> 8);
            out[0] = static_cast<uint8_t>(t >> 8);
            out[1] = static_cast<uint8_t>((t >> 24) | y);
            x = y;
        }
        if (bytes != 0) *out++ = static_cast<uint8_t>(((x << 4) | (x >> 8)) >> 8);
    }
#else
    size_t i = odd ? 1 : 0;
    for (; i + 1 < n; i += 2) *out++ = static_cast<uint8_t>((nib[i] << 4) | (nib[i + 1] & 0x0F));
    if (i < n) *out++ = static_cast<uint8_t>((nib[i] << 4));
#endif
    return out;
}

inline uint8_t* encode_string_header(uint8_t* out, size_t len) noexcept {
    if (len < 56) {
        *out++ = static_cast<uint8_t>(rlp::kEmptyStringCode + len);
    } else if (len < 256) {
        *out++ = 0xB8;
        *out++ = static_cast<uint8_t>(len);
    } else {
        auto be = endian::to_big_compact(len);
        *out++ = static_cast<uint8_t>(0xB7 + be.size());
        std::memcpy(out, be.data(), be.size());
        out += be.size();
    }
    return out;
}

inline bool hp_decode(ByteView in, bool& is_leaf, std::array<uint8_t, 64>& out, uint8_t& out_len) noexcept {
    if (in.empty()) [[unlikely]] return false;
    uint8_t flag = in[0] >> 4;
    is_leaf = (flag & 0x2) != 0;
    const bool odd = (flag & 0x1) != 0;
    // At most 64 nibbles (odd + 2 * (in.size() - 1) <= 64), checked once rather than per byte.
    if (in.size() - 1 > (odd ? 31u : 32u)) [[unlikely]] return false;
    uint8_t* o = out.data();
    if (odd) *o++ = in[0] & 0x0F;
    const uint8_t* const end = in.data() + in.size();
#pragma GCC unroll 4
    for (const uint8_t* p = in.data() + 1; p != end; ++p, o += 2) {
        const uint8_t b = *p;
        o[0] = static_cast<uint8_t>(b >> 4);
        o[1] = static_cast<uint8_t>(b & 0x0F);
    }
    out_len = static_cast<uint8_t>(odd + 2 * (in.size() - 1));
    return true;
}

// Index of a nonzero mask's lowest set bit by De Bruijn multiply (rv32im has no ctz).
[[gnu::always_inline]] inline unsigned lowest_set_bit(uint32_t m) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    static constexpr uint8_t kIndex[32] = {0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
                                           31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9};
    return kIndex[((m & (0u - m)) * 0x077CB531u) >> 27];
#else
    return static_cast<unsigned>(std::countr_zero(m));
#endif
}

#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
// Copies 32 bytes from 8-aligned src to dst with dst & 3 == Off (1..3), little endian.
template <unsigned Off>
[[gnu::always_inline]] inline void copy32_at_phase(uint8_t* dst, const uint8_t* src) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    typedef uint16_t __attribute__((may_alias)) h16;
    // Each source word is loaded once, before the stores: a store may alias src.
    const w32* const s = reinterpret_cast<const w32*>(std::assume_aligned<8>(src));
    if constexpr (Off == 2) {
        h16* const d = reinterpret_cast<h16*>(dst);
        for (size_t k = 0; k < 8; ++k) {
            const uint32_t v = s[k];
            d[2 * k] = static_cast<uint16_t>(v);
            d[2 * k + 1] = static_cast<uint16_t>(v >> 16);
        }
    } else {
        constexpr unsigned kLead = 4 - Off;
        uint32_t cur = s[0];
        for (unsigned k = 0; k < kLead; ++k) dst[k] = static_cast<uint8_t>(cur >> (8 * k));
        w32* const d = reinterpret_cast<w32*>(dst + kLead);
        for (size_t k = 0; k < 7; ++k) {
            const uint32_t next = s[k + 1];
            d[k] = (cur >> (8 * kLead)) | (next << (8 * Off));
            cur = next;
        }
        for (unsigned k = 0; k < Off; ++k) dst[kLead + 28 + k] = static_cast<uint8_t>(cur >> (8 * (kLead + k)));
    }
}

// Copies 32 bytes from 8-aligned src to dst at any alignment, with word stores where dst allows.
[[gnu::always_inline]] inline void copy32_from_aligned8(uint8_t* dst, const uint8_t* src) noexcept {
    switch (reinterpret_cast<uintptr_t>(dst) & 3) {
        case 0: {
            typedef uint32_t __attribute__((may_alias)) w32;
            const w32* const s = reinterpret_cast<const w32*>(std::assume_aligned<8>(src));
            w32* const d = reinterpret_cast<w32*>(dst);
            for (size_t k = 0; k < 8; ++k) d[k] = s[k];
            break;
        }
        case 1:
            copy32_at_phase<1>(dst, src);
            break;
        case 2:
            copy32_at_phase<2>(dst, src);
            break;
        default:
            copy32_at_phase<3>(dst, src);
            break;
    }
}
#endif

[[gnu::always_inline]] inline void put_child_hash(uint8_t* dst, const BranchNode& b, size_t i) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    // child_ptr points into the witness at any alignment; a rewritten slot holds its hash in child[i] (8-aligned).
    if (b.child_ptr[i] == nullptr) [[likely]] {
        copy32_from_aligned8(dst, b.child[i].bytes);
        return;
    }
#endif
    std::memcpy(dst, b.child_ptr[i] ? b.child_ptr[i] : b.child[i].bytes, 32);
}

// Whether b's witness node is a full branch: 16 hash refs, empty value, slot i at 3 + 33 i (no leading-zero header).
[[gnu::always_inline]] inline bool has_full_branch_orig(const BranchNode& b) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    const w32* const lens = reinterpret_cast<const w32*>(std::assume_aligned<8>(b.orig_child_len.data()));
    return b.orig_size == kprefix::kNodeSize && b.orig[0] == 0xf9 &&
           ((lens[0] ^ 0x20202020u) | (lens[1] ^ 0x20202020u) | (lens[2] ^ 0x20202020u) |
            (lens[3] ^ 0x20202020u)) == 0;
}

// Whether encode_branch(b) is the 8-aligned witness node b.orig with only dirty hashes rewritten (never written).
[[gnu::always_inline]] inline bool hashes_from_witness(const BranchNode& b) noexcept {
    return b.mask != 0 && b.orig != nullptr && (reinterpret_cast<uintptr_t>(b.orig) & 7) == 0 &&
           b.same_layout_as_orig() && has_full_branch_orig(b);
}

[[gnu::always_inline]] inline ByteView encode_branch(const BranchNode& b) {
    if (b.mask == 0) {
        return empty;
    }
    // Same length class in every slot keeps the witness layout: copy it and rewrite only the dirty slots.
    if (b.orig != nullptr && b.same_layout_as_orig()) {
        uint8_t* const out = static_buffer + (reinterpret_cast<uintptr_t>(b.orig) & 31);
        std::memcpy(out, b.orig, b.orig_size);
        if (b.dirty == 0) {
            return ByteView{out, b.orig_size};
        }
        // A full branch has slot i at 3 + 33 i, so dirty slots are addressed directly.
        if (has_full_branch_orig(b)) {
            for (unsigned dirty = b.dirty; dirty != 0; dirty &= dirty - 1) {
                const unsigned i = lowest_set_bit(dirty);
                uint8_t* const p = out + 3 + 33 * i;
                *p = 0xa0;
                put_child_hash(p + 1, b, i);
            }
            return ByteView{out, b.orig_size};
        }
        {
            const uint8_t b0 = b.orig[0];
            uint8_t* p = out + (b0 < 0xf8 ? 1 : 1 + (b0 - 0xf7));
            // Walk only up to the last dirty slot, with the mask in a local (byte copies may alias b).
            unsigned dirty = b.dirty;
            for (size_t i = 0; dirty != 0; ++i, dirty >>= 1) {
                const auto len = b.orig_child_len[i];
                if (dirty & 1u) {
                    if (len == 0) {
                        *p = rlp::kEmptyStringCode;
                    } else if (len == 32) {
                        *p = 0xa0;
                        put_child_hash(p + 1, b, i);
                    } else {
                        std::memcpy(p, b.child[i].bytes, len);
                    }
                }
                p += len == 0 ? 1 : len == 32 ? 33 : len;
            }
        }
        return ByteView{out, b.orig_size};
    }
    size_t payload_length = 0;
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];

        payload_length += (child_len == 0 || child_len == 32)
                                ? 1 + child_len
                                : child_len;

    }

    payload_length += rlp::length(b.value);
    uint8_t* p = encode_list_header(static_buffer, payload_length);
    const uint8_t* const begin = static_buffer;

    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];
        if (child_len == 0) {
            *p++ = rlp::kEmptyStringCode;
        } else if (child_len == 32) {
            *p++ = 0xa0;
            const uint8_t* href = b.child_ptr[i] ? b.child_ptr[i] : b.child[i].bytes;
            std::memcpy(p, href, 32);
            p += 32;
        } else {
            std::memcpy(p, b.child[i].bytes, child_len);
            p += child_len;
        }
    }
    p += rlp::encode_into(p, b.value);
    return ByteView{begin, static_cast<size_t>(p - begin)};
}

// Leading keccak blocks of full branch b's encoding its saved state covers, or 0; nonzero consumes the state.
[[gnu::always_inline]] inline unsigned take_resumable_blocks(const BranchNode& b, size_t row) noexcept {
    if (kprefix::tag_orig[row] != b.orig) return 0;
    // tag_sb is 1..3 while tagged; masked so the index stays inside kHeadSlots whatever the row holds.
    const unsigned blocks = kprefix::tag_sb[row] & 3u;
    if ((b.dirty & kprefix::kHeadSlots[blocks]) != 0) return 0;  // every slot change sets its dirty bit
    kprefix::tag_orig[row] = nullptr;
    return blocks;
}

// Leading blocks of full branch b's encoding still the witness node's: those before the first dirty slot's hash bytes.
[[gnu::always_inline]] inline unsigned full_branch_clean_blocks(const BranchNode& b) noexcept {
    return b.dirty == 0 ? 3u : kprefix::first_blocks(lowest_set_bit(b.dirty));
}

// Leading whole blocks of encode_branch(b) that are b's witness node bytes: those before the first dirty slot's item.
[[gnu::always_inline]] inline unsigned same_layout_clean_blocks(const BranchNode& b) noexcept {
    size_t clean = b.orig_size;
    if (b.dirty != 0) {
        const unsigned first = lowest_set_bit(b.dirty);
        const unsigned b0 = b.orig[0];
        clean = b0 < 0xf8u ? 1u : 1u + (b0 - 0xf7u);
        for (unsigned i = 0; i < first; ++i) {
            const unsigned len = b.orig_child_len[i];
            clean += len == 0 ? 1u : len == 32 ? 33u : len;
        }
    }
    return static_cast<unsigned>(clean / kprefix::kBlock);
}

// A payload below 256 bytes takes the one-byte long form; a longer one goes through encode_list_header.
inline uint8_t* encode_short_node_list_header(uint8_t* out, size_t payload) noexcept {
    if (payload < 56) {
        *out++ = static_cast<uint8_t>(rlp::kEmptyListCode + payload);
    } else if (payload < 256) {
        *out++ = 0xF8;
        *out++ = static_cast<uint8_t>(payload);
    } else {
        out = encode_list_header(out, payload);
    }
    return out;
}

// The HP flag byte is below 0x80: a one-byte path is its own RLP; a longer one has a one-byte string header.
inline uint8_t* encode_hp_path_rlp(uint8_t* out, const nibbles64& path, bool leaf) noexcept {
    const size_t hp_len = 1 + path.len / 2;
    if (hp_len != 1) *out++ = static_cast<uint8_t>(rlp::kEmptyStringCode + hp_len);
    return encode_hp_path(out, path.nib.data(), path.len, leaf);
}

inline size_t hp_path_rlp_length(const nibbles64& path) noexcept {
    const size_t hp_len = 1 + path.len / 2;
    return hp_len + (hp_len != 1 ? 1 : 0);
}

inline ByteView encode_ext(const ExtensionNode& e) {
    if (e.child_len == 0) {
        return empty;
    }

    const size_t child_rlp_len = (e.child_len == 32) ? 33 : e.child_len;
    const size_t payload = hp_path_rlp_length(e.path) + child_rlp_len;

    uint8_t* out = encode_short_node_list_header(static_buffer, payload);
    out = encode_hp_path_rlp(out, e.path, /*leaf*/ false);

    if (e.child_len == 32) {
        *out++ = 0xa0;
        std::memcpy(out, e.child.bytes, 32);
        out += 32;
    } else {
        std::memcpy(out, e.child.bytes, e.child_len);
        out += e.child_len;
    }

    return ByteView{static_buffer, static_cast<size_t>(out - static_buffer)};
}

inline ByteView encode_leaf(const LeafNode& l) {
    // Value RLP length: a single byte below 0x80 is its own encoding.
    const size_t vlen = l.value.size();
    const bool val_single = vlen == 1 && l.value[0] < rlp::kEmptyStringCode;
    const size_t val_rlp_len = val_single ? 1
                               : vlen < 56 ? 1 + vlen
                               : vlen < 256 ? 2 + vlen
                                            : 1 + intx::count_significant_bytes(vlen) + vlen;
    const size_t payload = hp_path_rlp_length(l.path) + val_rlp_len;

    uint8_t* out = encode_short_node_list_header(static_buffer, payload);
    out = encode_hp_path_rlp(out, l.path, /*leaf*/ true);

    if (val_single) {
        *out++ = l.value[0];
    } else {
        out = encode_string_header(out, vlen);
        // An empty value has a null data pointer, which memcpy must not be given even for zero bytes.
        if (vlen != 0) std::memcpy(out, l.value.data(), vlen);
        out += vlen;
    }

    return ByteView{static_buffer, static_cast<size_t>(out - static_buffer)};
}

// Stores one decoded child into branch slot i (empty, embedded or 0xa0 hash); start_byte is its RLP start byte.
[[gnu::always_inline]] inline bool fill_branch_child(BranchNode& out, size_t i,
                                                     uint8_t start_byte,
                                                     const uint8_t* data, size_t len) {
    if (len == 0) {
        out.child_len[i] = 0;
        out.child_ptr[i] = nullptr;
        return true;
    }
    if (start_byte != 0xa0) {
        if (len > 31) return false;  // embedded child must fit child[i].bytes (with header byte)
        out.child_len[i] = static_cast<uint8_t>(len + 1);
        out.child[i].bytes[0] = start_byte;
        out.child_ptr[i] = nullptr;
        std::copy_n(data, len, &out.child[i].bytes[1]);
    } else {
        out.child_len[i] = 32;
        out.child_ptr[i] = data;
    }
    out.mask |= (1 << i);
    return true;
}

// A branch child is only 0x80, 0xa0 + 32 bytes (hash ref) or a short embedded list (0xc0..0xf7); skips decode_header.
[[gnu::always_inline]] inline bool fill_branch_child_rlp(BranchNode& out, size_t i, ByteView& remaining) {
    if (remaining.empty()) return false;
    const uint8_t b0 = remaining[0];
    if (b0 == rlp::kEmptyStringCode) {
        out.child_len[i] = 0;
        out.child_ptr[i] = nullptr;
        remaining.remove_prefix(1);
        return true;
    }
    if (b0 == 0xa0) {
        if (remaining.size() < 33) return false;
        out.child_ptr[i] = remaining.data() + 1;
        out.child_len[i] = 32;
        out.mask |= (1u << i);
        remaining.remove_prefix(33);
        return true;
    }
    if (b0 >= 0xc0 && b0 <= 0xf7) {
        const size_t payload = static_cast<size_t>(b0 - 0xc0);
        if (payload > 31) return false;  // must fit child[i].bytes (header + payload)
        if (remaining.size() < 1 + payload) return false;
        out.child[i].bytes[0] = b0;
        std::copy_n(remaining.data() + 1, payload, &out.child[i].bytes[1]);
        out.child_len[i] = static_cast<uint8_t>(payload + 1);
        out.child_ptr[i] = nullptr;
        out.mask |= (1u << i);
        remaining.remove_prefix(1 + payload);
        return true;
    }
    return false;
}

inline bool decode_branch(ByteView payload, BranchNode& out) {
    out.mask = 0;

    ByteView remaining = payload;

    for (size_t i = 0; i < 16; ++i) {
        if (!fill_branch_child_rlp(out, i, remaining)) return false;
    }

    if (remaining.size() == 1 && remaining[0] == rlp::kEmptyStringCode) {
        out.value = {};
        return true;
    }
    auto hdr_value = rlp::decode_header(remaining);
    if (!hdr_value || hdr_value->list) return false;
    out.value = remaining.substr(0, hdr_value->payload_length);
    remaining.remove_prefix(hdr_value->payload_length);
    return remaining.empty();
}

inline bool decode_ext_or_leaf(ByteView payload, bool& is_leaf,
                               std::array<uint8_t, 64>& path, uint8_t& plen,
                               ByteView& second) {
    ByteView remaining = payload;

    auto h1 = rlp::decode_header(remaining);
    if (!h1 || h1->list) [[unlikely]] return false;
    ByteView hp_path = remaining.substr(0, h1->payload_length);
    remaining.remove_prefix(h1->payload_length);

    if (!hp_decode(hp_path, is_leaf, path, plen)) [[unlikely]] {
        return false;
    }

    const uint8_t* second_start = remaining.data();
    auto h2 = rlp::decode_header(remaining);
    if (!h2 || h2->list) [[unlikely]] return false;

    if (!is_leaf) {
        // Extension: a hash reference returns the 32-byte hash alone; an embedded node returns its full RLP.
        if (h2->payload_length == 32) {
            second = remaining.substr(0, 32);
        } else {
            size_t header_len = static_cast<size_t>(remaining.data() - second_start);
            size_t total_len = header_len + h2->payload_length;
            second = ByteView{second_start, total_len};
        }
    } else {
        second = remaining.substr(0, h2->payload_length);
    }

    remaining.remove_prefix(h2->payload_length);

    return remaining.empty();
}

inline Kind decode_node(ByteView payload, BranchNode& out_branch,
                            bool& is_leaf, std::array<uint8_t, 64>& path,
                            uint8_t& plen, ByteView& second) {
    // Fast path for a full branch (16 hash children, empty value): the layout fixes every pointer, length and the mask.
    if (payload.size() == 16 * 33 + 1 && payload[16 * 33] == rlp::kEmptyStringCode) {
        const uint8_t* const p = payload.data();
        bool hashes = true;
#pragma GCC unroll 16
        for (size_t i = 0; i < 16; ++i) {
            if (p[33 * i] != 0xa0) {
                hashes = false;
                break;
            }
        }
        if (hashes) [[likely]] {
#pragma GCC unroll 16
            for (size_t i = 0; i < 16; ++i) out_branch.child_ptr[i] = p + 33 * i + 1;
            // 4 word stores (child_len is alignas(8)); a memcpy here compiled to a call.
            typedef uint32_t __attribute__((may_alias)) w32;
            w32* const cl = reinterpret_cast<w32*>(std::assume_aligned<8>(out_branch.child_len.data()));
            cl[0] = cl[1] = cl[2] = cl[3] = 0x20202020u;
            out_branch.mask = 0xffff;
            out_branch.value = {};
            return kBranch;
        }
    }

    ByteView remaining = payload;

    const uint8_t e0_start = remaining.empty() ? 0 : *remaining.data();
    auto h0 = rlp::decode_header(remaining);
    if (!h0) return kInvalid;
    const ByteView e0_payload = remaining.substr(0, h0->payload_length);
    const bool e0_list = h0->list;
    remaining.remove_prefix(h0->payload_length);

    const uint8_t e1_start = remaining.empty() ? 0 : *remaining.data();
    const uint8_t* e1_start_ptr = remaining.data();
    auto h1 = rlp::decode_header(remaining);
    if (!h1) return kInvalid;
    const ByteView e1_payload = remaining.substr(0, h1->payload_length);
    const bool e1_list = h1->list;
    remaining.remove_prefix(h1->payload_length);

    if (remaining.empty()) {
        if (e0_list) [[unlikely]] return kInvalid;
        if (!hp_decode(e0_payload, is_leaf, path, plen)) [[unlikely]] return kInvalid;
        if (e1_list) [[unlikely]] return kInvalid;

        if (!is_leaf) {
            if (h1->payload_length == 32) {
                second = e1_payload;
            } else {
                size_t header_len = static_cast<size_t>(e1_payload.data() - e1_start_ptr);
                second = ByteView{e1_start_ptr, header_len + h1->payload_length};
            }
        } else {
            // No trie has a leaf without a value: its grid line would be empty and its fold would delete ancestors too.
            if (h1->payload_length == 0 || h1->payload_length > kMaxLeafValueSize) [[unlikely]] return kInvalid;
            second = e1_payload;
        }
        return kExtOrLeaf;
    }

    out_branch.mask = 0;
    if (!fill_branch_child(out_branch, 0, e0_start, e0_payload.data(), h0->payload_length)) return kInvalid;
    if (!fill_branch_child(out_branch, 1, e1_start, e1_payload.data(), h1->payload_length)) return kInvalid;

    {
        const uint8_t* p = remaining.data();
        const uint8_t* const end = p + remaining.size();
        unsigned mask = out_branch.mask;
        for (size_t i = 2; i < 16; ++i) {
            if (p == end) return kInvalid;
            const uint8_t b0 = *p;
            if (b0 == 0xa0) {
                if (end - p < 33) return kInvalid;
                out_branch.child_ptr[i] = p + 1;
                out_branch.child_len[i] = 32;
                mask |= 1u << i;
                p += 33;
            } else if (b0 == rlp::kEmptyStringCode) {
                out_branch.child_len[i] = 0;
                out_branch.child_ptr[i] = nullptr;
                ++p;
            } else if (b0 >= 0xc0 && b0 <= 0xf7) {
                const size_t plen_ = static_cast<size_t>(b0 - 0xc0);
                if (plen_ > 31) return kInvalid;
                if (static_cast<size_t>(end - p) < 1 + plen_) return kInvalid;
                out_branch.child[i].bytes[0] = b0;
                std::copy_n(p + 1, plen_, &out_branch.child[i].bytes[1]);
                out_branch.child_len[i] = static_cast<uint8_t>(plen_ + 1);
                out_branch.child_ptr[i] = nullptr;
                mask |= 1u << i;
                p += 1 + plen_;
            } else {
                return kInvalid;
            }
        }
        out_branch.mask = static_cast<uint16_t>(mask);
        remaining = ByteView{p, static_cast<size_t>(end - p)};
    }

    // The 17th value must be empty: keys are fixed-length, and a value would not fit the static_buffer budget.
    if (remaining.size() == 1 && remaining[0] == rlp::kEmptyStringCode) {
        out_branch.value = {};
        return kBranch;
    }
    return kInvalid;
}

inline bool is_empty(const GridLine& line) {
    switch (line.kind) {
        case kBranch:
            return line.branch.mask == 0;
        case kExt:
            return line.ext.child_len == 0;
        case kLeaf:
            return line.leaf.value.empty();
        default:
            std::unreachable();
    }
}

inline ByteView encode_line(const GridLine& line) {
    switch (line.kind) {
        case kBranch:
            return encode_branch(line.branch);
        case kExt:
            return encode_ext(line.ext);
        case kLeaf:
            if (line.parent_depth == 0xFF) {
                return empty;
            }
            return encode_leaf(line.leaf);
        default:
            std::unreachable();
    }
}

}  // namespace zilkworm