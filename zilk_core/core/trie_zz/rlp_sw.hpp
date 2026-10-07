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

// rlp/endian helpers live in silkworm; aliases for local readability.
namespace rlp = ::silkworm::rlp;
namespace endian = ::silkworm::endian;

// The encoding of one node, returned as a view by encode_line() and its encode_*() and valid
// until the next call. A fixed 32-byte aligned array rather than a Bytes: the copy-and-patch
// encode of a branch can then put its copy at the witness node's offset modulo 32 (the guest's
// memcpy copies same-phase operands in 32-byte CSR chunks), and the keccak of the result stays on
// its aligned path as witness node bodies are 8-aligned. A branch is at most 3 + 16 * 33 + 1 bytes
// (its value is empty in the fixed-key state and storage tries), a leaf holds at most an account.
// Witness nodes are untrusted, so decode_node() enforces both: a branch with a value and a leaf
// value over kMaxLeafValueSize are invalid, which bounds every node any encoder can produce.
inline constexpr size_t kNodeBufferSize = 2048;
/// The longest leaf value decode_node() accepts. An account is at most 110 bytes; this limit
/// only has to keep a leaf's encoding (list header, path, value header and value) in the buffer.
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

// Writes an RLP list header for a payload of `len` bytes at `out`, returns the position after it.
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
    // nib is a nibbles64 array (4-aligned, 64 bytes). With x a word of it masked to low nibbles,
    // t = x << 4 | x >> 8 holds n0 n1 in byte 0, n1 n2 in byte 1 and n2 n3 in byte 2.
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
    if (i < n) *out++ = static_cast<uint8_t>((nib[i] << 4));  // last high nibble only
#endif
    return out;
}

// Writes an RLP string header for a payload of `len` bytes at `out`, returns the position after it.
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

// HP decode -> (is_leaf, nibbles[]). Returns false on malformed.
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
        const uint8_t b = *p;  // read once: out may alias in as far as the compiler knows
        o[0] = static_cast<uint8_t>(b >> 4);
        o[1] = static_cast<uint8_t>(b & 0x0F);
    }
    out_len = static_cast<uint8_t>(odd + 2 * (in.size() - 1));
    return true;
}

// The index of a nonzero mask's lowest set bit. rv32im has no count-trailing-zeros instruction and
// std::countr_zero is a __ctzsi2 call there: isolate the bit and look its index up by a De Bruijn
// multiply instead.
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
// Copies the 32 bytes at the 8-aligned src to dst, where dst & 3 == Off (1..3), little endian. A dst
// at 2 mod 4 takes each source word as two halfwords. An odd dst takes the bytes before its first
// word boundary, then seven words each shifted together from two source words, then the last Off
// bytes.
template <unsigned Off>
[[gnu::always_inline]] inline void copy32_at_phase(uint8_t* dst, const uint8_t* src) noexcept {
    typedef uint32_t __attribute__((may_alias)) w32;
    typedef uint16_t __attribute__((may_alias)) h16;
    // Each source word is loaded once, ahead of the stores that use it: for all the compiler knows
    // a store may alias src, and it loaded the word again after one.
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

// Copies the 32 bytes at the 8-aligned src to dst at any alignment, with a word store wherever dst
// allows one: the guest's memcpy takes ~60 cycles when dst is not word-aligned.
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

// Writes branch slot i's 32-byte hash reference to dst.
[[gnu::always_inline]] inline void put_child_hash(uint8_t* dst, const BranchNode& b, size_t i) noexcept {
#if defined(AIRBENDER) && defined(__riscv) && __riscv_xlen == 32
    // child_ptr points into the witness at any alignment; a slot rewritten since holds its hash in
    // child[i], which is 8-aligned.
    if (b.child_ptr[i] == nullptr) [[likely]] {
        copy32_from_aligned8(dst, b.child[i].bytes);
        return;
    }
#endif
    std::memcpy(dst, b.child_ptr[i] ? b.child_ptr[i] : b.child[i].bytes, 32);
}

// Always inlined (the guest calls it from encode_line() only): grown by the inline hash copies
// above, it was otherwise compiled out of line and reached by a call.
[[gnu::always_inline]] inline ByteView encode_branch(const BranchNode& b) {
    if (b.mask == 0) {
        return empty;
    }
    // Same length class in every slot means the witness encoding's layout is unchanged:
    // copy it into the scratch buffer and rewrite only the dirty slots there. Clean slots
    // still read (hash) or were copied (embedded) from that encoding, so this matches
    // the full re-encode byte for byte. The original witness bytes are never written.
    if (b.orig != nullptr && b.same_layout_as_orig()) {
        // At the witness node's phase modulo 32, see static_buffer.
        uint8_t* const out = static_buffer + (reinterpret_cast<uintptr_t>(b.orig) & 31);
        std::memcpy(out, b.orig, b.orig_size);
        if (b.dirty == 0) {
            return ByteView{out, b.orig_size};
        }
        // A full branch (16 hash children, empty value: 3 + 16 * 33 + 1 bytes, most branches on
        // mainnet) has slot i at 3 + 33 i, so its dirty slots are addressed directly. The general
        // walk below sums the slot sizes up to the last dirty one.
        {
            typedef uint32_t __attribute__((may_alias)) w32;
            const auto* lens = reinterpret_cast<const w32*>(std::assume_aligned<8>(b.orig_child_len.data()));
            if (b.orig_size == 3 + 16 * 33 + 1 &&
                ((lens[0] ^ 0x20202020u) | (lens[1] ^ 0x20202020u) | (lens[2] ^ 0x20202020u) |
                 (lens[3] ^ 0x20202020u)) == 0) {
                for (unsigned dirty = b.dirty; dirty != 0; dirty &= dirty - 1) {
                    const unsigned i = lowest_set_bit(dirty);
                    uint8_t* const p = out + 3 + 33 * i;
                    *p = 0xa0;
                    put_child_hash(p + 1, b, i);
                }
                return ByteView{out, b.orig_size};
            }
        }
        {
            const uint8_t b0 = b.orig[0];
            uint8_t* p = out + (b0 < 0xf8 ? 1 : 1 + (b0 - 0xf7));  // list header length
            // Walk the slots only up to the last dirty one (the rest are already in place), with
            // the mask in a local: the byte copies below may alias b, so b.dirty was reloaded per slot.
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
    // Calculate payload for 16 children
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];

        // No double encoding for embedded node
        payload_length += (child_len == 0 || child_len == 32)
                                ? 1 + child_len
                                : child_len;

        // Double encoding of embedded node
        // payload_length += 1 + child_len;
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

// The number of leading keccak blocks of `encoded`, the encode_branch() of `b`, that the state saved
// for it in the pool already covers, or 0 when none does. A nonzero result consumes the saved state:
// the caller must resume from it, now, with the digest of `encoded` as the result.
//
// The saved state is that of the first 136 * blocks bytes of the witness node b.orig (see
// keccak_prefix.hpp). `encoded` is that node with the hash bytes of the dirty slots rewritten: the
// copy-and-patch path of encode_branch(), which b.orig != nullptr and an unchanged layout select,
// and which touches slot i only from byte 4 + 33 i on, a slot's header byte staying 0xa0. So the
// bytes before the first dirty slot are the node's, and the saved state may be used if none of the
// slots that begin inside the blocks it covers is dirty (kHeadSlots). That a clean slot is unchanged
// does not rest on the update that asked for the snapshot: every change to a slot sets its dirty bit,
// and the pool row is found by b.orig. A node with no dirty slot is the witness node and resumes too.
[[gnu::always_inline]] inline unsigned take_resumable_blocks(const BranchNode& b, size_t row, ByteView encoded) noexcept {
    if (b.orig == nullptr || kprefix::tag_orig[row] != b.orig) return 0;
    // The node as encode_branch() copied it: the whole witness node, laid out as it was. A node of
    // kNodeSize bytes has no room for a slot that is not a hash reference, so this is the full branch.
    if (b.orig_size != kprefix::kNodeSize ||
        !b.same_layout_as_orig() || (reinterpret_cast<uintptr_t>(b.orig) & 7) != 0 ||
        encoded.size() != kprefix::kNodeSize ||
        encoded.data() != static_buffer + (reinterpret_cast<uintptr_t>(b.orig) & 31))
        return 0;
    // tag_sb is 1..3 while the tag is set (verify_and_snap() stores the first_blocks() of a slot). Masked all the
    // same: the index stays inside kHeadSlots, and the count within what a resume takes, whatever the row holds.
    const unsigned blocks = kprefix::tag_sb[row] & 3u;
    if ((b.dirty & kprefix::kHeadSlots[blocks]) != 0) return 0;
    kprefix::tag_orig[row] = nullptr;
    return blocks;
}

// Writes the list header of a leaf or extension payload at `out`, returns the position after it. A payload
// below 256 bytes takes the one-byte long form without to_big_compact; a longer one (a leaf value of up to
// kMaxLeafValueSize) goes through encode_list_header.
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

// The HP path's flag byte is below 0x80 (flag <= 3), so a one-byte path (an empty or one-nibble one) is its own RLP
// encoding and a longer one has a one-byte string header (at most 33 bytes). Written in place, the path
// needs no stack copy.
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

    // Child RLP length.
    const size_t child_rlp_len = (e.child_len == 32) ? 33 : e.child_len;
    const size_t payload = hp_path_rlp_length(e.path) + child_rlp_len;

    uint8_t* out = encode_short_node_list_header(static_buffer, payload);
    out = encode_hp_path_rlp(out, e.path, /*leaf*/ false);

    // Child.
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

    // Value.
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

// ---------------------------------------------
// Decoding helpers for MPT nodes
// ---------------------------------------------

// Store one decoded child into branch slot i (empty / embedded / 0xa0-hash).
// start_byte is the child's RLP start byte; data/len is its decoded payload.
[[gnu::always_inline]] inline bool fill_branch_child(BranchNode& out, size_t i,
                                                     uint8_t start_byte,
                                                     const uint8_t* data, size_t len) {
    if (len == 0) {
        out.child_len[i] = 0;  // empty child (RLP empty string 0x80)
        out.child_ptr[i] = nullptr;
        return true;
    }
    if (start_byte != 0xa0) {
        if (len > 31) return false;  // embedded child must fit child[i].bytes (with header byte)
        out.child_len[i] = static_cast<uint8_t>(len + 1);
        out.child[i].bytes[0] = start_byte;  // keep header byte for embedded child
        out.child_ptr[i] = nullptr;
        std::copy_n(data, len, &out.child[i].bytes[1]);
    } else {
        out.child_len[i] = 32;  // 0xa0 hashref is always 32 bytes
        out.child_ptr[i] = data;  // reference witness blob; no copy
    }
    out.mask |= (1 << i);
    return true;
}

// Decode one branch child from `remaining` into slot i, advancing `remaining`.
// A branch child is only: 0x80 (empty) | 0xa0+32 (hash ref) | short embedded
// list (0xc0..0xf7, <32B). Skips the general decode_header (no single-byte /
// long-string / long-list handling a branch child never hits).
[[gnu::always_inline]] inline bool fill_branch_child_rlp(BranchNode& out, size_t i, ByteView& remaining) {
    if (remaining.empty()) return false;
    const uint8_t b0 = remaining[0];
    if (b0 == rlp::kEmptyStringCode) {  // 0x80 empty
        out.child_len[i] = 0;
        out.child_ptr[i] = nullptr;
        remaining.remove_prefix(1);
        return true;
    }
    if (b0 == 0xa0) {  // 32-byte hash ref
        if (remaining.size() < 33) return false;  // input-too-short (matches decode_header)
        out.child_ptr[i] = remaining.data() + 1;
        out.child_len[i] = 32;
        out.mask |= (1u << i);
        remaining.remove_prefix(33);
        return true;
    }
    if (b0 >= 0xc0 && b0 <= 0xf7) {  // embedded short list
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
    return false;  // not a valid branch child
}

inline bool decode_branch(ByteView payload, BranchNode& out) {
    out.mask = 0;

    ByteView remaining = payload;

    // Decode 16 children
    for (size_t i = 0; i < 16; ++i) {
        if (!fill_branch_child_rlp(out, i, remaining)) return false;
    }

    // Decode value - usually empty
    if (remaining.size() == 1 && remaining[0] == rlp::kEmptyStringCode) {
        out.value = {};
        return true;  // value empty + list fully consumed
    }
    // Rare: non-empty value.
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

    // First element - HP encoded path
    auto h1 = rlp::decode_header(remaining);
    if (!h1 || h1->list) [[unlikely]] return false;
    ByteView hp_path = remaining.substr(0, h1->payload_length);
    remaining.remove_prefix(h1->payload_length);

    // Decode HP path first to determine if it's a leaf or extension
    if (!hp_decode(hp_path, is_leaf, path, plen)) [[unlikely]] {
        return false;
    }

    // Second element - child hash (for extension) or value (for leaf)
    const uint8_t* second_start = remaining.data();
    auto h2 = rlp::decode_header(remaining);
    if (!h2 || h2->list) [[unlikely]] return false;

    if (!is_leaf) {
        // Extension: for hash references, return just the 32-byte hash (not RLP-encoded)
        // For embedded nodes, return the full RLP
        if (h2->payload_length == 32) {
            // Hash reference: return just the payload (32 bytes)
            second = remaining.substr(0, 32);
        } else {
            // Embedded node: return full RLP-encoded form (header + payload)
            size_t header_len = static_cast<size_t>(remaining.data() - second_start);
            size_t total_len = header_len + h2->payload_length;
            second = ByteView{second_start, total_len};
        }
    } else {
        // Leaf: return just the value payload
        second = remaining.substr(0, h2->payload_length);
    }

    remaining.remove_prefix(h2->payload_length);

    // Should have consumed everything
    return remaining.empty();
}

// Single-pass node decode
inline Kind decode_node(ByteView payload, BranchNode& out_branch,
                            bool& is_leaf, std::array<uint8_t, 64>& path,
                            uint8_t& plen, ByteView& second) {
    // A full branch: 16 hash children and an empty value, 16 * 33 + 1 payload bytes. That is
    // most witness branch nodes on mainnet (65% of those re-encoded). Once each child is seen
    // to be a 33-byte string (length byte 0xa0), the layout fixes every pointer and length and
    // the mask, which the general decode below derives one child at a time at ~20
    // instructions each.
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
            static constexpr uint32_t kAllHashLens[4] = {
                0x20202020u, 0x20202020u, 0x20202020u, 0x20202020u};
            std::memcpy(out_branch.child_len.data(), kAllHashLens, 16);  // 4 word stores
            out_branch.mask = 0xffff;
            out_branch.value = {};
            return kBranch;
        }
    }

    ByteView remaining = payload;

    // Element 0
    const uint8_t e0_start = remaining.empty() ? 0 : *remaining.data();
    auto h0 = rlp::decode_header(remaining);
    if (!h0) return kInvalid;
    const ByteView e0_payload = remaining.substr(0, h0->payload_length);
    const bool e0_list = h0->list;
    remaining.remove_prefix(h0->payload_length);

    // Element 1
    const uint8_t e1_start = remaining.empty() ? 0 : *remaining.data();
    const uint8_t* e1_start_ptr = remaining.data();
    auto h1 = rlp::decode_header(remaining);
    if (!h1) return kInvalid;
    const ByteView e1_payload = remaining.substr(0, h1->payload_length);
    const bool e1_list = h1->list;
    remaining.remove_prefix(h1->payload_length);

    if (remaining.empty()) {    // This is leaf or extension
        if (e0_list) [[unlikely]] return kInvalid;
        if (!hp_decode(e0_payload, is_leaf, path, plen)) [[unlikely]] return kInvalid;
        if (e1_list) [[unlikely]] return kInvalid;

        if (!is_leaf) {
            if (h1->payload_length == 32) {
                second = e1_payload;  // exactly the 32-byte hash payload
            } else {
                size_t header_len = static_cast<size_t>(e1_payload.data() - e1_start_ptr);
                second = ByteView{e1_start_ptr, header_len + h1->payload_length};
            }
        } else {
            if (h1->payload_length > kMaxLeafValueSize) [[unlikely]] return kInvalid;  // see static_buffer
            second = e1_payload;
        }
        return kExtOrLeaf;
    }

    // Elements 0 and 1 are already decoded; fill them, then decode slots 2..15.
    out_branch.mask = 0;
    if (!fill_branch_child(out_branch, 0, e0_start, e0_payload.data(), h0->payload_length)) return kInvalid;
    if (!fill_branch_child(out_branch, 1, e1_start, e1_payload.data(), h1->payload_length)) return kInvalid;

    // Slots 2..15: fill_branch_child_rlp() with the position in local pointers and the mask in a
    // local. `remaining` escapes into decode_header() below, so each of its updates was a stack
    // store, and out_branch.mask was reloaded and stored around every child's byte copy.
    {
        const uint8_t* p = remaining.data();
        const uint8_t* const end = p + remaining.size();
        unsigned mask = out_branch.mask;
        for (size_t i = 2; i < 16; ++i) {
            if (p == end) return kInvalid;
            const uint8_t b0 = *p;
            if (b0 == 0xa0) {  // 32-byte hash ref
                if (end - p < 33) return kInvalid;  // input-too-short (matches decode_header)
                out_branch.child_ptr[i] = p + 1;
                out_branch.child_len[i] = 32;
                mask |= 1u << i;
                p += 33;
            } else if (b0 == rlp::kEmptyStringCode) {  // 0x80 empty
                out_branch.child_len[i] = 0;
                out_branch.child_ptr[i] = nullptr;
                ++p;
            } else if (b0 >= 0xc0 && b0 <= 0xf7) {  // embedded short list
                const size_t plen_ = static_cast<size_t>(b0 - 0xc0);
                if (plen_ > 31) return kInvalid;  // must fit child[i].bytes (header + payload)
                if (static_cast<size_t>(end - p) < 1 + plen_) return kInvalid;
                out_branch.child[i].bytes[0] = b0;
                std::copy_n(p + 1, plen_, &out_branch.child[i].bytes[1]);
                out_branch.child_len[i] = static_cast<uint8_t>(plen_ + 1);
                out_branch.child_ptr[i] = nullptr;
                mask |= 1u << i;
                p += 1 + plen_;
            } else {
                return kInvalid;  // not a valid branch child
            }
        }
        out_branch.mask = static_cast<uint16_t>(mask);
        remaining = ByteView{p, static_cast<size_t>(end - p)};
    }

    // Value (17th): empty (0x80), and the list ends there. The state and storage tries have
    // fixed-length keys, so no key ends at a branch; a value would also not fit the encode buffer
    // budget for branches (see static_buffer).
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

// Encode the given line's node
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