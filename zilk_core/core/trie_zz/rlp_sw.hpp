// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
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
// its aligned path as witness node bodies are 8-aligned. A branch is at most 3 + 16 * 33 bytes
// (its value is empty in the fixed-key state and storage tries), a leaf holds at most an account.
inline constexpr size_t kNodeBufferSize = 2048;
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
    size_t i = odd ? 1 : 0;
    for (; i + 1 < n; i += 2) *out++ = static_cast<uint8_t>((nib[i] << 4) | (nib[i + 1] & 0x0F));
    if (i < n) *out++ = static_cast<uint8_t>((nib[i] << 4));  // last high nibble only
    return out;
}

// HP decode -> (is_leaf, nibbles[]). Returns false on malformed.
inline bool hp_decode(ByteView in, bool& is_leaf, std::array<uint8_t, 64>& out, uint8_t& out_len) noexcept {
    if (in.empty()) [[unlikely]] return false;
    uint8_t flag = in[0] >> 4;
    is_leaf = (flag & 0x2) != 0;
    const bool odd = (flag & 0x1) != 0;
    uint8_t nib0 = in[0] & 0x0F;

    size_t pos = 1;
    out_len = 0;

    if (odd) {
        out[out_len++] = nib0 & 0x0F;
    }
    for (; pos < in.size(); ++pos) {
        if (out_len > 62) [[unlikely]] return false;
        out[out_len++] = (in[pos] >> 4) & 0x0F;
        out[out_len++] = in[pos] & 0x0F;
    }
    return true;
}

inline ByteView encode_branch(const BranchNode& b) {
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
        if (b.dirty != 0) {
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
                        std::memcpy(p + 1, b.child_ptr[i] ? b.child_ptr[i] : b.child[i].bytes, 32);
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

inline ByteView encode_ext(const ExtensionNode& e) {
    if (e.child_len == 0) {
        return empty;
    }

    // HP-encode path on the stack.
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, e.path.nib.data(), e.path.len, /*leaf*/ false);
    const size_t hp_len = static_cast<size_t>(hp_end - hpbuf);

    // HP path RLP length.
    const size_t hp_rlp_len = hp_len + ((hp_len != 1 || hpbuf[0] >= rlp::kEmptyStringCode) ? 1 : 0);

    // Child RLP length.
    const size_t child_rlp_len = (e.child_len == 32) ? 33 : e.child_len;

    const size_t payload = hp_rlp_len + child_rlp_len;
    const size_t hdr_sz = (payload < 56) ? 1 : 1 + intx::count_significant_bytes(payload);
    const size_t total = hdr_sz + payload;

    uint8_t* out = static_buffer;

    // List header.
    if (payload < 56) {
        *out++ = static_cast<uint8_t>(rlp::kEmptyListCode + payload);
    } else {
        auto be = endian::to_big_compact(payload);
        *out++ = static_cast<uint8_t>(0xF7 + be.size());
        std::memcpy(out, be.data(), be.size());
        out += be.size();
    }

    // HP path: RLP string header + bytes.
    if (hp_len == 1 && hpbuf[0] < rlp::kEmptyStringCode) {
        *out++ = hpbuf[0];
    } else {
        *out++ = static_cast<uint8_t>(rlp::kEmptyStringCode + hp_len);
        std::memcpy(out, hpbuf, hp_len);
        out += hp_len;
    }

    // Child.
    if (e.child_len == 32) {
        *out++ = 0xa0;
        std::memcpy(out, e.child.bytes, 32);
        out += 32;
    } else {
        std::memcpy(out, e.child.bytes, e.child_len);
        out += e.child_len;
    }

    return ByteView{static_buffer, total};
}

inline ByteView encode_leaf(const LeafNode& l) {
    // HP-encode path on the stack.
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
    const size_t hp_len = static_cast<size_t>(hp_end - hpbuf);

    // HP path RLP length.
    const size_t hp_rlp_len = hp_len + ((hp_len != 1 || hpbuf[0] >= rlp::kEmptyStringCode) ? 1 : 0);

    // Value RLP length.
    const size_t val_rlp_len = rlp::length(l.value);

    const size_t payload = hp_rlp_len + val_rlp_len;
    const size_t hdr_sz = (payload < 56) ? 1 : 1 + intx::count_significant_bytes(payload);
    const size_t total = hdr_sz + payload;

    uint8_t* out = static_buffer;

    // List header.
    if (payload < 56) {
        *out++ = static_cast<uint8_t>(rlp::kEmptyListCode + payload);
    } else {
        auto be = endian::to_big_compact(payload);
        *out++ = static_cast<uint8_t>(0xF7 + be.size());
        std::memcpy(out, be.data(), be.size());
        out += be.size();
    }

    // HP path.
    if (hp_len == 1 && hpbuf[0] < rlp::kEmptyStringCode) {
        *out++ = hpbuf[0];
    } else {
        *out++ = static_cast<uint8_t>(rlp::kEmptyStringCode + hp_len);
        std::memcpy(out, hpbuf, hp_len);
        out += hp_len;
    }

    // Value.
    if (l.value.empty()) {
        *out++ = rlp::kEmptyStringCode;
    } else if (l.value.size() == 1 && l.value[0] < rlp::kEmptyStringCode) {
        *out++ = l.value[0];
    } else {
        if (l.value.size() < 56) {
            *out++ = static_cast<uint8_t>(rlp::kEmptyStringCode + l.value.size());
        } else {
            auto be = endian::to_big_compact(l.value.size());
            *out++ = static_cast<uint8_t>(0xB7 + be.size());
            std::memcpy(out, be.data(), be.size());
            out += be.size();
        }
        std::memcpy(out, l.value.data(), l.value.size());
        out += l.value.size();
    }

    return ByteView{static_buffer, total};
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

    // Value (17th) — empty (0x80) for fixed-length-key tries; short-circuit the common case.
    if (remaining.size() == 1 && remaining[0] == rlp::kEmptyStringCode) {
        out_branch.value = {};
        return kBranch;  // value empty + list fully consumed
    }
    // Rare: non-empty value.
    auto hv = rlp::decode_header(remaining);
    if (!hv || hv->list) return kInvalid;
    out_branch.value = remaining.substr(0, hv->payload_length);
    remaining.remove_prefix(hv->payload_length);
    return remaining.empty() ? kBranch : kInvalid;  // preserve the all-consumed check
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