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

// rlp helpers live in silkworm::rlp; alias for local readability.
namespace rlp = ::silkworm::rlp;

#if defined(__cpp_threadsafe_static_init) && !defined(NO_THREAD_LOCAL) && !defined(SP1) && !defined(QEMU_DEBUG)
inline thread_local Bytes static_buffer = []() {
    Bytes buf;
    buf.reserve(1024);
    return buf;
}();
#else
inline static Bytes static_buffer = []() {
    Bytes buf;
    buf.reserve(1024);
    return buf;
}();
#endif

// Helper to clear static buffer between test runs
inline void clear_static_buffer() {
    static_buffer.clear();
}

inline const Bytes empty{silkworm::rlp::kEmptyStringCode};


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

inline const Bytes& encode_branch(const BranchNode& b) {
    if (b.mask == 0) {
        return empty;
    }
    static_buffer.clear();
    rlp::Header h{.list = true, .payload_length = 0};
    // Calculate payload for 16 children
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];

        // No double encoding for embedded node
        h.payload_length += (child_len == 0 || child_len == 32)
                                ? 1 + child_len
                                : child_len;

        // Double encoding of embedded node
        // h.payload_length += 1 + child_len;
    }

    h.payload_length += rlp::length(b.value);
    rlp::encode_header(static_buffer, h);
    const size_t header_len = static_buffer.size();
    static_buffer.resize(header_len + h.payload_length);
    uint8_t* p = static_buffer.data() + header_len;

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
    return static_buffer;
}

inline const Bytes& encode_ext(const ExtensionNode& e) {
    if (e.child_len == 0) {
        return empty;
    }
    static_buffer.clear();

    // Encode HP path into stack buffer (avoid allocation)
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, e.path.nib.data(), e.path.len, /*leaf*/ false);
    ByteView hp_encoded{hpbuf, static_cast<size_t>(hp_end - hpbuf)};

    // Calculate payload length
    size_t child_rlp_len = e.child_len;
    if (child_rlp_len == 32) {
        // Hash reference: needs RLP encoding (0xa0 + 32 bytes = 33 bytes)
        child_rlp_len = 33;
    }

    rlp::Header h{
        .list = true,
        .payload_length = rlp::length(hp_encoded) + child_rlp_len};
    rlp::encode_header(static_buffer, h);
    rlp::encode(static_buffer, hp_encoded);

    // Encode child
    if (e.child_len == 32) {
        // Hash reference: RLP-encode the 32-byte hash
        ByteView child_hash{e.child.bytes, 32};
        rlp::encode(static_buffer, child_hash);
    } else {
        // Embedded node: already RLP-encoded, append as-is
        static_buffer.append(e.child.bytes, e.child_len);
    }

    // std::cout << "call to encode_ext " << static_buffer << std::endl;

    return static_buffer;
}

inline const Bytes& encode_leaf(const LeafNode& l) {
    static_buffer.clear();

    // Encode HP path
    uint8_t hpbuf[1 + 32];
    uint8_t* hp_end = encode_hp_path(hpbuf, l.path.nib.data(), l.path.len, /*leaf*/ true);
    ByteView hp_encoded{hpbuf, static_cast<size_t>(hp_end - hpbuf)};

    rlp::Header h{.list = true, .payload_length = 0};
    h.payload_length += rlp::length(hp_encoded);
    h.payload_length += rlp::length(l.value);

    rlp::encode_header(static_buffer, h);
    rlp::encode(static_buffer, hp_encoded);
    rlp::encode(static_buffer, l.value);
    return static_buffer;
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

    for (size_t i = 2; i < 16; ++i) {
        if (!fill_branch_child_rlp(out_branch, i, remaining)) return kInvalid;
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
inline const Bytes& encode_line(const GridLine& line) {
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