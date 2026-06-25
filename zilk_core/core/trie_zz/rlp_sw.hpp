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

    // Encode 16 children — must emit all 16 in order for valid RLP
    for (size_t i = 0; i < 16; ++i) {
        auto child_len = b.child_len[i];
        if (child_len == 0) {
            static_buffer.push_back(rlp::kEmptyStringCode);
        } else if (child_len == 32) {
            // hashed ref
            static_buffer.push_back(0xa0);
            static_buffer.append(b.child[i].bytes, 32);
        } else {
            // No double encoding of embedded node
            static_buffer.append(b.child[i].bytes, child_len);
            // Double encoding of embedded node
            // rlp::encode(static_buffer, ByteView{b.child[i].bytes, b.child_len[i]});        
        }
    }

    rlp::encode(static_buffer, b.value);
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

inline bool decode_branch(ByteView payload, BranchNode& out) {
    out.mask = 0;

    ByteView remaining = payload;

    // Decode 16 children
    for (size_t i = 0; i < 16; ++i) {
        // Save position before decode_header consumes the header

        if (remaining.empty()) return false;
        const uint8_t child_start = *remaining.data();
        auto hdr = rlp::decode_header(remaining);
        if (!hdr) return false;

        if (hdr->payload_length == 0) {
            // Empty child (RLP empty string 0x80)
            out.child_len[i] = 0;
        } else {
            if (child_start != 0xa0) {
                // embedded child keeps header byte; dest has 31 bytes after [0]
                if (hdr->payload_length > 31) return false;
                out.child_len[i] = hdr->payload_length + 1;
                out.child[i].bytes[0] = child_start;  // Keep the header byte for embedded child
                std::copy_n(remaining.data(), hdr->payload_length, &out.child[i].bytes[1]);
            } else {
                if (hdr->payload_length > 32) return false;
                out.child_len[i] = hdr->payload_length;
                std::copy_n(remaining.data(), hdr->payload_length, &out.child[i].bytes[0]);
            }
            out.mask |= (1 << i);
        }
        remaining.remove_prefix(hdr->payload_length);
    }

    // Decode value (17th element)
    auto hdr_value = rlp::decode_header(remaining);
    if (!hdr_value || hdr_value->list) return false;
    out.value = remaining.substr(0, hdr_value->payload_length);
    remaining.remove_prefix(hdr_value->payload_length);

    // Should have consumed everything
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