// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "slib_input.hpp"

#include <cstring>
#include <utility>

namespace zilkworm {

namespace {

// Alignment-agnostic little-endian reads (rv64im: no unaligned ld/sd). The caller
// guarantees off + width <= v.size() before calling.
[[gnu::always_inline]] inline std::uint32_t rd_u32(ByteView v, std::size_t off) noexcept {
    std::uint32_t x;
    std::memcpy(&x, v.data() + off, sizeof(x));
    return x;  // host is little-endian (guest rv64im is little-endian too)
}
[[gnu::always_inline]] inline std::uint64_t rd_u64(ByteView v, std::size_t off) noexcept {
    std::uint64_t x;
    std::memcpy(&x, v.data() + off, sizeof(x));
    return x;
}

// A bounds-checked, exception-free sub-view (ByteView::substr can throw on a bad pos;
// every call site here has already validated off + len <= v.size()).
[[gnu::always_inline]] inline ByteView subv(ByteView v, std::size_t off, std::size_t len) noexcept {
    return ByteView{v.data() + off, len};
}

// Decode a "list of variable-length byte strings" (SSZ List / ProgressiveList of
// ByteList): [offset table of N u32 LE][concatenated elements], N = first_offset / 4.
// Validates: first_offset % 4 == 0, first_offset in bounds, N <= count_cap, every
// offset monotonically non-decreasing and in bounds, and each element <= elem_cap.
// Returns false on any violation (never reads out of bounds). `out` is cleared first.
bool decode_bytelist_list(ByteView blob, std::uint32_t elem_cap, std::uint32_t count_cap,
                          std::vector<ByteView>& out) {
    out.clear();
    if (blob.empty()) return true;      // a legitimately empty list: zero elements
    if (blob.size() < 4) return false;  // a non-empty list needs at least one offset

    const std::uint32_t first = rd_u32(blob, 0);
    // The first offset points just past the offset table, so it must be a positive
    // multiple of 4 and lie within the blob. This is the "first offset == fixed-region
    // size" invariant for a list (the table is N*4 == first bytes).
    if (first < 4 || (first & 3u) != 0) return false;
    if (first > blob.size()) return false;

    const std::uint32_t n = first / 4u;  // element count
    if (n > count_cap) return false;
    // The offset table occupies exactly `first` (== n*4) bytes, already <= blob.size(),
    // so every rd_u32(blob, i*4) below with i < n is in bounds.

    out.reserve(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t off_i = (i == 0) ? first : rd_u32(blob, i * 4u);
        const std::uint32_t off_next =
            (i + 1 < n) ? rd_u32(blob, (i + 1) * 4u) : static_cast<std::uint32_t>(blob.size());
        if (off_i < first) return false;                 // element must start past the table
        if (off_i > off_next) return false;              // monotonically non-decreasing
        if (off_next > blob.size()) return false;        // in bounds
        const std::uint32_t len = off_next - off_i;
        if (len > elem_cap) return false;                // spec element-size cap
        out.push_back(subv(blob, off_i, len));
    }
    return true;
}

// Decode public_keys: a fixed 65-byte stride ByteVector list — plain concatenation,
// NO offset table. Requires len % 65 == 0 and count <= cap.
bool decode_public_keys(ByteView blob, std::vector<ByteView>& out) {
    out.clear();
    if (blob.size() % kPublicKeyBytes != 0) return false;
    const std::size_t n = blob.size() / kPublicKeyBytes;
    if (n > kMaxPublicKeys) return false;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
        out.push_back(subv(blob, i * kPublicKeyBytes, kPublicKeyBytes));
    return true;
}

}  // namespace

std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob) {
    // --- outer framing: 2-byte BIG-endian schema marker 15 01 (0x1501) ---
    if (blob.size() < 2) return std::nullopt;
    if (!(blob[0] == 0x15 && blob[1] == 0x01)) return std::nullopt;
    const ByteView body = subv(blob, 2, blob.size() - 2);

    // --- SszStatelessInput fixed region (20B) ---
    if (body.size() < kStatelessInputFixed) return std::nullopt;
    const std::uint32_t off_npr = rd_u32(body, 0);
    const std::uint32_t off_wit = rd_u32(body, 4);
    const std::uint64_t chain_id = rd_u64(body, 8);
    const std::uint32_t off_pk = rd_u32(body, 16);
    // First variable offset must equal the fixed-region size; the rest monotone & in bounds.
    if (off_npr != kStatelessInputFixed) return std::nullopt;
    if (off_wit < off_npr) return std::nullopt;
    if (off_pk < off_wit) return std::nullopt;
    if (off_pk > body.size()) return std::nullopt;

    const ByteView npr = subv(body, off_npr, off_wit - off_npr);
    const ByteView wit = subv(body, off_wit, off_pk - off_wit);
    const ByteView pk = subv(body, off_pk, body.size() - off_pk);

    // --- SszExecutionWitness fixed region (12B) ---
    if (wit.size() < kWitnessFixed) return std::nullopt;
    const std::uint32_t off_state = rd_u32(wit, 0);
    const std::uint32_t off_codes = rd_u32(wit, 4);
    const std::uint32_t off_headers = rd_u32(wit, 8);
    if (off_state != kWitnessFixed) return std::nullopt;
    if (off_codes < off_state) return std::nullopt;
    if (off_headers < off_codes) return std::nullopt;
    if (off_headers > wit.size()) return std::nullopt;

    const ByteView state_blob = subv(wit, off_state, off_codes - off_state);
    const ByteView codes_blob = subv(wit, off_codes, off_headers - off_codes);
    const ByteView headers_blob = subv(wit, off_headers, wit.size() - off_headers);

    DecodedStatelessInput out;
    out.chain_id = chain_id;
    out.new_payload_request = npr;
    if (!decode_bytelist_list(state_blob, kMaxBytesPerWitnessNode, kMaxWitnessStateNodes, out.state))
        return std::nullopt;
    if (!decode_bytelist_list(codes_blob, kMaxBytesPerCode, kMaxWitnessCodes, out.codes))
        return std::nullopt;
    if (!decode_bytelist_list(headers_blob, kMaxBytesPerHeader, kMaxWitnessHeaders, out.headers))
        return std::nullopt;
    if (!decode_public_keys(pk, out.public_keys)) return std::nullopt;
    return out;
}

std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs) {
    auto dec = decode_stateless_input(blob);
    if (!dec) return std::nullopt;

    // Feed the witness content stores. Each entry is keyed by its real keccak256 (identity
    // binding) and repeats are deduped. The stores keep views into `blob`, not copies.
    for (const ByteView node : dec->state) hs.add_node_borrowed(node);
    for (const ByteView code : dec->codes) hs.add_code_borrowed(code);

    StatelessInputView v;
    v.chain_id = dec->chain_id;
    v.new_payload_request = dec->new_payload_request;
    v.headers = std::move(dec->headers);
    v.public_keys = std::move(dec->public_keys);
    v.node_count = static_cast<std::uint32_t>(dec->state.size());
    v.code_count = static_cast<std::uint32_t>(dec->codes.size());
    return v;
}

std::optional<SlibRunResult> run_slib(ByteView blob, HashState& hs,
                                      const evmc::bytes32& prev_root) {
    auto v = parse_stateless_input(blob, hs);
    if (!v) return std::nullopt;
    const auto status = hs.build_state_from_trie(prev_root);
    return SlibRunResult{std::move(*v), status};
}

}  // namespace zilkworm
