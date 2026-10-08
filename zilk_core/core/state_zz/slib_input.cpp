// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "slib_input.hpp"

#include <algorithm>  // std::min / std::max (store size hints)
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

// A "list of variable-length byte strings" (SSZ List / ProgressiveList of ByteList) is
// [offset table of N u32 LE][concatenated elements], N = first_offset / 4. bytelist_count
// runs the list-level checks and returns N: the first offset points just past the offset
// table, so it must be a positive multiple of 4 and lie within the blob (the "first offset
// == fixed-region size" invariant for a list: the table is N*4 == first bytes), and N must
// not exceed count_cap. Every violation is a REJECTION (nullopt), never a clamp. An empty
// blob is a legitimately empty list (N = 0). Once N is returned, the offset table occupies
// exactly N*4 bytes <= blob.size(), so every rd_u32(blob, i*4) with i < N is in bounds.
std::optional<std::uint32_t> bytelist_count(ByteView blob, std::uint32_t count_cap) noexcept {
    if (blob.empty()) return 0u;               // a legitimately empty list: zero elements
    if (blob.size() < 4) return std::nullopt;  // a non-empty list needs at least one offset
    const std::uint32_t first = rd_u32(blob, 0);
    if (first < 4 || (first & 3u) != 0) return std::nullopt;
    if (first > blob.size()) return std::nullopt;
    const std::uint32_t n = first / 4u;  // element count
    if (n > count_cap) return std::nullopt;
    return n;
}

// Validate a byte-string list (bytelist_count's checks, then every offset monotonically
// non-decreasing and in bounds, and each element <= elem_cap) and hand each element, in
// order, to `sink(ByteView) -> bool` as soon as it is validated. Returns false on any
// violation, or when the sink returns false, without touching the elements past it (the
// caller decides what a partial feed means). Never reads out of bounds: one u32 read per
// element, the element's end offset, which is carried into the next iteration as its start.
template <class Sink>
bool for_each_bytelist(ByteView blob, std::uint32_t elem_cap, std::uint32_t count_cap,
                       Sink&& sink) {
    const auto count = bytelist_count(blob, count_cap);
    if (!count) return false;
    const std::uint32_t n = *count;
    const std::uint32_t first = n * 4u;  // == rd_u32(blob, 0): the table end, element 0's start
    std::uint32_t off_i = first;
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint32_t off_next =
            (i + 1 < n) ? rd_u32(blob, (i + 1) * 4u) : static_cast<std::uint32_t>(blob.size());
        if (off_i < first) return false;                 // element must start past the table
        if (off_i > off_next) return false;              // monotonically non-decreasing
        if (off_next > blob.size()) return false;        // in bounds
        const std::uint32_t len = off_next - off_i;
        if (len > elem_cap) return false;                // spec element-size cap
        if (!sink(subv(blob, off_i, len))) return false;
        off_i = off_next;
    }
    return true;
}

// The materialised form of for_each_bytelist: every element pushed into `out` (cleared
// first). Used for the small lists (headers) and by decode_stateless_input.
bool decode_bytelist_list(ByteView blob, std::uint32_t elem_cap, std::uint32_t count_cap,
                          std::vector<ByteView>& out) {
    out.clear();
    const auto count = bytelist_count(blob, count_cap);
    if (!count) return false;
    out.reserve(*count);
    return for_each_bytelist(blob, elem_cap, count_cap, [&out](ByteView element) {
        out.push_back(element);
        return true;
    });
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

// The blob's sections, each a view into it, once the outer framing has been validated.
struct Sections {
    std::uint64_t chain_id = 0;
    ByteView new_payload_request;
    ByteView state;        // the state list's bytes (offset table + elements)
    ByteView codes;        // the codes list's bytes
    ByteView headers;      // the headers list's bytes
    ByteView public_keys;  // the 65-byte-stride concatenation
};

// Validate the outer framing (schema marker, the 20-byte StatelessInput and 12-byte
// ExecutionWitness fixed regions, every section offset monotone and in bounds) and cut the
// blob into its sections. Decodes nothing inside a section. nullopt on any violation.
std::optional<Sections> split_stateless_input(ByteView blob) noexcept {
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

    Sections out;
    out.chain_id = chain_id;
    out.new_payload_request = npr;
    out.state = subv(wit, off_state, off_codes - off_state);
    out.codes = subv(wit, off_codes, off_headers - off_codes);
    out.headers = subv(wit, off_headers, wit.size() - off_headers);
    out.public_keys = pk;
    return out;
}

// Ceiling on the per-store size hint parse_stateless_input derives from an announced element
// count: 2.6x the largest mainnet witness seen (24,678 nodes), so a real block pays no growth,
// while a hostile offset table announcing up to the count cap (2^20 elements, 4 MB of offsets)
// cannot make the guest zero-fill ~100 MB of buckets per store up front. Growth still
// backstops any count above the hint.
constexpr std::uint32_t kReserveCap = 1u << 16;

}  // namespace

std::optional<DecodedStatelessInput> decode_stateless_input(ByteView blob) {
    const auto sec = split_stateless_input(blob);
    if (!sec) return std::nullopt;

    DecodedStatelessInput out;
    out.chain_id = sec->chain_id;
    out.new_payload_request = sec->new_payload_request;
    if (!decode_bytelist_list(sec->state, kMaxBytesPerWitnessNode, kMaxWitnessStateNodes, out.state))
        return std::nullopt;
    if (!decode_bytelist_list(sec->codes, kMaxBytesPerCode, kMaxWitnessCodes, out.codes))
        return std::nullopt;
    if (!decode_bytelist_list(sec->headers, kMaxBytesPerHeader, kMaxWitnessHeaders, out.headers))
        return std::nullopt;
    if (!decode_public_keys(sec->public_keys, out.public_keys)) return std::nullopt;
    return out;
}

std::optional<StatelessInputView> parse_stateless_input(ByteView blob, HashState& hs) {
    const auto sec = split_stateless_input(blob);
    if (!sec) return std::nullopt;

    // Size the stores from the element counts the two big lists announce, before the first
    // insert, so the feed below grows no table and the arenas the build fills later are
    // allocated once. The counts are read with the same list-level checks the feed repeats
    // (a count over the cap is rejected here, before anything is reserved). The hints:
    // nodes and codes as announced (capped); accounts at max(1024, nodes/8), which covers
    // every mainnet witness seen (accounts run near nodes/15); slots at the constructor's
    // 4096 (a bigger storage table only costs its zero-fill).
    const auto n_state = bytelist_count(sec->state, kMaxWitnessStateNodes);
    if (!n_state) return std::nullopt;
    const auto n_codes = bytelist_count(sec->codes, kMaxWitnessCodes);
    if (!n_codes) return std::nullopt;
    const std::uint32_t nodes_hint = std::min(*n_state, kReserveCap);
    hs.reserve_stores(nodes_hint, std::min(*n_codes, kReserveCap),
                      std::max<std::uint32_t>(1024u, nodes_hint / 8u), 4096u);

    // Feed the witness content stores straight from the offset table, one element as soon
    // as it is validated. Each entry is keyed by its real keccak256 (identity binding) and a
    // repeat is deduped at the index (the counts below include repeats). The stores keep
    // views into `blob`, not copies. A malformed element stops the feed: `hs` then holds
    // the elements before it and the caller discards it (see slib_input.hpp).
    StatelessInputView v;
    v.chain_id = sec->chain_id;
    v.new_payload_request = sec->new_payload_request;
    if (!for_each_bytelist(sec->state, kMaxBytesPerWitnessNode, kMaxWitnessStateNodes,
                           [&](ByteView node) {
                               hs.add_node_borrowed(node);
                               ++v.node_count;
                               return true;
                           }))
        return std::nullopt;
    if (!for_each_bytelist(sec->codes, kMaxBytesPerCode, kMaxWitnessCodes, [&](ByteView code) {
            hs.add_code_borrowed(code);
            ++v.code_count;
            return true;
        }))
        return std::nullopt;
    if (!decode_bytelist_list(sec->headers, kMaxBytesPerHeader, kMaxWitnessHeaders, v.headers))
        return std::nullopt;
    if (!decode_public_keys(sec->public_keys, v.public_keys)) return std::nullopt;
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
