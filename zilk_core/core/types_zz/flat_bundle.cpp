// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "flat_bundle.hpp"

#include <algorithm>
#include <cstring>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/state_zz/pre_state.hpp>
#include <zilk_core/print.hpp>

namespace zilkworm {

namespace {

inline size_t align8(size_t v) noexcept { return (v + 7u) & ~size_t{7u}; }

}  // namespace

// Member-init order matters: blob first, direct spans into blob.
FlatBundle::FlatBundle(std::span<uint8_t> blob_in,
                       silkworm::Block&& genesis_in,
                       std::vector<silkworm::ByteView>&& block_rlps_in,
                       std::vector<silkworm::BlockHeader>&& ancestors_in,
                       size_t prestate_off, size_t prestate_size,
                       size_t nodestore_off, size_t nodestore_size,
                       size_t network_off, size_t network_size) noexcept
    : blob{blob_in},
      genesis{std::move(genesis_in)},
      block_rlps{std::move(block_rlps_in)},
      ancestors{std::move(ancestors_in)},
      direct{
          std::span<uint8_t>{blob.data() + prestate_off, prestate_size},
          nodestore_size > 0
              ? std::span<uint8_t>{blob.data() + nodestore_off, nodestore_size}
              : std::span<uint8_t>{}},
      network{network_size > 0
                  ? std::string_view{
                        reinterpret_cast<const char*>(blob.data() + network_off),
                        network_size}
                  : std::string_view{}} {
}

std::vector<uint8_t> build_flat_bundle(
    silkworm::ByteView genesis_rlp,
    std::span<const silkworm::ByteView> block_rlps,
    silkworm::ByteView ancestors_rlp,
    const std::vector<uint8_t>& direct_state_blob,
    const std::vector<uint8_t>& node_store_blob,
    std::string_view network,
    std::span<const uint8_t> block_flags,
    std::span<const std::optional<BlockEngineRecord>> engine_records) {
    size_t blocks_payload = 0;
    for (const auto& br : block_rlps) {
        blocks_payload += align8(br.size());
    }
    // Engine records: [block_hash 32][u64 n][n * 32 versioned hashes], 8-aligned after the flags.
    size_t engine_size = 0;
    for (const auto& rec : engine_records) {
        if (rec) engine_size += 32 + sizeof(uint64_t) + rec->versioned_hashes.size();
    }
    const size_t flags_end = sizeof(uint64_t) + blocks_payload + block_flags.size();
    const size_t blocks_section_size = engine_size > 0 ? align8(flags_end) + engine_size : flags_end;

    const size_t hdr_size       = align8(sizeof(FlatBundleHeader));
    const size_t genesis_off    = hdr_size;
    const size_t blocks_off     = align8(genesis_off + genesis_rlp.size());
    const size_t anc_off        = align8(blocks_off + blocks_section_size);
    const size_t direct_off     = align8(anc_off + ancestors_rlp.size());
    const size_t node_off       = align8(direct_off + direct_state_blob.size());
    const size_t network_off    = align8(node_off + node_store_blob.size());
    const size_t total          = align8(network_off + network.size());

    std::vector<uint8_t> out(total, 0);
    auto* hdr = reinterpret_cast<FlatBundleHeader*>(out.data());
    hdr->magic                 = kFlatBundleMagic;
    hdr->version               = kFlatBundleVersion;
    hdr->genesis_rlp_off       = static_cast<uint32_t>(genesis_off);
    hdr->genesis_rlp_size      = static_cast<uint32_t>(genesis_rlp.size());
    hdr->blocks_rlp_off        = static_cast<uint32_t>(blocks_off);
    hdr->blocks_rlp_size       = static_cast<uint32_t>(blocks_section_size);
    hdr->ancestors_rlp_off     = static_cast<uint32_t>(anc_off);
    hdr->ancestors_rlp_size    = static_cast<uint32_t>(ancestors_rlp.size());
    hdr->direct_state_off      = static_cast<uint32_t>(direct_off);
    hdr->direct_state_size     = static_cast<uint32_t>(direct_state_blob.size());
    hdr->node_store_off        = static_cast<uint32_t>(node_off);
    hdr->node_store_size       = static_cast<uint32_t>(node_store_blob.size());
    hdr->network_off           = static_cast<uint32_t>(network_off);
    hdr->network_size          = static_cast<uint32_t>(network.size());

    if (!genesis_rlp.empty()) {
        std::memcpy(out.data() + genesis_off, genesis_rlp.data(), genesis_rlp.size());
    }

    const uint64_t n_blocks = static_cast<uint64_t>(block_rlps.size());
    std::memcpy(out.data() + blocks_off, &n_blocks, sizeof(uint64_t));
    size_t cursor = blocks_off + sizeof(uint64_t);
    for (const auto& br : block_rlps) {
        if (!br.empty()) {
            std::memcpy(out.data() + cursor, br.data(), br.size());
        }
        cursor += align8(br.size());
    }
    if (!block_flags.empty()) {
        std::memcpy(out.data() + cursor, block_flags.data(), block_flags.size());
    }
    if (engine_size > 0) {
        cursor = blocks_off + align8(flags_end);
        for (const auto& rec : engine_records) {
            if (!rec) continue;
            std::memcpy(out.data() + cursor, rec->block_hash.bytes, 32);
            const uint64_t n = rec->versioned_hashes.size() / 32;
            std::memcpy(out.data() + cursor + 32, &n, sizeof(uint64_t));
            if (!rec->versioned_hashes.empty()) {
                std::memcpy(out.data() + cursor + 40, rec->versioned_hashes.data(),
                            rec->versioned_hashes.size());
            }
            cursor += 40 + rec->versioned_hashes.size();
        }
    }

    // Skip zero-length sections: an empty ByteView/vector has a null data()
    // pointer, and memcpy is declared nonnull — passing null (even with size 0)
    // is UB that a plain -O0/-O2 build no-ops but a UBSan Debug build flags/aborts.
    // Copying nothing leaves `out` (zero-initialised) byte-identical either way.
    if (!ancestors_rlp.empty()) {
        std::memcpy(out.data() + anc_off, ancestors_rlp.data(), ancestors_rlp.size());
    }
    if (!direct_state_blob.empty()) {
        std::memcpy(out.data() + direct_off, direct_state_blob.data(), direct_state_blob.size());
    }
    if (!node_store_blob.empty()) {
        std::memcpy(out.data() + node_off, node_store_blob.data(), node_store_blob.size());
    }
    if (!network.empty()) {
        std::memcpy(out.data() + network_off, network.data(), network.size());
    }
    return out;
}


std::optional<FlatBundle> load_flat_bundle(std::span<uint8_t> blob) {
    if (blob.size() < sizeof(FlatBundleHeader)) [[unlikely]] {
        sys_println("load_flat_bundle: blob too small");
        return std::nullopt;
    }
    const auto* hdr = reinterpret_cast<const FlatBundleHeader*>(blob.data());
    if (hdr->magic != kFlatBundleMagic) [[unlikely]] {
        sys_println("load_flat_bundle: bad magic");
        return std::nullopt;
    }
    if (hdr->version != kFlatBundleVersion) [[unlikely]] {
        sys_println("load_flat_bundle: bad version");
        return std::nullopt;
    }

    auto bound = [&](uint32_t off, uint32_t size, const char* what) -> bool {
        const uint64_t end = static_cast<uint64_t>(off) + size;
        if (end > blob.size()) [[unlikely]] {
            sys_println(what);
            return false;
        }
        return true;
    };
    if (!bound(hdr->genesis_rlp_off,       hdr->genesis_rlp_size,       "load_flat_bundle: genesis section out of range")        ||
        !bound(hdr->blocks_rlp_off,        hdr->blocks_rlp_size,        "load_flat_bundle: blocks section out of range")         ||
        !bound(hdr->ancestors_rlp_off,     hdr->ancestors_rlp_size,     "load_flat_bundle: ancestors section out of range")      ||
        !bound(hdr->direct_state_off,      hdr->direct_state_size,      "load_flat_bundle: direct_state section out of range")   ||
        !bound(hdr->node_store_off,        hdr->node_store_size,        "load_flat_bundle: node_store section out of range")     ||
        !bound(hdr->network_off,           hdr->network_size,           "load_flat_bundle: network section out of range")) {
        return std::nullopt;
    }

    if ((hdr->direct_state_off % 8u) != 0) [[unlikely]] {
        sys_println("load_flat_bundle: direct_state_off misaligned");
        return std::nullopt;
    }

    struct Section { uint32_t off; uint32_t size; const char* name; };
    const Section sections[] = {
        {hdr->genesis_rlp_off,       hdr->genesis_rlp_size,       "genesis"},
        {hdr->blocks_rlp_off,        hdr->blocks_rlp_size,        "blocks"},
        {hdr->ancestors_rlp_off,     hdr->ancestors_rlp_size,     "ancestors"},
        {hdr->direct_state_off,      hdr->direct_state_size,      "direct_state"},
        {hdr->node_store_off,        hdr->node_store_size,        "node_store"},
        {hdr->network_off,           hdr->network_size,           "network"},
    };
    for (size_t i = 0; i < std::size(sections); ++i) {
        if (sections[i].size == 0) continue;
        for (size_t j = i + 1; j < std::size(sections); ++j) {
            if (sections[j].size == 0) continue;
            const uint64_t a_lo = sections[i].off;
            const uint64_t a_hi = a_lo + sections[i].size;
            const uint64_t b_lo = sections[j].off;
            const uint64_t b_hi = b_lo + sections[j].size;
            if (a_lo < b_hi && b_lo < a_hi) [[unlikely]] {
                sys_println("load_flat_bundle: section overlap");
                return std::nullopt;
            }
        }
    }

    // The node-store and direct_state sections are bounded and disjoint here; their
    // MphfMap layout is validated where the maps are built, in the DirectState constructor.

    silkworm::Block genesis;
    {
        silkworm::ByteView v{blob.data() + hdr->genesis_rlp_off, hdr->genesis_rlp_size};
        if (!silkworm::rlp::decode(v, genesis).has_value()) {
            sys_println("load_flat_bundle: genesis decode");
            return std::nullopt;
        }
    }

    std::vector<silkworm::ByteView> block_rlps;
    std::span<const uint8_t> block_flags{};
    std::vector<std::optional<BlockEngineRecord>> engine_records;
    {
        if (hdr->blocks_rlp_size < sizeof(uint64_t)) [[unlikely]] {
            sys_println("load_flat_bundle: blocks section too small");
            return std::nullopt;
        }
        uint64_t n_blocks = 0;
        std::memcpy(&n_blocks, blob.data() + hdr->blocks_rlp_off, sizeof(uint64_t));
        const size_t section_end = static_cast<size_t>(hdr->blocks_rlp_off) +
                                   static_cast<size_t>(hdr->blocks_rlp_size);
        size_t cursor = static_cast<size_t>(hdr->blocks_rlp_off) + sizeof(uint64_t);
        // Reserve is bounded by what the section can hold (an aligned block takes >= 8
        // bytes), so a hostile n_blocks cannot make reserve throw before the loop's own
        // "cursor past section end" check rejects the over-count.
        const size_t max_blocks = (section_end - cursor) / 8u + 1u;
        block_rlps.reserve(std::min(static_cast<size_t>(n_blocks), max_blocks));
        for (size_t i = 0; i < static_cast<size_t>(n_blocks); ++i) {
            if (cursor >= section_end) [[unlikely]] {
                sys_println("load_flat_bundle: blocks cursor past section end");
                return std::nullopt;
            }
            silkworm::ByteView v{blob.data() + cursor, section_end - cursor};
            auto outer = silkworm::rlp::decode_header(v);
            if (!outer.has_value() || !outer->list) [[unlikely]] {
                sys_println("load_flat_bundle: block outer header");
                return std::nullopt;
            }
            const size_t block_size_total = outer->payload_length +
                                       static_cast<size_t>(v.data() -
                                                           (blob.data() + cursor));
            if (cursor + block_size_total > section_end) [[unlikely]] {
                sys_println("load_flat_bundle: block overruns section");
                return std::nullopt;
            }
            block_rlps.push_back(silkworm::ByteView{blob.data() + cursor, block_size_total});
            cursor += block_size_total;
            cursor = align8(cursor);
        }
        // Optional trailing per-block flag bytes (kBlockFlagExpectInvalid).
        if (!block_rlps.empty() && cursor + block_rlps.size() <= section_end) {
            block_flags = {blob.data() + cursor, block_rlps.size()};
        }
        // Optional engine records, in block order, for blocks flagged kBlockFlagEngineRecord.
        if (std::ranges::any_of(block_flags, [](uint8_t f) { return (f & kBlockFlagEngineRecord) != 0; })) {
            engine_records.resize(block_rlps.size());
            size_t pos = align8(cursor + block_flags.size());
            for (size_t i = 0; i < block_flags.size(); ++i) {
                if ((block_flags[i] & kBlockFlagEngineRecord) == 0) continue;
                if (pos > section_end || section_end - pos < 40) [[unlikely]] {
                    sys_println("load_flat_bundle: engine record overruns section");
                    return std::nullopt;
                }
                BlockEngineRecord rec{};
                std::memcpy(rec.block_hash.bytes, blob.data() + pos, 32);
                uint64_t n = 0;
                std::memcpy(&n, blob.data() + pos + 32, sizeof(uint64_t));
                pos += 40;
                if (n > (section_end - pos) / 32) [[unlikely]] {
                    sys_println("load_flat_bundle: engine record overruns section");
                    return std::nullopt;
                }
                rec.versioned_hashes = {blob.data() + pos, static_cast<size_t>(n) * 32};
                pos += static_cast<size_t>(n) * 32;
                engine_records[i] = rec;
            }
        }
    }

    std::vector<silkworm::BlockHeader> ancestors;
    std::vector<silkworm::ByteView> ancestor_rlps;
    bool ancestors_well_formed = true;
    {
        silkworm::ByteView v{blob.data() + hdr->ancestors_rlp_off, hdr->ancestors_rlp_size};
        if (!v.empty()) {
            auto inner = silkworm::rlp::decode_header(v);
            if (inner.has_value() && inner->list) {
                silkworm::ByteView lv = v.substr(0, inner->payload_length);
                while (!lv.empty()) {
                    const silkworm::ByteView entry_start = lv;
                    auto eh = silkworm::rlp::decode_header(lv);
                    if (!eh.has_value() || eh->payload_length > lv.size()) {
                        sys_println("load_flat_bundle: bad ancestor entry");
                        return std::nullopt;
                    }
                    const size_t entry_len =
                        static_cast<size_t>(lv.data() - entry_start.data()) + eh->payload_length;
                    // An entry is a header RLP, or a byte string wrapping one (C++ hosts).
                    const silkworm::ByteView header_rlp =
                        eh->list ? entry_start.substr(0, entry_len) : lv.substr(0, eh->payload_length);
                    lv.remove_prefix(eh->payload_length);
                    silkworm::ByteView hv = header_rlp;
                    silkworm::BlockHeader header;
                    // It must decode as exactly one header; anything else is malformed witness.
                    if (!silkworm::rlp::decode(hv, header, silkworm::rlp::Leftover::kProhibit)) {
                        ancestors_well_formed = false;
                        continue;
                    }
                    ancestor_rlps.push_back(header_rlp);
                    ancestors.push_back(std::move(header));
                }
            } else {
                ancestors_well_formed = false;
            }
        }
    }

    const auto direct_off              = hdr->direct_state_off;
    const auto direct_size             = hdr->direct_state_size;
    const auto node_off                = hdr->node_store_off;
    const auto node_size               = hdr->node_store_size;
    const auto net_off                 = hdr->network_off;
    const auto net_size                = hdr->network_size;

    size_t bundle_size = sizeof(FlatBundleHeader);
    auto bump = [&](uint32_t off, uint32_t size) {
        const size_t e = static_cast<size_t>(off) + static_cast<size_t>(size);
        if (e > bundle_size) bundle_size = e;
    };
    bump(hdr->genesis_rlp_off,   hdr->genesis_rlp_size);
    bump(hdr->blocks_rlp_off,    hdr->blocks_rlp_size);
    bump(hdr->ancestors_rlp_off, hdr->ancestors_rlp_size);
    bump(hdr->direct_state_off,  hdr->direct_state_size);
    bump(hdr->node_store_off,    hdr->node_store_size);
    bump(hdr->network_off,       hdr->network_size);

    FlatBundle fb{
        std::span<uint8_t>{blob.data(), bundle_size},
        std::move(genesis),
        std::move(block_rlps),
        std::move(ancestors),
        direct_off, direct_size,
        node_off, node_size,
        net_off, net_size};
    fb.block_flags = block_flags;
    fb.engine_records = std::move(engine_records);
    fb.ancestor_rlps = std::move(ancestor_rlps);
    fb.ancestors_well_formed = ancestors_well_formed;
    return fb;
}

}  // namespace zilkworm
