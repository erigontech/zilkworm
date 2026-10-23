// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Differential test for the O(n) chain+bitmap mphf_entries_tile: it must accept and reject exactly
// the same maps as the std::sort tiling check it replaced, which is kept here verbatim as the
// oracle. Inputs: hand-made maps (overlap, gap, duplicate offset, misaligned, out-of-bounds, short
// body, empty, collision sidecar), real stores from witness bundles (directory in
// Z6M_IT106_TESTDATA, skipped when unset), and >=10K seeded random mutations per store kind.
// Maps whose header no longer bounds its tables are compared through the caller's verdict
// (validate_mphf first, the tile only after it), which both sides share.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using namespace zilkworm;

namespace {

constexpr uint32_t kSlack = 64;  // headroom so a corrupted data_size keeps every read in the buffer

uint64_t ld64(const uint8_t* p) {
    uint64_t v;
    std::memcpy(&v, p, 8);
    return v;
}
void st64(uint8_t* p, uint64_t v) { std::memcpy(p, &v, 8); }
void st32(uint8_t* p, uint32_t v) { std::memcpy(p, &v, 4); }
uint32_t round8(uint32_t v) { return (v + 7) & ~uint32_t{7}; }

// The oracle: mphf_entries_tile as of 9c5798b51, verbatim.
[[nodiscard]] bool mphf_entries_tile_old(const MphfMap& m) {
    if (!m.valid() || m.n_keys() == 0) return true;
    std::vector<uint32_t> offsets;
    offsets.reserve(m.n_keys());
    m.for_each_offset([&](uint64_t off) { offsets.push_back(static_cast<uint32_t>(off)); });
    std::sort(offsets.begin(), offsets.end());
    const uint8_t* const data = m.data_base();
    uint64_t expect = 8u;  // data[0..8) is the sentinel the builder reserves
    for (const uint32_t off : offsets) {
        if (off != expect) return false;  // a gap, an overlap, or a misaligned start
        const uint64_t body_len = ld64(data + off);
        expect = off + mphf_align8(static_cast<uint32_t>(8u + body_len));
    }
    return expect == m.data_size();
}

MphfMap map_of(std::vector<uint8_t>& region) {
    return MphfMap{reinterpret_cast<MphfMapHeader*>(region.data())};
}

/// Compare the two checks directly, on maps whose header still bounds its own tables.
void check_tiles(std::vector<uint8_t>& region, const std::string& what) {
    INFO("case: " << what);
    const MphfMap m = map_of(region);
    CHECK(mphf_entries_tile_old(m) == mphf_entries_tile(m));
}

/// Compare the caller's verdict: validate_mphf<KeySize> first, the tile only when it passes.
template <size_t KeySize>
void check_verdict(std::vector<uint8_t>& region, const std::string& what) {
    INFO("case: " << what);
    const std::span<const uint8_t> blob{region};
    if (!validate_mphf<KeySize>(blob, 0, static_cast<uint32_t>(region.size()), 0))
        return;  // rejected before the tile, by both
    check_tiles(region, what);
}

// ---------------------------------------------------------------------------
// Hand-made maps
// ---------------------------------------------------------------------------

struct CraftedEntry {
    uint32_t len{64};      // body length declared in [len:u64]
    uint32_t bytes{64};    // body bytes present (rounded up to 8)
    bool sidecar{false};   // referenced only by the collision table
};

/// header | displacement[n_buckets]:u64 | slot_offsets[n_keys]:u32 | collisions | data (chain).
/// The header always bounds its own tables; only slots, sidecar offsets, lengths and data_size
/// are corrupted afterwards. Trailing slack absorbs a grown data_size.
std::vector<uint8_t> make_map(const std::vector<CraftedEntry>& entries) {
    const uint32_t n_keys = static_cast<uint32_t>(entries.size());
    uint32_t n_coll = 0;
    for (const auto& e : entries) n_coll += e.sidecar ? 1u : 0u;
    const uint32_t n_buckets = n_keys ? n_keys / 2 + 1 : 1;

    std::vector<uint8_t> data(8, 0);  // the reserved sentinel
    std::vector<uint32_t> offsets;
    for (const auto& e : entries) {
        const uint32_t off = static_cast<uint32_t>(data.size());
        offsets.push_back(off);
        data.resize(off + 8 + round8(e.bytes), 0);
        st64(data.data() + off, e.len);
        for (uint32_t k = off + 8, j = 0; k < data.size(); ++k, ++j)
            data[k] = static_cast<uint8_t>(j * 7 + 1);
    }

    const uint32_t disp_off = sizeof(MphfMapHeader);
    const uint32_t disp_size = n_buckets * 8u;
    const uint32_t slots_off = disp_off + disp_size;
    const uint32_t slots_size = n_keys * 4u;
    const uint32_t coll_off = round8(slots_off + slots_size);
    const uint32_t coll_size = n_coll * sizeof(MphfCollisionEntry);
    const uint32_t data_off = round8(coll_off + coll_size);

    std::vector<uint8_t> region(data_off + data.size() + kSlack, 0);
    auto* h = reinterpret_cast<MphfMapHeader*>(region.data());
    h->magic = 0;  // magic is not part of the tiling contract
    h->version = kMphfMapVersion;
    h->n_keys = n_keys;
    h->n_buckets = n_buckets;
    h->seed = 1;
    h->seed_factor = 7;
    h->collisions_offset = coll_off;
    h->collisions_size = coll_size;
    h->displacement_offset = disp_off;
    h->slot_offsets_offset = slots_off;
    h->data_offset = data_off;
    h->data_size = static_cast<uint32_t>(data.size());
    for (uint32_t b = 0; b < n_buckets; ++b) st64(region.data() + disp_off + 8 * b, b * 0x9E3779B9u);
    std::vector<uint32_t> sidecar;
    for (uint32_t i = 0; i < n_keys; ++i) {
        st32(region.data() + slots_off + 4 * i, entries[i].sidecar ? 0u : offsets[i]);
        if (entries[i].sidecar) sidecar.push_back(offsets[i]);
    }
    for (uint32_t c = 0; c < sidecar.size(); ++c) {  // keys ascend with c: sorted as built
        st64(region.data() + coll_off + 16 * c, 0x1000 + c);
        st64(region.data() + coll_off + 16 * c + 8, sidecar[c]);
    }
    std::memcpy(region.data() + data_off, data.data(), data.size());
    return region;
}

std::vector<CraftedEntry> chain(size_t n, size_t sidecars = 0) {
    std::vector<CraftedEntry> e(n);
    for (size_t i = 0; i < n; ++i) {
        e[i].len = static_cast<uint32_t>(32 + (i % 5) * 9);
        e[i].bytes = e[i].len;
        e[i].sidecar = i < sidecars;
    }
    return e;
}

MphfMapHeader* hdr(std::vector<uint8_t>& r) { return reinterpret_cast<MphfMapHeader*>(r.data()); }
uint32_t* slot(std::vector<uint8_t>& r, uint32_t i) {
    const auto* h = hdr(r);
    return reinterpret_cast<uint32_t*>(r.data() + h->slot_offsets_offset) + i;
}
uint64_t* coll_offset(std::vector<uint8_t>& r, uint32_t i) {
    const auto* h = hdr(r);
    return reinterpret_cast<uint64_t*>(r.data() + h->collisions_offset) + 2 * i + 1;
}
uint8_t* datum(std::vector<uint8_t>& r, uint32_t off) {
    return r.data() + hdr(r)->data_offset + off;
}

/// The entry offsets as the chain lays them out, ascending.
std::vector<uint32_t> chain_offsets(const std::vector<uint8_t>& r) {
    const auto* h = reinterpret_cast<const MphfMapHeader*>(r.data());
    const uint8_t* data = r.data() + h->data_offset;
    std::vector<uint32_t> out;
    for (uint32_t off = 8; off < h->data_size && out.size() < h->n_keys + 2;) {
        out.push_back(off);
        off += mphf_align8(static_cast<uint32_t>(8u + ld64(data + off)));
    }
    return out;
}

enum class Corruption {
    none, swap, overlap, overlap2, gap, duplicate, misalign_1, misalign_4, oob_size, oob_past,
    oob_wrap, oob_huge, len_zero, len_small, len_huge, truncate, grow, sidecar_overlap,
    sidecar_oob, sidecar_dup, unchain,
};

void apply(std::vector<uint8_t>& r, Corruption c) {
    const auto offs = chain_offsets(r);
    if (offs.empty() || hdr(r)->n_keys == 0) return;
    const uint32_t a = offs.front();
    auto* h = hdr(r);
    switch (c) {
      case Corruption::none: break;
      case Corruption::swap:
          if (offs.size() > 2) std::swap(*slot(r, 0), *slot(r, 2));
          break;
      case Corruption::overlap: *slot(r, h->n_keys - 1) = a + 16; break;
      case Corruption::overlap2: *slot(r, h->n_keys - 1) = a + 24; break;
      case Corruption::gap: *slot(r, h->n_keys - 1) = 0; break;
      case Corruption::duplicate: *slot(r, h->n_keys - 1) = a; break;
      case Corruption::misalign_1: *slot(r, 0) = a + 1; break;
      case Corruption::misalign_4: *slot(r, 0) = a + 4; break;
      case Corruption::oob_size: *slot(r, 0) = h->data_size; break;
      case Corruption::oob_past: *slot(r, 0) = h->data_size + 8; break;
      case Corruption::oob_wrap: *slot(r, 0) = 0xFFFFFFF8u; break;  // off + 8 wraps
      case Corruption::oob_huge: *slot(r, 0) = 0xFFFFFFFFu; break;
      case Corruption::len_zero: st64(datum(r, a), 0); break;        // re-tiles with an empty body
      case Corruption::len_small: st64(datum(r, a), 4); break;
      case Corruption::len_huge: st64(datum(r, a), h->data_size); break;
      case Corruption::truncate: h->data_size -= 8; break;
      case Corruption::grow: h->data_size += 8; break;
      case Corruption::sidecar_overlap: *coll_offset(r, 0) = offs.front() + 16; break;
      case Corruption::sidecar_oob: *coll_offset(r, 0) = h->data_size + 4; break;
      case Corruption::sidecar_dup: *coll_offset(r, 0) = *coll_offset(r, 1); break;
      case Corruption::unchain: st64(datum(r, a), 16); break;        // the chain skips ahead
    }
}

void random_mutate(std::vector<uint8_t>& r, std::mt19937_64& rng, uint32_t lo, uint32_t hi) {
    if (lo + 8 >= hi) return;
    std::uniform_int_distribution<uint32_t> pos(lo, hi - 1);
    std::uniform_int_distribution<uint32_t> kind(0, 3);
    const uint32_t p = pos(rng);
    if (kind(rng) == 0) {
        r[p] ^= static_cast<uint8_t>(uint8_t{1} << (rng() % 8));
    } else {
        const uint32_t w = p & ~uint32_t{7};
        const uint64_t v = ld64(r.data() + w);
        const uint64_t d = (rng() % 4 == 0) ? rng() : (rng() % 64) + 1;
        st64(r.data() + w, v ^ d);
    }
}

std::vector<uint8_t> load_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> b{std::istreambuf_iterator<char>{f}, std::istreambuf_iterator<char>{}};
    b.resize(b.size() + kSlack, 0);  // a vector's data is 8-aligned, as the guest's sections are
    return b;
}

}  // namespace

TEST_CASE("mphf tile equiv: hand-made maps", "[common_zz][mphf]") {
    const Corruption all[] = {
        Corruption::none, Corruption::swap, Corruption::overlap, Corruption::overlap2,
        Corruption::gap, Corruption::duplicate, Corruption::misalign_1, Corruption::misalign_4,
        Corruption::oob_size, Corruption::oob_past, Corruption::oob_wrap, Corruption::oob_huge,
        Corruption::len_zero, Corruption::len_small, Corruption::len_huge, Corruption::truncate,
        Corruption::grow, Corruption::sidecar_overlap, Corruption::sidecar_oob,
        Corruption::sidecar_dup, Corruption::unchain,
    };
    for (const auto& [n, sc] : std::vector<std::pair<size_t, size_t>>{
             {0, 0}, {1, 0}, {2, 0}, {5, 2}, {40, 0}, {40, 9}, {200, 33}}) {
        const bool two = n >= 2;
        for (const auto c : all) {
            const bool needs_two = c == Corruption::swap || c == Corruption::unchain;
            const bool needs_sc = c == Corruption::sidecar_overlap || c == Corruption::sidecar_oob;
            const bool needs_2sc = c == Corruption::sidecar_dup;
            if (needs_two && !two) continue;
            if (needs_sc && sc < 1) continue;
            if (needs_2sc && sc < 2) continue;
            auto r = make_map(chain(n, std::min(sc, n)));
            apply(r, c);
            check_tiles(r, "entries=" + std::to_string(n) + " sidecars=" + std::to_string(sc) +
                               " corrupt=" + std::to_string(static_cast<int>(c)));
        }
    }
    // Bodies shorter than any key: the tile chains over them, the caller's validate is the gate.
    for (const uint32_t len : {0u, 1u, 7u, 8u, 31u, 32u, 33u}) {
        std::vector<CraftedEntry> e(3);
        for (auto& x : e) { x.len = 32; x.bytes = 32; }
        e[1].len = len;
        e[1].bytes = std::min(len, 32u);
        auto r = make_map(e);
        check_tiles(r, "short body len=" + std::to_string(len));
    }
    // Nothing referred: all slots the 0 sentinel, and an empty map.
    {
        auto r = make_map(chain(3));
        for (uint32_t i = 0; i < hdr(r)->n_keys; ++i) *slot(r, i) = 0;
        check_tiles(r, "all sentinel");
        auto empty = make_map({});
        check_tiles(empty, "empty map");
    }
}

TEST_CASE("mphf tile equiv: random mutations", "[common_zz][mphf]") {
    std::mt19937_64 rng{0x106u};
    for (uint32_t i = 0; i < 10000; ++i) {
        auto r = make_map(chain(20, 4));
        random_mutate(r, rng, 0, static_cast<uint32_t>(r.size()) - kSlack);
        check_verdict<32>(r, "crafted20 #" + std::to_string(i));
    }
    for (uint32_t i = 0; i < 10000; ++i) {
        auto r = make_map(chain(3, 1));
        random_mutate(r, rng, 0, static_cast<uint32_t>(r.size()) - kSlack);
        check_verdict<32>(r, "crafted3sc #" + std::to_string(i));
    }
}

TEST_CASE("mphf tile equiv: real bundle stores", "[common_zz][mphf]") {
    const char* dir = std::getenv("Z6M_IT106_TESTDATA");
    if (dir == nullptr) {
        WARN("Z6M_IT106_TESTDATA unset: real-store cases skipped");
        return;
    }
    int loaded = 0;
    for (const auto* blk : {"24521911", "24545494", "24493658"}) {
        const auto blob = load_file(std::string(dir) + "/real_" + blk + ".bin");
        const auto node = load_file(std::string(dir) + "/real_" + blk + "_node.bin");
        if (blob.empty() || node.empty()) {
            WARN("missing fixture for " << blk);
            continue;
        }
        ++loaded;
        struct Meta {  // PreStateMeta's leading fields
            uint32_t magic, version, n_accounts, n_block_hashes, prestate_offset,
                addr_hashes_offset, block_hashes_offset, code_store_offset, code_store_size;
        };
        const auto& m = *reinterpret_cast<const Meta*>(blob.data());
        const auto slice = [](const std::vector<uint8_t>& b, uint32_t off, uint32_t size) {
            std::vector<uint8_t> out(b.begin() + off, b.begin() + off + size);
            out.resize(out.size() + kSlack, 0);
            return out;
        };
        const uint32_t addr_size = m.addr_hashes_offset - m.prestate_offset;
        std::vector<uint8_t> addr, code{slice(blob, m.code_store_offset, m.code_store_size)}, ns;
        if (m.n_accounts > 0) addr = slice(blob, m.prestate_offset, addr_size);
        ns = node;
        if (m.n_accounts > 0) check_verdict<20>(addr, "real addr map");
        check_verdict<32>(code, "real code store");
        check_verdict<32>(ns, "real node store");

        std::mt19937_64 rng{static_cast<std::mt19937_64::result_type>(0x900d + static_cast<uint64_t>(loaded))};
        for (uint32_t i = 0; i < 10000; ++i) {
            auto c = code;
            random_mutate(c, rng, 0, m.code_store_size);
            check_verdict<32>(c, "real code #" + std::to_string(i));
        }
        if (m.n_accounts > 0) {
            for (uint32_t i = 0; i < 10000; ++i) {
                auto c = addr;
                random_mutate(c, rng, 0, addr_size);
                check_verdict<20>(c, "real addr #" + std::to_string(i));
            }
        }
        const uint32_t node_size = static_cast<uint32_t>(node.size() - kSlack);
        for (uint32_t i = 0; i < 10000; ++i) {
            auto c = ns;
            random_mutate(c, rng, 0, node_size);
            check_verdict<32>(c, "real node #" + std::to_string(i));
        }
    }
    REQUIRE(loaded > 0);
}
