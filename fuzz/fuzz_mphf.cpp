// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the MphfMap layer: validate_mphf is the layout contract and
// every read after it is unchecked, so the harness validates a hostile blob (with an
// attacker-chosen map magic), and on success performs lookups and full-entry sweeps
// through the unchecked paths — which must stay inside the validated bounds.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <zilk_core/core/common_zz/index_key.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using namespace zilkworm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16 || size > (1u << 20)) {
        return 0;
    }
    static thread_local std::vector<uint8_t> buf;
    buf.assign(data, data + size);

    // The LAST byte picks one of the three map magics the readers use; the region
    // starts at the buffer (the 8-alignment the maps require).
    uint32_t magic = kMphfAddrMapMagic;
    switch (buf[size - 1] % 3) {
        case 1: magic = kMphfCodeStoreMagic; break;
        case 2: magic = kMphfNodeStoreMagic; break;
        default: break;
    }

    if (!validate_mphf<32>(std::span<const uint8_t>{buf.data(), size}, 0,
                           static_cast<uint32_t>(size), magic)) {
        return 0;
    }

    const MphfMap map{reinterpret_cast<MphfMapHeader*>(buf.data())};

    // Lookups keyed by hashes derived from the input: the unchecked index_lookup and
    // find paths must never leave the validated region.
    for (size_t i = 0; i < 8 && i + 4 <= size; ++i) {
        const size_t off = (i * (size / 8)) & (size - 4);
        const size_t len = std::min(size - off, size_t{64});
        const auto h = silkworm::keccak256(ByteView{buf.data() + off, len});
        uint8_t key[32];
        std::memcpy(key, h.bytes, 32);
        const auto found = map.find<32, 0, &hash_key8>(key);
        if (found) {
            // A validated entry's body must not run past the buffer.
            if (found->data() + found->size() > buf.data() + size) {
                std::abort();
            }
        }
    }

    // Sweep every entry the map advertises: the same walk the validators and the
    // DirectState code-store seal use.
    map.for_each<32, 0>([&](const uint8_t*, std::span<uint8_t> body) noexcept {
        if (body.data() + body.size() > buf.data() + size) {
            std::abort();
        }
    });

    return 0;
}
