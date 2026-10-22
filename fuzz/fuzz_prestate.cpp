// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the DirectState (MFBD prestate) parser: the 'PRES' blob and
// the node-store MphfMap are fully attacker-controlled here. After construction the
// harness binds the witness (sanitize) and performs account/storage/code/node reads
// keyed by keccak256 of input-derived slices, exercising the lazy-verify read paths.

#include <cstdint>
#include <cstring>
#include <vector>

#include <evmc/evmc.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

using namespace zilkworm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 68 || size > (1u << 26)) {
        return 0;
    }
    static thread_local std::vector<uint8_t> buf;
    buf.assign(data, data + size);

    // [u32 LE prestate_size + 4 pad][prestate blob][node-store blob]: the payload
    // starts 8-aligned, as the bundle layout requires. The bundles concatenate the
    // two sections this way; a mutated boundary is part of the input space.
    uint32_t prestate_size{0};
    std::memcpy(&prestate_size, buf.data(), sizeof(prestate_size));
    if (prestate_size < 8 || prestate_size > size - 8) {
        return 0;
    }
    const std::span<uint8_t> prestate{buf.data() + 8, prestate_size};
    const std::span<uint8_t> nodestore{buf.data() + 8 + prestate_size, size - 8 - prestate_size};
    // The constructor aborts on a malformed blob (the guest fails the proof; there is
    // no graceful path yet), so the layout validators are applied here first: fuzzing
    // targets the read paths of blobs that pass validation, and validate_mphf itself
    // (called by these) is what sweeps hostile layouts.
    if (!validate_prestate_layout(prestate) || !validate_nodestore_layout(nodestore)) {
        return 0;
    }
    DirectState st{prestate, nodestore};

    if (!st.sanitize()) {
        return 0;
    }

    // Reads keyed by hashes derived from the input itself.
    for (size_t i = 0; i < 8 && i + 4 <= size; ++i) {
        const size_t off = (i * (size / 8)) & (size - 4);
        const size_t len = std::min(size - off, size_t{64});
        const auto h = silkworm::keccak256(ByteView{buf.data() + off, len});

        evmc::address addr{};
        std::memcpy(addr.bytes, h.bytes, sizeof(addr.bytes));
        evmc::bytes32 key{};
        std::memcpy(key.bytes, h.bytes, sizeof(key.bytes));
        const Account* pa = st.read_account(addr);
        if (pa != nullptr) {
            (void)st.read_storage(addr, key);
            (void)st.read_code(addr);
        }
        (void)st.find_node_rlp(key);
    }

    return 0;
}
