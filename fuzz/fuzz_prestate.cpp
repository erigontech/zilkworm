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
    if (size < 64 || size > (1u << 20)) {
        return 0;
    }
    static thread_local std::vector<uint8_t> buf;
    buf.assign(data, data + size);

    // Split into a prestate blob and a node-store blob; 8-align the boundary as the
    // bundle layout does.
    size_t mid = size / 2;
    mid &= ~size_t{7};
    DirectState st{std::span<uint8_t>{buf.data(), mid},
                   std::span<uint8_t>{buf.data() + mid, size - mid}};

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
