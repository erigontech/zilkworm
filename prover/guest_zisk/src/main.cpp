// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

#include "include/zisk_syscalls.hpp"

#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string>

extern "C" int main()
{
    using namespace silkworm;

    const ZiskInput input = zisk_read_input();

    sys_println("Zilkworm guest initialized");

    std::span<uint8_t> envelope{input.ptr, input.len};
    auto st = cmd::state_transition::StateTransition(envelope);
    const auto r = st.run();

    // Public values: see docs/architecture.md
    uint8_t pv[112];
    static_assert(sizeof(pv) <= zisk::kPublicSlots * 4);
    auto store_u64_le = [](uint8_t* dst, uint64_t value) {
        for (int i = 0; i < 8; i++)
            dst[i] = static_cast<uint8_t>(value >> (i * 8));
    };

    store_u64_le(pv, r.gas_used);
    std::memcpy(pv + 8, r.pre_state_root.bytes, 32);
    std::memcpy(pv + 40, r.post_state_root.bytes, 32);
    std::memcpy(pv + 72, r.block_hash.bytes, 32);
    store_u64_le(pv + 104, r.chain_id);
    zisk_commit_public(pv, sizeof(pv));

    if (st.failed()) {
        if (r.block_hash != kZeroHash) {
            sys_println(std::format("[state_transition] FAILED, gas used: {}, block hash: {}",
                                    r.gas_used, to_hex(r.block_hash)));
        } else {
            sys_println(std::format("[state_transition] FAILED, gas used: {}", r.gas_used));
        }
        return 1;
    }

    if (r.block_hash != kZeroHash) {
        sys_println(std::format(
            "[state_transition] run successful, gas used: {}, block hash: {}, pre-state root: {}, post-state root: {}",
            r.gas_used, to_hex(r.block_hash), to_hex(r.pre_state_root), to_hex(r.post_state_root)));
    } else {
        sys_println(std::format("[state_transition] run successful, gas used: {}", r.gas_used));
    }
    return 0;
}
