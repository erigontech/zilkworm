// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

#include "include/sp1_syscalls.hpp"

#include <cstdint>
#include <format>
#include <span>
#include <string>

extern "C" int main()
{
    using namespace silkworm;

    ReadVecResult input_buf = read_vec_raw();

    sys_println("Zilkworm guest initialized");

    std::span<uint8_t> envelope{input_buf.ptr, input_buf.len};
    auto st = cmd::state_transition::StateTransition(envelope);
    const auto r = st.run();

    // Committed Public Values (see docs/architecture.md for details)
    auto syscall_write_u64_le = [](uint64_t value) {
        uint8_t le_bytes8[8];
        for (int i = 0; i < 8; i++)
            le_bytes8[i] = static_cast<uint8_t>(value >> (i * 8));
        syscall_write(SP1_FD_PUBLIC_VALUES, le_bytes8, 8);
    };

    if (r.sib) {
        // SSZ StatelessValidationResult: the harness compares these 43 bytes with statelessOutputBytes.
        syscall_write(SP1_FD_PUBLIC_VALUES, r.new_payload_request_root.bytes, 32);
        const uint8_t ok = r.successful_validation ? 1 : 0;
        syscall_write(SP1_FD_PUBLIC_VALUES, &ok, 1);
        syscall_write_u64_le(r.chain_id);
        const uint8_t schema_le[2] = {static_cast<uint8_t>(r.schema_id), static_cast<uint8_t>(r.schema_id >> 8)};
        syscall_write(SP1_FD_PUBLIC_VALUES, schema_le, 2);
        sys_println(std::format("[state_transition] stateless input: valid={}, gas used: {}, block hash: {}",
                                r.successful_validation, r.gas_used, to_hex(r.block_hash)));
        return 0;
    }

    syscall_write_u64_le(r.gas_used);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.pre_state_root.bytes, 32);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.post_state_root.bytes, 32);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.block_hash.bytes, 32);
    syscall_write_u64_le(r.chain_id);

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
