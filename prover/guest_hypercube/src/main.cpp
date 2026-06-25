// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>

#include "include/sp1_syscalls.hpp"

#include <cstdint>
#include <format>
#include <span>
#include <string>

extern "C" int main()
{
    ReadVecResult input_buf = read_vec_raw();

    sys_println("Zilkworm guest initialized");

    std::span<uint8_t> envelope{input_buf.ptr, input_buf.len};
    auto st = silkworm::cmd::state_transition::StateTransition(envelope);
    uint64_t result = st.run();

    uint8_t result_bytes[8];
    for (int i = 0; i < 8; i++)
        result_bytes[i] = static_cast<uint8_t>(result >> (i * 8));

    syscall_write(SP1_FD_PUBLIC_VALUES, result_bytes, 8);

    if (st.failed()) {
        sys_println(std::format("[state_transition] FAILED, gas used: {}", result));
        return 1;
    }

    sys_println(std::format("[state_transition] run successful, gas used: {}", result));
    return 0;
}
