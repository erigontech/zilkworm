// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include "rust/cxx.h"

#include <cstdint>
#include <array>
#include <iostream>
#include <sstream>
#include "include/sp1_syscalls.hpp"

/* These magic symbols are provided by the linker.  */
extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);
extern void (*__fini_array_start[])(void);
extern void (*__fini_array_end[])(void);

extern "C" uint64_t sample_run_wrapped(rust::Vec<uint8_t> envelope_vec)
{
    // SP1's _start doesn't run global ctors.
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
    {
        (*p)();
    }
    for (auto p = __init_array_start; p != __init_array_end; ++p)
    {
        (*p)();
    }
    sys_println("\nZilkworm guest initialized");

    silkworm::ByteView view(envelope_vec.data(), envelope_vec.size());
    auto state_transition = silkworm::cmd::state_transition::StateTransition(view);
    auto msg = "state_transition object initialized input size: " + std::to_string(envelope_vec.size());
    sys_println(msg.c_str());
    uint64_t res = state_transition.run();

    if (state_transition.failed())
    {
        std::string done_msg = "[state_transition] FAILED, gas used: " + std::to_string(res);
        sys_println(done_msg.c_str());
        return res;
    }

    std::string done_msg = "[state_transition] run successful, gas used: " + std::to_string(res);
    sys_println(done_msg.c_str());
    return res;
}
