// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <cstdint>
#include <array>
#include <span>
#include <string>
#include "include/semihosting.hpp"

/* These magic symbols are provided by the linker.  */
extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);
extern void (*__fini_array_start[])(void);
extern void (*__fini_array_end[])(void);

extern "C" uint64_t sample_run_wrapped(std::string envelope_str) {
    // SP1's _start doesn't run global ctors.
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p) {
        (*p)();
    }
    for (auto p = __init_array_start; p != __init_array_end; ++p) {
        (*p)();
    }

    sys_println("\nZilkworm guest initialized");

    std::span<uint8_t> env{
        reinterpret_cast<uint8_t*>(envelope_str.data()),
        envelope_str.size()};
    auto state_transition = silkworm::cmd::state_transition::StateTransition(env);
    uint64_t res = state_transition.run();
    std::string msg = "[state_transition] run successful, gas used: " + std::to_string(res);
    sys_println(msg.c_str());
    return res;
}
