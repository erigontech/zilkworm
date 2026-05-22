// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <cstdint>
#include <string>
#include "include/cppextern.hpp"
#include "include/semihosting.hpp"

extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

extern "C" uint64_t sample_run_wrapped(bool is_json, std::string input_str) {
    // SP1's `_start` doesn't run global ctors; do it on first entry.
    static bool inited = false;
    if (!inited) {
        for (auto p = __preinit_array_start; p != __preinit_array_end; ++p) (*p)();
        for (auto p = __init_array_start; p != __init_array_end; ++p) (*p)();
        sys_println("\nZilkworm guest initialized");
        inited = true;
    }

    using silkworm::cmd::state_transition::StateTransition;
    uint64_t res;
    if (is_json) {
        auto state_transition = StateTransition(input_str, /*terminate_on_error=*/false, /*show_diagnostics=*/true);
        res = state_transition.run();
    } else {
        auto state_transition = StateTransition(std::move(input_str));
        res = state_transition.run_rlp();
        std::string msg = "[state_transition] run successful, gas used: " + std::to_string(res);
        sys_println(msg.c_str());
    }

    if (res == StateTransition::kRunFailure) return 1;
    if (res == StateTransition::kRunSkipped) return 2;
    return 0;
}
