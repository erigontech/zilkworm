// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include "rust/cxx.h"

// bn254_add.hpp
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

extern "C" uint64_t sample_run_wrapped(bool is_test, rust::Vec<uint8_t> rlp_or_json_input_vec)
{
    std::string json_str;
    // Call global constructors because SP1's _start function doesn't.
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
    {
        (*p)();
    }
    for (auto p = __init_array_start; p != __init_array_end; ++p)
    {
        (*p)();
    }
    sys_println("\nZilkworm guest initialized");
    uint64_t res = 0;
    if (is_test)
    {
        json_str = std::string(reinterpret_cast<const char *>(rlp_or_json_input_vec.data()), rlp_or_json_input_vec.size());
        auto state_transition = silkworm::cmd::state_transition::StateTransition(json_str, false, true);
        auto msg = "state_transition object initialized input size: " + std::to_string(json_str.size());
        sys_println(msg.c_str());
        res = state_transition.run();
    }
    else
    {
        silkworm::ByteView view(rlp_or_json_input_vec.data(), rlp_or_json_input_vec.size());
        auto state_transition = silkworm::cmd::state_transition::StateTransition(view);
        res = state_transition.run_rlp();
    }
    std::string msg = "[state_transition] run successful, gas used: " + std::to_string(res);
    sys_println(msg.c_str());
    return res;
}

// #include "tests/sp1_syscalls_tests.cpp"

// extern "C" uint64_t sample_run_wrapped(uint32_t n, rust::Str jsonStr1) {
//     run_sp1_basic_smoke_tests();
//     run_sp1_crypto_shape_tests();
//     // return uint32_t(P.at(0));
//     return 0;
// }
