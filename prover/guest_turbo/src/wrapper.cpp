// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include "rust/cxx.h"

#include <cstdint>
#include <array>
#include <cstring>
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

// sp1_zkvm's own syscall_halt (which commits the public-values digest before
// the HALT ecall) is private to the crate, so the C-side name has no Rust
// definition to bind to. The C++ guest only reaches halt on fatal paths inside
// zilk_core — paths whose proofs would be discarded — so issue the bare HALT
// ecall (number 0) without the digest commit.
extern "C" [[noreturn]] void syscall_halt(uint8_t exit_code)
{
    register uint32_t t0 asm("t0") = 0;  // SP1 syscall number: HALT
    register uint32_t a0 asm("a0") = exit_code;
    asm volatile("ecall" : : "r"(t0), "r"(a0));
    __builtin_unreachable();
}

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
    auto state_transition = silkworm::cmd::state_transition::StateTransition(
        std::span<uint8_t>(const_cast<uint8_t *>(envelope_vec.data()), envelope_vec.size()));
    auto msg = "state_transition object initialized input size: " + std::to_string(envelope_vec.size());
    sys_println(msg.c_str());
    const auto result = state_transition.run();
    const uint64_t gas_used = result.gas_used;

    // Commit the same 112-byte public values the HyperCube guest writes
    // (guest_hypercube/src/main.cpp): gas_used u64 LE at offset 0 (so a reader
    // that reads one u64 is unaffected), then the roots, block hash and chain
    // id that bind the proof to a concrete state transition. SP1 stdin is
    // private, so without these the proof attests only "some input returned
    // gas G".
    {
        uint8_t pv[112];
        for (int i = 0; i < 8; ++i)
            pv[i] = static_cast<uint8_t>(gas_used >> (i * 8));
        std::memcpy(pv + 8, result.pre_state_root.bytes, 32);
        std::memcpy(pv + 40, result.post_state_root.bytes, 32);
        std::memcpy(pv + 72, result.block_hash.bytes, 32);
        const uint64_t chain_id = result.chain_id;
        for (int i = 0; i < 8; ++i)
            pv[104 + i] = static_cast<uint8_t>(chain_id >> (i * 8));
        syscall_write(SP1_FD_PUBLIC_VALUES, pv, sizeof(pv));
    }

    if (state_transition.failed())
    {
        std::string done_msg = "[state_transition] FAILED, gas used: " + std::to_string(gas_used);
        sys_println(done_msg.c_str());
        return gas_used;
    }

    std::string done_msg = "[state_transition] run successful, gas used: " + std::to_string(gas_used);
    sys_println(done_msg.c_str());
    return gas_used;
}
