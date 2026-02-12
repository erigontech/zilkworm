#include <zilk_core/dev/state_transition.hpp>
#include <cstdint>
#include <array>
#include <string>

#include "include/airbender_csr.hpp"
#include "include/quasi_uart.hpp"

extern "C"
{
    // Boundaries of the heap
    extern uint32_t _sheap;
    extern uint32_t _eheap;

    // Boundaries of the stack
    extern uint32_t _sstack;
    extern uint32_t _estack;

    // Boundaries of the .data section (and it's part in ROM)
    extern uint32_t _sidata;
    extern uint32_t _sdata;
    extern uint32_t _edata;

    // Boundaries of the .rodata section
    extern uint32_t _sirodata;
    extern uint32_t _srodata;
    extern uint32_t _erodata;
}

extern "C" void eh_personality() {}

struct MachineTrapFrame
{
    uint32_t registers[32];
};

extern "C" [[noreturn]] void _start_rust() __attribute__((section(".init.rust")));
extern "C" uint32_t _machine_start_trap_rust(MachineTrapFrame *) __attribute__((section(".trap.rust")));

static constexpr uint32_t kModulus = 7919;

static void copy_section(const uint8_t *src, uint8_t *dst, const uint8_t *end)
{
    while (dst < end)
    {
        *dst++ = *src++;
    }
}

static void init_memory()
{
    // Copy .rodata section from ROM to RAM
    const uint8_t *sirodata = reinterpret_cast<const uint8_t *>(&_sirodata);
    uint8_t *srodata = reinterpret_cast<uint8_t *>(&_srodata);
    const uint8_t *erodata = reinterpret_cast<const uint8_t *>(&_erodata);
    if (srodata < erodata)
    {
        copy_section(sirodata, srodata, erodata);
    }

    // Copy .data section from ROM to RAM
    uint8_t *sdata = reinterpret_cast<uint8_t *>(&_sdata);
    const uint8_t *edata = reinterpret_cast<const uint8_t *>(&_edata);
    if (sdata < edata)
    {
        copy_section(reinterpret_cast<const uint8_t *>(&_sidata), sdata, edata);
    }
}

namespace
{
    uint64_t run_json_test(const std::string &json_str)
    {
        const auto terminate_on_error = false;
        const auto show_diagnostics = true;
        auto state_transition = silkworm::cmd::state_transition::StateTransition(json_str, terminate_on_error, show_diagnostics);
        return state_transition.run();
    }

    uint64_t run_unified_rlp(const std::string &unified_rlp_str)
    {
        auto state_transition = silkworm::cmd::state_transition::StateTransition(unified_rlp_str);
        // Run the state transition function of silkworm - EVMONE - silkworm_validate_transition and back
        auto res = state_transition.run_rlp();
        std::string msg = "[state_transition] run successful, gas used: " + std::to_string(res);
        sys_println(msg.c_str());
        return res;
    }
}

static std::string read_blob_string_from_csr()
{
    uint32_t num_bytes = airbender::csr_read_word();
    sys_println("File size");
    sys_println(std::to_string(num_bytes));
    std::string result;
    result.resize(static_cast<size_t>(num_bytes));

    size_t written = 0;
    size_t words = (num_bytes + 3) / 4;
    for (size_t i = 0; i < words; ++i)
    {
        uint32_t word = airbender::csr_read_word();
        for (size_t j = 0; j < 4 && written < num_bytes; ++j)
        {
            result[written] = static_cast<char>((word >> (8 * j)) & 0xFFu);
            ++written;
        }
    }
    sys_println("[dbg] read done, written=");
    sys_println(std::to_string(written));
    return result;
}

[[noreturn]] static void workload()
{
    auto input_string = read_blob_string_from_csr();
    uint32_t out[8] = {29, 8, 0, 0, 0, 0, 0, 0};
    airbender::finish_success(out);
}

extern "C" [[noreturn]] void _start_rust()
{
    init_memory();
    workload();
}

extern "C" uint32_t _machine_start_trap_rust(MachineTrapFrame *)
{
    while (true)
    {
    }
}