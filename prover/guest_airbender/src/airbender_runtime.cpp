// Airbender zkVM bare-metal runtime.
// Handles memory init, trap handler, and calls main().

#include <cstdint>

#include "include/airbender_csr.hpp"

extern "C"
{
    // Linker-provided section boundaries
    extern uint32_t _sheap, _eheap;
    extern uint32_t _sstack, _estack;
    extern uint32_t _sidata, _sdata, _edata;
    extern uint32_t _sirodata, _srodata, _erodata;

    // C++ global constructor/destructor arrays (from .init_array/.fini_array)
    extern void (*__preinit_array_start[])(void);
    extern void (*__preinit_array_end[])(void);
    extern void (*__init_array_start[])(void);
    extern void (*__init_array_end[])(void);
}

extern "C" void eh_personality() {}

int main();

struct MachineTrapFrame { uint32_t registers[32]; };

extern "C" [[noreturn]] void _start_rust() __attribute__((section(".init.rust")));
extern "C" uint32_t _machine_start_trap_rust(MachineTrapFrame*) __attribute__((section(".trap.rust")));

static void copy_section(const uint8_t* src, uint8_t* dst, const uint8_t* end)
{
    while (dst < end)
        *dst++ = *src++;
}

static void init_memory()
{
    const uint8_t* sirodata = reinterpret_cast<const uint8_t*>(&_sirodata);
    uint8_t* srodata = reinterpret_cast<uint8_t*>(&_srodata);
    const uint8_t* erodata = reinterpret_cast<const uint8_t*>(&_erodata);
    if (srodata < erodata)
        copy_section(sirodata, srodata, erodata);

    uint8_t* sdata = reinterpret_cast<uint8_t*>(&_sdata);
    const uint8_t* edata = reinterpret_cast<const uint8_t*>(&_edata);
    if (sdata < edata)
        copy_section(reinterpret_cast<const uint8_t*>(&_sidata), sdata, edata);
}

static void run_global_constructors()
{
    for (auto p = __preinit_array_start; p != __preinit_array_end; ++p)
        (*p)();
    for (auto p = __init_array_start; p != __init_array_end; ++p)
        (*p)();
}

extern "C" [[noreturn]] void _start_rust()
{
    init_memory();
    run_global_constructors();
    main();
}

extern "C" uint32_t _machine_start_trap_rust(MachineTrapFrame*)
{
    while (true) {}
}
