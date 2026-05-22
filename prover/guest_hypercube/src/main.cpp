#include <zilk_core/dev/state_transition.hpp>
#include "include/sp1_syscalls.hpp"
#include <cstdint>
#include <cstring>
#include <format>

// Stdin/Stdout full spec in `docs/architecture.md` "Bundle format" and "Public output".

namespace {

uint32_t read_u32_le(const uint8_t*& p) {
    uint32_t v;
    std::memcpy(&v, p, 4);
    p += 4;
    return v;
}

void write_u32_le(uint32_t v) {
    uint8_t bytes[4];
    std::memcpy(bytes, &v, 4);
    syscall_write(SP1_FD_PUBLIC_VALUES, bytes, 4);
}

void write_u64_le(uint64_t v) {
    uint8_t bytes[8];
    std::memcpy(bytes, &v, 8);
    syscall_write(SP1_FD_PUBLIC_VALUES, bytes, 8);
}

}  // namespace

extern "C" int main()
{
    ReadVecResult input_buf = read_vec_raw();

    sys_println("Zilkworm guest initialized");

    const uint8_t* p = input_buf.ptr;
    const uint32_t n = read_u32_le(p);
    write_u32_le(n);

    using silkworm::cmd::state_transition::StateTransition;
    for (uint32_t i = 0; i < n; i++) {
        const uint32_t len = read_u32_le(p);
        silkworm::ByteView view(p, len);
        p += len;

        auto st = StateTransition(view);
        const uint64_t result = st.run_rlp();

        if (result == StateTransition::kRunFailure) {
            sys_println(std::format("[state_transition] subtest {}: FAILED", i));
        } else if (result == StateTransition::kRunSkipped) {
            sys_println(std::format("[state_transition] subtest {}: SKIPPED", i));
        }

        write_u64_le(result);
    }

    return 0;
}
