// Airbender zkVM guest — Ethereum block execution.

#include <zilk_core/dev/state_transition.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

#include "include/airbender_csr.hpp"

int main()
{
    // Single input blob: an envelope self-described by its leading 4-byte
    // magic — MFBD (flat witness bundle) or EJSN (minified EEST JSON test).
    auto [buf, len] = airbender::read_input_from_csr();

    using silkworm::cmd::state_transition::StateTransition;
    auto st = StateTransition(std::span<uint8_t>{buf, len});
    const uint64_t result = st.run();

    if (result == StateTransition::kRunFailure || st.failed()) {
        sys_println("[state_transition] run FAILED");
        airbender::finish_error();
    }
    if (result == StateTransition::kRunSkipped) {
        sys_println("[state_transition] run skipped");
    } else {
        std::string msg = "[state_transition] run successful, gas used: " + std::to_string(result);
        sys_println(msg.c_str());
    }

    uint32_t out[8] = {static_cast<uint32_t>(result), static_cast<uint32_t>(result >> 32), 0, 0, 0, 0, 0, 0};
    airbender::finish_success(out);
}
