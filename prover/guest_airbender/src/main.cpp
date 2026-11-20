// Airbender zkVM guest — Ethereum block execution.

#include <zilk_core/dev/state_transition.hpp>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>

#include "include/airbender_csr.hpp"
#include "include/airbender_input.hpp"

int main()
{
    // One input blob led by a 4-byte magic: MFBD (flat witness bundle) or EJSN (minified EEST JSON).
    auto [buf, len] = airbender::read_input_from_csr();

    using silkworm::cmd::state_transition::StateTransition;
    auto st = StateTransition(std::span<uint8_t>{buf, len});
    const auto r = st.run();
    const uint64_t result = r.gas_used;

    if (result == StateTransition::kRunFailure || st.failed()) {
        sys_println("[state_transition] run FAILED");
        airbender::finish_error();
    }
    // A skipped run must fail: its zero hash would pass for a legitimate run that validated no block.
    if (result == StateTransition::kRunSkipped) {
        sys_println("[state_transition] run skipped");
        airbender::finish_error();
    }
    std::string msg = "[state_transition] run successful, gas used: " + std::to_string(result);
    sys_println(msg.c_str());

    // The last validated hash (zero if none) binds the run: pre-state anchored, chain and roots checked.
    uint32_t out[8];
    std::memcpy(out, r.block_hash.bytes, sizeof(out));
    airbender::finish_success(out);
}
