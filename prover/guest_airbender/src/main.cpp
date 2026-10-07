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
    // Single input blob: an envelope self-described by its leading 4-byte
    // magic — MFBD (flat witness bundle) or EJSN (minified EEST JSON test).
    auto [buf, len] = airbender::read_input_from_csr();

    using silkworm::cmd::state_transition::StateTransition;
    auto st = StateTransition(std::span<uint8_t>{buf, len});
    const auto r = st.run();
    const uint64_t result = r.gas_used;

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

    // The public output is the hash of the last block the run validated, its bytes in order as
    // little-endian words (zero when no block was validated: EJSN tests, skipped runs). The hash
    // binds that block's chain: its bundle's pre-state is anchored at the state root of the header
    // the first block's parent hash names, every later block must extend the one before it, and
    // each header's state root and gas used are checked against the execution.
    uint32_t out[8];
    std::memcpy(out, r.block_hash.bytes, sizeof(out));
    airbender::finish_success(out);
}
