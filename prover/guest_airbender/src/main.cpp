// Airbender zkVM guest — Ethereum block execution.

#include <zilk_core/dev/state_transition.hpp>
#include <cstdint>
#include <string>
#include <utility>

#include "include/airbender_csr.hpp"


namespace
{
    uint64_t run_json_test(const std::string& json_str)
    {
        const auto terminate_on_error = false;
        const auto show_diagnostics = true;
        auto st = silkworm::cmd::state_transition::StateTransition(json_str, terminate_on_error, show_diagnostics);
        return st.run();
    }

    uint64_t run_unified_rlp(silkworm::ByteView input)
    {
        auto st = silkworm::cmd::state_transition::StateTransition(input);
        auto res = st.run_rlp();
        std::string msg = "[state_transition] run successful, gas used: " + std::to_string(res);
        sys_println(msg.c_str());
        return res;
    }
}

int main()
{
    auto [buf, len] = airbender::read_input_from_csr();
    silkworm::ByteView bv{buf, len};
    auto result = run_unified_rlp(bv);

    uint32_t out[8] = {static_cast<uint32_t>(result), 8, 0, 0, 0, 0, 0, 0};
    airbender::finish_success(out);
}
