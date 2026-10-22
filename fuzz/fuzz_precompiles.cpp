// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the precompiles, through evmone::state::call_precompile —
// the production dispatch every EVM frame goes through (input parsing, gas analysis,
// output sizing and execution for all 18 precompiles). Plus a differential: ecrecover
// through z6m's ecrec_run (silkworm_recover_address) and through evmone's
// secp256k1::ecrecover (strict, EIP-2 low-s) must agree.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <test/state/precompiles.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/execution/precompile.hpp>

using namespace silkworm;

namespace {

[[gnu::noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "FUZZPRECOMPILE: %s\n", what);
    std::abort();
}

/// Zero-padded first 128 bytes, as every ecrecover implementation reads them.
std::array<uint8_t, 128> pad128(ByteView input) noexcept {
    std::array<uint8_t, 128> d{};
    if (!input.empty()) {
        std::memcpy(d.data(), input.data(), std::min(input.size(), d.size()));
    }
    return d;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 4096) {
        return 0;
    }
    const ByteView input{data, size};

    // ---- ecrecover differential: z6m's ecrec_run vs evmone's production dispatch ----
    {
        const auto d = pad128(input);
        const auto z6m_out = precompile::ecrec_run(input);
        const bool z6m_ok = z6m_out.has_value() && !z6m_out->empty();

        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = 1 << 20;
        msg.code_address.bytes[19] = 1;  // ecrecover, enabled in every revision
        msg.input_data = d.data();
        msg.input_size = d.size();
        const auto evm = evmone::state::call_precompile(EVMC_CANCUN, msg);
        const bool evm_ok =
            evm.status_code == EVMC_SUCCESS && evm.output_size == 32;

        if (z6m_ok != evm_ok) {
            fail("ecrecover disagreement: success mismatch");
        }
        if (z6m_ok) {
            // Both write the 20-byte address at [12..32) of a zero-padded 32-byte output.
            if (std::memcmp(z6m_out->data() + 12, evm.output_data + 12, 20) != 0) {
                fail("ecrecover disagreement: address mismatch");
            }
        }
    }

    // ---- the production precompile dispatch, all 18 precompiles ----
    if (size >= 6) {
        evmc_message msg{};
        msg.kind = EVMC_CALL;
        msg.gas = static_cast<int64_t>(data[0]) << 16;  // 0..~16M gas, never negative
        const evmc_revision rev = static_cast<evmc_revision>(data[2] % 12);
        msg.code_address.bytes[19] = static_cast<uint8_t>(data[1] % 18 + 1);  // precompile 1..18
        // The production path calls call_precompile only after is_precompile() passed;
        // mirror that guard (the dispatch table has null entries otherwise).
        if (!evmone::state::is_precompile(rev, msg.code_address)) {
            return 0;
        }
        msg.input_data = data + 6;
        msg.input_size = size - 6;
        const auto result = evmone::state::call_precompile(rev, msg);
        (void)result;
    }

    return 0;
}
