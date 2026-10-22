// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the whole stateless-transition envelope: the same entry the
// zkVM guest exposes. The first bytes select the input kind (SIB 0x1501 / EJSN
// 'EJSN' / MFBD 'MFBD' envelopes, or a bare FBND bundle), and everything after is
// attacker controlled. No proofs are produced here — this runs block execution and
// witness validation only.

#include <cstdint>
#include <span>
#include <vector>

#include <zilk_core/dev/state_transition.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > (1u << 24)) {
        return 0;  // Skip absurd sizes: the guest's inputs are bounded by the witness caps.
    }
    // The envelope parsers hold ByteViews into the input; a mutable copy with stable
    // alignment mirrors how the host loads a bundle file.
    static thread_local std::vector<uint8_t> buf;
    buf.assign(data, data + size);
    silkworm::cmd::state_transition::StateTransition st{std::span<uint8_t>{buf.data(), buf.size()}};
    const auto result = st.run();
    (void)result;
    return 0;
}
