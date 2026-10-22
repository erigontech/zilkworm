// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0

// libFuzzer harness for the SLIB (statelessInputBytes, EIP-8025) path: the SSZ
// structural decoder, the NewPayloadRequest decoder, feeding the witness nodes and
// codes into a HashState, and the trie build anchored at the payload's state root.

#include <cstdint>

#include <evmc/evmc.hpp>
#include <zilk_core/core/state_zz/hash_state.hpp>
#include <zilk_core/core/state_zz/slib_input.hpp>
#include <zilk_core/core/state_zz/slib_payload.hpp>

using namespace zilkworm;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > (1u << 24)) {
        return 0;  // The schema caps keep real inputs far below this.
    }
    const ByteView blob{data, size};

    // Structural decode (never reads out of bounds on its own).
    const auto input = decode_stateless_input(blob);
    if (!input) {
        return 0;
    }

    HashState hs;
    const auto parsed = parse_stateless_input(blob, hs);
    if (!parsed) {
        return 0;
    }

    // The payload's own state root anchors the trie build when it decodes.
    evmc::bytes32 prev_root{};
    if (const auto payload = decode_slib_payload(input->new_payload_request); payload) {
        prev_root = payload->state_root;
    }
    const auto run = run_slib(blob, hs, prev_root);
    (void)run;
    return 0;
}
