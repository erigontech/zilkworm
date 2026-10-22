// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for the MFBD runner's bundle-cursor overshoot:
//
//   run_mfbd advanced the cursor with `cursor = align8(cursor + bundle_size)`
//   after EVERY bundle, including the last. A bundle whose sections end at a
//   non-8-aligned offset with the envelope ending right there made align8
//   overshoot `end` by up to 7 bytes; the NEXT iteration (n_bundles lying
//   about the count) computed `end - cursor` as a negative ptrdiff that
//   wrapped into a ~2^64-byte span, and load_flat_bundle read its 8-byte
//   header past the envelope. ASAN: heap-buffer-overflow READ at
//   flat_bundle.cpp:151 (the header magic read), reached from
//   state_transition.cpp run_mfbd. See the report for the PoC envelope.
//
//   The fix aligns the cursor only while another bundle follows and rejects
//   an overshoot. A well-formed envelope (bundles 8-aligned inside it) is
//   unchanged: its cursor never overshoots.
//
// Standalone test (no gtest); exit code = failure count.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <print>
#include <span>
#include <vector>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

#include "../state_transition.hpp"

using namespace silkworm;
using silkworm::cmd::state_transition::StateTransition;

namespace {

int g_failures = 0;

void expect_true(bool cond, const char* msg) {
    if (!cond) {
        std::println(stderr, "[FAIL] {}", msg);
        ++g_failures;
    } else {
        std::println("[ ok ] {}", msg);
    }
}

// A decodable genesis Block RLP (all fields zero/empty decode symmetrically).
Bytes genesis_rlp() {
    Block genesis;
    Bytes rlp;
    rlp::encode(rlp, genesis);
    return rlp;
}

// One minimal flat bundle: valid empty prestate (build_blob_from_accounts with no
// accounts), no blocks, no ancestors, network "Mainnet". Its section ends are
// 8-aligned except the network section's: bundle_size == network_off + 7, i.e.
// the bundle's byte size is 7 mod 8 — exactly the shape that used to overshoot.
std::vector<uint8_t> make_bundle() {
    const Bytes g = genesis_rlp();
    const auto prestate = zilkworm::DirectState::build_blob_from_accounts({}, {}, {});
    return zilkworm::build_flat_bundle(ByteView{g}, {}, ByteView{}, prestate, {}, "Mainnet", {}, {});
}

// The MFBD envelope: header + n_bundles + bundle bytes. With trim_last_byte a
// single bundle's trailing pad byte is dropped but n_bundles still claims two:
// the envelope ends exactly where that bundle's sections end, so align8 of the
// consumed size overshoots — the shape the PoC used.
std::vector<uint8_t> make_envelope(const std::vector<uint8_t>& b1, bool trim_last_byte,
                                   size_t n_bundles) {
    std::vector<uint8_t> env;
    const size_t one = b1.size() - (trim_last_byte ? 1 : 0);
    const size_t regions = trim_last_byte ? 1 : n_bundles;
    env.resize(zilkworm::kInputHeaderSizeMFBD + one * regions);
    const uint32_t magic = zilkworm::kInputMagicMFBD;
    const uint32_t version = zilkworm::kInputVersionMFBD;
    const uint64_t n = n_bundles;
    std::memcpy(env.data() + 0, &magic, sizeof(uint32_t));
    std::memcpy(env.data() + 4, &version, sizeof(uint32_t));
    std::memcpy(env.data() + 8, &n, sizeof(uint64_t));
    for (size_t i = 0; i < regions; ++i) {
        std::memcpy(env.data() + zilkworm::kInputHeaderSizeMFBD + one * i, b1.data(), one);
    }
    return env;
}

void run_envelope(const std::vector<uint8_t>& env, bool expect_failure) {
    // Exact-size heap allocation: a std::vector's capacity slack would hide the
    // out-of-bounds header read from ASAN.
    auto buf = std::make_unique_for_overwrite<uint8_t[]>(env.size());
    std::memcpy(buf.get(), env.data(), env.size());
    StateTransition st{std::span<uint8_t>{buf.get(), env.size()}};
    const auto res = st.run();
    if (expect_failure) {
        expect_true(st.failed(), "overshooting envelope is rejected");
        expect_true(res.gas_used == StateTransition::kRunFailure, "overshooting envelope reports kRunFailure");
    } else {
        expect_true(!st.failed(), "well-formed two-bundle envelope still runs");
        expect_true(res.gas_used == 0, "well-formed envelope commits zero gas (no blocks)");
    }
}

}  // namespace

int main() {
    const auto b1 = make_bundle();
    // build_flat_bundle pads the total to 8: with a 7-byte network the last byte is
    // padding, and the bundle's section end (what load_flat_bundle reports as its
    // size) is 7 mod 8.
    expect_true(b1.size() % 8 == 0, "builder output is 8-aligned");
    const auto trimmed = make_envelope(b1, /*trim_last_byte=*/true, /*n_bundles=*/2);
    // The first bundle's consumed size (its section end) is 7 mod 8: align8 of
    // cursor + that size overshoots the envelope end by 1.
    expect_true((b1.size() - 1) % 8 == 7, "the bundle's consumed size is 7 mod 8");
    run_envelope(trimmed, /*expect_failure=*/true);

    // Guard the fix's other half: a well-formed envelope (each bundle padded to 8
    // inside it) with two bundles must still be accepted. Under Z6M_HASH_STATE the
    // MFBD path is disabled fail-closed, so every MFBD input is a failure there.
    const auto full = make_envelope(b1, /*trim_last_byte=*/false, /*n_bundles=*/2);
#ifdef Z6M_HASH_STATE
    run_envelope(full, /*expect_failure=*/true);
#else
    run_envelope(full, /*expect_failure=*/false);
#endif

    return g_failures;
}
