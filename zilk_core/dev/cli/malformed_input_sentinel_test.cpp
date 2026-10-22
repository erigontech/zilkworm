// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Regression test for the input-decoder sentinel contract:
//
//   Hostile input used to escape StateTransition::run() as a C++ exception.
//   The native CLI catches in main(), but the GUEST entry (guest_hypercube
//   main.cpp) has no handler, so the exception reached std::terminate and
//   killed the guest: a malformed EJSN envelope (nlohmann::json::parse_error,
//   std::bad_optional_access from from_hex(...).value()) or a small MFBD
//   envelope whose blocks section names a huge count
//   (block_rlps.reserve(n_blocks) throwing before the loop rejects the
//   over-count) crashed the prover instead of reporting kRunFailure.
//
//   run() now catches around its dispatch (failed_ = true, kRunFailure) and
//   load_flat_bundle bounds the reserve by what the section can hold.
//
// Standalone test (no gtest); exit code = failure count.

#include <cstdint>
#include <cstring>
#include <memory>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/types/block.hpp>

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

// Exact-size heap allocation, as a guest's input buffer would be. The buffer must
// outlive the StateTransition (it holds a span into it), so the caller keeps it.
void expect_run_failure(std::string_view bytes, const char* msg) {
    auto buf = std::make_unique_for_overwrite<uint8_t[]>(bytes.size());
    std::memcpy(buf.get(), bytes.data(), bytes.size());
    StateTransition st{std::span<uint8_t>{buf.get(), bytes.size()}};
    const auto res = st.run();
    expect_true(st.failed(), msg);
    expect_true(res.gas_used == StateTransition::kRunFailure, msg);
}

std::string ejsn_envelope(std::string_view json) {
    std::string env;
    env.resize(zilkworm::kInputHeaderSizeEJSN + json.size());
    const uint32_t magic = zilkworm::kInputMagicEJSN;
    const uint32_t version = zilkworm::kInputVersionEJSN;
    std::memcpy(env.data(), &magic, sizeof(uint32_t));
    std::memcpy(env.data() + 4, &version, sizeof(uint32_t));
    std::memcpy(env.data() + zilkworm::kInputHeaderSizeEJSN, json.data(), json.size());
    return env;
}

std::string mfbd_envelope_with_block_count(uint64_t n_blocks, uint32_t blocks_size) {
    // One flat bundle: a decodable genesis and a valid (empty) prestate, so
    // load_flat_bundle reaches the blocks loop; the blocks section is just the u64
    // count of n_blocks.
    Block genesis;
    Bytes genesis_rlp;
    rlp::encode(genesis_rlp, genesis);
    const auto prestate_blob =
        zilkworm::DirectState::build_blob_from_accounts({}, {}, {});
    const auto align8 = [](size_t v) { return (v + 7u) & ~size_t{7u}; };
    const size_t blocks_off = align8(56 + genesis_rlp.size());
    const size_t prestate_off = align8(blocks_off + 8 + blocks_size);
    std::string b;
    b.resize(prestate_off + prestate_blob.size());
    const uint32_t magic = zilkworm::kFlatBundleMagic;
    const uint32_t version = zilkworm::kFlatBundleVersion;
    std::memcpy(b.data() + 0, &magic, sizeof(uint32_t));
    std::memcpy(b.data() + 4, &version, sizeof(uint32_t));
    struct { uint32_t off, size; } secs[6] = {
        {56, static_cast<uint32_t>(genesis_rlp.size())},
        {static_cast<uint32_t>(blocks_off), blocks_size + 8},
        {0, 0},
        {static_cast<uint32_t>(prestate_off), static_cast<uint32_t>(prestate_blob.size())},
        {0, 0}, {0, 0},
    };
    for (int i = 0; i < 6; ++i) {
        std::memcpy(b.data() + 8 + 8 * i, &secs[i].off, 4);
        std::memcpy(b.data() + 8 + 8 * i + 4, &secs[i].size, 4);
    }
    std::memcpy(b.data() + 56, genesis_rlp.data(), genesis_rlp.size());
    std::memcpy(b.data() + blocks_off, &n_blocks, sizeof(uint64_t));
    if (!prestate_blob.empty()) {
        std::memcpy(b.data() + prestate_off, prestate_blob.data(), prestate_blob.size());
    }

    std::string env;
    env.resize(zilkworm::kInputHeaderSizeMFBD + b.size());
    const uint32_t m = zilkworm::kInputMagicMFBD;
    const uint32_t v = zilkworm::kInputVersionMFBD;
    const uint64_t n_bundles = 1;
    std::memcpy(env.data(), &m, sizeof(uint32_t));
    std::memcpy(env.data() + 4, &v, sizeof(uint32_t));
    std::memcpy(env.data() + 8, &n_bundles, sizeof(uint64_t));
    std::memcpy(env.data() + zilkworm::kInputHeaderSizeMFBD, b.data(), b.size());
    return env;
}

}  // namespace

int main() {
    // Malformed JSON: nlohmann::json::parse used to throw parse_error out of run().
    expect_run_failure(ejsn_envelope("this is not json"), "garbage EJSN JSON reports kRunFailure");
    // Valid JSON, bad genesisRLP hex: from_hex(...).value() used to throw bad_optional_access.
    expect_run_failure(ejsn_envelope(R"({"t":{"network":"Mainnet","genesisRLP":"zz","blocks":[]}})"),
                       "bad genesisRLP hex reports kRunFailure");
    // Wrong-typed JSON field: .get<std::string>() on a number used to throw type_error.
    expect_run_failure(ejsn_envelope(R"({"t":{"network":"Mainnet","genesisRLP":5}})"),
                       "wrong-typed genesisRLP reports kRunFailure");
    // MFBD: a blocks section naming ~2^64 blocks must reject, not throw from reserve().
    expect_run_failure(mfbd_envelope_with_block_count(UINT64_MAX, 0),
                       "hostile MFBD block count reports kRunFailure");

    return g_failures;
}
