// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// A stateless witness omits bytecode that an earlier CREATE in the same block already
// deployed: EIP-7928 code_writes satisfy the read, so the body need not travel with the
// witness. A pre-existing account sharing that code hash then arrives with its hash intact
// and no code-store entry (code_store_len == 0), and read_code() must serve the in-block
// copy. Serving empty code instead executes calls to the account as no-ops, observed on
// glamsterdam-devnet-8 blocks 236593/236594 as a receipts-root mismatch.

#include <catch2/catch_test_macros.hpp>

#include <bit>
#include <span>
#include <vector>

#include <zilk_core/core/state_zz/account_read_test_util.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>

namespace zilkworm {

TEST_CASE("pre-state code omitted from the witness resolves from an in-block CREATE",
          "[state_zz][direct_state][code]") {
    Bytes code;
    for (int i = 0; i < 40; ++i)
        code.push_back(static_cast<uint8_t>(0x60 + (i % 16)));
    const auto code_hash =
        std::bit_cast<bytes32>(silkworm::keccak256(ByteView{code.data(), code.size()}));

    evmc::address existing{};
    existing.bytes[19] = 0x11;
    evmc::address deployed{};
    deployed.bytes[19] = 0x22;

    // `existing` keeps its code hash; its body is absent from the witness code store.
    std::vector<DirectState::AccountInfo> accounts{
        test_util::make_contract(existing, 1, intx::uint256{0}, code_hash, /*code_len=*/0),
        test_util::make_eoa(deployed, 0, intx::uint256{0})};
    auto blob = DirectState::build_blob_from_accounts(accounts, {}, test_util::build_code_store({}));
    std::vector<uint8_t> nodestore;
    DirectState ds{std::span<uint8_t>{blob}, std::span<uint8_t>{nodestore}};
    REQUIRE(ds.sanitize());

    // An earlier transaction deploys the same bytecode elsewhere.
    evmone::state::StateDiff diff;
    auto& e = diff.modified_accounts.emplace_back();
    e.addr = deployed;
    e.nonce = 1;
    e.balance = 0;
    e.code = evmc::bytes{code.begin(), code.end()};
    ds.apply_state_diff(diff);

    const auto served = ds.read_code(existing);
    REQUIRE(served.size() == code.size());
    CHECK(Bytes{served.begin(), served.end()} == code);
}

}  // namespace zilkworm
