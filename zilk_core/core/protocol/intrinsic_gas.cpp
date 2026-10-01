// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "intrinsic_gas.hpp"

#include <algorithm>

#include <evmone/constants.hpp>
#include <evmone/instructions_traits.hpp>

#include "param.hpp"

namespace silkworm::protocol {

intx::uint128 intrinsic_gas(const UnsignedTransaction& txn, const evmc_revision rev) noexcept {
    intx::uint128 gas{fee::kGTransaction};

    const bool contract_creation{!txn.to};
    if (contract_creation && rev >= EVMC_HOMESTEAD) {
        gas += fee::kGTxCreate;
    }

    // EIP-2930: Optional access lists
    gas += intx::uint128{txn.access_list.size()} * fee::kAccessListAddressCost;
    intx::uint128 total_num_of_storage_keys{0};
    for (const AccessListEntry& e : txn.access_list) {
        total_num_of_storage_keys += e.storage_keys.size();
    }
    gas += total_num_of_storage_keys * fee::kAccessListStorageKeyCost;

    // EIP-7702 Set EOA account code
    gas += txn.authorizations.size() * fee::kPerEmptyAccountCost;

    const uint64_t data_len{txn.data.size()};
    if (data_len == 0) {
        return gas;
    }

    const intx::uint128 non_zero_bytes{std::ranges::count_if(txn.data, [](uint8_t c) { return c != 0; })};
    const intx::uint128 non_zero_gas{rev >= EVMC_ISTANBUL ? fee::kGTxDataNonZeroIstanbul : fee::kGTxDataNonZeroFrontier};
    gas += non_zero_bytes * non_zero_gas;
    const intx::uint128 zero_bytes{data_len - non_zero_bytes};
    gas += zero_bytes * fee::kGTxDataZero;

    // EIP-3860: Limit and meter initcode
    if (contract_creation && rev >= EVMC_SHANGHAI) {
        gas += num_words(data_len) * fee::kInitCodeWordCost;
    }

    return gas;
}

// EIP-7623: Increase calldata cost
uint64_t floor_cost(const UnsignedTransaction& txn) noexcept {
    const uint64_t zero_bytes = static_cast<uint64_t>(std::ranges::count(txn.data, 0));
    const uint64_t non_zero_bytes{txn.data.size() - zero_bytes};
    return fee::kGTransaction + (zero_bytes + non_zero_bytes * 4) * fee::kTotalCostFloorPerToken;
}

TxGasCost amsterdam_tx_gas_cost(const Transaction& txn) noexcept {
    // Sender cost: ECDSA recovery, the sender's account access and write, block inclusion.
    static constexpr int64_t kTxBaseCost = 12000;
    // Recipient balance write plus the EIP-7708 transfer log performed by a value transfer.
    static constexpr int64_t kTxValueCost = 6000;
    // EIP-8038: CREATE_ACCESS = ACCOUNT_WRITE + COLD_ACCOUNT_ACCESS (12000).
    static constexpr int64_t kCreateAccess = evmone::instr::CREATE_ACCESS;
    static constexpr int64_t kDataTokenStandard = 4;
    static constexpr int64_t kDataTokenFloor = 16;
    static constexpr int64_t kInitcodeWordCost = 2;
    static constexpr int64_t kAccessListAddressFloorTokens = 80;      // 20 bytes x 4.
    static constexpr int64_t kAccessListStorageKeyFloorTokens = 128;  // 32 bytes x 4.
    // EIP-8038: the access-list entries prepay the cold access minus the warm access still
    // charged when the transaction touches the prepaid address/slot. COLD_STORAGE_ACCESS is
    // only a rename of COLD_SLOAD_COST, so the storage-key entry is not repriced.
    static constexpr int64_t kAccessListAddressCost =
        evmone::instr::COLD_ACCOUNT_ACCESS_AMSTERDAM - evmone::instr::WARM_ACCESS;
    static constexpr int64_t kAccessListStorageKeyCost =
        evmone::instr::COLD_STORAGE_ACCESS - evmone::instr::WARM_ACCESS;
    static constexpr int64_t kPrecompileEcrecover = 3000;
    static constexpr int64_t kAuthTupleBytes = 101;  // chain_id 8 + addr 20 + nonce 8 + v/r/s 65.
    // EIP-8037: EXECUTION_PER_AUTH_BASE_COST = AUTH_TUPLE_BYTES x DATA_TOKEN_FLOOR
    //   + PRECOMPILE_ECRECOVER + COLD_ACCOUNT_ACCESS + 2 x WARM_ACCESS (7816).
    static constexpr int64_t kExecutionPerAuthBaseCost =
        kAuthTupleBytes * kDataTokenFloor + kPrecompileEcrecover +
        evmone::instr::COLD_ACCOUNT_ACCESS_AMSTERDAM +
        2 * evmone::instr::WARM_ACCESS;

    const bool is_create = !txn.to;
    // A tx with an unrecoverable sender is rejected on signature grounds; the
    // self-transfer discount not applying here cannot make a valid tx invalid.
    const auto sender = txn.sender();
    const bool is_self_transfer = txn.to && sender && *txn.to == *sender;
    const bool has_value = txn.value != 0;

    const auto zero_bytes = static_cast<int64_t>(std::ranges::count(txn.data, 0));
    const auto non_zero_bytes = static_cast<int64_t>(txn.data.size()) - zero_bytes;
    const int64_t num_tokens = 4 * non_zero_bytes + zero_bytes;
    const int64_t data_cost = num_tokens * kDataTokenStandard;

    // Recipient cost depends on the transaction kind. A self-transfer touches nothing. The
    // created account's NEW_ACCOUNT state gas is state-dependent and charged at the top frame.
    int64_t recipient_regular = 0;
    int64_t init_code_gas = 0;
    if (is_create) {
        // A value transfer adds nothing: the recipient balance write is part of CREATE_ACCESS.
        recipient_regular = kCreateAccess;
        init_code_gas = kInitcodeWordCost * static_cast<int64_t>(num_words(txn.data.size()));
    } else if (!is_self_transfer) {
        recipient_regular = evmone::instr::COLD_ACCOUNT_ACCESS_AMSTERDAM;
        if (has_value) recipient_regular += kTxValueCost;
    }

    const auto num_addresses = static_cast<int64_t>(txn.access_list.size());
    int64_t num_storage_keys = 0;
    for (const AccessListEntry& e : txn.access_list) {
        num_storage_keys += static_cast<int64_t>(e.storage_keys.size());
    }
    const int64_t access_list_regular =
        num_addresses * kAccessListAddressCost + num_storage_keys * kAccessListStorageKeyCost;
    const int64_t access_list_tokens = num_addresses * kAccessListAddressFloorTokens +
                                       num_storage_keys * kAccessListStorageKeyFloorTokens;
    const int64_t access_list_cost = access_list_regular + access_list_tokens * kDataTokenFloor;

    // Only the state-independent per-authorization base cost is charged here; the ACCOUNT_WRITE
    // regular gas and the NEW_ACCOUNT/AUTH_BASE state gas are charged at the top frame.
    const auto num_auth = static_cast<int64_t>(txn.authorizations.size());
    const int64_t auth_regular = num_auth * kExecutionPerAuthBaseCost;

    // Decomposed regular-gas intrinsic base (EIP-2780), which also anchors the calldata floor so
    // the floor never undercuts the transaction's own intrinsic base (EELS #3120).
    const int64_t base_regular = kTxBaseCost + recipient_regular;

    const int64_t regular =
        base_regular + init_code_gas + data_cost + access_list_cost + auth_regular;

    // Floor cost (EIP-7623 / EIP-7976): every calldata byte plus access-list tokens at the floor
    // rate, anchored on base_regular. floor_tokens = len(data) x DATA_TOKEN_STANDARD + AL tokens.
    const int64_t floor_tokens =
        static_cast<int64_t>(txn.data.size()) * kDataTokenStandard + access_list_tokens;
    const int64_t floor = floor_tokens * kDataTokenFloor + base_regular;

    return {regular, floor};
}

}  // namespace silkworm::protocol
