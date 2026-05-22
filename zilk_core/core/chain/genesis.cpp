// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "genesis.hpp"

#include <bit>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/chain/genesis_amoy.hpp>
#include <zilk_core/core/chain/genesis_bor_mainnet.hpp>
#include <zilk_core/core/chain/genesis_holesky.hpp>
#include <zilk_core/core/chain/genesis_mainnet.hpp>
#include <zilk_core/core/chain/genesis_sepolia.hpp>
#include <zilk_core/core/common/assert.hpp>
#include <zilk_core/core/common/bytes_to_string.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

#include <zilk_core/print.hpp>
namespace silkworm {

std::string_view read_genesis_data(ChainId chain_id) {
    switch (chain_id) {
        case *kKnownChainNameToId.find("mainnet"):
            return kGenesisMainnetJson;
        case *kKnownChainNameToId.find("holesky"):
            return kGenesisHoleskyJson;
        case *kKnownChainNameToId.find("sepolia"):
            return kGenesisSepoliaJson;
        case *kKnownChainNameToId.find("bor-mainnet"):
            return kGenesisBorMainnetJson;
        case *kKnownChainNameToId.find("amoy"):
            return kGenesisAmoyJson;
        default:
            return "{";  // <- Won't be lately parsed as valid json value
    }
}

BlockHeader read_genesis_header(const nlohmann::json& genesis, const evmc::bytes32& state_root) {
    BlockHeader header;

    if (genesis.contains("extraData")) {
        const std::string extra_data_str{genesis["extraData"].get<std::string>()};
        if (has_hex_prefix(extra_data_str)) {
            const std::optional<Bytes> extra_data_hex{from_hex(extra_data_str)};
            // SILKWORM_ASSERT(extra_data_hex.has_value());
            header.extra_data = *extra_data_hex;
        } else {
            header.extra_data = string_view_to_byte_view(extra_data_str);
        }
    }
    if (genesis.contains("mixHash")) {
        const std::optional<Bytes> mix_hash{from_hex(genesis["mixHash"].get<std::string>())};
        // SILKWORM_ASSERT(mix_hash.has_value());
        std::memcpy(header.prev_randao.bytes, mix_hash->data(), mix_hash->size());
    }
    if (genesis.contains("nonce")) {
        const uint64_t nonce{std::stoull(genesis["nonce"].get<std::string>(), nullptr, 0)};
        endian::store_big_u64(header.nonce.data(), nonce);
    }
    if (genesis.contains("difficulty")) {
        const auto difficulty_str{genesis["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
    }

    header.ommers_hash = kEmptyListHash;
    header.state_root = state_root;
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    header.gas_limit = std::stoull(genesis["gasLimit"].get<std::string>(), nullptr, 0);
    header.timestamp = std::stoull(genesis["timestamp"].get<std::string>(), nullptr, 0);

    const std::optional<ChainConfig> chain_config{ChainConfig::from_json(genesis["config"])};
    // SILKWORM_ASSERT(chain_config.has_value());
    if (chain_config->revision(0, header.timestamp) >= EVMC_LONDON) {
        header.base_fee_per_gas = protocol::kInitialBaseFee;
    }

    return header;
}

InMemoryState read_genesis_allocation(const nlohmann::json& alloc) {
    InMemoryState state;
    for (const auto& item : alloc.items()) {
        const evmc::address address{hex_to_address(item.key())};
        const nlohmann::json& account_json{item.value()};

        Account account;
        account.balance = intx::from_string<intx::uint256>(account_json.at("balance"));
        if (account_json.contains("nonce")) {
            account.nonce = std::stoull(account_json["nonce"].get<std::string>(), nullptr, /*base=*/16);
        }
        if (account_json.contains("code")) {
            const Bytes code{*from_hex(account_json["code"].get<std::string>())};
            if (!code.empty()) {
                account.code_hash = std::bit_cast<evmc_bytes32>(keccak256(code));
                state.update_account_code(address, account.code_hash, code);
            }
        }
        state.update_account(address, /*initial=*/std::nullopt, account);

        if (account_json.contains("storage")) {
            for (const auto& storage : account_json["storage"].items()) {
                const Bytes key{*from_hex(storage.key())};
                const Bytes value{*from_hex(storage.value().get<std::string>())};
                state.update_storage(address, to_bytes32(key), /*initial=*/{}, to_bytes32(value));
            }
        }
    }
    return state;
}

// Modified version with proper code handling
InMemoryState read_pre_state_from_rlp(ByteView rlp_view) {
    InMemoryState state;
    auto mega_header{rlp::decode_header(rlp_view)};
    if (!mega_header || !mega_header->list) {
        sys_println("Invalid mega_header");
    }

    ByteView payload_view = rlp_view.substr(0, mega_header->payload_length);

    // Process accounts
    auto accounts_header{rlp::decode_header(payload_view)};  // List of accounts
    if (!accounts_header || !accounts_header->list) {
        sys_println("Invalid accounts_header");
    }
    ByteView accounts_view = payload_view.substr(0, accounts_header->payload_length);

    while (!accounts_view.empty()) {
        auto entry_header{rlp::decode_header(accounts_view)};
        if (!entry_header || !entry_header->list) {
            sys_println("Invalid accounts_header");
        }
        ByteView acc_items_list = accounts_view.substr(0, entry_header->payload_length);
        evmc::address address;
        Account account;
        rlp::decode(acc_items_list, address);
        rlp::decode(acc_items_list, account.nonce);
        rlp::decode(acc_items_list, account.balance);
        rlp::decode(acc_items_list, account.code_hash);
        rlp::decode(acc_items_list, account.storage_root_);
        state.update_account(address, /*initial=*/std::nullopt, account);
        accounts_view.remove_prefix(entry_header->payload_length);
    }
    payload_view.remove_prefix(accounts_header->payload_length);

    // Process storage
    auto storage_header{rlp::decode_header(payload_view)};
    if (!storage_header || !storage_header->list) {
        sys_println("Invalid storage_header");
    }
    ByteView storage_view = payload_view.substr(0, storage_header->payload_length);

    while (!storage_view.empty()) {
        auto entry_header{rlp::decode_header(storage_view)};
        if (!entry_header || !entry_header->list) {
            sys_println("Invalid storage entry_header");
        }
        ByteView entry_payload = storage_view.substr(0, entry_header->payload_length);
        // sys_println("Storage entry:");
        // sys_println(to_hex(entry_payload).c_str());
        evmc::address address;
        rlp::decode(entry_payload, address);
        // Decode [k,v,k,v,...]
        auto kvs_header{rlp::decode_header(entry_payload)};
        if (!kvs_header || !kvs_header->list) {
            sys_println("Invalid kvs_header");
        }
        ByteView kvs_view = entry_payload.substr(0, kvs_header->payload_length);

        while (!kvs_view.empty()) {
            intx::uint256 key, value;
            if (!rlp::decode(kvs_view, key, rlp::Leftover::kAllow)) {
                sys_println("Failed to decode kv_key");
            }
            if (!rlp::decode(kvs_view, value, rlp::Leftover::kAllow)) {
                sys_println("Failed to decode kv_value");
            }
            evmc::bytes32 key32 = intx::be::store<evmc::bytes32>(key);
            evmc::bytes32 value32 = intx::be::store<evmc::bytes32>(value);

            state.update_storage(address, key32, /*initial=*/{}, value32);
        }
        storage_view.remove_prefix(entry_header->payload_length);
    }
    payload_view.remove_prefix(storage_header->payload_length);

    auto codes_header{rlp::decode_header(payload_view)};
    ByteView codes_view = payload_view.substr(0, codes_header->payload_length);
    evmc::address address{};
    while (!codes_view.empty()) {
        // auto entry_header{rlp::decode_header(codes_view)};
        // ByteView entry_payload = codes_view.substr(0, entry_header->payload_length);

        evmc::bytes32 code_hash;
        Bytes code;

        if (!rlp::decode(codes_view, code_hash, rlp::Leftover::kAllow)) {
            sys_println("Failed to decode code_hash from codes_view");
        }
        if (!rlp::decode(codes_view, code, rlp::Leftover::kAllow)) {
            sys_println("Failed to decode code from codes_view");
        }

        state.update_account_code(address, code_hash, code);
    }

    return state;
}

}  // namespace silkworm
