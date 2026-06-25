// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "genesis.hpp"

#include <bit>
#include <unordered_map>

#include <zilk_core/core/chain/config.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/chain/genesis_holesky.hpp>
#include <zilk_core/core/chain/genesis_mainnet.hpp>
#include <zilk_core/core/chain/genesis_sepolia.hpp>
#include <zilk_core/core/common/assert.hpp>
#include <zilk_core/core/common/bytes_to_string.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

#include <zilk_core/print.hpp>

using ::zilkworm::DirectState;

namespace silkworm {

std::string_view read_genesis_data(ChainId chain_id) {
    switch (chain_id) {
        case *kKnownChainNameToId.find("mainnet"):
            return kGenesisMainnetJson;
        case *kKnownChainNameToId.find("holesky"):
            return kGenesisHoleskyJson;
        case *kKnownChainNameToId.find("sepolia"):
            return kGenesisSepoliaJson;
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

std::vector<uint8_t> read_genesis_allocation(const nlohmann::json& alloc) {
    std::vector<DirectState::AccountInfo> infos;
    infos.reserve(alloc.size());
    std::unordered_map<evmc::bytes32, Bytes> code_map;
    for (const auto& item : alloc.items()) {
        const evmc::address address{hex_to_address(item.key())};
        const nlohmann::json& account_json{item.value()};

        DirectState::AccountInfo info{};
        info.addr = address;
        const auto balance_v = intx::from_string<intx::uint256>(account_json.at("balance"));
        std::memcpy(info.account.balance, &balance_v, 32);
        if (account_json.contains("nonce")) {
            info.account.nonce = std::stoull(account_json["nonce"].get<std::string>(), nullptr, /*base=*/16);
        }
        // Default code_hash = kEmptyHash so absent-code matches the trie leaf.
        std::memcpy(info.account.code_hash, kEmptyHash.bytes, 32);
        if (account_json.contains("code")) {
            Bytes code{*from_hex(account_json["code"].get<std::string>())};
            if (!code.empty()) {
                const auto code_hash_v = keccak256(code);
                std::memcpy(info.account.code_hash, code_hash_v.bytes, 32);
                info.account.code_store_len = static_cast<uint32_t>(code.size());
                evmc::bytes32 ch{};
                std::memcpy(ch.bytes, code_hash_v.bytes, 32);
                code_map.try_emplace(ch, std::move(code));
            }
        }
        // storage_root is recomputed by execution; default to kEmptyRoot so
        // an empty allocation matches the trie leaf.
        std::memcpy(info.account.storage_root, kEmptyRoot.bytes, 32);

        if (account_json.contains("storage")) {
            for (const auto& storage : account_json["storage"].items()) {
                const Bytes key{*from_hex(storage.key())};
                const Bytes value{*from_hex(storage.value().get<std::string>())};
                info.storage.emplace_back(to_bytes32(key), to_bytes32(value));
            }
        }
        infos.push_back(std::move(info));
    }
    std::vector<uint8_t> code_store_blob;
    if (!code_map.empty()) {
        ::zilkworm::MphfBuilder<32> cb{::zilkworm::kMphfCodeStoreMagic,
                                       ::zilkworm::kMphfMapVersion};
        std::vector<uint8_t> enc;
        for (const auto& [ch, code_bytes] : code_map) {
            enc.clear();
            ::zilkworm::FlatKv::encode(enc, ch, ByteView{code_bytes.data(), code_bytes.size()});
            cb.add(::zilkworm::hash_key8(ch), ByteView{enc.data(), enc.size()});
        }
        code_store_blob = std::move(cb).finalize();
    }
    return DirectState::build_blob_from_accounts(std::move(infos), {},
                                                 std::move(code_store_blob));
}

}  // namespace silkworm
