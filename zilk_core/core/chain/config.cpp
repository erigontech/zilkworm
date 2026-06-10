// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <algorithm>
#include <functional>
#include <set>
#include <string>

#include <zilk_core/core/common/overloaded.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

namespace silkworm {

static constexpr std::string_view kTerminalTotalDifficulty{"terminalTotalDifficulty"};

static void member_to_json(nlohmann::json& json, const std::string& key, const std::optional<uint64_t>& source) {
    if (source) {
        json[key] = source.value();
    }
}

static void read_json_config_member(
    const nlohmann::json& json,
    const std::string& key,
    std::optional<uint64_t>& target) {
    if (json.contains(key)) {
        target = json[key].get<uint64_t>();
    }
}

nlohmann::json ChainConfig::to_json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

    nlohmann::json empty_object(nlohmann::json::value_t::object);
    std::visit(
        Overloaded{
            [&](const protocol::NoPreMergeConfig&) {},
            [&](const protocol::EthashConfig& x) { ret.emplace("ethash", x.to_json()); },
        },
        rule_set_config);

    member_to_json(ret, "homesteadBlock", homestead_block);
    member_to_json(ret, "daoForkBlock", dao_block);
    member_to_json(ret, "eip150Block", tangerine_whistle_block);
    member_to_json(ret, "eip155Block", spurious_dragon_block);
    member_to_json(ret, "byzantiumBlock", byzantium_block);
    member_to_json(ret, "constantinopleBlock", constantinople_block);
    member_to_json(ret, "petersburgBlock", petersburg_block);
    member_to_json(ret, "istanbulBlock", istanbul_block);
    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "berlinBlock", berlin_block);
    member_to_json(ret, "londonBlock", london_block);

    if (!burnt_contract.empty()) {
        nlohmann::json burnt_contract_json = nlohmann::json::object();
        for (const auto& [from, contract] : burnt_contract) {
            burnt_contract_json[std::to_string(from)] = address_to_hex(contract);
        }
        ret["burntContract"] = burnt_contract_json;
    }

    member_to_json(ret, "arrowGlacierBlock", arrow_glacier_block);
    member_to_json(ret, "grayGlacierBlock", gray_glacier_block);

    if (terminal_total_difficulty) {
        // TODO(yperbasis): geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*terminal_total_difficulty);
    }

    member_to_json(ret, "mergeNetsplitBlock", merge_netsplit_block);
    member_to_json(ret, "shanghaiTime", shanghai_time);
    member_to_json(ret, "cancunTime", cancun_time);
    member_to_json(ret, "pragueTime", prague_time);

    if (genesis_hash.has_value()) {
        ret["genesisBlockHash"] = to_hex(*genesis_hash, /*with_prefix=*/true);
    }

    return ret;
}

bool ChainConfig::valid_pre_merge_config() const noexcept {
    const bool has_pre_merge_config{!std::holds_alternative<protocol::NoPreMergeConfig>(rule_set_config)};
    const bool has_merge_at_genesis{!terminal_total_difficulty || terminal_total_difficulty == 0};
    return has_pre_merge_config || has_merge_at_genesis;
}

std::optional<ChainConfig> ChainConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.contains("chainId") || !json["chainId"].is_number()) {
        return std::nullopt;
    }

    ChainConfig config{};
    config.chain_id = json["chainId"].get<uint64_t>();

    if (json.contains("ethash")) {
        std::optional<protocol::EthashConfig> ethash_config{protocol::EthashConfig::from_json(json["ethash"])};
        if (!ethash_config) {
            return std::nullopt;
        }
        config.rule_set_config = *ethash_config;
    } else {
        config.rule_set_config = protocol::NoPreMergeConfig{};
    }

    read_json_config_member(json, "homesteadBlock", config.homestead_block);
    read_json_config_member(json, "daoForkBlock", config.dao_block);
    read_json_config_member(json, "eip150Block", config.tangerine_whistle_block);
    read_json_config_member(json, "eip155Block", config.spurious_dragon_block);
    read_json_config_member(json, "byzantiumBlock", config.byzantium_block);
    read_json_config_member(json, "constantinopleBlock", config.constantinople_block);
    read_json_config_member(json, "petersburgBlock", config.petersburg_block);
    read_json_config_member(json, "istanbulBlock", config.istanbul_block);
    read_json_config_member(json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(json, "berlinBlock", config.berlin_block);
    read_json_config_member(json, "londonBlock", config.london_block);

    if (json.contains("burntContract")) {
        const auto items = json["burntContract"].items();
        auto it = items.begin();
        for (size_t i{0}; i < SmallMap<BlockNum, evmc::address>::max_size() && it != items.end(); ++i, ++it) {
            config.burnt_contract.emplace_back(std::stoull(it.key(), nullptr, 0), hex_to_address(it.value().get<std::string>()));
        }
    }

    read_json_config_member(json, "arrowGlacierBlock", config.arrow_glacier_block);
    read_json_config_member(json, "grayGlacierBlock", config.gray_glacier_block);

    if (json.contains(kTerminalTotalDifficulty)) {
        // We handle terminalTotalDifficulty serialized both as JSON string *and* as JSON number
        if (json[kTerminalTotalDifficulty].is_string()) {
            /* This is still present to maintain compatibility with previous Silkworm format */
            config.terminal_total_difficulty =
                intx::from_string<intx::uint256>(json[kTerminalTotalDifficulty].get<std::string>());
        } else if (json[kTerminalTotalDifficulty].is_number()) {
            /* This is for compatibility with Erigon that uses a JSON number */
            // nlohmann::json treats JSON numbers that overflow 64-bit unsigned integer as floating-point numbers and
            // intx::uint256 cannot currently be constructed from a floating-point number or string in scientific notation
            config.terminal_total_difficulty =
                from_string_sci<intx::uint256>(json[kTerminalTotalDifficulty].dump().c_str());
        }
    }

    read_json_config_member(json, "mergeNetsplitBlock", config.merge_netsplit_block);
    read_json_config_member(json, "shanghaiTime", config.shanghai_time);
    read_json_config_member(json, "cancunTime", config.cancun_time);
    read_json_config_member(json, "pragueTime", config.prague_time);

    /* Note ! genesis_hash is purposely omitted. It must be loaded from db after the
     * effective genesis block has been persisted */

    if (!config.valid_pre_merge_config()) {
        return std::nullopt;
    }
    return config;
}

bool ChainConfig::withdrawals_activated(BlockTime block_time) const noexcept {
    return shanghai_time && block_time >= shanghai_time;
}
bool ChainConfig::is_london(BlockNum block_num) const noexcept {
    return (london_block && block_num >= london_block);
}

bool ChainConfig::is_prague(BlockNum block_num, BlockTime block_time) const noexcept {
    return revision(block_num, block_time) >= EVMC_PRAGUE;
}

evmc_revision ChainConfig::revision(uint64_t block_num, uint64_t block_time) const noexcept {
    if (osaka_time && block_time >= osaka_time) return EVMC_OSAKA;
    if (prague_time && block_time >= prague_time) return EVMC_PRAGUE;
    if (cancun_time && block_time >= cancun_time) return EVMC_CANCUN;
    if (shanghai_time && block_time >= shanghai_time) return EVMC_SHANGHAI;

    if (london_block && block_num >= london_block) return EVMC_LONDON;
    if (berlin_block && block_num >= berlin_block) return EVMC_BERLIN;
    if (istanbul_block && block_num >= istanbul_block) return EVMC_ISTANBUL;
    if (petersburg_block && block_num >= petersburg_block) return EVMC_PETERSBURG;
    if (constantinople_block && block_num >= constantinople_block) return EVMC_CONSTANTINOPLE;
    if (byzantium_block && block_num >= byzantium_block) return EVMC_BYZANTIUM;
    if (spurious_dragon_block && block_num >= spurious_dragon_block) return EVMC_SPURIOUS_DRAGON;
    if (tangerine_whistle_block && block_num >= tangerine_whistle_block) return EVMC_TANGERINE_WHISTLE;
    if (homestead_block && block_num >= homestead_block) return EVMC_HOMESTEAD;

    return EVMC_FRONTIER;
}

BlobParams ChainConfig::blob_params(uint64_t block_time) const noexcept {
    if (bpo4_time && block_time >= bpo4_time) {
        return {14, 21, 13739630};
    }
    if (bpo3_time && block_time >= bpo3_time) {
        return {21, 32, 20609697};
    }
    if (bpo2_time && block_time >= bpo2_time) {
        return {14, 21, 11684671};
    }
    if (bpo1_time && block_time >= bpo1_time) {
        return {10, 15, 8346193};
    }
    if (osaka_time && block_time >= osaka_time) {
        return {6, 9, 5007716};
    }
    if (prague_time && block_time >= prague_time) {
        return {6, 9, 5007716};
    }
    if (cancun_time && block_time >= cancun_time) {
        return {3, 6, 3338477};
    }
    return {};
}

std::vector<BlockNum> ChainConfig::distinct_fork_block_nums() const {
    std::set<BlockNum> ret;

    // Add forks identified by *block number* in ascending order
    ret.insert(homestead_block.value_or(0));
    ret.insert(dao_block.value_or(0));
    ret.insert(tangerine_whistle_block.value_or(0));
    ret.insert(spurious_dragon_block.value_or(0));
    ret.insert(byzantium_block.value_or(0));
    ret.insert(constantinople_block.value_or(0));
    ret.insert(petersburg_block.value_or(0));
    ret.insert(istanbul_block.value_or(0));
    ret.insert(muir_glacier_block.value_or(0));
    ret.insert(berlin_block.value_or(0));
    ret.insert(london_block.value_or(0));
    ret.insert(arrow_glacier_block.value_or(0));
    ret.insert(gray_glacier_block.value_or(0));
    ret.insert(merge_netsplit_block.value_or(0));

    ret.erase(0);  // Block 0 is not a fork number
    return {ret.cbegin(), ret.cend()};
}

std::vector<BlockTime> ChainConfig::distinct_fork_times() const {
    std::set<BlockTime> ret;

    // Add forks identified by *block timestamp* in ascending order
    ret.insert(shanghai_time.value_or(0));
    ret.insert(cancun_time.value_or(0));
    ret.insert(prague_time.value_or(0));

    ret.erase(0);  // Block 0 is not a fork timestamp
    return {ret.cbegin(), ret.cend()};
}

std::vector<uint64_t> ChainConfig::distinct_fork_points() const {
    auto block_nums{distinct_fork_block_nums()};
    auto times{distinct_fork_times()};

    std::vector<uint64_t> points;
    points.resize(block_nums.size() + times.size());
    std::ranges::move(block_nums, points.begin());
    std::ranges::move(times, points.begin() + (block_nums.end() - block_nums.begin()));

    return points;
}

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

constinit const ChainConfig kMainnetConfig{
    .chain_id = 1,
    .homestead_block = 1'150'000,
    .dao_block = 1'920'000,
    .tangerine_whistle_block = 2'463'000,
    .spurious_dragon_block = 2'675'000,
    .byzantium_block = 4'370'000,
    .constantinople_block = 7'280'000,
    .petersburg_block = 7'280'000,
    .istanbul_block = 9'069'000,
    .muir_glacier_block = 9'200'000,
    .berlin_block = 12'244'000,
    .london_block = 12'965'000,
    .arrow_glacier_block = 13'773'000,
    .gray_glacier_block = 15'050'000,
    .terminal_total_difficulty = intx::from_string<intx::uint256>("58750000000000000000000"),
    .shanghai_time = 1681338455,
    .cancun_time = 1710338135,
    .prague_time = 1746612311,
    .osaka_time = 1764798551,
    .bpo1_time = 1765290071,
    .bpo2_time = 1767747671,
    .rule_set_config = protocol::EthashConfig{},
};

constinit const ChainConfig kHoleskyConfig{
    .chain_id = 17000,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .terminal_total_difficulty = 0,
    .shanghai_time = 1696000704,
    .cancun_time = 1707305664,
    .prague_time = 1740434112,
    .osaka_time = 1759308480,
    .bpo1_time = 1759800000,
    .bpo2_time = 1760389824,
    .rule_set_config = protocol::NoPreMergeConfig{},
};

constinit const ChainConfig kSepoliaConfig{
    .chain_id = 11155111,
    .homestead_block = 0,
    .tangerine_whistle_block = 0,
    .spurious_dragon_block = 0,
    .byzantium_block = 0,
    .constantinople_block = 0,
    .petersburg_block = 0,
    .istanbul_block = 0,
    .muir_glacier_block = 0,
    .berlin_block = 0,
    .london_block = 0,
    .terminal_total_difficulty = 17000000000000000,
    .merge_netsplit_block = 1'735'371,
    .shanghai_time = 1677557088,
    .cancun_time = 1706655072,
    .prague_time = 1741159776,
    .osaka_time = 1760427360,
    .bpo1_time = 1761017184,
    .bpo2_time = 1761607008,
    .rule_set_config = protocol::EthashConfig{},
};


}  // namespace silkworm
