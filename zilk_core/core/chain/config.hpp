// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>
#include <zilk_core/core/common/base.hpp>
#include <zilk_core/core/common/small_map.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/ethash_config.hpp>

namespace silkworm {

namespace protocol {

    // Already merged at genesis
    struct NoPreMergeConfig {
        bool operator==(const NoPreMergeConfig&) const = default;
    };

    using PreMergeRuleSetConfig = std::variant<NoPreMergeConfig, EthashConfig>;

}  // namespace protocol

using ChainId = uint64_t;

struct BlobParams {
    uint16_t target{0};
    uint16_t max{0};
    uint32_t base_fee_update_fraction{0};
};

struct ChainConfig {
    ChainId chain_id{0};

    std::optional<evmc::bytes32> genesis_hash;

    std::optional<BlockNum> homestead_block{std::nullopt};
    std::optional<BlockNum> dao_block{std::nullopt};
    std::optional<BlockNum> tangerine_whistle_block{std::nullopt};
    std::optional<BlockNum> spurious_dragon_block{std::nullopt};
    std::optional<BlockNum> byzantium_block{std::nullopt};
    std::optional<BlockNum> constantinople_block{std::nullopt};
    std::optional<BlockNum> petersburg_block{std::nullopt};
    std::optional<BlockNum> istanbul_block{std::nullopt};
    std::optional<BlockNum> muir_glacier_block{std::nullopt};
    std::optional<BlockNum> berlin_block{std::nullopt};
    std::optional<BlockNum> london_block{std::nullopt};

    // (Optional) contract where EIP-1559 fees will be sent to that otherwise would be burnt since the London fork
    SmallMap<BlockNum, evmc::address> burnt_contract{};

    std::optional<BlockNum> arrow_glacier_block{std::nullopt};
    std::optional<BlockNum> gray_glacier_block{std::nullopt};

    // EIP-3675: PoS switch
    std::optional<intx::uint256> terminal_total_difficulty{std::nullopt};
    std::optional<BlockNum> merge_netsplit_block{std::nullopt};  // FORK_NEXT_VALUE in EIP-3675

    // Starting from Shanghai, forks are triggered by block time rather than number
    std::optional<BlockTime> shanghai_time{std::nullopt};
    std::optional<BlockTime> cancun_time{std::nullopt};
    std::optional<BlockTime> prague_time{std::nullopt};
    std::optional<BlockTime> osaka_time{std::nullopt};
    std::optional<BlockTime> bpo1_time{std::nullopt};
    std::optional<BlockTime> bpo2_time{std::nullopt};
    std::optional<BlockTime> bpo3_time{std::nullopt};
    std::optional<BlockTime> bpo4_time{std::nullopt};
    std::optional<BlockTime> amsterdam_time{std::nullopt};

    protocol::PreMergeRuleSetConfig rule_set_config{protocol::NoPreMergeConfig{}};

    // The Shanghai hard fork has withdrawals, but Agra does not
    bool withdrawals_activated(BlockTime block_time) const noexcept;
    bool is_london(BlockNum block_num) const noexcept;
    bool is_prague(BlockNum block_num, BlockTime block_time) const noexcept;

    evmc_revision revision(BlockNum block_num, uint64_t block_time) const noexcept;

    BlobParams blob_params(uint64_t block_time) const noexcept;

    std::vector<BlockNum> distinct_fork_block_nums() const;
    std::vector<BlockTime> distinct_fork_times() const;
    std::vector<uint64_t> distinct_fork_points() const;

    bool valid_pre_merge_config() const noexcept;

    nlohmann::json to_json() const noexcept;

    static std::optional<ChainConfig> from_json(const nlohmann::json& json) noexcept;

    friend bool operator==(const ChainConfig&, const ChainConfig&) = default;
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj);

using namespace evmc::literals;

inline constexpr evmc::bytes32 kMainnetGenesisHash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
constinit extern const ChainConfig kMainnetConfig;

inline constexpr evmc::bytes32 kHoleskyGenesisHash{0xb5f7f912443c940f21fd611f12828d75b534364ed9e95ca4e307729a4661bde4_bytes32};
constinit extern const ChainConfig kHoleskyConfig;

inline constexpr evmc::bytes32 kSepoliaGenesisHash{0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9_bytes32};
constinit extern const ChainConfig kSepoliaConfig;

inline constexpr SmallMap<std::string_view, ChainId> kKnownChainNameToId{
    {"holesky", 17000},
    {"mainnet", 1},
    {"sepolia", 11155111},
};

inline constexpr SmallMap<ChainId, const ChainConfig*> kKnownChainConfigs{
    {*kKnownChainNameToId.find("mainnet"), &kMainnetConfig},
    {*kKnownChainNameToId.find("holesky"), &kHoleskyConfig},
    {*kKnownChainNameToId.find("sepolia"), &kSepoliaConfig},
};

}  // namespace silkworm
