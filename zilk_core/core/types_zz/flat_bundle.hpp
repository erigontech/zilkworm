// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/types/block.hpp>

namespace zilkworm {

inline constexpr uint32_t kInputMagicMFBD = 0x4442464Du;  // "MFBD"
inline constexpr uint32_t kInputMagicEJSN = 0x4E534A45u;  // "EJSN"

// The MFBD envelope layout (magic/version/count + concatenated bundles) is
// unchanged; the semantic break of the hashed-key pre-state is gated by
// kFlatBundleVersion and pre_state kVersion below/in pre_state.hpp.
inline constexpr uint32_t kInputVersionMFBD = 1u;
inline constexpr uint32_t kInputVersionEJSN = 1u;

inline constexpr std::size_t kInputHeaderSizeMFBD = 16;
inline constexpr std::size_t kInputHeaderSizeEJSN = 8;

// Per-block flag bits (optional trailing bytes of the blocks section).
inline constexpr uint8_t kBlockFlagExpectInvalid = 0x01;

// blob must be declared before direct; direct holds spans into blob.
struct FlatBundle {
    std::span<uint8_t> blob;
    silkworm::Block genesis;
    std::vector<silkworm::ByteView> block_rlps;  // views into blob
    std::vector<silkworm::BlockHeader> ancestors;
    DirectState direct;
    std::string_view network;
    std::span<const uint8_t> block_flags;  // empty when absent

    FlatBundle(const FlatBundle&) = delete;
    FlatBundle& operator=(const FlatBundle&) = delete;
    FlatBundle(FlatBundle&&) noexcept = default;
    FlatBundle& operator=(FlatBundle&&) noexcept = default;

    FlatBundle(std::span<uint8_t> blob_in,
               silkworm::Block&& genesis_in,
               std::vector<silkworm::ByteView>&& block_rlps_in,
               std::vector<silkworm::BlockHeader>&& ancestors_in,
               size_t prestate_off, size_t prestate_size,
               size_t nodestore_off, size_t nodestore_size,
               size_t network_off, size_t network_size) noexcept;
};

inline constexpr uint32_t kFlatBundleMagic   = 0x444E4246u;  // 'FBND'
// v14: direct-state keyed by trie keys (keccak256(address)/keccak256(slot));
// bundles produced with raw-address keying (<= v13) are rejected.
inline constexpr uint32_t kFlatBundleVersion = 14u;
struct alignas(8) FlatBundleHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t genesis_rlp_off;       uint32_t genesis_rlp_size;
    uint32_t blocks_rlp_off;        uint32_t blocks_rlp_size;
    uint32_t ancestors_rlp_off;     uint32_t ancestors_rlp_size;
    uint32_t direct_state_off;      uint32_t direct_state_size;
    uint32_t node_store_off;        uint32_t node_store_size;
    uint32_t network_off;           uint32_t network_size;
};
static_assert(std::is_trivially_copyable_v<FlatBundleHeader>);
static_assert(sizeof(FlatBundleHeader) == 56);

std::optional<FlatBundle> load_flat_bundle(std::span<uint8_t> blob);

std::vector<uint8_t> build_flat_bundle(
    silkworm::ByteView genesis_rlp,
    std::span<const silkworm::ByteView> block_rlps,
    silkworm::ByteView ancestors_rlp,
    const std::vector<uint8_t>& direct_state_blob,
    const std::vector<uint8_t>& node_store_blob,
    std::string_view network,
    std::span<const uint8_t> block_flags = {});

}  // namespace zilkworm
