// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Legacy outer RLP layout (5 items): prev_block, current_block, pre_state,
// ancestors, pre_trie. Converter is self-contained to keep legacy decoders
// out of main code paths.

#include <bit>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>      // silkworm::bytes32 alias
#include <zilk_core/core/types/address.hpp>    // rlp::decode(ByteView&, evmc::address&)
#include <zilk_core/core/types/block.hpp>      // rlp::decode<Block>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types/withdrawal.hpp>

#include <zilk_core/core/types_zz/flat_bundle.hpp>

#include "legacy_witness.hpp"

using silkworm::ByteView;
using silkworm::Bytes;
using zilkworm::DirectState;
using ::zilkworm::build_flat_bundle;
namespace legacy = ::zilkworm::legacy;

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <unifiedBlockAndStateRlp.bin> <flatWitnessBundle.mfbd>\n";
        return 1;
    }

    auto raw = legacy::read_file(argv[1]);
    if (raw.empty()) {
        std::cerr << argv[1] << ": empty or missing\n";
        return 1;
    }

    std::string err;
    const auto sections = legacy::split_sections(ByteView{raw.data(), raw.size()}, err);
    if (!sections) {
        std::cerr << argv[1] << ": " << err << "\n";
        return 1;
    }
    const ByteView genesis_rlp = sections->genesis_rlp;
    const ByteView block_rlp = sections->block_rlp;
    const ByteView pre_state_rlp = sections->pre_state_rlp;
    const ByteView ancestors_rlp = sections->ancestors_rlp;
    const ByteView pre_trie_rlp = sections->pre_trie_rlp;

    std::vector<DirectState::AccountInfo> accounts;
    std::unordered_map<evmc::address, size_t> addr_to_idx;
    std::unordered_map<evmc::bytes32, Bytes> code_map;

    {
        ByteView ps = pre_state_rlp;
        auto pso = silkworm::rlp::decode_header(ps);
        if (!pso || !pso->list) {
            std::cerr << "bad pre_state header\n";
            return 1;
        }
        ByteView psp = ps.substr(0, pso->payload_length);

        // accounts_list: [[addr, nonce, balance, code_hash, storage_root], ...]
        auto al_h = silkworm::rlp::decode_header(psp);
        if (!al_h || !al_h->list) {
            std::cerr << "bad accounts_list header\n";
            return 1;
        }
        ByteView al = psp.substr(0, al_h->payload_length);
        psp.remove_prefix(al_h->payload_length);

        while (!al.empty()) {
            auto eh = silkworm::rlp::decode_header(al);
            if (!eh || !eh->list) {
                std::cerr << "bad account entry header\n";
                return 1;
            }
            ByteView entry = al.substr(0, eh->payload_length);
            al.remove_prefix(eh->payload_length);

            DirectState::AccountInfo info{};
            using silkworm::rlp::decode;
            using silkworm::rlp::Leftover;
            intx::uint256 balance_v;
            evmc::bytes32 code_hash_v;
            evmc::bytes32 storage_root_v;
            if (!decode(entry, info.addr, Leftover::kAllow) ||
                !decode(entry, info.account.nonce, Leftover::kAllow) ||
                !decode(entry, balance_v, Leftover::kAllow) ||
                !decode(entry, code_hash_v, Leftover::kAllow) ||
                !decode(entry, storage_root_v, Leftover::kAllow)) {
                std::cerr << "bad account fields\n";
                return 1;
            }
            std::memcpy(info.account.balance, &balance_v, 32);
            std::memcpy(info.account.code_hash, code_hash_v.bytes, 32);
            std::memcpy(info.account.storage_root, storage_root_v.bytes, 32);
            addr_to_idx[info.addr] = accounts.size();
            accounts.push_back(std::move(info));
        }

        // storage_list: [[addr, [[key, value], ...]], ...]
        auto sl_h = silkworm::rlp::decode_header(psp);
        if (!sl_h || !sl_h->list) {
            std::cerr << "bad storage_list header\n";
            return 1;
        }
        ByteView sl = psp.substr(0, sl_h->payload_length);
        psp.remove_prefix(sl_h->payload_length);

        while (!sl.empty()) {
            auto eh = silkworm::rlp::decode_header(sl);
            if (!eh || !eh->list) {
                std::cerr << "bad storage entry header\n";
                return 1;
            }
            ByteView entry = sl.substr(0, eh->payload_length);
            sl.remove_prefix(eh->payload_length);

            evmc::address addr;
            using silkworm::rlp::decode;
            using silkworm::rlp::Leftover;
            if (!decode(entry, addr, Leftover::kAllow)) {
                std::cerr << "bad storage addr\n";
                return 1;
            }

            auto kvs_h = silkworm::rlp::decode_header(entry);
            if (!kvs_h || !kvs_h->list) {
                std::cerr << "bad kvs header\n";
                return 1;
            }
            ByteView kvs = entry.substr(0, kvs_h->payload_length);

            auto it = addr_to_idx.find(addr);
            if (it == addr_to_idx.end()) {
                continue;
            }
            auto& info = accounts[it->second];
            while (!kvs.empty()) {
                intx::uint256 key, value;
                if (!decode(kvs, key, Leftover::kAllow) ||
                    !decode(kvs, value, Leftover::kAllow)) {
                    std::cerr << "bad kv pair\n";
                    return 1;
                }
                info.storage.emplace_back(
                    intx::be::store<evmc::bytes32>(key),
                    intx::be::store<evmc::bytes32>(value));
            }
        }

    }

    {
        std::vector<std::pair<evmc::bytes32, Bytes>> codes;
        if (!legacy::parse_codes(pre_state_rlp, codes, err)) {
            std::cerr << err << "\n";
            return 1;
        }
        for (auto& [code_hash, code] : codes) {
            code_map.emplace(code_hash, std::move(code));
        }
    }

    for (auto& info : accounts) {
        const auto code_hash_v = std::bit_cast<evmc::bytes32>(info.account.code_hash);
        if (code_hash_v != silkworm::kEmptyHash) {
            auto it = code_map.find(code_hash_v);
            if (it != code_map.end()) {
                info.account.code_store_len = static_cast<uint32_t>(it->second.size());
            }
        }
    }

    // pre_trie entries: (hash, raw node RLP), the legacy string wrap already stripped.
    std::vector<std::pair<evmc::bytes32, ByteView>> ns_entries;
    if (!legacy::parse_trie_nodes(pre_trie_rlp, ns_entries, err)) {
        std::cerr << err << "\n";
        return 1;
    }

    std::vector<zilkworm::BlockHashEntry> block_hashes;
    {
        std::vector<ByteView> headers;
        if (!legacy::parse_headers(ancestors_rlp, headers, err)) {
            std::cerr << argv[1] << ": " << err << "\n";
            return 1;
        }
        for (ByteView ev : headers) {
            silkworm::BlockHeader header;
            if (!silkworm::rlp::decode(ev, header).has_value()) {
                std::cerr << argv[1] << ": ancestor header decode failed\n";
                return 1;
            }
            zilkworm::BlockHashEntry e{};
            e.block_number = header.number;
            const auto h = header.hash();
            std::memcpy(e.block_hash, h.bytes, 32);
            block_hashes.push_back(e);
        }
    }

    std::vector<uint8_t> code_store_blob;
    if (!code_map.empty()) {
        zilkworm::MphfBuilder<32> cb{zilkworm::kMphfCodeStoreMagic,
                                     zilkworm::kMphfMapVersion};
        std::vector<uint8_t> enc;
        for (const auto& [ch, code_bytes] : code_map) {
            enc.clear();
            zilkworm::FlatKv::encode(enc, ch, ByteView{code_bytes.data(), code_bytes.size()});
            cb.add(zilkworm::hash_key8(ch), ByteView{enc.data(), enc.size()});
        }
        code_store_blob = std::move(cb).finalize();
        if (code_store_blob.empty()) {
            std::cerr << "code-store MPHF build failed\n";
            return 1;
        }
    }

    std::vector<uint8_t> direct_blob =
        DirectState::build_blob_from_accounts(std::move(accounts),
                                              std::move(block_hashes),
                                              std::move(code_store_blob));
    if (direct_blob.empty()) {
        std::cerr << "DirectState build failed\n";
        return 1;
    }

    const bool had_nodes = !ns_entries.empty();
    std::vector<uint8_t> node_store_blob;
    if (had_nodes) {
        zilkworm::MphfBuilder<32> b{zilkworm::kMphfNodeStoreMagic,
                                    zilkworm::kMphfMapVersion};
        std::vector<uint8_t> with_hash;
        for (const auto& [hash, body] : ns_entries) {
            with_hash.clear();
            zilkworm::FlatKv::encode(with_hash, hash, body);
            b.add(zilkworm::hash_key8(hash), ByteView{with_hash.data(), with_hash.size()});
        }
        node_store_blob = std::move(b).finalize();
        if (node_store_blob.empty()) {
            std::cerr << "node-store MPHF build failed\n";
            return 1;
        }
    }

    const silkworm::ByteView block_rlps_arr[] = {block_rlp};
    std::vector<uint8_t> bundle = build_flat_bundle(
        genesis_rlp, std::span<const silkworm::ByteView>{block_rlps_arr},
        ancestors_rlp, direct_blob, node_store_blob,
        std::string_view{"Mainnet"});

    std::vector<uint8_t> envelope;
    envelope.resize(zilkworm::kInputHeaderSizeMFBD + bundle.size());
    const uint32_t mfbd_magic = zilkworm::kInputMagicMFBD;
    const uint32_t mfbd_version = zilkworm::kInputVersionMFBD;
    const uint64_t n_bundles = 1;
    std::memcpy(envelope.data() + 0,  &mfbd_magic,   sizeof(uint32_t));
    std::memcpy(envelope.data() + 4,  &mfbd_version, sizeof(uint32_t));
    std::memcpy(envelope.data() + 8,  &n_bundles,    sizeof(uint64_t));
    std::memcpy(envelope.data() + zilkworm::kInputHeaderSizeMFBD,
                bundle.data(), bundle.size());

    if (!legacy::write_file(argv[2], envelope)) {
        std::cerr << argv[2] << ": write failed\n";
        return 1;
    }
    return 0;
}
