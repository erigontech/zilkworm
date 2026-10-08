// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Converts a legacy unifiedBlockAndStateRlp<N>.bin witness into HashState input, so HashState
// can run the same mainnet blocks the DirectState benchmark does. The output is a SLIB
// envelope (binary: network, block RLP, statelessInputBytes), or, when the output path ends
// in ".json", a one-block blockchain-test JSON carrying the same statelessInputBytes.
//
// The blob is a benchmark encoding: the full witness (state nodes, codes, ancestor headers)
// with an empty new_payload_request and no public keys. HashState reads neither and executes
// the block from its RLP. Other EIP-8025 tools would reject it.

#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state_zz/slib_encode.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

#include "legacy_witness.hpp"

using silkworm::Bytes;
using silkworm::ByteView;
namespace legacy = ::zilkworm::legacy;

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0]
                  << " <unifiedBlockAndStateRlp.bin> <statelessInput.slib | ethTests.json>\n";
        return 1;
    }

    const auto raw = legacy::read_file(argv[1]);
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

    std::vector<std::pair<evmc::bytes32, ByteView>> nodes;
    std::vector<std::pair<evmc::bytes32, Bytes>> codes;
    std::vector<ByteView> headers;
    if (!legacy::parse_trie_nodes(sections->pre_trie_rlp, nodes, err) ||
        !legacy::parse_codes(sections->pre_state_rlp, codes, err) ||
        !legacy::parse_headers(sections->ancestors_rlp, headers, err)) {
        std::cerr << argv[1] << ": " << err << "\n";
        return 1;
    }

    std::vector<ByteView> state_views;
    state_views.reserve(nodes.size());
    for (const auto& [hash, node] : nodes) state_views.push_back(node);
    std::vector<ByteView> code_views;
    code_views.reserve(codes.size());
    for (const auto& [hash, code] : codes) code_views.emplace_back(code);

    const auto blob = ::zilkworm::encode_stateless_input(state_views, code_views, headers, /*chain_id=*/1);
    if (!blob) {
        std::cerr << argv[1] << ": witness exceeds a statelessInputBytes limit\n";
        return 1;
    }

    // "Mainnet" gives chain id 1 and the mainnet fork schedule.
    const std::string network = "Mainnet";
    const std::string out_path = argv[2];
    if (!out_path.ends_with(".json")) {
        const auto u32 = [](Bytes& b, uint32_t v) {
            for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
        };
        Bytes env;
        env.reserve(::zilkworm::kInputHeaderSizeSLIB + network.size() + sections->block_rlp.size() +
                    blob->size());
        u32(env, ::zilkworm::kInputMagicSLIB);
        u32(env, ::zilkworm::kInputVersionSLIB);
        u32(env, static_cast<uint32_t>(network.size()));
        u32(env, static_cast<uint32_t>(sections->block_rlp.size()));
        env.append(reinterpret_cast<const uint8_t*>(network.data()), network.size());
        env.append(sections->block_rlp);
        env += *blob;
        if (!legacy::write_file(out_path, std::vector<uint8_t>(env.begin(), env.end()))) {
            std::cerr << out_path << ": write failed\n";
            return 1;
        }
        return 0;
    }

    // The block number names the test. The runner scores a name as a witness-validation
    // negative only when it contains "eip8025_optional_proofs" together with one of the
    // ::test_validation_* markers (is_stateless_witness_negative); "mainnet_<N>" has neither.
    silkworm::Block block;
    ByteView block_view = sections->block_rlp;
    if (!silkworm::rlp::decode(block_view, block)) {
        std::cerr << argv[1] << ": block RLP decode failed\n";
        return 1;
    }

    // Only the fields the runner reads: the guest parses the whole JSON, so anything else
    // costs cycles.
    nlohmann::ordered_json test;
    test["network"] = network;
    test["genesisRLP"] = silkworm::to_hex(sections->genesis_rlp, true);
    test["blocks"] = nlohmann::ordered_json::array(
        {{{"rlp", silkworm::to_hex(sections->block_rlp, true)},
          {"statelessInputBytes", silkworm::to_hex(ByteView{*blob}, true)}}});
    nlohmann::ordered_json out;
    out["mainnet_" + std::to_string(block.header.number)] = std::move(test);

    const std::string text = out.dump();
    if (!legacy::write_file(out_path, std::vector<uint8_t>(text.begin(), text.end()))) {
        std::cerr << out_path << ": write failed\n";
        return 1;
    }
    return 0;
}
