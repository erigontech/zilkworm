// SCRATCH (not for commit): MFBD -> SLIB envelope (+ one-block blockchain-test JSON) for HashState runs.
#include <fstream>
#include <iostream>
#include <iterator>
#include <algorithm>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/slib_encode.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>
using silkworm::Bytes; using silkworm::ByteView;
int main(int argc, char** argv) {
    if (argc != 4) { std::cerr << "usage: mfbd_to_slib in.mfbd out.slib out.json\n"; return 1; }
    std::ifstream f(argv[1], std::ios::binary);
    std::vector<uint8_t> env((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>{});
    std::span<uint8_t> tail{env.data() + zilkworm::kInputHeaderSizeMFBD, env.size() - zilkworm::kInputHeaderSizeMFBD};
    auto fb = zilkworm::load_flat_bundle(tail);
    if (!fb) { std::cerr << "load_flat_bundle failed\n"; return 1; }
    std::vector<Bytes> nodes, codes;
    fb->direct.scratch_node_store_map().for_each<32, 0>([&](const uint8_t*, std::span<uint8_t> body) {
        ByteView b{body.data(), body.size()}; nodes.emplace_back(zilkworm::FlatKv::payload(b)); });
    fb->direct.scratch_code_store_map().for_each<32, 0>([&](const uint8_t*, std::span<uint8_t> body) {
        ByteView b{body.data(), body.size()}; codes.emplace_back(zilkworm::FlatKv::payload(b)); });
    // Headers: ancestors plus the parent (genesis section), oldest first, deduped by number.
    std::vector<silkworm::BlockHeader> hdrs = fb->ancestors;
    bool have_parent = false;
    for (auto& h : hdrs) if (h.number == fb->genesis.header.number) have_parent = true;
    if (!have_parent) hdrs.push_back(fb->genesis.header);
    std::sort(hdrs.begin(), hdrs.end(), [](auto& a, auto& b) { return a.number < b.number; });
    std::vector<Bytes> hrlp; for (auto& h : hdrs) { Bytes o; silkworm::rlp::encode(o, h); hrlp.push_back(std::move(o)); }
    std::vector<ByteView> sv, cv, hv;
    for (auto& n : nodes) sv.emplace_back(n);
    for (auto& c : codes) cv.emplace_back(c);
    for (auto& h : hrlp) hv.emplace_back(h);
    const auto blob = zilkworm::encode_stateless_input(sv, cv, hv, 1);
    if (!blob) { std::cerr << "encode_stateless_input limit\n"; return 1; }
    ByteView block_rlp = fb->block_rlps.at(0);
    const std::string network = "Mainnet";
    Bytes out;
    auto u32 = [&](uint32_t v) { for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i))); };
    u32(zilkworm::kInputMagicSLIB); u32(zilkworm::kInputVersionSLIB);
    u32(static_cast<uint32_t>(network.size())); u32(static_cast<uint32_t>(block_rlp.size()));
    out.append(reinterpret_cast<const uint8_t*>(network.data()), network.size());
    out.append(block_rlp); out += *blob;
    std::ofstream(argv[2], std::ios::binary).write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    Bytes genesis_rlp; silkworm::rlp::encode(genesis_rlp, fb->genesis);
    nlohmann::ordered_json test;
    test["network"] = network;
    test["genesisRLP"] = silkworm::to_hex(genesis_rlp, true);
    test["blocks"] = nlohmann::ordered_json::array({{{"rlp", silkworm::to_hex(block_rlp, true)}, {"statelessInputBytes", silkworm::to_hex(ByteView{*blob}, true)}}});
    nlohmann::ordered_json j; j["mainnet_" + std::to_string(fb->genesis.header.number + 1)] = std::move(test);
    std::ofstream(argv[3]) << j.dump();
    std::cerr << "nodes=" << nodes.size() << " codes=" << codes.size() << " headers=" << hrlp.size() << " slib=" << out.size() << "\n";
    return 0;
}
