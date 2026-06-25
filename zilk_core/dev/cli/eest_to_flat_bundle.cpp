// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// EEST blockchain_test JSON -> MFBD-wrapped FlatBundle converter.

#include <algorithm>
#include <bit>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <nlohmann/json.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/rlp/encode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie/node.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/core/types_zz/flat_kv.hpp>

using silkworm::ByteView;
using silkworm::Bytes;
using zilkworm::DirectState;
using silkworm::from_hex;
using silkworm::hex_to_address;
using silkworm::keccak256;
using silkworm::to_bytes32;
using silkworm::zeroless_view;
using ::zilkworm::Account;
using ::zilkworm::build_flat_bundle;
using ::zilkworm::FlatKv;
using ::zilkworm::MphfBuilder;

namespace fs = std::filesystem;
namespace trie = silkworm::trie;

namespace {

std::string read_file_to_string(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{}};
}

std::optional<Bytes> decode_hex(std::string_view s) {
    if (s.size() >= 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    return from_hex(s);
}

uint64_t hex_to_u64(std::string_view s) {
    if (s.size() >= 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    if (s.empty()) return 0;
    return std::stoull(std::string(s), nullptr, /*base=*/16);
}

intx::uint256 hex_or_dec_to_u256(std::string_view s) {
    return intx::from_string<intx::uint256>(std::string(s));
}

struct PreAccount {
    evmc::address                                              addr;
    uint64_t                                                   nonce{0};
    intx::uint256                                              balance{0};
    Bytes                                                      code;
    evmc::bytes32                                              code_hash{};
    std::vector<std::pair<evmc::bytes32, evmc::bytes32>>       storage;
    evmc::bytes32                                              storage_root{};
};

bool parse_pre_account(const nlohmann::json& j, const std::string& addr_hex,
                      PreAccount& out) {
    out.addr = hex_to_address(addr_hex);
    out.balance = hex_or_dec_to_u256(j.at("balance").get<std::string>());
    if (j.contains("nonce")) {
        out.nonce = hex_to_u64(j["nonce"].get<std::string>());
    }
    out.code_hash = std::bit_cast<evmc::bytes32>(silkworm::kEmptyHash);
    if (j.contains("code")) {
        auto code_bytes = decode_hex(j["code"].get<std::string>());
        if (!code_bytes) return false;
        if (!code_bytes->empty()) {
            out.code = std::move(*code_bytes);
            const auto h = keccak256(ByteView{out.code.data(), out.code.size()});
            std::memcpy(out.code_hash.bytes, h.bytes, 32);
        }
    }
    if (j.contains("storage")) {
        for (const auto& it : j["storage"].items()) {
            const auto key_b = decode_hex(it.key());
            const auto val_b = decode_hex(it.value().get<std::string>());
            if (!key_b || !val_b) return false;
            out.storage.emplace_back(to_bytes32(*key_b), to_bytes32(*val_b));
        }
    }
    return true;
}

struct CapturedNode {
    evmc::bytes32 hash;
    Bytes         rlp;
};

struct BuildResult {
    evmc::bytes32              root;
    std::vector<CapturedNode>  nodes_a;
};

BuildResult build_trie_via_hashbuilder(
        const std::vector<std::pair<evmc::bytes32, Bytes>>& pairs,
        const std::string& context) {
    std::vector<CapturedNode> nodes_a;
    std::vector<CapturedNode>* sink_a_ptr = &nodes_a;
    trie::HashBuilder hb_a;
    hb_a.rlp_collector = [sink_a_ptr](ByteView node_rlp) {
        CapturedNode cn{};
        const auto h = keccak256(node_rlp);
        std::memcpy(cn.hash.bytes, h.bytes, 32);
        cn.rlp.assign(node_rlp.begin(), node_rlp.end());
        sink_a_ptr->push_back(std::move(cn));
    };
    for (const auto& [k, v] : pairs) {
        hb_a.add_leaf(trie::unpack_nibbles(k.bytes), v);
    }
    const auto root_a = hb_a.root_hash();

    std::vector<CapturedNode> nodes_b;
    std::vector<CapturedNode>* sink_b_ptr = &nodes_b;
    trie::HashBuilder hb_b;
    hb_b.rlp_collector = [sink_b_ptr](ByteView node_rlp) {
        CapturedNode cn{};
        const auto h = keccak256(node_rlp);
        std::memcpy(cn.hash.bytes, h.bytes, 32);
        cn.rlp.assign(node_rlp.begin(), node_rlp.end());
        sink_b_ptr->push_back(std::move(cn));
    };
    for (const auto& [k, v] : pairs) {
        hb_b.add_leaf(trie::unpack_nibbles(k.bytes), v);
    }
    const auto root_b = hb_b.root_hash();

    if (root_a != root_b) {
        std::cerr << "[eest_to_flat_bundle] WARN: trie-root disagreement for "
                  << context << ": pathA=" << silkworm::to_hex(root_a)
                  << " pathB=" << silkworm::to_hex(root_b) << "\n";
    } else {
        auto hashes = [](const std::vector<CapturedNode>& v) {
            std::vector<evmc::bytes32> h;
            h.reserve(v.size());
            for (const auto& n : v) h.push_back(n.hash);
            std::sort(h.begin(), h.end(),
                      [](const evmc::bytes32& a, const evmc::bytes32& b) {
                          return std::memcmp(a.bytes, b.bytes, 32) < 0;
                      });
            h.erase(std::unique(h.begin(), h.end()), h.end());
            return h;
        };
        const auto ha = hashes(nodes_a);
        const auto hb = hashes(nodes_b);
        if (ha != hb) {
            std::cerr << "[eest_to_flat_bundle] WARN: trie node-set "
                         "disagreement for "
                      << context << " (root matched but node sets differ)\n";
        }
    }
    return BuildResult{root_a, std::move(nodes_a)};
}

struct Bytes32Less {
    bool operator()(const evmc::bytes32& a, const evmc::bytes32& b) const noexcept {
        return std::memcmp(a.bytes, b.bytes, 32) < 0;
    }
};
using NodeMap = std::map<evmc::bytes32, Bytes, Bytes32Less>;

void merge_nodes(NodeMap& sink, std::vector<CapturedNode>&& src) {
    for (auto& n : src) {
        sink.emplace(n.hash, std::move(n.rlp));
    }
}

std::vector<uint8_t> build_subtest(const nlohmann::json& test,
                                  const std::string& subtest_name) {
    if (!test.contains("blocks") || test["blocks"].empty()) {
        return {};
    }
    if (!test.contains("genesisRLP") || !test.contains("pre")) {
        std::cerr << "[eest_to_flat_bundle] skip " << subtest_name
                  << ": missing genesisRLP or pre\n";
        return {};
    }

    const auto genesis_rlp = decode_hex(test["genesisRLP"].get<std::string>());
    if (!genesis_rlp) {
        std::cerr << "[eest_to_flat_bundle] " << subtest_name
                  << ": bad genesisRLP hex\n";
        return {};
    }

    std::vector<Bytes> block_rlps_owned;
    std::vector<uint8_t> block_flags;
    bool any_invalid = false;
    block_rlps_owned.reserve(test["blocks"].size());
    for (const auto& blk : test["blocks"]) {
        if (!blk.contains("rlp")) continue;
        auto r = decode_hex(blk["rlp"].get<std::string>());
        if (!r) {
            std::cerr << "[eest_to_flat_bundle] " << subtest_name
                      << ": bad block.rlp hex\n";
            return {};
        }
        // expectException marks blocks the engine must reject.
        const bool expect_invalid = blk.contains("expectException");
        if (expect_invalid) {
            // Drop invalid blocks our Block decoder cannot represent.
            silkworm::Block probe;
            ByteView v{*r};
            if (!silkworm::rlp::decode(v, probe).has_value()) {
                continue;
            }
        }
        block_flags.push_back(expect_invalid ? ::zilkworm::kBlockFlagExpectInvalid : 0);
        any_invalid |= expect_invalid;
        block_rlps_owned.push_back(std::move(*r));
    }
    if (block_rlps_owned.empty()) {
        return {};
    }

    std::vector<PreAccount> pre;
    pre.reserve(test["pre"].size());
    for (const auto& [addr_hex, j] : test["pre"].items()) {
        PreAccount a{};
        if (!parse_pre_account(j, addr_hex, a)) {
            std::cerr << "[eest_to_flat_bundle] " << subtest_name
                      << ": bad pre account " << addr_hex << "\n";
            return {};
        }
        pre.push_back(std::move(a));
    }

    NodeMap node_store;

    for (auto& acc : pre) {
        if (acc.storage.empty()) {
            std::memcpy(acc.storage_root.bytes, silkworm::kEmptyRoot.bytes, 32);
            continue;
        }
        std::vector<std::pair<evmc::bytes32, Bytes>> pairs;
        pairs.reserve(acc.storage.size());
        for (const auto& [key, value] : acc.storage) {
            // Zero-valued slots are not stored in the trie.
            if (evmc::is_zero(value)) continue;
            evmc::bytes32 kh{};
            const auto h = keccak256(ByteView{key.bytes, 32});
            std::memcpy(kh.bytes, h.bytes, 32);
            Bytes leaf_rlp;
            silkworm::rlp::encode(leaf_rlp, zeroless_view(ByteView{value.bytes, 32}));
            pairs.emplace_back(kh, std::move(leaf_rlp));
        }
        if (pairs.empty()) {
            std::memcpy(acc.storage_root.bytes, silkworm::kEmptyRoot.bytes, 32);
            continue;
        }
        std::sort(pairs.begin(), pairs.end(),
                  [](const auto& l, const auto& r) {
                      return std::memcmp(l.first.bytes, r.first.bytes, 32) < 0;
                  });
        auto br = build_trie_via_hashbuilder(
            pairs, "storage subtest=" + subtest_name + " addr="
                       + silkworm::to_hex({acc.addr.bytes, 20}));
        acc.storage_root = br.root;
        merge_nodes(node_store, std::move(br.nodes_a));
    }

    {
        std::vector<std::pair<evmc::bytes32, Bytes>> pairs;
        pairs.reserve(pre.size());
        for (const auto& acc : pre) {
            Account wire{};
            std::memcpy(wire.addr, acc.addr.bytes, 20);
            wire.nonce = acc.nonce;
            std::memcpy(wire.balance, &acc.balance, 32);
            std::memcpy(wire.code_hash, acc.code_hash.bytes, 32);
            std::memcpy(wire.storage_root, acc.storage_root.bytes, 32);
            uint8_t buf[silkworm::kHashLength * 4 + 16];
            const auto n = wire.rlp_into(buf, acc.storage_root);
            Bytes leaf(buf, buf + n);

            evmc::bytes32 kh{};
            const auto h = keccak256(ByteView{acc.addr.bytes, 20});
            std::memcpy(kh.bytes, h.bytes, 32);
            pairs.emplace_back(kh, std::move(leaf));
        }
        std::sort(pairs.begin(), pairs.end(),
                  [](const auto& l, const auto& r) {
                      return std::memcmp(l.first.bytes, r.first.bytes, 32) < 0;
                  });
        auto br = build_trie_via_hashbuilder(
            pairs, "state subtest=" + subtest_name);
        merge_nodes(node_store, std::move(br.nodes_a));
        (void)br.root;
    }

    std::vector<DirectState::AccountInfo> infos;
    infos.reserve(pre.size());
    std::unordered_map<evmc::bytes32, Bytes> code_map;
    for (auto& acc : pre) {
        DirectState::AccountInfo info{};
        info.addr = acc.addr;
        info.account.nonce = acc.nonce;
        std::memcpy(info.account.balance, &acc.balance, 32);
        std::memcpy(info.account.code_hash, acc.code_hash.bytes, 32);
        std::memcpy(info.account.storage_root, acc.storage_root.bytes, 32);
        info.account.code_store_len = static_cast<uint32_t>(acc.code.size());
        if (!acc.code.empty()) {
            code_map.try_emplace(acc.code_hash, acc.code);
        }
        // Drop zero-valued slots: storage trie omits them.
        std::vector<std::pair<evmc::bytes32, evmc::bytes32>> nonzero_storage;
        nonzero_storage.reserve(acc.storage.size());
        for (const auto& kv : acc.storage) {
            if (evmc::is_zero(kv.second)) continue;
            nonzero_storage.push_back(kv);
        }
        std::sort(nonzero_storage.begin(), nonzero_storage.end(),
                  [](const auto& l, const auto& r) {
                      return std::memcmp(l.first.bytes, r.first.bytes, 32) < 0;
                  });
        info.storage = std::move(nonzero_storage);
        infos.push_back(std::move(info));
    }
    std::vector<uint8_t> code_store_blob;
    if (!code_map.empty()) {
        MphfBuilder<32> cb{::zilkworm::kMphfCodeStoreMagic,
                           ::zilkworm::kMphfMapVersion};
        std::vector<uint8_t> enc;
        for (const auto& [ch, code_bytes] : code_map) {
            enc.clear();
            FlatKv::encode(enc, ch, ByteView{code_bytes.data(), code_bytes.size()});
            cb.add(::zilkworm::hash_key8(ch), ByteView{enc.data(), enc.size()});
        }
        code_store_blob = std::move(cb).finalize();
        if (code_store_blob.empty()) {
            std::cerr << "[eest_to_flat_bundle] " << subtest_name
                      << ": code-store MPHF build failed\n";
            return {};
        }
    }

    auto direct_blob =
        DirectState::build_blob_from_accounts(std::move(infos), /*block_hashes=*/{},
                                              std::move(code_store_blob));
    if (direct_blob.empty()) {
        std::cerr << "[eest_to_flat_bundle] " << subtest_name
                  << ": DirectState blob build failed\n";
        return {};
    }

    std::vector<uint8_t> node_store_blob;
    if (!node_store.empty()) {
        MphfBuilder<32> b{::zilkworm::kMphfNodeStoreMagic,
                          ::zilkworm::kMphfMapVersion};
        std::vector<uint8_t> enc;
        for (const auto& [hash, rlp] : node_store) {
            enc.clear();
            FlatKv::encode(enc, hash, ByteView{rlp.data(), rlp.size()});
            b.add(::zilkworm::hash_key8(hash), ByteView{enc.data(), enc.size()});
        }
        node_store_blob = std::move(b).finalize();
        if (node_store_blob.empty()) {
            std::cerr << "[eest_to_flat_bundle] " << subtest_name
                      << ": node-store MPHF build failed\n";
            return {};
        }
    }

    std::vector<ByteView> block_views;
    block_views.reserve(block_rlps_owned.size());
    for (const auto& b : block_rlps_owned) {
        block_views.emplace_back(b);
    }
    std::string network;
    if (test.contains("network") && test["network"].is_string()) {
        network = test["network"].get<std::string>();
    } else {
        network = "Mainnet";
    }
    auto bundle = build_flat_bundle(
        ByteView{*genesis_rlp},
        std::span<const ByteView>{block_views.data(), block_views.size()},
        /*ancestors_rlp=*/ByteView{},
        direct_blob,
        node_store_blob,
        std::string_view{network},
        any_invalid ? std::span<const uint8_t>{block_flags}
                    : std::span<const uint8_t>{});
    return bundle;
}

auto align8 = [](size_t v) noexcept { return (v + 7u) & ~size_t{7u}; };

std::vector<uint8_t> wrap_mfbd(const std::vector<std::vector<uint8_t>>& bundles) {
    size_t total = ::zilkworm::kInputHeaderSizeMFBD;
    for (size_t i = 0; i < bundles.size(); ++i) {
        const bool last = (i + 1 == bundles.size());
        total += last ? bundles[i].size() : align8(bundles[i].size());
    }
    std::vector<uint8_t> env(total, 0);
    const uint32_t magic = ::zilkworm::kInputMagicMFBD;
    const uint32_t version = ::zilkworm::kInputVersionMFBD;
    const uint64_t n = bundles.size();
    std::memcpy(env.data() + 0, &magic,   sizeof(uint32_t));
    std::memcpy(env.data() + 4, &version, sizeof(uint32_t));
    std::memcpy(env.data() + 8, &n,       sizeof(uint64_t));
    size_t cursor = ::zilkworm::kInputHeaderSizeMFBD;
    for (size_t i = 0; i < bundles.size(); ++i) {
        std::memcpy(env.data() + cursor, bundles[i].data(), bundles[i].size());
        const bool last = (i + 1 == bundles.size());
        cursor += last ? bundles[i].size() : align8(bundles[i].size());
    }
    return env;
}

std::vector<std::pair<std::string, nlohmann::json>>
list_subtests(const nlohmann::json& root) {
    std::vector<std::pair<std::string, nlohmann::json>> out;
    if (!root.is_object()) return out;
    for (const auto& [name, body] : root.items()) {
        out.emplace_back(name, body);
    }
    return out;
}

int run_emit(const std::string& json_path, size_t index) {
    const auto data = read_file_to_string(json_path);
    if (data.empty()) {
        std::cerr << "[eest_to_flat_bundle] empty/missing file: "
                  << json_path << "\n";
        return 1;
    }
    nlohmann::json root;
    try {
        root = nlohmann::json::parse(data);
    } catch (const std::exception& e) {
        std::cerr << "[eest_to_flat_bundle] " << json_path
                  << ": JSON parse error: " << e.what() << "\n";
        return 1;
    }
    auto subs = list_subtests(root);
    if (index >= subs.size()) {
        std::cerr << "[eest_to_flat_bundle] index " << index
                  << " out of range (n=" << subs.size() << ") in "
                  << json_path << "\n";
        return 1;
    }
    auto bundle = build_subtest(subs[index].second, subs[index].first);
    if (bundle.empty()) {
        std::cerr << "[eest_to_flat_bundle] subtest produced empty bundle: "
                  << subs[index].first << "\n";
        return 1;
    }
    auto env = wrap_mfbd({std::move(bundle)});
    std::cout.write(reinterpret_cast<const char*>(env.data()),
                    static_cast<std::streamsize>(env.size()));
    return 0;
}

struct FileResult {
    fs::path src;
    fs::path dst;
    bool     ok{false};
    std::string error;
};

FileResult convert_one_file(const fs::path& src, const fs::path& dst) {
    FileResult r{src, dst, false, {}};
    try {
        const auto data = read_file_to_string(src);
        if (data.empty()) {
            r.error = "empty/missing";
            return r;
        }
        nlohmann::json root;
        try {
            root = nlohmann::json::parse(data);
        } catch (const std::exception& e) {
            r.error = std::string("JSON parse error: ") + e.what();
            return r;
        }
        auto subs = list_subtests(root);
        std::vector<std::vector<uint8_t>> bundles;
        bundles.reserve(subs.size());
        for (auto& [name, body] : subs) {
            auto b = build_subtest(body, name);
            if (!b.empty()) bundles.push_back(std::move(b));
        }
        if (bundles.empty()) {
            r.ok = true;
            r.error = "no accepted subtests; skipped";
            return r;
        }
        auto env = wrap_mfbd(bundles);
        fs::create_directories(dst.parent_path());
        std::ofstream out(dst, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(env.data()),
                  static_cast<std::streamsize>(env.size()));
        if (!out.good()) {
            r.error = "write failed";
            return r;
        }
        r.ok = true;
    } catch (const std::exception& e) {
        r.error = std::string("exception: ") + e.what();
    } catch (...) {
        r.error = "unknown exception";
    }
    return r;
}

int run_bulk_convert(const std::string& input_dir, const std::string& output_dir) {
    fs::path in_root{input_dir};
    fs::path out_root{output_dir};
    if (!fs::exists(in_root) || !fs::is_directory(in_root)) {
        std::cerr << "[eest_to_flat_bundle] bad --input-dir: " << input_dir << "\n";
        return 1;
    }

    std::vector<std::pair<fs::path, fs::path>> jobs;
    for (const auto& e : fs::recursive_directory_iterator(in_root)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() != ".json") continue;
        const auto rel = fs::relative(e.path(), in_root);
        auto dst = out_root / rel;
        dst.replace_extension(".mfbd");
        jobs.emplace_back(e.path(), std::move(dst));
    }

    if (jobs.empty()) {
        std::cerr << "[eest_to_flat_bundle] no .json files found under "
                  << input_dir << "\n";
        return 0;
    }

    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    unsigned forced = 0;
    if (const char* env = std::getenv("ZILK_EEST_BULK_WORKERS")) {
        forced = static_cast<unsigned>(std::stoul(env));
    }
    const size_t batch = forced > 0
        ? std::min<size_t>(forced, jobs.size())
        : std::min<size_t>(hw, jobs.size());
    std::cerr << "[eest_to_flat_bundle] converting " << jobs.size()
              << " files with " << batch << " workers\n";

    std::atomic<size_t> next{0};
    std::atomic<size_t> done{0};
    std::atomic<size_t> err{0};
    std::mutex log_mu;

    auto worker = [&]() {
        while (true) {
            const size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= jobs.size()) break;
            const auto& [src, dst] = jobs[i];
            auto r = convert_one_file(src, dst);
            if (!r.ok) {
                err.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard<std::mutex> g(log_mu);
                std::cerr << "[eest_to_flat_bundle] FAIL " << src
                          << ": " << r.error << "\n";
            } else if (!r.error.empty()) {
                std::lock_guard<std::mutex> g(log_mu);
                std::cerr << "[eest_to_flat_bundle] note " << src
                          << ": " << r.error << "\n";
            }
            done.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::vector<std::future<void>> fts;
    fts.reserve(batch);
    for (size_t w = 0; w < batch; ++w) {
        fts.push_back(std::async(std::launch::async, worker));
    }
    for (auto& f : fts) f.get();

    std::cerr << "[eest_to_flat_bundle] done: " << done.load()
              << " files, " << err.load() << " errors\n";
    return err.load() == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " emit --json <PATH> --index <N>\n"
                  << "  " << argv[0] << " bulk-convert --input-dir <D> --output-dir <D>\n";
        return 1;
    }
    const std::string cmd = argv[1];

    auto find_arg = [&](std::string_view name) -> std::optional<std::string> {
        for (int i = 2; i + 1 < argc; ++i) {
            if (name == argv[i]) return std::string(argv[i + 1]);
        }
        return std::nullopt;
    };

    if (cmd == "emit") {
        auto path = find_arg("--json");
        auto idx_s = find_arg("--index");
        if (!path || !idx_s) {
            std::cerr << "emit: need --json <PATH> --index <N>\n";
            return 1;
        }
        const size_t idx = std::stoull(*idx_s);
        return run_emit(*path, idx);
    }
    if (cmd == "bulk-convert") {
        auto in_d  = find_arg("--input-dir");
        auto out_d = find_arg("--output-dir");
        if (!in_d || !out_d) {
            std::cerr << "bulk-convert: need --input-dir <D> --output-dir <D>\n";
            return 1;
        }
        return run_bulk_convert(*in_d, *out_d);
    }
    std::cerr << "unknown subcommand: " << cmd << "\n";
    return 1;
}
