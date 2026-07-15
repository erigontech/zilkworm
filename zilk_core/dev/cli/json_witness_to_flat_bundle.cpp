// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Reads a witness JSON document on stdin, emits a FlatBundle on stdout.

#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <intx/intx.hpp>
#include <nlohmann/json.hpp>
#include <evmone_precompiles/keccak.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/state_zz/direct_state.hpp>
#include <zilk_core/core/common_zz/mphf_builder.hpp>
#include <zilk_core/core/common_zz/mphf_map.hpp>
#include <zilk_core/core/types_zz/account.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types/withdrawal.hpp>

#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/core/types_zz/witness_trie.hpp>

namespace {

using silkworm::ByteView;
using silkworm::Bytes;

std::vector<uint8_t> read_all_stdin() {
    std::vector<uint8_t> buf;
    constexpr size_t kChunk = 64 * 1024;
    uint8_t tmp[kChunk];
    while (true) {
        size_t n = std::fread(tmp, 1, kChunk, stdin);
        if (n == 0) break;
        buf.insert(buf.end(), tmp, tmp + n);
        if (n < kChunk) break;
    }
    return buf;
}

evmc::bytes32 keccak_view(ByteView v) {
    return std::bit_cast<evmc::bytes32>(silkworm::keccak256(v));
}

evmc::bytes32 nibbles_to_bytes32(std::span<const uint8_t> nibs) {
    evmc::bytes32 out{};
    if (nibs.size() != 64) return out;
    for (size_t i = 0; i < 32; ++i) {
        out.bytes[i] = static_cast<uint8_t>((nibs[2 * i] << 4) | (nibs[2 * i + 1] & 0x0F));
    }
    return out;
}

bool decode_storage_value(ByteView leaf_value, evmc::bytes32& out) {
    intx::uint256 v;
    if (auto r = silkworm::rlp::decode(leaf_value, v); !r) return false;
    out = intx::be::store<evmc::bytes32>(v);
    return true;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool decode_hex(std::string_view s, std::vector<uint8_t>& out) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    if (s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool collect_hex_records(const nlohmann::json& v, std::vector<std::vector<uint8_t>>& out) {
    out.clear();
    if (v.is_null()) return true;
    auto take = [&](const nlohmann::json& item) {
        if (!item.is_string()) return false;
        std::vector<uint8_t> buf;
        if (!decode_hex(item.get<std::string_view>(), buf)) return false;
        out.push_back(std::move(buf));
        return true;
    };
    if (v.is_array()) {
        for (const auto& item : v) {
            if (!take(item)) return false;
        }
        return true;
    }
    if (v.is_object()) {
        for (auto it = v.begin(); it != v.end(); ++it) {
            if (!take(it.value())) return false;
        }
        return true;
    }
    return false;
}

}  // namespace


int main() {
    std::vector<uint8_t> input = read_all_stdin();

    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(input);
    } catch (const std::exception& e) {
        std::cerr << "flat_bundle_builder: JSON parse failed: " << e.what() << "\n";
        return 1;
    }

    std::vector<uint8_t> current_block_rlp;
    auto load_hex = [&](const char* field, std::vector<uint8_t>& dst) {
        const auto it = doc.find(field);
        if (it == doc.end() || !it->is_string()) {
            std::cerr << "flat_bundle_builder: missing/invalid field '" << field << "'\n";
            return false;
        }
        if (!decode_hex(it->get<std::string_view>(), dst)) {
            std::cerr << "flat_bundle_builder: bad hex in '" << field << "'\n";
            return false;
        }
        return true;
    };
    if (!load_hex("block", current_block_rlp)) return 1;

    const auto headers_it = doc.find("headers");
    if (headers_it == doc.end() || !headers_it->is_array()) {
        std::cerr << "flat_bundle_builder: missing/invalid 'headers' array\n";
        return 1;
    }
    std::vector<silkworm::BlockHeader> ancestors;
    ancestors.reserve(headers_it->size());
    std::vector<std::vector<uint8_t>> header_blobs;
    header_blobs.reserve(headers_it->size());
    for (const auto& h_json : *headers_it) {
        if (!h_json.is_string()) {
            std::cerr << "flat_bundle_builder: headers entry not a hex string\n";
            return 1;
        }
        std::vector<uint8_t> bytes;
        if (!decode_hex(h_json.get<std::string_view>(), bytes)) {
            std::cerr << "flat_bundle_builder: bad hex in headers entry\n";
            return 1;
        }
        ByteView v{bytes.data(), bytes.size()};
        silkworm::BlockHeader header;
        if (!silkworm::rlp::decode(v, header, silkworm::rlp::Leftover::kProhibit)
                 .has_value()) {
            std::cerr << "flat_bundle_builder: ancestor header decode failed\n";
            return 1;
        }
        ancestors.push_back(std::move(header));
        header_blobs.push_back(std::move(bytes));
    }
    if (ancestors.empty()) {
        std::cerr << "flat_bundle_builder: headers must contain at least one entry\n";
        return 1;
    }
    const silkworm::BlockHeader& prev_header = ancestors.back();

    // ancestors.back() is trusted as the immediate parent; verify before use so a
    // mis-ordered/wrong header can't silently feed a bogus pre_root.
    {
        silkworm::Block cur_block;
        ByteView cur_v{current_block_rlp.data(), current_block_rlp.size()};
        if (!silkworm::rlp::decode(cur_v, cur_block, silkworm::rlp::Leftover::kAllow)
                 .has_value()) {
            std::cerr << "flat_bundle_builder: current block header decode failed\n";
            return 1;
        }
        const silkworm::BlockHeader& cur_header = cur_block.header;
        const evmc::bytes32 parent_hash = prev_header.hash();
        if (prev_header.number != cur_header.number - 1 ||
            parent_hash != cur_header.parent_hash) {
            std::cerr << "ERROR: flat_bundle_builder: ancestors.back() is not the parent (got number="
                      << prev_header.number
                      << ", hash=" << silkworm::to_hex(ByteView{parent_hash.bytes, 32}, true)
                      << "; expected number=" << (cur_header.number - 1)
                      << ", parent_hash=" << silkworm::to_hex(ByteView{cur_header.parent_hash.bytes, 32}, true) << ")\n";
            return 1;
        }
    }

    evmc::bytes32 pre_root = prev_header.state_root;

    silkworm::Bytes prev_block_rlp;
    {
        silkworm::Block prev_block;
        prev_block.header = prev_header;
        silkworm::rlp::encode(prev_block_rlp, prev_block);
    }

    silkworm::Bytes ancestors_rlp;
    {
        size_t payload = 0;
        for (const auto& hb : header_blobs) payload += hb.size();
        silkworm::rlp::encode_header(ancestors_rlp,
                                     {.list = true, .payload_length = payload});
        for (const auto& hb : header_blobs) {
            ancestors_rlp.insert(ancestors_rlp.end(), hb.begin(), hb.end());
        }
    }

    // The "keys" (preimage) section is intentionally ignored: the flat
    // pre-state is keyed by the trie keys (keccak256(address) /
    // keccak256(slot)), which are always derivable from the leaf paths.
    std::vector<std::vector<uint8_t>> state_records;
    std::vector<std::vector<uint8_t>> code_records;
    if (!collect_hex_records(doc.value("state",  nlohmann::json::array()), state_records) ||
        !collect_hex_records(doc.value("codes",  nlohmann::json::array()), code_records)) {
        std::cerr << "flat_bundle_builder: bad state/codes section\n";
        return 1;
    }

    zilkworm::witness::NodeMap nodes;
    std::vector<std::pair<evmc::bytes32, ByteView>> ns_entries;
    nodes.reserve(state_records.size());
    ns_entries.reserve(state_records.size());
    for (const auto& node : state_records) {
        ByteView v{node.data(), node.size()};
        evmc::bytes32 h = keccak_view(v);
        nodes.emplace(h, v);
        ns_entries.emplace_back(h, v);
    }

    std::unordered_map<evmc::bytes32,
                       ByteView,
                       zilkworm::witness::NodeHash> code_map;
    code_map.reserve(code_records.size());
    for (const auto& code : code_records) {
        ByteView v{code.data(), code.size()};
        code_map.emplace(keccak_view(v), v);
    }

    // Every account/storage leaf reachable from pre_root MUST be included in
    // the flat pre-state, keyed by its trie key. A leaf we cannot represent
    // is a hard error — silently dropping it would let execution observe an
    // existing account/slot as empty (soundness gap, see block 25538620).
    std::vector<zilkworm::DirectState::AccountInfo> accounts;
    bool walk_error = false;

    zilkworm::witness::for_each_leaf(nodes, pre_root,
        [&](std::span<const uint8_t> nibbles, ByteView account_rlp) {
            if (walk_error) return;
            if (nibbles.size() != 64) {
                std::cerr << "flat_bundle_builder: account leaf at depth "
                          << nibbles.size() << " != 64 nibbles\n";
                walk_error = true;
                return;
            }
            const evmc::bytes32 hashed_addr = nibbles_to_bytes32(nibbles);

            zilkworm::Account acc{};
            if (!zilkworm::decode_trie_account(account_rlp, acc)) {
                std::cerr << "flat_bundle_builder: undecodable account leaf\n";
                walk_error = true;
                return;
            }

            zilkworm::DirectState::AccountInfo info;
            info.addr_hash = hashed_addr;
            info.storage_keys_hashed = true;
            info.account = acc;

            const auto acc_code_hash    = std::bit_cast<evmc::bytes32>(acc.code_hash);
            const auto acc_storage_root = std::bit_cast<evmc::bytes32>(acc.storage_root);
            if (acc_code_hash != silkworm::kEmptyHash) {
                if (auto cit = code_map.find(acc_code_hash); cit != code_map.end()) {
                    info.account.code_store_len = static_cast<uint32_t>(cit->second.size());
                }
            }

            if (!evmc::is_zero(acc_storage_root) && acc_storage_root != silkworm::kEmptyRoot) {
                zilkworm::witness::for_each_leaf(nodes, acc_storage_root,
                    [&](std::span<const uint8_t> slot_nibs, ByteView slot_rlp) {
                        if (walk_error) return;
                        if (slot_nibs.size() != 64) {
                            std::cerr << "flat_bundle_builder: storage leaf at depth "
                                      << slot_nibs.size() << " != 64 nibbles\n";
                            walk_error = true;
                            return;
                        }
                        const evmc::bytes32 hashed_slot = nibbles_to_bytes32(slot_nibs);
                        evmc::bytes32 slot_value{};
                        if (!decode_storage_value(slot_rlp, slot_value)) {
                            std::cerr << "flat_bundle_builder: undecodable storage leaf\n";
                            walk_error = true;
                            return;
                        }
                        if (evmc::is_zero(slot_value)) {
                            std::cerr << "flat_bundle_builder: zero-valued storage leaf in trie\n";
                            walk_error = true;
                            return;
                        }
                        info.storage.emplace_back(hashed_slot, slot_value);
                    });
            }
            if (walk_error) return;

            accounts.push_back(std::move(info));
        });
    if (walk_error) {
        return 1;
    }

    std::vector<zilkworm::BlockHashEntry> block_hashes;
    block_hashes.reserve(ancestors.size());
    for (const auto& header : ancestors) {
        zilkworm::BlockHashEntry e{};
        e.block_number = header.number;
        const auto h = header.hash();
        std::memcpy(e.block_hash, h.bytes, 32);
        block_hashes.push_back(e);
    }

    std::vector<uint8_t> code_store_blob;
    if (!code_map.empty()) {
        zilkworm::MphfBuilder<32> cb{zilkworm::kMphfCodeStoreMagic,
                                     zilkworm::kMphfMapVersion};
        std::vector<uint8_t> enc;
        for (const auto& [ch, code_view] : code_map) {
            enc.clear();
            zilkworm::FlatKv::encode(enc, ch, code_view);
            cb.add(zilkworm::hash_key8(ch), ByteView{enc.data(), enc.size()});
        }
        code_store_blob = std::move(cb).finalize();
        if (code_store_blob.empty()) {
            std::cerr << "code-store MPHF build failed\n";
            return 1;
        }
    }

    std::vector<uint8_t> direct_blob =
        zilkworm::DirectState::build_blob_from_accounts(std::move(accounts),
                                                        std::move(block_hashes),
                                                        std::move(code_store_blob));
    if (direct_blob.empty()) {
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

    const silkworm::ByteView block_rlps_arr[] = {
        ByteView{current_block_rlp.data(), current_block_rlp.size()}
    };
    std::vector<uint8_t> bundle = zilkworm::build_flat_bundle(
        ByteView{prev_block_rlp.data(), prev_block_rlp.size()},
        std::span<const silkworm::ByteView>{block_rlps_arr},
        ByteView{ancestors_rlp.data(), ancestors_rlp.size()},
        direct_blob, node_store_blob,
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

    if (std::fwrite(envelope.data(), 1, envelope.size(), stdout) != envelope.size()) {
        std::cerr << "flat_bundle_builder: short write to stdout\n";
        return 2;
    }
    return 0;
}
