// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// Reader for the legacy unifiedBlockAndStateRlp<N>.bin witness files, shared by
// legacy_to_flat_bundle and legacy_to_slib_fixture. A file is one RLP list of five
// string-wrapped items: prev_block, current_block, pre_state, ancestors, pre_trie.

#pragma once

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <evmc/evmc.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/rlp/decode.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

namespace zilkworm::legacy {

using silkworm::Bytes;
using silkworm::ByteView;

inline std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>{});
}

inline bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return f.good();
}

// Peels the outer RLP string wrap; returns inner payload bytes.
inline ByteView take_item(ByteView& cur) {
    auto h = silkworm::rlp::decode_header(cur);
    if (!h) return {};
    ByteView payload = cur.substr(0, h->payload_length);
    cur.remove_prefix(h->payload_length);
    return payload;
}

struct Sections {
    ByteView genesis_rlp;    // parent block N-1 as [header, [], [], []]
    ByteView block_rlp;      // block N
    ByteView pre_state_rlp;  // [accounts, storage, codes], flattened values
    ByteView ancestors_rlp;  // list of string-wrapped header RLPs, oldest first; may be empty
    ByteView pre_trie_rlp;   // [0xA0 hash32, string-wrapped node RLP]*
};

// Splits a whole file into its five sections. On failure returns std::nullopt and sets err.
inline std::optional<Sections> split_sections(ByteView file, std::string& err) {
    auto outer = silkworm::rlp::decode_header(file);
    if (!outer || !outer->list) {
        err = "bad outer RLP header";
        return std::nullopt;
    }
    ByteView pv = file.substr(0, outer->payload_length);
    Sections s;
    s.genesis_rlp = take_item(pv);
    s.block_rlp = take_item(pv);
    s.pre_state_rlp = take_item(pv);
    s.ancestors_rlp = take_item(pv);
    s.pre_trie_rlp = take_item(pv);
    if (s.genesis_rlp.empty() || s.block_rlp.empty() || s.pre_state_rlp.empty() ||
        s.pre_trie_rlp.empty()) {
        err = "missing section";
        return std::nullopt;
    }
    return s;
}

// pre_trie: each entry is `0xA0 hash[32]` followed by the string-wrapped node RLP. Appends
// (hash, raw node RLP) pairs in file order; the views point into pre_trie_rlp.
inline bool parse_trie_nodes(ByteView pre_trie_rlp, std::vector<std::pair<evmc::bytes32, ByteView>>& out,
                             std::string& err) {
    ByteView pt = pre_trie_rlp;
    auto pt_h = silkworm::rlp::decode_header(pt);
    if (!pt_h || !pt_h->list) {
        err = "bad pre_trie header";
        return false;
    }
    ByteView ptp = pt.substr(0, pt_h->payload_length);
    while (!ptp.empty()) {
        if (ptp.size() < 33 || ptp[0] != 0xA0) {
            err = "bad hash prefix in pre_trie";
            return false;
        }
        evmc::bytes32 h;
        std::memcpy(h.bytes, ptp.data() + 1, 32);
        ptp.remove_prefix(33);
        auto body_h = silkworm::rlp::decode_header(ptp);
        if (!body_h || body_h->list) {
            err = "bad node body header";
            return false;
        }
        out.emplace_back(h, ptp.substr(0, body_h->payload_length));
        ptp.remove_prefix(body_h->payload_length);
    }
    return true;
}

// pre_state's third list: flat (code_hash, code) pairs, after the accounts and storage lists.
// Appends non-empty codes in file order (the guest never looks up empty code). A missing codes
// list is not an error.
inline bool parse_codes(ByteView pre_state_rlp, std::vector<std::pair<evmc::bytes32, Bytes>>& out,
                        std::string& err) {
    ByteView ps = pre_state_rlp;
    auto pso = silkworm::rlp::decode_header(ps);
    if (!pso || !pso->list) {
        err = "bad pre_state header";
        return false;
    }
    ByteView psp = ps.substr(0, pso->payload_length);
    for (const char* name : {"accounts_list", "storage_list"}) {
        auto h = silkworm::rlp::decode_header(psp);
        if (!h || !h->list) {
            err = std::string{"bad "} + name + " header";
            return false;
        }
        psp.remove_prefix(h->payload_length);
    }
    auto cl_h = silkworm::rlp::decode_header(psp);
    if (!cl_h) return true;
    ByteView cl = psp.substr(0, cl_h->payload_length);
    using silkworm::rlp::decode;
    using silkworm::rlp::Leftover;
    while (!cl.empty()) {
        evmc::bytes32 code_hash;
        Bytes code;
        if (!decode(cl, code_hash, Leftover::kAllow) || !decode(cl, code, Leftover::kAllow)) {
            err = "bad code entry";
            return false;
        }
        if (!code.empty()) out.emplace_back(code_hash, std::move(code));
    }
    return true;
}

// ancestors: a list whose entries are strings, each wrapping one header's RLP. Appends those
// header RLPs in file order. An empty or non-list section yields no headers.
inline bool parse_headers(ByteView ancestors_rlp, std::vector<ByteView>& out, std::string& err) {
    ByteView v = ancestors_rlp;
    if (v.empty()) return true;
    auto inner = silkworm::rlp::decode_header(v);
    if (!inner.has_value() || !inner->list) return true;
    ByteView lv = v.substr(0, inner->payload_length);
    while (!lv.empty()) {
        auto eh = silkworm::rlp::decode_header(lv);
        if (!eh.has_value()) {
            err = "bad ancestor entry";
            return false;
        }
        out.push_back(lv.substr(0, eh->payload_length));
        lv.remove_prefix(eh->payload_length);
    }
    return true;
}

}  // namespace zilkworm::legacy
