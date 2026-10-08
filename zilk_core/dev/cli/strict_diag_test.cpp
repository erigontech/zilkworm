// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The STRICT diagnostic of the EEST JSON runner (run_json_block's fail_strict) is built by string
// concatenation, not std::format, so the guest links no Ryu/unicode/locale code (about 190 KB of
// .rodata that is copied to RAM at the start of every block). Differential test against the
// std::format version it replaced: the bytes written for a rejected-but-unexpected block must be
// identical, for every rejection gate and for crafted and random expectation strings. Also checks
// that evmone's "advanced" option is still available in this native build (only the Airbender
// guest compiles it out, EVMONE_ADVANCED=0) and that the baseline interpreter runs (the "cgoto"
// option is covered by cmp_jumpi_fusion_test).

#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <evmc/mocked_host.hpp>
#include <evmone/evmone.h>
#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>

#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/types/block.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/dev/state_transition.hpp>

using silkworm::Bytes;
using silkworm::cmd::state_transition::StateTransition;

namespace {

struct CoutCapture {
    std::ostringstream buf;
    std::streambuf* old;
    CoutCapture() : old{std::cout.rdbuf(buf.rdbuf())} {}
    ~CoutCapture() { std::cout.rdbuf(old); }
    CoutCapture(const CoutCapture&) = delete;
    CoutCapture& operator=(const CoutCapture&) = delete;
};

std::string genesis_rlp_hex() {
    silkworm::Block genesis;
    genesis.header.gas_limit = 5000;
    genesis.header.difficulty = 1;
    genesis.header.ommers_hash = silkworm::kEmptyListHash;
    Bytes rlp;
    silkworm::rlp::encode(rlp, genesis);
    return silkworm::to_hex(rlp);
}

/// A block that decodes but cannot be inserted: its parent is not the genesis.
std::string orphan_block_rlp_hex() {
    silkworm::Block b;
    b.header.number = 1;
    b.header.gas_limit = 5000;
    b.header.difficulty = 1;
    b.header.ommers_hash = silkworm::kEmptyListHash;
    b.header.parent_hash.bytes[0] = 0xab;
    Bytes rlp;
    silkworm::rlp::encode(rlp, b);
    return silkworm::to_hex(rlp);
}

/// Runs one EEST-style blockchain test with a single block through StateTransition::run (the
/// guest's entry point for EJSN input) and returns what it printed.
std::string run_block(const std::string& block_rlp_hex, const std::string& expect_exception,
                      bool* failed = nullptr) {
    nlohmann::json block{{"rlp", block_rlp_hex}};
    if (!expect_exception.empty())
        block["expectException"] = expect_exception;
    const nlohmann::json doc{
        {"t", {{"network", "Frontier"},
               {"genesisRLP", genesis_rlp_hex()},
               {"pre", nlohmann::json::object()},
               {"blocks", nlohmann::json::array({block})}}}};
    const std::string json = doc.dump();

    std::vector<uint8_t> env(zilkworm::kInputHeaderSizeEJSN + json.size());
    const uint32_t magic = zilkworm::kInputMagicEJSN;
    const uint32_t version = zilkworm::kInputVersionEJSN;
    std::memcpy(env.data(), &magic, 4);
    std::memcpy(env.data() + 4, &version, 4);
    std::memcpy(env.data() + zilkworm::kInputHeaderSizeEJSN, json.data(), json.size());

    CoutCapture cap;
    StateTransition st{std::span<uint8_t>{env}};
    st.run();
    if (failed)
        *failed = st.failed();
    return cap.buf.str();
}

/// The line sys_println writes natively for the std::format diagnostic that fail_strict used to
/// print. sys_println takes a c_str(), so the text stops at the first NUL.
std::string old_diag_line(std::string_view mode, const std::string& expectation) {
    const std::string s = std::format("STRICT: rejected via {} but expected {}", mode, expectation);
    return "stdout: " + std::string(s.c_str()) + "\n";
}

bool contains_line(const std::string& out, const std::string& line) {
    return out.find(line) != std::string::npos;
}

// Expectations that no entry of the runner's exception map resolves for a pre-insert rejection.
const std::vector<std::string>& crafted_expectations() {
    static const std::vector<std::string> v{
        "TransactionException.NONCE_IS_MAX",
        "BlockException.INVALID_GASLIMIT|TransactionException.INSUFFICIENT_ACCOUNT_FUNDS",
        "X",
        "|",
        "||",
        "{}",
        "{0}{1}{",
        "}{",
        "100% done %s %d",
        "caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80",
        "tab\tnewline\ncr\r end",
        std::string("nul\0tail", 8),
        std::string(1000, 'x'),
        " leading and trailing ",
        "BlockException.",
        "unknown.EXCEPTION",
    };
    return v;
}

}  // namespace

TEST_CASE("STRICT diagnostic: bad-hex gate matches the std::format output byte for byte",
          "[strict_diag][state_transition]") {
    for (const auto& e : crafted_expectations()) {
        bool failed = false;
        const auto out = run_block("zz", e, &failed);
        CAPTURE(e);
        REQUIRE(failed);
        REQUIRE(contains_line(out, old_diag_line("bad-hex", e)));
    }
}

TEST_CASE("STRICT diagnostic: rlp-decode gate matches the std::format output byte for byte",
          "[strict_diag][state_transition]") {
    for (const auto& e : crafted_expectations()) {
        bool failed = false;
        const auto out = run_block("c0", e, &failed);  // valid hex, not a block
        CAPTURE(e);
        REQUIRE(failed);
        REQUIRE(contains_line(out, old_diag_line("rlp-decode", e)));
    }
}

TEST_CASE("STRICT diagnostic: validation gate prints the ValidationResult name",
          "[strict_diag][state_transition]") {
    const auto block = orphan_block_rlp_hex();
    // Learn the rejection from the run that does not expect it, then check the STRICT text.
    bool failed = false;
    const auto plain = run_block(block, "", &failed);
    REQUIRE(failed);
    const std::string prefix = "stdout: ERROR: validation error ";
    const auto at = plain.find(prefix);
    REQUIRE(at != std::string::npos);
    const auto name_begin = at + prefix.size();
    const std::string mode = plain.substr(name_begin, plain.find('\n', name_begin) - name_begin);
    REQUIRE(!mode.empty());
    REQUIRE(magic_enum::enum_cast<silkworm::ValidationResult>(mode).has_value());

    for (const auto& e : crafted_expectations()) {
        const auto out = run_block(block, e, &failed);
        CAPTURE(e, mode);
        REQUIRE(failed);
        REQUIRE(contains_line(out, old_diag_line(mode, e)));
    }
}

TEST_CASE("STRICT diagnostic: random expectation strings match the std::format output",
          "[strict_diag][state_transition]") {
    std::mt19937_64 rng{0x57121C7};
    for (int i = 0; i < 300; ++i) {
        // Valid UTF-8 only (the JSON layer rejects the rest): printable ASCII, control characters
        // other than NUL (except once in a while), '{', '}' and '%'.
        std::string e;
        const auto len = 1 + rng() % 120;
        for (uint64_t k = 0; k < len; ++k) {
            switch (rng() % 8) {
            case 0: e += "{}"[rng() % 2]; break;
            case 1: e += static_cast<char>(1 + rng() % 31); break;
            case 2: e += "\xc3\xa9"; break;
            case 3: e += "\xe2\x82\xac"; break;
            case 4: e += '|'; break;
            case 5: if (rng() % 16 == 0) e.push_back('\0'); else e += '%'; break;
            default: e += static_cast<char>(0x20 + rng() % 95); break;
            }
        }
        const char* modes[] = {"bad-hex", "rlp-decode"};
        const std::string mode = modes[rng() % 2];
        bool failed = false;
        const auto out = run_block(mode == "bad-hex" ? "zz" : "c0", e, &failed);
        CAPTURE(i, e, mode);
        REQUIRE(failed);
        REQUIRE(contains_line(out, old_diag_line(mode, e)));
    }
}

TEST_CASE("STRICT diagnostic: matching expectations still pass without a diagnostic",
          "[strict_diag][state_transition]") {
    // Mapped to the pre-insert reject marker, so a bad-hex block is a pass: no STRICT line.
    bool failed = true;
    const auto out = run_block("zz", "BlockException.INCORRECT_BLOCK_FORMAT", &failed);
    REQUIRE_FALSE(failed);
    REQUIRE(out.find("STRICT:") == std::string::npos);
}

TEST_CASE("evmone: the advanced option exists natively, the baseline interpreter runs",
          "[strict_diag][evmone]") {
    // Separate instance: the option switches the interpreter of the one it is set on.
    evmc::VM advanced_vm{evmc_create_evmone()};
    REQUIRE(advanced_vm.set_option("advanced", "") == EVMC_SET_OPTION_SUCCESS);

    evmc::VM vm{evmc_create_evmone()};
    REQUIRE(vm.set_option("not-an-option", "") == EVMC_SET_OPTION_INVALID_NAME);

    // PUSH1 7 PUSH1 0 MSTORE8 PUSH1 1 PUSH1 0 RETURN -> one byte 0x07.
    const uint8_t code[] = {0x60, 0x07, 0x60, 0x00, 0x53, 0x60, 0x01, 0x60, 0x00, 0xf3};
    evmc::MockedHost host;
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.gas = 100000;
    const auto r = vm.execute(host, EVMC_CANCUN, msg, code, sizeof(code));
    REQUIRE(r.status_code == EVMC_SUCCESS);
    REQUIRE(r.output_size == 1);
    REQUIRE(r.output_data[0] == 0x07);
    // 4 x PUSH1 (3) + MSTORE8 (3 + 3 memory expansion) + RETURN (0)
    REQUIRE(r.gas_left == 100000 - (3 * 4 + 3 + 3));
}
