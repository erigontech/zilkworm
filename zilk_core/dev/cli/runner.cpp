// Copyright 2025 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>

#include "../state_transition.hpp"

using namespace silkworm::cmd::state_transition;

namespace {

uint32_t read_u32_le(const uint8_t*& p, const uint8_t* end) {
    if (p + 4 > end) throw std::runtime_error("truncated batched-RLP framing");
    uint32_t v;
    std::memcpy(&v, p, 4);
    p += 4;
    return v;
}

// Single raw unified-RLP blob (no bundle). Ad-hoc debugging path, see `docs/architecture.md` "Transport variants".
int run_unified_rlp(std::string input_str) {
    auto state_transition = StateTransition(std::move(input_str));
    const auto gas = state_transition.run_rlp();
    if (gas == StateTransition::kRunFailure) return 1;
    if (gas == StateTransition::kRunSkipped) return 2;
    std::cout << "Cumulative Gas Used: " << gas << "\n";
    return 0;
}

// EEST JSON test fixture.
int run_json_test_file(const std::string& input_str) {
    constexpr bool terminate_on_error = false;
    constexpr bool show_diagnostics = true;
    auto state_transition = StateTransition(input_str, terminate_on_error, show_diagnostics);
    const auto rc = state_transition.run();
    if (rc == StateTransition::kRunFailure) return 1;
    if (rc == StateTransition::kRunSkipped) return 2;
    return 0;
}

// Unified-RLP bundle: each item is a unified-RLP blob (see `docs/architecture.md` "Bundle format").
int run_unified_rlp_bundle(const std::string& input_str) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(input_str.data());
    const uint8_t* end = p + input_str.size();
    const uint32_t n = read_u32_le(p, end);
    bool any_failed = false;
    bool any_passed = false;
    uint64_t cumulative_gas = 0;
    for (uint32_t i = 0; i < n; i++) {
        const uint32_t len = read_u32_le(p, end);
        if (p + len > end) throw std::runtime_error("truncated batched-RLP item");
        std::string blob(reinterpret_cast<const char*>(p), len);
        p += len;
        auto st = StateTransition(std::move(blob));
        const uint64_t gas = st.run_rlp();
        if (gas == StateTransition::kRunFailure) {
            any_failed = true;
        } else if (gas == StateTransition::kRunSkipped) {
            // skip — neither pass nor fail
        } else {
            cumulative_gas += gas;
            any_passed = true;
        }
    }
    if (any_failed) return 1;
    if (!any_passed) return 2;  // all skipped (or N=0): ctest SKIP_RETURN_CODE
    std::cout << "Cumulative Gas Used: " << cumulative_gas << "\n";
    return 0;
}

}  // namespace

int main(int argc, const char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <path>|-\n"
                      << "       `.rlp`  → bundled unified RLP (see docs/architecture.md \"Bundle format\").\n"
                      << "       `.json` → EEST JSON fixture, parsed in-process.\n"
                      << "       Anything else (including stdin `-`) is one raw unified-RLP blob.\n";
            return 1;
        }
        const std::string file_path = argv[1];

        enum class Mode { RawRlp, BundleRlp, Json } mode = Mode::RawRlp;
        std::string input_str;
        if (file_path == "-") {
            std::ios_base::sync_with_stdio(false);
            input_str.assign(std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>());
        } else {
            std::ifstream file(file_path, std::ios::binary);
            input_str.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
            if (file.fail()) {
                throw std::runtime_error("Failed to read file: " + file_path);
            }
            if (file_path.ends_with(".rlp")) mode = Mode::BundleRlp;
            else if (file_path.ends_with(".json")) mode = Mode::Json;
        }
        switch (mode) {
            case Mode::Json:      return run_json_test_file(input_str);
            case Mode::BundleRlp: return run_unified_rlp_bundle(input_str);
            case Mode::RawRlp:    return run_unified_rlp(std::move(input_str));
        }
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 3;
    } catch (...) {
        std::cerr << "An unknown exception occurred" << std::endl;
        return 4;
    }
    return 0;
}
