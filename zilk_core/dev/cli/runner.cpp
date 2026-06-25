// Copyright 2025 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

#include "../state_transition.hpp"
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>

using namespace silkworm::cmd::state_transition;

namespace {

int run_json_test_file(const std::string& file_path) {
    std::ifstream file(file_path);
    const auto input_str = std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    if (file.fail()) {
        throw std::runtime_error("Failed to read file: " + file_path);
    }
    std::cout << file_path << "\n";

    std::vector<uint8_t> envelope;
    envelope.resize(zilkworm::kInputHeaderSizeEJSN + input_str.size());
    const uint32_t magic = zilkworm::kInputMagicEJSN;
    const uint32_t version = zilkworm::kInputVersionEJSN;
    std::memcpy(envelope.data() + 0, &magic, sizeof(uint32_t));
    std::memcpy(envelope.data() + 4, &version, sizeof(uint32_t));
    std::memcpy(envelope.data() + zilkworm::kInputHeaderSizeEJSN,
                input_str.data(), input_str.size());

    auto state_transition = StateTransition(std::span<uint8_t>{envelope});
    const uint64_t rc = state_transition.run();
    if (rc == StateTransition::kRunFailure) return 1;
    if (rc == StateTransition::kRunSkipped) return 2;
    return 0;
}

int run_flat_bundle_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (file.fail()) {
        std::cerr << "Failed to read file: " << file_path << "\n";
        return 3;
    }
    std::vector<uint8_t> blob(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>{});

    auto state_transition = StateTransition(std::span<uint8_t>{blob});
    const uint64_t rc = state_transition.run();
    if (rc == StateTransition::kRunFailure) {
        std::cout << "FAIL: " << file_path << "\n";
        return 1;
    }
    if (rc == StateTransition::kRunSkipped) {
        std::cout << "SKIP: " << file_path << "\n";
        return 2;
    }
    std::cout << "Cumulative Gas Used: " << rc << "\n";
    return 0;
}

}  // namespace

int main(int argc, const char* argv[]) {
    try {
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <flatWitnessBundle.mfbd>|<test.json>|<test_dir>\n";
            return 1;
        }
        const std::string file_path = argv[1];

        if (std::filesystem::is_directory(file_path)) {
            bool any_failed = false;
            bool any_passed = false;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(file_path)) {
                const auto& path = entry.path();
                int rc = -1;
                if (path.extension() == ".json") {
                    rc = run_json_test_file(path.string());
                } else if (path.extension() == ".bin") {
                    std::cout << path << ":\n";
                    rc = run_flat_bundle_file(path.string());
                } else {
                    continue;
                }
                if (rc == 0) any_passed = true;
                else if (rc == 2) { /* skipped: neither pass nor fail */ }
                else any_failed = true;  // rc==1 (fail) or rc==3 (hard error)
            }
            if (any_failed) return 1;
            if (!any_passed) return 2;  // all skipped or empty: ctest SKIP_RETURN_CODE
            return 0;
        }

        if (file_path.ends_with(".json")) {
            return run_json_test_file(file_path);
        }

        return run_flat_bundle_file(file_path);
    } catch (const std::exception& e) {
        const auto desc = e.what();
        std::cerr << "Exception: " << desc << std::endl;
        return 3;
    } catch (...) {
        std::cerr << "An unknown exception occurred" << std::endl;
        return 4;
    }
    return 0;
}
