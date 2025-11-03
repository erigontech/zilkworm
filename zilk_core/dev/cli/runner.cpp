// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <filesystem>

// #include <CLI/CLI.hpp>

#include <fstream>

#include "../state_transition.hpp"

// void execute_test(const std::string& json_str, bool terminate_flag, bool diagnostics_flag);
using namespace silkworm::cmd::state_transition;

int main(int argc, const char* argv[]) {
    try {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " <num_runs> <json_file_path>\n";
            return 1;
        }

        const uint32_t num_runs = std::stoul(argv[1]);
        const std::string json_file_path = argv[2];
        std::cout << "n: " << num_runs << "\n";

        const std::string json_str = [](const std::string& path) {
            std::ifstream file(path);
            if (!file.is_open()) {
                throw std::runtime_error("Could not open file: " + path);
            }
            return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        }(json_file_path);
        auto state_transition = StateTransition(json_str, false, true);
        auto total_gas = state_transition.run(num_runs);
        std::cout << "Cumulative Gas Used: " << total_gas << "\n";

    } catch (const std::exception& e) {
        // code to handle exceptions of type std::exception and its derived classes
        const auto desc = e.what();
        std::cerr << "Exception: " << desc << std::endl;
    } catch (...) {
        // code to handle any other type of exception
        std::cerr << "An unknown exception occurred" << std::endl;
    }
}
