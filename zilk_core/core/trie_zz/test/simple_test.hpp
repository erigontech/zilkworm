// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

namespace simple_test {

// ANSI color codes
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"

struct TestStats {
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;
    int total_checks = 0;
    int passed_checks = 0;
    int failed_checks = 0;
    bool test_should_abort = false;
};

static TestStats global_stats;
static const char* current_test_name = nullptr;
static const char* current_section_name = nullptr;

inline void print_result(bool condition, const char* expr, const char* file, int line) {
    global_stats.total_checks++;
    if (condition) {
        global_stats.passed_checks++;
    } else {
        global_stats.failed_checks++;
        printf(COLOR_RED "  ❌ CHECK FAILED: " COLOR_RESET "%s\n", expr);
        printf(COLOR_YELLOW "     at %s:%d" COLOR_RESET "\n", file, line);
    }
}

inline void require_result(bool condition, const char* expr, const char* file, int line) {
    global_stats.total_checks++;
    if (condition) {
        global_stats.passed_checks++;
    } else {
        global_stats.failed_checks++;
        printf(COLOR_RED "  ❌ REQUIRE FAILED: " COLOR_RESET "%s\n", expr);
        printf(COLOR_YELLOW "     at %s:%d" COLOR_RESET "\n", file, line);
        printf(COLOR_RED "  Aborting test." COLOR_RESET "\n");
        global_stats.test_should_abort = true;
    }
}

#define CHECK(expr) \
    simple_test::print_result((expr), #expr, __FILE__, __LINE__)

#define REQUIRE(expr)                                                   \
    do {                                                                \
        simple_test::require_result((expr), #expr, __FILE__, __LINE__); \
        if (simple_test::global_stats.test_should_abort) return;        \
    } while (0)

class TestCase {
  public:
    using TestFunc = std::function<void()>;

    TestCase(const char* name, TestFunc func) : name_(name), func_(func) {
        get_tests().push_back(this);
    }

    void run() {
        current_test_name = name_;
        current_section_name = nullptr;
        global_stats.total_tests++;
        global_stats.test_should_abort = false;

        printf("\n" COLOR_CYAN "▶ Running: " COLOR_RESET COLOR_BOLD "%s" COLOR_RESET "\n", name_);

        func_();

        if (global_stats.test_should_abort) {
            global_stats.failed_tests++;
            printf(COLOR_RED "  ✗ FAILED" COLOR_RESET "\n");
        } else {
            global_stats.passed_tests++;
            printf(COLOR_GREEN "  ✓ PASSED" COLOR_RESET "\n");
        }
    }

    static std::vector<TestCase*>& get_tests() {
        static std::vector<TestCase*> tests;
        return tests;
    }

    static int run_all() {
        printf("\n" COLOR_BOLD "═══════════════════════════════════════" COLOR_RESET "\n");
        printf(COLOR_BOLD COLOR_CYAN "  Simple Test Framework" COLOR_RESET "\n");
        printf(COLOR_BOLD "═══════════════════════════════════════" COLOR_RESET "\n");

        for (auto* test : get_tests()) {
            test->run();
        }

        printf("\n" COLOR_BOLD "═══════════════════════════════════════" COLOR_RESET "\n");
        printf(COLOR_BOLD COLOR_CYAN "  Test Summary" COLOR_RESET "\n");
        printf(COLOR_BOLD "═══════════════════════════════════════" COLOR_RESET "\n");

        if (global_stats.failed_tests > 0) {
            printf("  Tests:  %d total, " COLOR_GREEN "%d passed" COLOR_RESET ", " COLOR_RED "%d failed" COLOR_RESET "\n",
                   global_stats.total_tests,
                   global_stats.passed_tests,
                   global_stats.failed_tests);
        } else {
            printf("  Tests:  %d total, " COLOR_GREEN "%d passed" COLOR_RESET ", %d failed\n",
                   global_stats.total_tests,
                   global_stats.passed_tests,
                   global_stats.failed_tests);
        }

        if (global_stats.failed_checks > 0) {
            printf("  Checks: %d total, " COLOR_GREEN "%d passed" COLOR_RESET ", " COLOR_RED "%d failed" COLOR_RESET "\n",
                   global_stats.total_checks,
                   global_stats.passed_checks,
                   global_stats.failed_checks);
        } else {
            printf("  Checks: %d total, " COLOR_GREEN "%d passed" COLOR_RESET ", %d failed\n",
                   global_stats.total_checks,
                   global_stats.passed_checks,
                   global_stats.failed_checks);
        }

        printf(COLOR_BOLD "═══════════════════════════════════════" COLOR_RESET "\n");

        return global_stats.failed_tests > 0 ? 1 : 0;
    }

  private:
    const char* name_;
    TestFunc func_;
};

// Helper macro to expand __LINE__ properly
#define TEST_CASE_CONCAT_IMPL(a, b) a##b
#define TEST_CASE_CONCAT(a, b) TEST_CASE_CONCAT_IMPL(a, b)
#define TEST_CASE_UNIQUE(prefix) TEST_CASE_CONCAT(prefix, __LINE__)

#define TEST_CASE(name)                                                                            \
    static void TEST_CASE_UNIQUE(test_func_)();                                                    \
    static simple_test::TestCase TEST_CASE_UNIQUE(test_case_)(name, TEST_CASE_UNIQUE(test_func_)); \
    static void TEST_CASE_UNIQUE(test_func_)()

#define SECTION(name) \
    if (true) /* Allow section to create new scope */

}  // namespace simple_test