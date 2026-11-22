// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "assert.hpp"

#include <csignal>

#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("SILKWORM_ASSERT aborts when its expression is false", "[assert]") {
    const pid_t pid{fork()};
    REQUIRE(pid >= 0);
    if (pid == 0) {
        std::signal(SIGABRT, SIG_DFL);  // the child dies of the signal, unreported by Catch2
        SILKWORM_ASSERT(false);
        _exit(0);
    }
    int status{0};
    REQUIRE(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSIGNALED(status));
    CHECK(WTERMSIG(status) == SIGABRT);
}

}  // namespace silkworm
