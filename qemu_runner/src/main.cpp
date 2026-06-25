// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "./include/cppextern.hpp"
#include <algorithm>
#include <cstdio>
#include <string>
#include "./include/semihosting.hpp"
#include <format>

static char ENV_BUF[200 * 1024 * 1024];

int main(int /*argc*/, char* /*argv*/[])
{
    int h = sh::open_file_read("stdin_payload.bin");
    if (h < 0)
    {
        sys_println("Failed to open file stdin_payload");
        sh::exit(1);
    }

    std::size_t total = 0;
    constexpr std::size_t kChunk = 64 * 1024;
    while (total < sizeof(ENV_BUF))
    {
        const std::size_t want = std::min<std::size_t>(kChunk, sizeof(ENV_BUF) - total);
        const std::size_t got = sh::read_handle(h, ENV_BUF + total, want);
        if (got == 0)
            break;
        total += got;
    }

    if (total == sizeof(ENV_BUF))
    {
        sys_println("Payload exceeded ENV_BUF capacity");
        sh::exit(1);
    }

    std::string envelope_str(ENV_BUF, ENV_BUF + total);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "Input envelope size: %zu", envelope_str.size());
    sys_println(buf);
    const uint64_t res = sample_run_wrapped(envelope_str);

    sys_println(std::format("Run complete. Result: {}", res));
    sh::exit(static_cast<int>(res));
}
