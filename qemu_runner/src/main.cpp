// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "./include/cppextern.hpp"
#include "./include/semihosting.hpp"
#include <cstdio>
#include <cstring>
#include <format>
#include <string>

// Shared buffer used for both batched-RLP and JSON inputs (sized for the larger of the two).
static char BUF[200 * 1024 * 1024];

namespace {

// Format byte prepended to `stdin_payload.bin` by the qemu_run_{rlp,json}.sh driver scripts.
// See `docs/architecture.md` "Transport variants".
constexpr char kFmtBatchedRlp = 'R';  // bundled unified RLP
constexpr char kFmtEestJson   = 'J';  // raw EEST JSON text

uint32_t read_u32_le(const char* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

// Per-subtest dispatch: returns ctest-style exit code.
int run_one(bool is_json, const char* p, std::size_t len, uint32_t idx) {
    std::string blob(p, p + len);
    const uint64_t rc = sample_run_wrapped(is_json, std::move(blob));
    sys_println(std::format("subtest {}: rc={}", idx, rc).c_str());
    return static_cast<int>(rc);
}

}  // namespace

int main(int argc, char* argv[])
{
    int h = sh::open_file_read("stdin_payload.bin");
    if (h < 0) {
        sys_println("Failed to open file stdin_payload.bin");
        sh::exit(1);
    }

    long flen = sh::flen(h);
    if (flen < 0) {
        sys_println("Failed to get stdin_payload.bin length");
        sh::exit(1);
    }
    if (static_cast<std::size_t>(flen) > sizeof(BUF)) {
        sys_println("stdin_payload.bin too large for BUF");
        sh::exit(1);
    }

    std::size_t got = sh::read_exact_handle(h, BUF, static_cast<std::size_t>(flen));
    if (got != static_cast<std::size_t>(flen)) {
        sys_println("Short read on stdin_payload.bin");
        sh::exit(1);
    }

    char info_buf[64];
    std::snprintf(info_buf, sizeof(info_buf), "Input file read length: %zu", got);
    sys_println(info_buf);

    if (got < 1) {
        sys_println("Empty stdin_payload.bin");
        sh::exit(1);
    }

    const char fmt = BUF[0];
    const char* p = BUF + 1;
    const char* end = BUF + got;

    bool any_failed = false;
    bool any_passed = false;

    if (fmt == kFmtEestJson) {
        std::size_t json_len = static_cast<std::size_t>(end - p);
        sys_println(std::format("input: JSON ({} bytes)", json_len).c_str());
        const int rc = run_one(/*is_json=*/true, p, json_len, 0);
        if (rc == 1) any_failed = true;
        else if (rc == 0) any_passed = true;
    } else if (fmt == kFmtBatchedRlp) {
        if (end - p < 4) {
            sys_println("Truncated batch header");
            sh::exit(1);
        }
        const uint32_t n = read_u32_le(p);
        p += 4;
        sys_println(std::format("input: batched RLP, {} subtests", n).c_str());
        for (uint32_t i = 0; i < n; i++) {
            if (p + 4 > end) {
                sys_println("Truncated batched-RLP item header");
                sh::exit(1);
            }
            const uint32_t len = read_u32_le(p);
            p += 4;
            if (p + len > end) {
                sys_println("Truncated batched-RLP item payload");
                sh::exit(1);
            }
            const int rc = run_one(/*is_json=*/false, p, len, i);
            p += len;
            if (rc == 1) any_failed = true;
            else if (rc == 0) any_passed = true;
        }
    } else {
        sys_println(std::format("Unknown stdin_payload.bin format byte {:#x}", static_cast<unsigned>(fmt) & 0xff).c_str());
        sh::exit(1);
    }

    // Aggregate per-subtest results into one process-level exit code.
    int exit_code;
    if (any_failed) exit_code = 1;
    else if (!any_passed) exit_code = 2;  // ctest SKIP_RETURN_CODE
    else exit_code = 0;

    sys_println(std::format("Run complete. exit={}", exit_code).c_str());
    sh::exit(exit_code);
}
