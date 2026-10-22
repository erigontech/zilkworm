// Copyright 2026 The Zilkworm Authors (modifications)
// SPDX-License-Identifier: Apache-2.0
//
// Guest-side phase attribution (enabled with -DZ6M_PHASE_TRACE, profiling builds only).
// Emits the SP1 executor's cycle-tracker-report protocol lines on stdout:
//   cycle-tracker-report-start: <label> / cycle-tracker-report-end: <label>
// The executor accumulates the cycles between the two writes into
// ExecutionReport.cycle_tracker[label] (see sp1 core/executor/src/minimal/write.rs), so a
// 1-block execute run reports exact per-phase guest cycle counts. Each marker is one
// syscall_write (a few dozen cycles), so keep labels coarse (phase level, not per call).

#pragma once

#include <string>

#include <zilk_core/print.hpp>

#ifdef Z6M_PHASE_TRACE

namespace z6m::phase {

struct Scope {
    const char* label_;
    explicit Scope(const char* label) : label_{label} {
        sys_println((std::string{"cycle-tracker-report-start: "} + label_).c_str());
    }
    ~Scope() {
        sys_println((std::string{"cycle-tracker-report-end: "} + label_).c_str());
    }
    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;
};

}  // namespace z6m::phase

#define Z6M_PHASE_CONCAT2(a, b) a##b
#define Z6M_PHASE_CONCAT(a, b)  Z6M_PHASE_CONCAT2(a, b)
#define Z6M_PHASE(label)                                                    \
    [[maybe_unused]] ::z6m::phase::Scope Z6M_PHASE_CONCAT(z6m_phase_, __LINE__){label}

#else

#define Z6M_PHASE(label) ((void)0)

#endif  // Z6M_PHASE_TRACE
