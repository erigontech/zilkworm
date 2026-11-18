// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <utility>

namespace silkworm {

// Single-threaded only; use the Abseil-based version above otherwise.
class ResettableOnceFlag {
  public:
    constexpr ResettableOnceFlag() = default;

    ResettableOnceFlag(const ResettableOnceFlag&) = default;
    ResettableOnceFlag& operator=(const ResettableOnceFlag&) = default;

    void reset() { done_ = false; }

    template <typename Callable, typename... Args>
    void call_once(Callable&& fn, Args&&... args) {
        if (!done_) {
            std::invoke(std::forward<Callable>(fn), std::forward<Args>(args)...);
            done_ = true;
        }
    }

  private:
    bool done_{false};
};

}  // namespace silkworm
