// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <utility>

namespace silkworm {

// Warning: this version is only suitable for protecting lazy fields in a single-threaded environment.
// In a multi-threaded environment use the Abseil-based version above.
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
